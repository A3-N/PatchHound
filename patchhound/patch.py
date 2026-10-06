#!/usr/bin/env python3
import hashlib
import os
import re
import sys
import threading
import time
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

import requests

from patchhound.api import (
    extract_error_message,
    load_session,
    pretty_json,
    redact_secret,
    redact_token,
)
from patchhound.conn import DEFAULT_PASS, DEFAULT_URI, DEFAULT_USER
from patchhound.credentials import (
    analyze_ntlm_file,
    analyze_potfile,
    check_file,
)
from patchhound.identity import build_target_index, match_rows
from patchhound.pwetty import YELLOW, paint, progress_bar
from patchhound.pwetty import markers as make_markers

NEO4J_UPDATE_BATCH = 5000
MANAGED_SELECTOR_PREFIX = "PatchHound Owned"


def _print_json_block(markers, label: str, value) -> None:
    print(f"{markers['info']} {label}:")
    for line in pretty_json(value).splitlines():
        print(f"    {line}")


def _verbose_hint(verbose: bool, nocolor: bool) -> str:
    if verbose:
        return ""
    return f" use {paint('(-v)', YELLOW, nocolor)}"


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from exc
    if value < minimum:
        raise RuntimeError(f"{name} must be at least {minimum}, got {value}")
    return value


def _env_float(name: str, default: float, minimum: float = 0.0) -> float:
    raw = os.getenv(name, str(default))
    try:
        value = float(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a number, got {raw!r}") from exc
    if value < minimum:
        raise RuntimeError(f"{name} must be at least {minimum}, got {value}")
    return value


def _progress(done: int, total: int, prefix: str, nocolor: bool):
    bar, pct = progress_bar(done, total, nocolor, width=28)
    sys.stdout.write(f"\r{prefix} [{bar}] {done}/{total} ({pct}%)")
    sys.stdout.flush()
    if done >= total:
        sys.stdout.write("\n")
        sys.stdout.flush()


def _collect_neo4j_target_index(session):
    domain_query = """
    MATCH (d:Domain)
    RETURN d.name AS name,
           d.domain AS domain,
           d.netbios AS netbios
    """
    node_query = """
    MATCH (n)
    WHERE n:User OR n:Computer
    RETURN labels(n) AS labels,
           n.objectid AS objectid,
           n.name AS name,
           n.domain AS domain,
           n.distinguishedname AS distinguishedname,
           n.samaccountname AS sam,
           coalesce(n.userprincipalname, n.userPrincipalName) AS upn
    """
    domains = [record.data() for record in session.run(domain_query)]
    nodes = (record.data() for record in session.run(node_query))
    return build_target_index(domains, nodes)


def _apply_updates(session, rows: list[dict[str, object]], write_credentials: bool) -> int:
    query = """
    UNWIND $rows AS r
    MATCH (n:__LABEL__ {objectid:r.objectid})
    SET n.Patchhound_has_hash = true,
        n.Patchhound_has_pass = r.pwd IS NOT NULL
    FOREACH (_ IN CASE WHEN $write_credentials THEN [1] ELSE [] END |
        SET n.Patchhound_nt = r.nt,
            n.Patchhound_pass = r.pwd
    )
    RETURN count(DISTINCT n) AS updated
    """
    updated = 0
    for kind in ("User", "Computer"):
        kind_rows = [row for row in rows if row.get("kind") == kind]
        if not kind_rows:
            continue
        result = session.run(
            query.replace("__LABEL__", kind),
            rows=kind_rows,
            write_credentials=write_credentials,
        ).single()
        updated += int(result["updated"] or 0) if result else 0
    return updated


def _collect_owned_candidate_sids(
    session, updates: list[dict[str, object]]
) -> tuple[list[dict[str, str]], int, set]:
    """Return cracked users, hybrid-link count, and all processed user SIDs."""

    by_sid = {}
    for row in updates:
        if row.get("kind") != "User":
            continue
        sid = str(row.get("objectid") or "").strip()
        if sid:
            by_sid[sid.casefold()] = {
                "sid": sid,
                "name": str(row.get("target_name") or sid),
                "owned": row.get("pwd") is not None,
            }
    processed_sids = {item["sid"].upper() for item in by_sid.values()}
    candidates = sorted(
        ({"sid": item["sid"], "name": item["name"]} for item in by_sid.values() if item["owned"]),
        key=lambda item: item["sid"].casefold(),
    )
    if not candidates:
        return [], 0, processed_sids

    query = """
    UNWIND $sids AS sid
    MATCH (u:User {objectid:sid})
    OPTIONAL MATCH (u)-[:SyncedToEntraUser]->(az:AZUser)
    WITH sid, count(az) AS hits
    RETURN count(CASE WHEN hits > 0 THEN 1 END) AS linked
    """
    record = session.run(query, sids=[item["sid"] for item in candidates]).single()
    linked = int(record["linked"] or 0) if record else 0
    return candidates, linked, processed_sids


class _RateLimiter:
    def __init__(self, min_interval: float):
        self.min_interval = max(0.0, float(min_interval or 0.0))
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self):
        with self._lock:
            now = time.monotonic()
            sleep_for = self._next_allowed - now
            if sleep_for > 0:
                time.sleep(sleep_for)
                now = time.monotonic()
            self._next_allowed = max(self._next_allowed, now) + self.min_interval

    def defer(self, seconds: float):
        """Pause all workers after the API reports a shared rate limit."""
        with self._lock:
            self._next_allowed = max(self._next_allowed, time.monotonic() + max(0.0, seconds))


def _batched_selector_payload(
    entries: list[dict[str, str]], batch_index: int
) -> tuple[str, dict[str, object]]:
    sids = sorted({str(entry["sid"]).upper() for entry in entries})
    digest_input = "\n".join(sids)
    digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:12]
    safe_name = f"{MANAGED_SELECTOR_PREFIX} {batch_index:06d} {digest}"
    seeds = [{"type": 1, "value": sid} for sid in sids]
    return safe_name, {"name": safe_name, "seeds": seeds}


def _retry_after(resp, fallback: float) -> float:
    raw = resp.headers.get("Retry-After") if resp is not None else None
    if raw:
        try:
            return max(0.0, float(raw))
        except ValueError:
            try:
                retry_at = parsedate_to_datetime(raw)
                if retry_at.tzinfo is None:
                    retry_at = retry_at.replace(tzinfo=UTC)
                return max(0.0, (retry_at - datetime.now(UTC)).total_seconds())
            except (TypeError, ValueError, OverflowError):
                pass
    return fallback


def _selector_sids(selector: dict) -> set:
    sids = set()
    for seed in selector.get("seeds") or []:
        if not isinstance(seed, dict):
            continue
        value = seed.get("value")
        if isinstance(value, str) and value.upper().startswith("S-1-"):
            sids.add(value.upper())
    return sids


def _selector_page(body) -> tuple[list[dict], int | None]:
    data = body.get("data") if isinstance(body, dict) else body
    if isinstance(data, dict):
        items = data.get("selectors") or []
        total = body.get("count", data.get("count"))
    elif isinstance(data, list):
        items = data
        total = body.get("count") if isinstance(body, dict) else None
    else:
        items = []
        total = None
    return [item for item in items if isinstance(item, dict)], total


def _fetch_existing_owned_selectors(
    base_url: str,
    token: str,
    tag_id: int,
    markers,
    verbose: bool,
    limiter: _RateLimiter | None = None,
    max_retries: int = 6,
) -> list[dict] | None:
    """Read selector metadata required for a safe managed-state reconciliation."""
    url = f"{base_url.rstrip('/')}/api/v2/asset-group-tags/{tag_id}/selectors"
    headers = {"Authorization": f"Bearer {token}", "accept": "application/json"}
    selectors = []
    skip = 0
    limit = 1000
    limiter = limiter or _RateLimiter(0)
    max_retries = max(1, int(max_retries or 1))

    while True:
        resp = None
        for attempt in range(max_retries):
            try:
                limiter.wait()
                resp = requests.get(
                    url,
                    headers=headers,
                    params={"skip": skip, "limit": limit},
                    timeout=30,
                )
            except requests.RequestException as exc:
                if attempt < max_retries - 1:
                    time.sleep(min(2**attempt, 16))
                    continue
                print(f"{markers['warn']} Owned API: could not query existing selectors: {exc}")
                return None

            if resp.status_code == 429 and attempt < max_retries - 1:
                limiter.defer(_retry_after(resp, min(2**attempt, 16)))
                continue
            if resp.status_code in (500, 502, 503, 504) and attempt < max_retries - 1:
                time.sleep(min(2**attempt, 16))
                continue
            break

        if resp is None:
            return None

        if resp.status_code in (404, 405):
            print(
                f"{markers['warn']} Owned API: selector inventory is unavailable "
                f"({resp.status_code})"
            )
            return None
        if resp.status_code >= 400:
            print(
                f"{markers['warn']} Owned API: selector inventory failed "
                f"({resp.status_code}): {extract_error_message(resp)}"
            )
            return None

        try:
            body = resp.json()
        except ValueError:
            print(f"{markers['warn']} Owned API: selector inventory returned non-JSON")
            return None

        items, total = _selector_page(body)
        selectors.extend(items)
        page_size = len(items)
        skip += page_size
        if page_size == 0:
            break
        if total is not None and skip >= int(total):
            break
        if total is None and page_size < limit:
            break

    if verbose:
        print(f"{markers['info']} Owned API: read {len(selectors)} existing selector(s)")
    return selectors


def _managed_selector_slot(name: str) -> int | None:
    if not str(name).startswith(f"{MANAGED_SELECTOR_PREFIX} "):
        return None
    match = re.search(r"(?:^| )(\d{6})(?: [0-9a-fA-F]{12})?$", str(name))
    return int(match.group(1)) if match else None


def _plan_owned_selector_sync(
    base_url: str,
    tag_id: int,
    candidates: list[dict[str, str]],
    seeds_per_selector: int,
    existing: list[dict],
) -> tuple[list[dict], list[dict], int]:
    """Plan a stable reconciliation that changes as few batches as possible."""
    collection_url = f"{base_url.rstrip('/')}/api/v2/asset-group-tags/{tag_id}/selectors"
    seeds_per_selector = max(1, int(seeds_per_selector or 1))
    managed = []
    used_slots = set()
    for selector in existing:
        selector_id = selector.get("id")
        slot = _managed_selector_slot(selector.get("name") or "")
        if selector_id is None or slot is None:
            continue
        while slot in used_slots:
            slot += 1
        used_slots.add(slot)
        managed.append(
            {
                "id": selector_id,
                "slot": slot,
                "name": str(selector.get("name") or ""),
                "sids": _selector_sids(selector),
            }
        )
    managed.sort(key=lambda selector: (selector["slot"], str(selector["id"])))

    desired_sids = sorted({str(entry["sid"]).upper() for entry in candidates})
    desired_set = set(desired_sids)
    assigned = set()
    retained_by_selector = []
    for selector in managed:
        # Honor a smaller configured batch size on later runs. Overflow stays
        # unassigned so it can be retained by a later selector or placed in a
        # new one; this avoids silently keeping an oversized API payload.
        retained = sorted((selector["sids"] & desired_set) - assigned)[:seeds_per_selector]
        assigned.update(retained)
        retained_by_selector.append((selector, retained))

    remaining = [sid for sid in desired_sids if sid not in assigned]
    upserts = []
    deletes = []
    unchanged_seeds = 0
    for selector, retained in retained_by_selector:
        capacity = max(0, seeds_per_selector - len(retained))
        target_sids = retained + remaining[:capacity]
        del remaining[:capacity]

        if not target_sids:
            deletes.append(
                {
                    "method": "DELETE",
                    "url": f"{collection_url}/{selector['id']}",
                    "name": selector["name"],
                    "payload": None,
                    "seed_count": len(selector["sids"]),
                    "success": "deleted",
                }
            )
            continue

        # Preserve the selector's stable slot even when earlier batches change.
        name, payload = _batched_selector_payload(
            [{"sid": sid} for sid in target_sids], selector["slot"]
        )
        if selector["name"] == name and selector["sids"] == set(target_sids):
            unchanged_seeds += len(target_sids)
            continue
        upserts.append(
            {
                "name": name,
                "payload": payload,
                "seed_count": len(target_sids),
                "batch_index": selector["slot"],
                "method": "PATCH",
                "url": f"{collection_url}/{selector['id']}",
                "success": "updated",
            }
        )

    next_slot = 1
    while remaining:
        while next_slot in used_slots:
            next_slot += 1
        chunk = remaining[:seeds_per_selector]
        del remaining[:seeds_per_selector]
        used_slots.add(next_slot)
        name, payload = _batched_selector_payload([{"sid": sid} for sid in chunk], next_slot)
        upserts.append(
            {
                "name": name,
                "payload": payload,
                "seed_count": len(chunk),
                "batch_index": next_slot,
                "method": "POST",
                "url": collection_url,
                "success": "created",
            }
        )
        next_slot += 1

    return upserts, deletes, unchanged_seeds


def _send_owned_selector(
    headers: dict[str, str], item: dict[str, object], limiter: _RateLimiter, max_retries: int
) -> dict[str, object]:
    safe_name = str(item.get("name") or "PatchHound Owned")
    seed_count = int(item.get("seed_count") or 0)
    rate_limited = 0
    method = str(item["method"])
    kwargs = {"headers": headers, "timeout": 30}
    if item.get("payload") is not None:
        kwargs["json"] = item["payload"]

    for attempt in range(max_retries):
        try:
            limiter.wait()
            resp = requests.request(method, item["url"], **kwargs)
        except requests.RequestException as e:
            if attempt < max_retries - 1:
                time.sleep(min(2**attempt, 16))
                continue
            return {
                "status": "failed",
                "name": safe_name,
                "error": str(e),
                "seed_count": seed_count,
            }

        if resp.status_code in (200, 201, 202, 204):
            return {
                "status": item["success"],
                "name": safe_name,
                "rate_limited": rate_limited,
                "seed_count": seed_count,
            }
        if method == "DELETE" and resp.status_code == 404:
            return {
                "status": "deleted",
                "name": safe_name,
                "rate_limited": rate_limited,
                "seed_count": seed_count,
            }
        if resp.status_code == 429:
            rate_limited += 1
            if attempt < max_retries - 1:
                retry_delay = _retry_after(resp, min(2**attempt, 16))
                limiter.defer(retry_delay)
                continue
        if resp.status_code in (500, 502, 503, 504) and attempt < max_retries - 1:
            time.sleep(min(2**attempt, 16))
            continue
        return {
            "status": "failed",
            "name": safe_name,
            "http_status": resp.status_code,
            "error": extract_error_message(resp),
            "rate_limited": rate_limited,
            "seed_count": seed_count,
        }

    return {
        "status": "failed",
        "name": safe_name,
        "error": "retry budget exhausted",
        "seed_count": seed_count,
    }


def _run_owned_operations(
    operations: list[dict],
    headers: dict[str, str],
    workers: int,
    limiter: _RateLimiter,
    max_retries: int,
    markers,
    verbose: bool,
    nocolor: bool,
) -> dict[str, int]:
    counts = {
        "created": 0,
        "updated": 0,
        "deleted": 0,
        "failed": 0,
        "rate_limited": 0,
        "requests": 0,
    }
    if not operations:
        return counts

    pending = set()
    iterator = iter(operations)
    max_pending = max(workers * 8, workers)

    def submit_more(executor):
        while len(pending) < max_pending:
            try:
                item = next(iterator)
            except StopIteration:
                break
            pending.add(executor.submit(_send_owned_selector, headers, item, limiter, max_retries))

    done = 0
    failures_seen = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        submit_more(executor)
        while pending:
            finished, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in finished:
                try:
                    result = future.result()
                except Exception as e:
                    result = {
                        "status": "failed",
                        "name": "(worker)",
                        "error": str(e),
                        "seed_count": 0,
                    }

                status = str(result.get("status") or "failed")
                seed_count = int(result.get("seed_count") or 0)
                if status == "failed":
                    counts["failed"] += max(seed_count, 1)
                else:
                    counts[status] += seed_count
                counts["rate_limited"] += int(result.get("rate_limited") or 0)
                counts["requests"] += 1
                done += 1
                if status == "failed":
                    failures_seen += 1
                    code = result.get("http_status")
                    suffix = f" ({code})" if code else ""
                    if verbose or failures_seen <= 20:
                        print(
                            f"\n{markers['warn']} Owned API{suffix} for "
                            f"{result.get('name')}: {result.get('error') or 'Error'}"
                        )
                _progress(done, len(operations), "Owned API requests", nocolor)
            submit_more(executor)
    if failures_seen > 20 and not verbose:
        print(
            f"{markers['warn']} Owned API: suppressed "
            f"{failures_seen - 20} additional failure message(s); use -v to show all"
        )
    return counts


def _append_owned_selectors(
    base_url: str,
    token: str,
    tag_id: int,
    candidates: list[dict[str, str]],
    markers,
    verbose: bool,
    workers: int = 4,
    rate_delay: float = 0.0,
    max_retries: int = 6,
    seeds_per_selector: int = 500,
    processed_sids: set | None = None,
    nocolor: bool = False,
) -> dict[str, int]:
    """Reconcile PatchHound-managed selectors with this run's cracked AD users."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    unique = {
        str(entry["sid"]).upper(): {
            "sid": str(entry["sid"]).upper(),
            "name": str(entry.get("name") or entry["sid"]),
        }
        for entry in candidates
    }
    workers = max(1, int(workers or 1))
    rate_delay = max(0.0, float(rate_delay or 0.0))
    max_retries = max(1, int(max_retries or 1))
    limiter = _RateLimiter(rate_delay)
    existing = _fetch_existing_owned_selectors(
        base_url,
        token,
        tag_id,
        markers,
        verbose,
        limiter=limiter,
        max_retries=max_retries,
    )
    if existing is None:
        return {
            "attempted": len(candidates),
            "selector_requests": 0,
            "selector_request_total": 0,
            "added": 0,
            "updated": 0,
            "removed": 0,
            "exists": 0,
            "failed": len(candidates) or 1,
            "rate_limited": 0,
        }

    # A SID absent from successfully written rows is not safe to remove: it
    # may belong to an unmapped account or a partial input. SIDs that were
    # processed this run are authoritative and are retained only when their
    # current hash is cracked.
    if processed_sids is not None:
        processed = {str(sid).upper() for sid in processed_sids}
        for selector in existing:
            if _managed_selector_slot(selector.get("name") or "") is None:
                continue
            for sid in _selector_sids(selector):
                if sid not in processed:
                    unique.setdefault(sid, {"sid": sid, "name": sid})

    candidates = sorted(unique.values(), key=lambda entry: str(entry["sid"]))
    existing_managed_sids = {
        sid
        for selector in existing
        if _managed_selector_slot(selector.get("name") or "") is not None
        for sid in _selector_sids(selector)
    }
    desired_sids = {str(entry["sid"]).upper() for entry in candidates}
    added_sids = len(desired_sids - existing_managed_sids)
    removed_sids = len(existing_managed_sids - desired_sids)
    upserts, deletes, unchanged = _plan_owned_selector_sync(
        base_url, tag_id, candidates, seeds_per_selector, existing
    )
    if verbose:
        _print_json_block(
            markers,
            "Owned reconciliation plan",
            {
                "tag_id": tag_id,
                "candidate_sids": len(candidates),
                "existing_selectors": len(existing),
                "managed_selectors": sum(
                    _managed_selector_slot(selector.get("name") or "") is not None
                    for selector in existing
                ),
                "seeds_per_selector": seeds_per_selector,
                "workers": workers,
                "minimum_request_interval_seconds": rate_delay,
                "maximum_attempts_per_request": max_retries,
                "unchanged_seeds": unchanged,
                "upsert_requests": len(upserts),
                "delete_requests": len(deletes),
                "operation_sample": [
                    {
                        "method": item["method"],
                        "url": item["url"],
                        "name": item["name"],
                        "seed_count": item["seed_count"],
                    }
                    for item in (upserts + deletes)[:10]
                ],
            },
        )
    upsert_counts = _run_owned_operations(
        upserts, headers, workers, limiter, max_retries, markers, verbose, nocolor
    )

    # Only remove obsolete selectors after every desired batch is safely in
    # place. A partial upsert therefore leaves stale ownership rather than
    # accidentally dropping current ownership.
    if upsert_counts["failed"]:
        delete_counts = {
            "created": 0,
            "updated": 0,
            "deleted": 0,
            "failed": 0,
            "rate_limited": 0,
            "requests": 0,
        }
        if deletes:
            print(
                f"{markers['warn']} Owned API: retaining {len(deletes)} obsolete "
                "selector(s) because an upsert failed"
            )
    else:
        delete_counts = _run_owned_operations(
            deletes, headers, workers, limiter, max_retries, markers, verbose, nocolor
        )

    failed = upsert_counts["failed"] + delete_counts["failed"]
    requests_done = upsert_counts["requests"] + delete_counts["requests"]
    request_total = len(upserts) + len(deletes)
    rate_limited = upsert_counts["rate_limited"] + delete_counts["rate_limited"]
    applied_added = added_sids if upsert_counts["failed"] == 0 else 0
    applied_removed = removed_sids if failed == 0 else 0

    print(
        f"{markers['ok']} Owned API: current {len(candidates)} seed(s), "
        f"unchanged {unchanged}, added {applied_added}, "
        f"updated seeds {upsert_counts['updated']}, removed {applied_removed}, "
        f"requests {requests_done}/{request_total}, failed {failed}, "
        f"429 retries {rate_limited}"
    )
    return {
        "attempted": len(candidates),
        "selector_requests": requests_done,
        "selector_request_total": request_total,
        "added": applied_added,
        "updated": upsert_counts["updated"],
        "removed": applied_removed,
        "exists": unchanged,
        "failed": failed,
        "rate_limited": rate_limited,
    }


def _print_samples(label: str, samples: list[str], total: int) -> None:
    print(f"    {label} (showing {len(samples)} of {total}):")
    for sample in samples:
        print(f"      - {sample}")
    if total > len(samples):
        print(f"      ... ({total - len(samples)} more)")


def _print_pot_stats(markers, stats, verbose: bool):
    if not verbose:
        print(f"{markers['ok']} Potfile Check")
        return

    keys = (
        "lines_total",
        "entries_total",
        "valid_entries",
        "excluded_count",
        "ntlm32_valid",
        "hex_wrapped",
        "hex_decoded",
        "unique_hashes",
    )
    _print_json_block(markers, "Potfile statistics", {key: stats[key] for key in keys})
    _print_samples("excluded_lines", stats.get("excluded_lines", []), stats["excluded_count"])
    _print_samples(
        "hex_decoded_lines (hash:$HEX:password)",
        stats.get("hex_decoded_lines", []),
        stats["hex_decoded"],
    )


def _print_nt_stats(markers, stats, verbose: bool):
    if not verbose:
        print(f"{markers['ok']} NTLM Check")
        return

    keys = (
        "lines_total",
        "lines_with_hash",
        "hashes_total",
        "unique_hashes",
        "valid_records",
        "current_accounts",
        "excluded_count",
    )
    _print_json_block(markers, "NTLM statistics", {key: stats[key] for key in keys})
    _print_samples("excluded_lines", stats.get("excluded_lines", []), stats["excluded_count"])


def _reason_summary(rows: list[dict[str, object]]) -> str:
    counts = _reason_counts(rows)
    return ", ".join(f"{reason}={count}" for reason, count in sorted(counts.items()))


def _reason_counts(rows: list[dict[str, object]]) -> dict[str, int]:
    return dict(Counter(str(row.get("match_reason") or "unspecified") for row in rows))


def run(args, markers=None, no_color=False) -> bool:
    nocolor = bool(no_color or getattr(args, "no_color", False))
    verbose = bool(getattr(args, "verbose", False))
    write_credentials = bool(getattr(args, "tag", False))
    do_owned = bool(getattr(args, "owned", False))

    if markers is None:
        markers = make_markers(nocolor)

    base_url = None
    token = None
    owned_result = None
    if do_owned:
        try:
            base_url, token = load_session()
        except RuntimeError as e:
            print(f"{markers['warn']} {e}")
            return False

        url = f"{base_url.rstrip('/')}/api/version"
        headers = {
            "accept": "application/json",
            "Prefer": "wait=0",
            "Authorization": f"Bearer {token}",
        }

        if verbose:
            print(f"{markers['info']} Verifying token via {url}")
            redacted_headers = dict(headers)
            redacted_headers["Authorization"] = "Bearer " + redact_token(token)
            _print_json_block(markers, "Request headers", redacted_headers)

        try:
            resp = requests.get(url, headers=headers, timeout=15)
        except requests.RequestException as e:
            print(f"{markers['warn']} Request failed: {e}")
            return False

        if verbose:
            status_marker = markers["ok"] if resp.status_code < 400 else markers["warn"]
            print(f"{status_marker} Response status: {resp.status_code}")
            try:
                _print_json_block(markers, "Response JSON", resp.json())
            except ValueError:
                print(f"{markers['info']} Response (non-JSON):\n{resp.text}")

        if resp.status_code != 200:
            print(f"{markers['warn']} {extract_error_message(resp)}")
            return False

        if verbose:
            print(f"{markers['info']} Using session token: {redact_token(token)}")
            print(f"{markers['info']} Base URL: {base_url}")
        else:
            print(f"{markers['ok']} JWT valid")

    clears = getattr(args, "clears", None)
    ntlm = getattr(args, "ntlm", None)

    try:
        check_file(clears, "Clears file")
        check_file(ntlm, "NTLM file")
    except RuntimeError as e:
        print(f"{markers['warn']} {e}")
        return False

    if verbose:
        _print_json_block(markers, "Input files", {"potfile": clears, "ntlm": ntlm})

    pot_stats = analyze_potfile(clears)
    cracked_map: dict[str, str] = pot_stats.pop("_cracked_map")
    _print_pot_stats(markers, pot_stats, verbose)

    nt_stats = analyze_ntlm_file(ntlm)
    _print_nt_stats(markers, nt_stats, verbose)

    if pot_stats["valid_entries"] == 0:
        print(f"{markers['warn']} potfile appears to have no usable NTLM entries (32-hex)")
    if nt_stats["current_accounts"] == 0:
        print(f"{markers['warn']} NTLM file contains no valid account records")
        return False

    db_uri = getattr(args, "db_uri", None) or DEFAULT_URI
    db_user = getattr(args, "db_user", None) or DEFAULT_USER
    db_pass = getattr(args, "db_pass", None) or DEFAULT_PASS

    if verbose:
        _print_json_block(
            markers,
            "Neo4j connection",
            {
                "uri": db_uri,
                "user": db_user,
                "password": redact_secret(db_pass),
            },
        )

    try:
        from neo4j import GraphDatabase
    except Exception:
        print(f"{markers['warn']} Neo4j driver not installed. Install with: pip install neo4j")
        return False

    driver = None
    try:
        driver = GraphDatabase.driver(db_uri, auth=(db_user, db_pass))
        with driver.session() as session:
            _ = session.run("RETURN 1 AS ok").single()
        print(f"{markers['ok']} Neo4j auth OK")

        records = nt_stats.get("_records", [])

        raw_rows: list[dict[str, object]] = []
        for rec in records:
            nt = rec["nt"]
            pwd = cracked_map.get(nt)
            raw_rows.append(
                {
                    "name": rec["name"],
                    "domain": rec.get("domain", ""),
                    "sam": rec["sam"],
                    "upn": rec["upn"],
                    "nt": nt,
                    "pwd": pwd,
                }
            )

        rows = raw_rows

        total = len(rows)
        update_rows: list[dict[str, object]] = []
        written_updates: list[dict[str, object]] = []
        unmatched_all: list[dict[str, object]] = []
        ambiguous_all: list[dict[str, object]] = []
        failures = []
        if total == 0:
            print(f"{markers['ok']} Nothing to apply")
        else:
            neo4j_update_batch = _env_int("PATCHHOUND_NEO4J_UPDATE_BATCH", NEO4J_UPDATE_BATCH)
            if verbose:
                print(
                    f"{markers['info']} Applying to Neo4j: {total} candidates "
                    f"(write_credentials={write_credentials})"
                )
                print(f"    neo4j_update_batch  : {neo4j_update_batch}")

            applied = 0
            print(f"{markers['ok']} Waiting for Neo4j")

            with driver.session() as s:
                if verbose:
                    print(f"{markers['info']} Building domain-aware BloodHound node index")
                index, index_stats = _collect_neo4j_target_index(s)
                update_rows, unmatched_all, ambiguous_all = match_rows(rows, index)

                learned_aliases = index.get("learned_domain_aliases", {})
                if verbose:
                    _print_json_block(markers, "BloodHound node index", index_stats)
                    _print_json_block(
                        markers,
                        "Identity mapping",
                        {
                            "matched_nodes": len(update_rows),
                            "unmatched_accounts": len(unmatched_all),
                            "ambiguous_accounts": len(ambiguous_all),
                            "match_routes": _reason_counts(update_rows),
                            "unmatched_reasons": _reason_counts(unmatched_all),
                            "ambiguous_reasons": _reason_counts(ambiguous_all),
                            "learned_domain_aliases": {
                                alias: sorted(domains) for alias, domains in learned_aliases.items()
                            },
                        },
                    )

                update_total = len(update_rows)
                if not update_total:
                    _progress(total, total, "Applying", nocolor)
                for offset in range(0, update_total, neo4j_update_batch):
                    sub = update_rows[offset : offset + neo4j_update_batch]
                    try:
                        upd = _apply_updates(s, sub, write_credentials)
                        applied += upd
                        if upd == len(sub):
                            written_updates.extend(sub)
                        else:
                            failures.append(
                                (f"expected {len(sub)} updates, Neo4j reported {upd}", sub)
                            )
                    except Exception as e:
                        failures.append((str(e), sub))
                    finally:
                        _progress(
                            min(offset + len(sub), update_total), update_total, "Applying", nocolor
                        )

            print(f"{markers['ok']} Updated nodes: {applied}")
            if unmatched_all:
                print(
                    f"{markers['warn']} Failed to map: {len(unmatched_all)} "
                    f"({_reason_summary(unmatched_all)}){_verbose_hint(verbose, nocolor)}"
                )
                if verbose:
                    for r in unmatched_all:
                        nm = r.get("name") or "(unknown)"
                        reason = r.get("match_reason") or "no match"
                        print(f"{markers['info']} {nm} -> {reason}")
            if ambiguous_all:
                print(
                    f"{markers['warn']} Refused ambiguous mappings: {len(ambiguous_all)} "
                    f"({_reason_summary(ambiguous_all)}){_verbose_hint(verbose, nocolor)}"
                )
                if verbose:
                    for r in ambiguous_all:
                        nm = r.get("name") or "(unknown)"
                        reason = r.get("match_reason") or "ambiguous"
                        print(f"{markers['info']} {nm} -> {reason}")
            if failures:
                print(
                    f"{markers['warn']} Write failures: {len(failures)}"
                    f"{_verbose_hint(verbose, nocolor)}"
                )
                if verbose:
                    for msg, sub in failures:
                        ex_count = len(sub)
                        sample = sub[0] if sub else {}
                        who = (
                            sample.get("name")
                            or sample.get("sam")
                            or sample.get("upn")
                            or "(unknown)"
                        )
                        print(
                            f"{markers['info']} {ex_count} rows failed starting at {who} -> {msg}"
                        )

        if do_owned and failures:
            print(f"{markers['warn']} Skipping Owned reconciliation because Neo4j writes failed")

        if do_owned and not failures:
            print(f"{markers['ok']} Waiting for Neo4j and API")

            with driver.session() as s:
                candidates, sids_with_az, processed_sids = _collect_owned_candidate_sids(
                    s, written_updates
                )

            tag_id = getattr(args, "asset_group_tag_id", None)
            if tag_id is None:
                tag_id = _env_int("PATCHHOUND_ASSET_GROUP_TAG_ID", 2)
            else:
                tag_id = int(tag_id)

            owned_seeds_per_selector = getattr(args, "owned_seeds_per_selector", None) or _env_int(
                "PATCHHOUND_OWNED_SEEDS_PER_SELECTOR", 500
            )
            owned_workers = _env_int("PATCHHOUND_OWNED_WORKERS", 4)
            default_rate_delay = 0.0 if owned_seeds_per_selector > 1 else 0.02
            owned_rate_delay = _env_float("PATCHHOUND_OWNED_RATE_DELAY", default_rate_delay)
            owned_max_retries = _env_int("PATCHHOUND_OWNED_MAX_RETRIES", 6)

            owned_result = _append_owned_selectors(
                base_url,
                token,
                tag_id,
                candidates,
                markers,
                verbose,
                workers=owned_workers,
                rate_delay=owned_rate_delay,
                max_retries=owned_max_retries,
                seeds_per_selector=owned_seeds_per_selector,
                processed_sids=processed_sids,
                nocolor=nocolor,
            )

            # final summary (verbose only)
            if verbose:
                _print_json_block(
                    markers,
                    "Owned summary",
                    {
                        "cracked_users_this_run": len(candidates),
                        "distinct_sids_sent": len(candidates),
                        "sids_with_entra_link": sids_with_az,
                        "asset_group_tag_id": tag_id,
                        "seeds_added": owned_result["added"],
                        "seeds_updated": owned_result["updated"],
                        "seeds_removed": owned_result["removed"],
                        "seeds_unchanged": owned_result["exists"],
                        "seeds_failed": owned_result["failed"],
                        "rate_limit_retries": owned_result["rate_limited"],
                        "selector_requests_completed": owned_result["selector_requests"],
                        "selector_requests_planned": owned_result["selector_request_total"],
                    },
                )

            else:
                print(f"{markers['ok']} Owned Check")

        return not failures and (
            not do_owned or (owned_result is not None and owned_result["failed"] == 0)
        )

    finally:
        if driver is not None:
            try:
                driver.close()
            except Exception:
                pass
