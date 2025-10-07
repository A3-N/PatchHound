# src/patch.py
#!/usr/bin/env python3
import os
import re
import sys
import json
import tempfile
import requests
from typing import Tuple, List, Dict, Optional

from src.conn import DEFAULT_URI, DEFAULT_USER, DEFAULT_PASS
from src.pwetty import progress_bar

SESSION_PATH = os.path.join(tempfile.gettempdir(), "patchhound.session.json")

BATCH_SIZE = 1000
APPLY_STEP = 50
API_BATCH = 500

HEX32 = re.compile(r'\b[a-fA-F0-9]{32}\b')
HEX_WRAP = re.compile(r'^\s*\$HEX\[([0-9A-Fa-f]+)\]\s*$')
UPN_RE = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')

EXCLUDED_PRINT_LIMIT = 200
HEX_PRINT_LIMIT = 200

def _make_markers(nocolor: bool) -> Dict[str, str]:
    return {"ok": "[+]", "info": "[*]", "warn": "[!]"}


def _progress(done: int, total: int, prefix: str, nocolor: bool):
    bar, pct = progress_bar(done, total, nocolor, width=28)
    sys.stdout.write(f"\r{prefix} [{bar}] {done}/{total} ({pct}%)")
    sys.stdout.flush()
    if done >= total:
        sys.stdout.write("\n")
        sys.stdout.flush()

def _load_session() -> Tuple[str, str]:
    if not os.path.exists(SESSION_PATH):
        raise RuntimeError("No session found — run `auth` first.")
    try:
        with open(SESSION_PATH, "r") as f:
            data = json.load(f)
    except Exception:
        raise RuntimeError("Session file is invalid — re-run `auth`.")
    base_url = data.get("base_url")
    token = data.get("session_token")
    if not base_url or not token:
        raise RuntimeError("Session file missing base_url or session_token — re-run `auth`.")
    return base_url, token


def _redact_token(tok: str) -> str:
    if not tok:
        return "<missing>"
    return tok[:6] + "..." + tok[-6:] if len(tok) > 12 else tok[:3] + "..." + tok[-3:]


def _redact_secret(_: str) -> str:
    return "████████"


def _extract_error_message(resp) -> str:
    try:
        body = resp.json()
        errs = body.get("errors")
        if isinstance(errs, list) and errs:
            msg = errs[0].get("message")
            if isinstance(msg, str) and msg.strip():
                return msg.strip()
    except ValueError:
        pass
    return "Error"


def _check_file(path: str, what: str):
    if not path:
        return
    if not os.path.exists(path):
        raise RuntimeError(f"{what} not found: {path}")
    if not os.path.isfile(path):
        raise RuntimeError(f"{what} is not a file: {path}")

def _decode_hex_pw(pw: str) -> Tuple[str, bool, Optional[str]]:
    m = HEX_WRAP.match(pw)
    if not m:
        return pw, False, None
    try:
        b = bytes.fromhex(m.group(1))
        try:
            return b.decode("utf-8"), True, m.group(0)
        except UnicodeDecodeError:
            return b.decode("latin-1"), True, m.group(0)
    except Exception:
        return pw, False, None


def _analyze_potfile(path: str) -> Dict[str, object]:
    stats = {
        "lines_total": 0,
        "entries_total": 0,
        "valid_entries": 0,
        "excluded_count": 0,
        "ntlm32_valid": 0,
        "hex_wrapped": 0,
        "hex_decoded": 0,
        "unique_hashes": 0,
        "excluded_lines": [],
        "hex_decoded_lines": [],
    }
    cracked: Dict[str, str] = {}

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            stats["lines_total"] += 1
            line = raw.rstrip("\n")
            s = line.strip()

            if not s or s.startswith("#"):
                stats["excluded_lines"].append(f"blank_or_comment | {line}")
                stats["excluded_count"] += 1
                continue

            stats["entries_total"] += 1
            if ":" not in s:
                stats["excluded_lines"].append(f"no_colon | {line}")
                stats["excluded_count"] += 1
                continue

            h, pwd = s.split(":", 1)
            h = h.strip().lower()

            if HEX32.fullmatch(h) is None:
                stats["excluded_lines"].append(f"hash_not_32hex | {line}")
                stats["excluded_count"] += 1
                continue

            stats["valid_entries"] += 1
            stats["ntlm32_valid"] += 1

            decoded, was_hex, orig_token = _decode_hex_pw(pwd)
            if was_hex:
                stats["hex_wrapped"] += 1
                stats["hex_decoded"] += 1
                stats["hex_decoded_lines"].append(f"{h}:{orig_token}:{decoded}")

            cracked[h] = decoded

    stats["unique_hashes"] = len(cracked)
    stats["_cracked_map"] = cracked
    return stats


def _canonicalize_account(tokens: List[str]) -> Optional[str]:
    for t in tokens:
        t = t.strip()
        if "\\" in t:
            return t
    return tokens[0].strip() if tokens else None


def _extract_upn(tokens: List[str]) -> Optional[str]:
    for t in tokens:
        t = t.strip()
        if UPN_RE.match(t):
            return t
    return None


def _split_account(acct: str):
    if "\\" in acct:
        dom, sam = acct.split("\\", 1)
        return dom, sam
    return None, acct


def _analyze_ntlm_file(path: str) -> Dict[str, object]:
    stats = {
        "lines_total": 0,
        "lines_with_hash": 0,
        "hashes_total": 0,
        "unique_hashes": 0,
        "accounts_total": 0,
        "pairs_total": 0,
        "unique_pairs": 0,
        "valid_records": 0,
        "excluded_count": 0,
        "excluded_lines": [],
    }
    records: List[Dict[str, str]] = []
    hashes_seen = set()

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            stats["lines_total"] += 1
            line = raw.rstrip("\n")
            s = line.strip()

            if not s or s.startswith("#"):
                stats["excluded_lines"].append(f"blank_or_comment | {line}")
                stats["excluded_count"] += 1
                continue

            hashes = HEX32.findall(s)
            if hashes:
                stats["lines_with_hash"] += 1
                stats["hashes_total"] += len(hashes)

            tokens = [p for p in re.split(r'[:\s,;]+', s) if p]
            acct = _canonicalize_account(tokens)
            upn = _extract_upn(tokens)

            if acct:
                stats["accounts_total"] += 1

            if not hashes:
                stats["excluded_lines"].append(f"no_32hex_hash | {line}")
                stats["excluded_count"] += 1
                continue

            if not acct:
                stats["excluded_lines"].append(f"no_account_token | {line}")
                stats["excluded_count"] += 1
                continue

            dom, sam = _split_account(acct)
            if not upn and dom and '.' in dom and sam:
                upn = f"{sam}@{dom.lower()}"

            rec_sam = (sam or "").upper()
            rec_upn = (upn or "").upper()

            for h in hashes:
                h = h.lower()
                records.append({"name": acct, "sam": rec_sam, "upn": rec_upn, "nt": h})
                hashes_seen.add(h)
                stats["valid_records"] += 1

    seen_pairs = set()
    out_records: List[Dict[str, str]] = []
    for rec in records:
        key = (rec["name"].lower(), rec["nt"])
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        out_records.append(rec)

    stats["unique_hashes"] = len(hashes_seen)
    stats["pairs_total"] = len(records)
    stats["unique_pairs"] = len(out_records)
    stats["_records"] = out_records
    return stats

def _pre_match(session, rows):
    q = """
    UNWIND $rows AS r
    OPTIONAL MATCH (u_exact:User {name:r.name})
    OPTIONAL MATCH (u_sam:User)
      WHERE r.sam <> '' AND toUpper(coalesce(u_sam.samaccountname,'')) = r.sam
    OPTIONAL MATCH (u_upn:User)
      WHERE r.upn <> '' AND toUpper(coalesce(u_upn.userprincipalname, u_upn.userPrincipalName, '')) = r.upn
    OPTIONAL MATCH (az_upn:AZUser)
      WHERE r.upn <> '' AND toUpper(coalesce(az_upn.userprincipalname, az_upn.userPrincipalName, '')) = r.upn
    OPTIONAL MATCH (c:Computer)
      WHERE r.sam <> '' AND toUpper(coalesce(c.samaccountname,'')) = r.sam
    WITH r,
         (CASE WHEN u_exact IS NULL THEN [] ELSE [u_exact] END) +
         (CASE WHEN u_sam   IS NULL THEN [] ELSE [u_sam]   END) +
         (CASE WHEN u_upn   IS NULL THEN [] ELSE [u_upn]   END) +
         (CASE WHEN az_upn  IS NULL THEN [] ELSE [az_upn]  END) +
         (CASE WHEN c       IS NULL THEN [] ELSE [c]       END) AS targets
    WITH {r:r, has:size(targets)>0} AS row
    RETURN
      [x IN collect(row) WHERE NOT x.has | x.r] AS missing,
      [x IN collect(row) WHERE x.has | x.r] AS found
    """
    res = session.run(q, rows=rows).single()
    missing = res["missing"] if res and res["missing"] else []
    found = res["found"] if res and res["found"] else []
    return found, missing


def _apply_updates(session, rows, write_temp: bool) -> int:
    q = """
    UNWIND $rows AS r
    OPTIONAL MATCH (u_exact:User {name:r.name})
    OPTIONAL MATCH (u_sam:User)
      WHERE r.sam <> '' AND toUpper(coalesce(u_sam.samaccountname,'')) = r.sam
    OPTIONAL MATCH (u_upn:User)
      WHERE r.upn <> '' AND toUpper(coalesce(u_upn.userprincipalname, u_upn.userPrincipalName, '')) = r.upn
    OPTIONAL MATCH (az_upn:AZUser)
      WHERE r.upn <> '' AND toUpper(coalesce(az_upn.userprincipalname, az_upn.userPrincipalName, '')) = r.upn
    OPTIONAL MATCH (c:Computer)
      WHERE r.sam <> '' AND toUpper(coalesce(c.samaccountname,'')) = r.sam
    WITH r,
         (CASE WHEN u_exact IS NULL THEN [] ELSE [u_exact] END) +
         (CASE WHEN u_sam   IS NULL THEN [] ELSE [u_sam]   END) +
         (CASE WHEN u_upn   IS NULL THEN [] ELSE [u_upn]   END) +
         (CASE WHEN az_upn  IS NULL THEN [] ELSE [az_upn]  END) +
         (CASE WHEN c       IS NULL THEN [] ELSE [c]       END) AS targets
    UNWIND targets AS n
    SET n.Patchhound_has_hash = true,
        n.Patchhound_has_pass = CASE WHEN r.pwd IS NULL THEN false ELSE true END
    FOREACH (_ IN CASE WHEN $write_temp THEN [1] ELSE [] END |
        SET n.Patchhound_nt   = r.nt,
            n.Patchhound_pass = r.pwd
    )
    RETURN count(DISTINCT n) AS updated
    """
    res = session.run(q, rows=rows, write_temp=write_temp).single()
    return res["updated"] if res and "updated" in res else 0

def _collect_owned_candidate_sids(session) -> Tuple[List[str], int, int, int]:
    q1 = """
    MATCH (u:User)
    WHERE coalesce(u.Patchhound_has_pass,false) = true
    RETURN collect(DISTINCT u.objectid) AS sids_all,
           count(u) AS pass_users_total
    """
    rec1 = session.run(q1).single()
    if not rec1:
        return [], 0, 0, 0

    sids_all = rec1["sids_all"] or []
    pass_users_total = int(rec1["pass_users_total"] or 0)

    sids = [sid for sid in sids_all if sid and str(sid).strip()]
    pass_users_with_sid = len(sids)

    if not sids:
        return [], pass_users_total, 0, 0

    q2 = """
    UNWIND $sids AS sid
    OPTIONAL MATCH (az:AZUser)
      WHERE toUpper(coalesce(az.onpremisessid,
                             az.onpremisessecurityidentifier,
                             az.onPremisesSecurityIdentifier,
                             az.onPremSid,
                             az.onprem_sid, '')) = toUpper(sid)
    WITH sid, count(az) AS hits
    RETURN count(CASE WHEN hits > 0 THEN 1 END) AS sids_with_az
    """
    rec2 = session.run(q2, sids=sids).single()
    sids_with_az = int(rec2["sids_with_az"] or 0) if rec2 else 0

    return sids, pass_users_total, pass_users_with_sid, sids_with_az

def _append_owned_selectors(base_url: str, token: str, asset_group_id: int, sids: List[str], markers, verbose: bool):
    if not sids:
        print(f"{markers['info']} Owned API: no SIDs to add")
        return

    url = f"{base_url.rstrip('/')}/api/v2/asset-groups/{asset_group_id}/selectors"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    total = len(sids)
    done = 0
    for i in range(0, total, API_BATCH):
        batch = sids[i:i + API_BATCH]
        payload = [{"selector_name": "Manual", "sid": sid, "action": "add"} for sid in batch]
        try:
            resp = requests.put(url, headers=headers, json=payload, timeout=30)
            resp.raise_for_status()
        except requests.RequestException as e:
            body = None
            try:
                body = resp.text
            except Exception:
                body = str(e)
            print(f"{markers['warn']} Owned API batch failed ({i+1}-{i+len(batch)}): {body}")
        done += len(batch)
        _progress(done, total, "Owned API", False)

    print(f"{markers['ok']} Owned API: attempted {total} selector adds")

def _print_pot_stats(markers, stats, verbose: bool):
    if not verbose:
        print(f"{markers['ok']} Potfile Check")
        return

    print(f"{markers['info']} Potfile stats:")
    print(f"    lines_total    : {stats['lines_total']}")
    print(f"    entries_total  : {stats['entries_total']}")
    print(f"    valid_entries  : {stats['valid_entries']}")
    print(f"    excluded_count : {stats['excluded_count']}")
    print(f"    ntlm32_valid   : {stats['ntlm32_valid']}")
    print(f"    $HEX_found     : {stats['hex_wrapped']}")
    print(f"    $HEX_decoded   : {stats['hex_decoded']}")
    print(f"    unique_hashes  : {stats['unique_hashes']}")

    excl = stats.get("excluded_lines", [])
    print(f"    excluded_lines ({len(excl)}):")
    if excl:
        to_show = excl if EXCLUDED_PRINT_LIMIT is None else excl[:EXCLUDED_PRINT_LIMIT]
        for line in to_show:
            print(f"      - {line}")
        if EXCLUDED_PRINT_LIMIT is not None and len(excl) > EXCLUDED_PRINT_LIMIT:
            print(f"      ... ({len(excl) - EXCLUDED_PRINT_LIMIT} more)")

    hex_lines = stats.get("hex_decoded_lines", [])
    print(f"    $HEX decodes ({len(hex_lines)}):  format => nthash:HEXHASHCAT:password")
    if hex_lines:
        to_show = hex_lines if HEX_PRINT_LIMIT is None else hex_lines[:HEX_PRINT_LIMIT]
        for line in to_show:
            print(f"      {line}")
        if HEX_PRINT_LIMIT is not None and len(hex_lines) > HEX_PRINT_LIMIT:
            print(f"      ... ({len(hex_lines) - HEX_PRINT_LIMIT} more)")

def _print_nt_stats(markers, stats, verbose: bool):
    if not verbose:
        print(f"{markers['ok']} NTLM Check")
        return

    print(f"{markers['info']} NTLM file stats:")
    print(f"    lines_total     : {stats['lines_total']}")
    print(f"    lines_with_hash : {stats['lines_with_hash']}")
    print(f"    hashes_total    : {stats['hashes_total']}")
    print(f"    unique_hashes   : {stats['unique_hashes']}")
    print(f"    accounts_total  : {stats['accounts_total']}")
    print(f"    pairs_total     : {stats['pairs_total']}")
    print(f"    unique_pairs    : {stats['unique_pairs']}")
    print(f"    valid_records   : {stats['valid_records']}")
    print(f"    excluded_count  : {stats['excluded_count']}")

    excl = stats.get("excluded_lines", [])
    print(f"    excluded_lines ({len(excl)}):")
    if excl:
        to_show = excl if EXCLUDED_PRINT_LIMIT is None else excl[:EXCLUDED_PRINT_LIMIT]
        for line in to_show:
            print(f"      - {line}")
        if EXCLUDED_PRINT_LIMIT is not None and len(excl) > EXCLUDED_PRINT_LIMIT:
            print(f"      ... ({len(excl) - EXCLUDED_PRINT_LIMIT} more)")

def run(args, markers=None, no_color=False) -> bool:
    nocolor = bool(no_color) if no_color is not None else bool(getattr(args, "no_color", False))
    verbose = bool(getattr(args, "verbose", False))
    write_temp = bool(getattr(args, "temp", False))
    do_owned = bool(getattr(args, "owned", False))

    if markers is None:
        markers = _make_markers(nocolor)

    try:
        base_url, token = _load_session()
    except RuntimeError as e:
        print(f"{markers['warn']} {e}")
        return False

    url = f"{base_url.rstrip('/')}/api/version"
    headers = {"accept": "application/json", "Prefer": "0", "Authorization": f"Bearer {token}"}

    if verbose:
        print(f"{markers['info']} Verifying token via {url}")
        redacted_headers = dict(headers)
        redacted_headers["Authorization"] = "Bearer " + _redact_token(token)
        print(f"{markers['info']} Headers:\n{json.dumps(redacted_headers, indent=2)}")

    try:
        resp = requests.get(url, headers=headers, timeout=15)
    except requests.RequestException as e:
        print(f"{markers['warn']} Request failed: {e}")
        return False

    if verbose:
        print(f"{markers['info']} Response status: {resp.status_code}")
        try:
            pretty = json.dumps(resp.json(), indent=2, ensure_ascii=False)
            print(f"{markers['info']} Response JSON:\n{pretty}")
        except ValueError:
            print(f"{markers['info']} Response (non-JSON):\n{resp.text}")

    if resp.status_code != 200:
        print(f"{markers['warn']} {_extract_error_message(resp)}")
        return False

    if verbose:
        print(f"{markers['info']} Using session token: {_redact_token(token)}")
        print(f"{markers['info']} Base URL: {base_url}")
    else:
        print(f"{markers['ok']} JWT valid")

    clears = getattr(args, "clears", None)
    ntlm = getattr(args, "ntlm", None)
    kerberos = getattr(args, "kerberos", None)

    if not clears or (not ntlm and not kerberos):
        print(f"{markers['warn']} Usage error: --clears is required, plus at least one of --ntlm or --kerberos.")
        return False

    try:
        _check_file(clears, "Clears file")
        if ntlm:
            _check_file(ntlm, "NTLM file")
        if kerberos:
            _check_file(kerberos, "Kerberos file")
    except RuntimeError as e:
        print(f"{markers['warn']} {e}")
        return False

    pot_stats = _analyze_potfile(clears)
    cracked_map: Dict[str, str] = pot_stats.pop("_cracked_map")
    _print_pot_stats(markers, pot_stats, verbose)

    nt_stats = {"_records": [], "lines_total": 0, "lines_with_hash": 0, "hashes_total": 0,
                "unique_hashes": 0, "accounts_total": 0, "pairs_total": 0, "unique_pairs": 0,
                "valid_records": 0, "excluded_count": 0, "excluded_lines": []}
    if ntlm:
        nt_stats = _analyze_ntlm_file(ntlm)
        _print_nt_stats(markers, nt_stats, verbose)

    if pot_stats["valid_entries"] == 0:
        print(f"{markers['warn']} potfile appears to have no usable NTLM entries (32-hex)")
    if ntlm and nt_stats["unique_pairs"] == 0:
        print(f"{markers['warn']} ntlm file appears to have no valid (acct, hash) pairs")

    if verbose:
        print(f"{markers['info']} Neo4j defaults:")
        print(f"    uri={DEFAULT_URI}")
        print(f"    user={DEFAULT_USER}")
        print(f"    pass={_redact_secret(DEFAULT_PASS)}")

    try:
        from neo4j import GraphDatabase
    except Exception:
        print(f"{markers['warn']} Neo4j driver not installed. Install with: pip install neo4j")
        return False

    driver = None
    try:
        driver = GraphDatabase.driver(DEFAULT_URI, auth=(DEFAULT_USER, DEFAULT_PASS))
        with driver.session() as session:
            _ = session.run("RETURN 1 AS ok").single()
        print(f"{markers['ok']} Neo4j auth OK")

        records = nt_stats.get("_records", []) if ntlm else []

        rows: List[Dict[str, str]] = []
        for rec in records:
            nt = rec["nt"]
            pwd = cracked_map.get(nt)
            rows.append({"name": rec["name"], "sam": rec["sam"], "upn": rec["upn"], "nt": nt, "pwd": pwd})

        total = len(rows)
        if total == 0:
            print(f"{markers['ok']} Nothing to apply")
        else:
            if verbose:
                print(f"{markers['info']} Applying to Neo4j: {total} candidates (write_temp={write_temp})")

            applied = 0
            done = 0
            unmatched_all = []
            failures = []

            print(f"{markers['ok']} Waiting for Neo4j")

            with driver.session() as s:
                for i in range(0, total, BATCH_SIZE):
                    chunk = rows[i:i+BATCH_SIZE]
                    found, missing = _pre_match(s, chunk)

                    if missing:
                        unmatched_all.extend(missing)
                        done += len(missing)
                        _progress(done, total, "Applying", nocolor)

                    if not found:
                        continue

                    for j in range(0, len(found), APPLY_STEP):
                        sub = found[j:j+APPLY_STEP]
                        try:
                            upd = _apply_updates(s, sub, write_temp)
                            applied += upd
                        except Exception as e:
                            failures.append((str(e), sub))
                        finally:
                            done += len(sub)
                            _progress(done, total, "Applying", nocolor)

            print(f"{markers['ok']} Updated nodes: {applied}")
            if unmatched_all:
                print(f"{markers['warn']} Failed to map: {len(unmatched_all)}")
                if verbose:
                    for r in unmatched_all:
                        nm = r.get("name") or "(unknown)"
                        sm = r.get("sam") or "(none)"
                        up = r.get("upn") or "(none)"
                        print(f"{markers['info']} {nm} -> no match on name, SAM ({sm}), or UPN ({up})")
            if failures:
                print(f"{markers['warn']} Write failures: {len(failures)}")
                if verbose:
                    for msg, sub in failures:
                        ex_count = len(sub)
                        sample = sub[0] if sub else {}
                        who = sample.get("name") or sample.get("sam") or sample.get("upn") or "(unknown)"
                        print(f"{markers['info']} {ex_count} rows failed starting at {who} -> {msg}")

        if do_owned:
            print(f"{markers['ok']} Waiting for Neo4j and API")

            with driver.session() as s:
                sids, pass_total, pass_with_sid, sids_with_az = _collect_owned_candidate_sids(s)

            agid = getattr(args, "asset_group_id", None)
            if agid is None:
                agid = int(os.getenv("PATCHHOUND_ASSET_GROUP_ID", "2"))
            else:
                agid = int(agid)

            _append_owned_selectors(base_url, token, agid, sids, markers, verbose)

            # final summary (verbose only)
            if verbose:
                ex_sid = sids[0] if sids else None
                print(f"{markers['info']} Owned summary:")
                print(f"    users_with_password_true  : {pass_total}")
                print(f"    with_sid                  : {pass_with_sid}")
                print(f"    distinct_sids_sent        : {len(sids)}")
                print(f"    sids_with_azuser_link     : {sids_with_az}")
                print(f"    asset_group_id            : {agid}")
                if ex_sid:
                    ex_url = f"{base_url.rstrip('/')}/api/v2/asset-groups/{agid}/selectors"
                    example_payload = [{"selector_name": "Manual", "sid": ex_sid, "action": "add"}]
                    print(f"    example_request:")
                    print(f"      PUT {ex_url}")
                    print(f"      payload: {json.dumps(example_payload)}")

            else:
                print(f"{markers['ok']} Owned Check")

        return True

    finally:
        if driver is not None:
            try:
                driver.close()
            except Exception:
                pass
