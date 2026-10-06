# src/patch.py
#!/usr/bin/env python3
import os
import re
import sys
import json
import time
import tempfile
import threading
import requests
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from getpass import getpass
from typing import Tuple, List, Dict, Optional
from urllib.parse import urljoin

from src.conn import DEFAULT_URI, DEFAULT_USER, DEFAULT_PASS
from src.pwetty import progress_bar

SESSION_PATH = os.path.join(tempfile.gettempdir(), "patchhound.session.json")

BATCH_SIZE = 1000
APPLY_STEP = 50
NEO4J_UPDATE_BATCH = 5000

HEX32 = re.compile(r'\b[a-fA-F0-9]{32}\b')
LM_NT_RE = re.compile(r'\b([a-fA-F0-9]{32}):([a-fA-F0-9]{32})\b')
HEX_WRAP = re.compile(r'^\s*\$HEX\[([0-9A-Fa-f]+)\]\s*$')
UPN_RE = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
NTDS_STATUS_RE = re.compile(r'\(\s*status\s*=\s*(enabled|disabled)\s*\)', re.IGNORECASE)

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

def _normalize_base(url: str) -> str:
    url = (url or "").strip()
    return url if url.endswith("/") else f"{url}/"


def _atomic_write_json(payload: dict, path: str = SESSION_PATH):
    d = os.path.dirname(path) or "."
    with tempfile.NamedTemporaryFile("w", dir=d, delete=False) as tmp:
        json.dump(payload, tmp, indent=2, ensure_ascii=False)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = tmp.name
    os.replace(tmp_path, path)
    os.chmod(path, 0o600)


def _load_session_data() -> Dict[str, str]:
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
    data["base_url"] = _normalize_base(base_url)
    return data


def _extract_session_token(resp) -> Optional[str]:
    try:
        top = resp.json()
    except ValueError:
        return None

    body = top.get("data", top) if isinstance(top, dict) else {}
    if not isinstance(body, dict):
        return None
    token = body.get("session_token")
    return token if isinstance(token, str) and token else None


class _BloodHoundAPISession:
    """Small wrapper around the BHCE session token used by long owned uploads."""

    def __init__(self, data: Dict[str, str], args, markers: dict, verbose: bool):
        self.base_url = _normalize_base(data["base_url"])
        self.token = data["session_token"]
        self.username = (
            getattr(args, "api_user", None)
            or os.getenv("PATCHHOUND_API_USER")
            or data.get("username")
        )
        self.secret = (
            getattr(args, "api_pass", None)
            or os.getenv("PATCHHOUND_API_PASS")
        )
        self._session_data = dict(data)
        self._markers = markers
        self._verbose = verbose
        self._refresh_lock = threading.RLock()

    def _headers(self, headers: Optional[Dict[str, str]], token: str) -> Dict[str, str]:
        merged = dict(headers or {})
        merged["Authorization"] = f"Bearer {token}"
        return merged

    def _get_username(self) -> Optional[str]:
        if self.username:
            return self.username
        try:
            self.username = input("BloodHound username: ").strip()
        except (EOFError, KeyboardInterrupt):
            self.username = None
        return self.username

    def _get_secret(self) -> Optional[str]:
        if self.secret:
            return self.secret
        try:
            self.secret = getpass("BloodHound password/API secret: ")
        except (EOFError, KeyboardInterrupt):
            self.secret = None
        return self.secret

    def refresh(self, observed_token: Optional[str] = None) -> bool:
        with self._refresh_lock:
            if observed_token and observed_token != self.token:
                return True

            username = self._get_username()
            secret = self._get_secret()
            if not username or not secret:
                print(f"\n{self._markers['warn']} API token expired and no BloodHound API credentials were available to renew it.")
                print(f"{self._markers['info']} Set PATCHHOUND_API_USER/PATCHHOUND_API_PASS for unattended owned uploads.")
                return False

            login_url = urljoin(self.base_url, "api/v2/login")
            if self._verbose:
                print(f"\n{self._markers['info']} API token expired; renewing via {login_url}")
            else:
                print(f"\n{self._markers['info']} API token expired; renewing session before continuing")

            payload = {"login_method": "secret", "username": username, "secret": secret}
            try:
                resp = requests.post(
                    login_url,
                    headers={"Content-Type": "application/json"},
                    data=json.dumps(payload),
                    timeout=15,
                )
            except requests.RequestException as e:
                print(f"{self._markers['warn']} Token renewal request failed: {e}")
                return False

            if resp.status_code not in (200, 201):
                print(f"{self._markers['warn']} Token renewal failed ({resp.status_code}): {_extract_error_message(resp)}")
                return False

            token = _extract_session_token(resp)
            if not token:
                print(f"{self._markers['warn']} Token renewal response did not include a session token")
                return False

            self.token = token
            self.username = username
            self._session_data.update({"base_url": self.base_url, "session_token": token, "username": username})
            try:
                _atomic_write_json(self._session_data)
            except Exception as e:
                print(f"{self._markers['warn']} Token renewed, but failed to update session cache: {e}")

            print(f"{self._markers['ok']} API token renewed: {_redact_token(token)}")
            return True

    def request(self, method: str, url: str, *, headers: Optional[Dict[str, str]] = None,
                retry_auth: bool = True, **kwargs):
        observed_token = self.token
        resp = requests.request(method, url, headers=self._headers(headers, observed_token), **kwargs)
        if retry_auth and resp.status_code == 401 and self.refresh(observed_token):
            resp = requests.request(method, url, headers=self._headers(headers, self.token), **kwargs)
        return resp

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
    # Use a dict keyed by (account_lower) so later NT hashes always overwrite
    records_by_acct: Dict[str, Dict[str, str]] = {}
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

            # Look for the LM:NT pattern — two consecutive 32-hex values
            # separated by a colon.  The NT hash is always the second one.
            lm_nt_matches = LM_NT_RE.findall(s)
            if lm_nt_matches:
                # Each match is (lm_hash, nt_hash); take the NT from the
                # first LM:NT pair found on this line.
                nt_hash = lm_nt_matches[0][1].lower()
                stats["lines_with_hash"] += 1
                stats["hashes_total"] += 1
            else:
                # No LM:NT pair — skip this line
                stats["excluded_lines"].append(f"no_lm_nt_pair | {line}")
                stats["excluded_count"] += 1
                continue

            tokens = [p for p in re.split(r'[:\s,;]+', s) if p]
            acct = _canonicalize_account(tokens)
            upn = _extract_upn(tokens)
            status_match = NTDS_STATUS_RE.search(s)
            status = status_match.group(1).lower() if status_match else ""

            if acct:
                stats["accounts_total"] += 1

            if not acct:
                stats["excluded_lines"].append(f"no_account_token | {line}")
                stats["excluded_count"] += 1
                continue

            dom, sam = _split_account(acct)
            if not upn and dom and '.' in dom and sam:
                upn = f"{sam}@{dom.lower()}"

            rec_sam = (sam or "").upper()
            rec_upn = (upn or "").upper()

            # Always overwrite — the last NT hash seen for this account wins
            acct_key = acct.lower()
            records_by_acct[acct_key] = {
                "name": acct,
                "sam": rec_sam,
                "upn": rec_upn,
                "nt": nt_hash,
                "status": status,
            }
            hashes_seen.add(nt_hash)
            stats["valid_records"] += 1

    out_records = list(records_by_acct.values())

    stats["unique_hashes"] = len(hashes_seen)
    stats["pairs_total"] = stats["valid_records"]
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
         collect(DISTINCT u_exact) +
         collect(DISTINCT u_sam) +
         collect(DISTINCT u_upn) +
         collect(DISTINCT az_upn) +
         collect(DISTINCT c) AS targets
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
        n.Patchhound_has_pass = CASE
            WHEN r.pwd IS NOT NULL THEN true
            ELSE coalesce(n.Patchhound_has_pass, false)
        END
    FOREACH (_ IN CASE WHEN $write_temp THEN [1] ELSE [] END |
        SET n.Patchhound_nt = CASE
                WHEN r.pwd IS NOT NULL THEN r.nt
                ELSE coalesce(n.Patchhound_nt, r.nt)
            END,
            n.Patchhound_pass = CASE
                WHEN r.pwd IS NOT NULL THEN r.pwd
                ELSE coalesce(n.Patchhound_pass, r.pwd)
            END
    )
    RETURN count(DISTINCT n) AS updated
    """
    res = session.run(q, rows=rows, write_temp=write_temp).single()
    return res["updated"] if res and "updated" in res else 0


def _text_value(value) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _upper_value(value) -> str:
    return _text_value(value).upper()


def _add_lookup(mapping: Dict[str, set], key: str, node_id: int):
    if not key:
        return
    mapping.setdefault(key, set()).add(node_id)


def _collect_neo4j_target_index(session) -> Tuple[Dict[str, Dict[str, set]], Dict[str, int]]:
    """Build a local lookup of BH nodes once, avoiding repeated Cypher scans per row."""
    q = """
    MATCH (n)
    WHERE n:User OR n:AZUser OR n:Computer
    RETURN id(n) AS node_id,
           labels(n) AS labels,
           n.name AS name,
           n.samaccountname AS sam,
           n.userprincipalname AS upn,
           n.userPrincipalName AS upn_alt
    """
    index: Dict[str, Dict[str, set]] = {
        "user_name": {},
        "user_sam": {},
        "user_upn": {},
        "az_upn": {},
        "computer_sam": {},
    }
    stats = {"nodes": 0, "users": 0, "azusers": 0, "computers": 0}

    for rec in session.run(q):
        node_id = int(rec["node_id"])
        labels = set(rec["labels"] or [])
        stats["nodes"] += 1

        if "User" in labels:
            stats["users"] += 1
            _add_lookup(index["user_name"], _text_value(rec["name"]), node_id)
            _add_lookup(index["user_sam"], _upper_value(rec["sam"]), node_id)
            _add_lookup(index["user_upn"], _upper_value(rec["upn"] or rec["upn_alt"]), node_id)

        if "AZUser" in labels:
            stats["azusers"] += 1
            _add_lookup(index["az_upn"], _upper_value(rec["upn"] or rec["upn_alt"]), node_id)

        if "Computer" in labels:
            stats["computers"] += 1
            _add_lookup(index["computer_sam"], _upper_value(rec["sam"]), node_id)

    return index, stats


def _match_rows_with_neo4j_index(rows: List[Dict[str, str]],
                                 index: Dict[str, Dict[str, set]]) -> Tuple[List[Dict[str, object]], List[Dict[str, str]]]:
    updates_by_node: Dict[int, Dict[str, object]] = {}
    unmatched: List[Dict[str, str]] = []

    for row in rows:
        targets = set()
        name = _text_value(row.get("name"))
        sam = _upper_value(row.get("sam"))
        upn = _upper_value(row.get("upn"))

        if name:
            targets.update(index["user_name"].get(name, ()))
        if sam:
            targets.update(index["user_sam"].get(sam, ()))
            targets.update(index["computer_sam"].get(sam, ()))
        if upn:
            targets.update(index["user_upn"].get(upn, ()))
            targets.update(index["az_upn"].get(upn, ()))

        if not targets:
            unmatched.append(row)
            continue

        for node_id in targets:
            existing = updates_by_node.get(node_id)
            # Prefer rows with cracked passwords when several account tokens map
            # to the same BH node.
            if existing is None or (row.get("pwd") is not None and existing.get("pwd") is None):
                updates_by_node[node_id] = {
                    "node_id": node_id,
                    "nt": row.get("nt"),
                    "pwd": row.get("pwd"),
                }

    return list(updates_by_node.values()), unmatched


def _apply_updates_by_node_id(session, rows: List[Dict[str, object]], write_temp: bool) -> int:
    q = """
    UNWIND $rows AS r
    MATCH (n)
    WHERE id(n) = r.node_id
    SET n.Patchhound_has_hash = true,
        n.Patchhound_has_pass = CASE
            WHEN r.pwd IS NOT NULL THEN true
            ELSE coalesce(n.Patchhound_has_pass, false)
        END
    FOREACH (_ IN CASE WHEN $write_temp THEN [1] ELSE [] END |
        SET n.Patchhound_nt = CASE
                WHEN r.pwd IS NOT NULL THEN r.nt
                ELSE coalesce(n.Patchhound_nt, r.nt)
            END,
            n.Patchhound_pass = CASE
                WHEN r.pwd IS NOT NULL THEN r.pwd
                ELSE coalesce(n.Patchhound_pass, r.pwd)
            END
    )
    RETURN count(DISTINCT n) AS updated
    """
    res = session.run(q, rows=rows, write_temp=write_temp).single()
    return res["updated"] if res and "updated" in res else 0

def _collect_owned_candidate_sids(session) -> Tuple[List[Dict[str, str]], int, int, int]:
    """Return owned candidates as [{sid, name}, ...] plus stats."""
    q1 = """
    MATCH (u:User)
    WHERE coalesce(u.Patchhound_has_pass,false) = true
    WITH DISTINCT u.objectid AS sid, u.name AS name
    WHERE sid IS NOT NULL AND sid <> ''
    RETURN collect({sid: sid, name: coalesce(name, sid)}) AS entries,
           count(*) AS pass_users_total
    """
    rec1 = session.run(q1).single()
    if not rec1:
        return [], 0, 0, 0

    entries = rec1["entries"] or []
    pass_users_total = int(rec1["pass_users_total"] or 0)

    candidates = [e for e in entries if e.get("sid") and str(e["sid"]).strip()]
    pass_users_with_sid = len(candidates)

    if not candidates:
        return [], pass_users_total, 0, 0

    sids = [e["sid"] for e in candidates]

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

    return candidates, pass_users_total, pass_users_with_sid, sids_with_az

class _RateLimiter:
    def __init__(self, min_interval: float):
        self.min_interval = max(0.0, float(min_interval or 0.0))
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self):
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            sleep_for = self._next_allowed - now
            if sleep_for > 0:
                time.sleep(sleep_for)
                now = time.monotonic()
            self._next_allowed = now + self.min_interval


def _selector_payload(entry: Dict[str, str]) -> Tuple[str, Dict[str, object]]:
    sid = entry["sid"]
    name = entry.get("name") or sid.replace("-", "_")
    # Sanitize name: BHCE only allows alphanumeric, underscores, spaces
    safe_name = re.sub(r'[^A-Za-z0-9_ ]', '_', name)
    return safe_name, {"name": safe_name, "seeds": [{"type": 1, "value": sid}]}


def _batched_selector_payload(entries: List[Dict[str, str]], batch_index: int,
                              run_id: str) -> Tuple[str, Dict[str, object]]:
    safe_name = f"PatchHound Owned {run_id} {batch_index:06d}"
    seeds = [{"type": 1, "value": entry["sid"]} for entry in entries]
    return safe_name, {"name": safe_name, "seeds": seeds}


def _build_owned_selector_work(candidates: List[Dict[str, str]],
                               seeds_per_selector: int) -> List[Dict[str, object]]:
    seeds_per_selector = max(1, int(seeds_per_selector or 1))
    if seeds_per_selector == 1:
        work = []
        for entry in candidates:
            safe_name, payload = _selector_payload(entry)
            work.append({
                "name": safe_name,
                "payload": payload,
                "seed_count": 1,
            })
        return work

    run_id = time.strftime("%Y%m%d%H%M%S")
    work = []
    for offset in range(0, len(candidates), seeds_per_selector):
        chunk = candidates[offset:offset+seeds_per_selector]
        batch_index = (offset // seeds_per_selector) + 1
        safe_name, payload = _batched_selector_payload(chunk, batch_index, run_id)
        work.append({
            "name": safe_name,
            "payload": payload,
            "seed_count": len(chunk),
        })
    return work


def _retry_after(resp, fallback: float) -> float:
    raw = resp.headers.get("Retry-After") if resp is not None else None
    if raw:
        try:
            return max(0.0, float(raw))
        except ValueError:
            pass
    return fallback


def _walk_selector_sids(obj, out: set):
    if isinstance(obj, dict):
        seeds = obj.get("seeds")
        if isinstance(seeds, list):
            for seed in seeds:
                if isinstance(seed, dict):
                    value = seed.get("value")
                    if isinstance(value, str) and value.upper().startswith("S-1-"):
                        out.add(value.upper())
        for value in obj.values():
            _walk_selector_sids(value, out)
    elif isinstance(obj, list):
        for item in obj:
            _walk_selector_sids(item, out)


def _fetch_existing_owned_sids(api: _BloodHoundAPISession, tag_id: int, markers, verbose: bool) -> set:
    """Best-effort selector inventory to make interrupted re-runs cheaper."""
    url = f"{api.base_url.rstrip('/')}/api/v2/asset-group-tags/{tag_id}/selectors"
    try:
        resp = api.request("GET", url, headers={"accept": "application/json"}, timeout=30)
    except requests.RequestException as e:
        if verbose:
            print(f"{markers['warn']} Owned API: could not query existing selectors: {e}")
        return set()

    if resp.status_code in (404, 405):
        if verbose:
            print(f"{markers['info']} Owned API: selector inventory endpoint unavailable ({resp.status_code}); continuing without pre-skip")
        return set()

    if resp.status_code >= 400:
        if verbose:
            print(f"{markers['warn']} Owned API: selector inventory failed ({resp.status_code}): {_extract_error_message(resp)}")
        return set()

    try:
        body = resp.json()
    except ValueError:
        if verbose:
            print(f"{markers['warn']} Owned API: selector inventory returned non-JSON; continuing without pre-skip")
        return set()

    existing = set()
    _walk_selector_sids(body, existing)
    if existing:
        print(f"{markers['info']} Owned API: found {len(existing)} existing owned selector SID(s); skipping duplicates")
    return existing


def _post_owned_selector(api: _BloodHoundAPISession, url: str, item: Dict[str, object],
                         limiter: _RateLimiter, max_retries: int, abort_event: threading.Event) -> Dict[str, object]:
    if abort_event.is_set():
        return {"status": "skipped_abort", "name": item.get("name"), "seed_count": int(item.get("seed_count") or 1)}

    safe_name = str(item.get("name") or "PatchHound Owned")
    payload = item["payload"]
    seed_count = int(item.get("seed_count") or 1)
    headers = {"Content-Type": "application/json"}
    max_retries = max(1, int(max_retries or 1))
    rate_limited = 0

    for attempt in range(max_retries):
        if abort_event.is_set():
            return {"status": "skipped_abort", "name": safe_name, "seed_count": seed_count}

        try:
            limiter.wait()
            resp = api.request("POST", url, headers=headers, json=payload, timeout=30)
        except requests.RequestException as e:
            if attempt < max_retries - 1:
                time.sleep(min(2 ** attempt, 16))
                continue
            return {"status": "failed", "name": safe_name, "error": str(e), "seed_count": seed_count}

        if resp.status_code in (200, 201, 202, 204):
            return {"status": "added", "name": safe_name, "rate_limited": rate_limited, "seed_count": seed_count}
        if resp.status_code == 409:
            return {"status": "exists", "name": safe_name, "rate_limited": rate_limited, "seed_count": seed_count}
        if resp.status_code == 401:
            return {
                "status": "auth_failed",
                "name": safe_name,
                "http_status": resp.status_code,
                "error": _extract_error_message(resp),
                "seed_count": seed_count,
            }
        if resp.status_code == 429 and attempt < max_retries - 1:
            rate_limited += 1
            time.sleep(_retry_after(resp, min(2 ** attempt, 16)))
            continue
        if resp.status_code in (500, 502, 503, 504) and attempt < max_retries - 1:
            time.sleep(min(2 ** attempt, 16))
            continue
        if resp.status_code >= 400:
            return {
                "status": "failed",
                "name": safe_name,
                "http_status": resp.status_code,
                "error": _extract_error_message(resp),
                "rate_limited": rate_limited,
                "seed_count": seed_count,
            }

        return {"status": "added", "name": safe_name, "rate_limited": rate_limited, "seed_count": seed_count}

    return {"status": "failed", "name": safe_name, "error": "retry budget exhausted", "rate_limited": rate_limited, "seed_count": seed_count}


def _append_owned_selectors(api: _BloodHoundAPISession, tag_id: int,
                            candidates: List[Dict[str, str]], markers, verbose: bool,
                            workers: int = 4, rate_delay: float = 0.02,
                            skip_existing: bool = True, max_retries: int = 6,
                            seeds_per_selector: int = 1, nocolor: bool = False):
    """Create selectors on the Owned asset-group-tag via the BHCE API.

    Matches the exact call the BHCE UI makes for 'Add to Owned':
        POST /api/v2/asset-group-tags/{tag_id}/selectors
        {"name": "<display_name>", "seeds": [{"type": 1, "value": "<SID>"}]}
    """
    if not candidates:
        print(f"{markers['info']} Owned API: no SIDs to add")
        return {"attempted": 0, "added": 0, "exists": 0, "failed": 0, "skipped_existing": 0}

    initial_total = len(candidates)
    skipped_existing = 0
    if skip_existing:
        existing = _fetch_existing_owned_sids(api, tag_id, markers, verbose)
        if existing:
            filtered = [entry for entry in candidates if str(entry["sid"]).upper() not in existing]
            skipped_existing = initial_total - len(filtered)
            candidates = filtered

    if not candidates:
        print(f"{markers['ok']} Owned API: all {initial_total} selector SID(s) already exist")
        return {"attempted": 0, "added": 0, "exists": 0, "failed": 0, "skipped_existing": skipped_existing}

    url = f"{api.base_url.rstrip('/')}/api/v2/asset-group-tags/{tag_id}/selectors"
    workers = max(1, int(workers or 1))
    rate_delay = max(0.0, float(rate_delay or 0.0))
    max_retries = max(1, int(max_retries or 1))
    seeds_per_selector = max(1, int(seeds_per_selector or 1))
    limiter = _RateLimiter(rate_delay)
    abort_event = threading.Event()

    work_items = _build_owned_selector_work(candidates, seeds_per_selector)
    total = len(candidates)
    request_total = len(work_items)
    done = 0
    requests_done = 0
    counts = {
        "added": 0,
        "exists": 0,
        "failed": 0,
        "auth_failed": 0,
        "skipped_abort": 0,
        "rate_limited": 0,
    }
    failures = []

    if verbose:
        print(f"{markers['info']} Owned API settings:")
        print(f"    candidates_after_skip : {total}")
        print(f"    skipped_existing      : {skipped_existing}")
        print(f"    workers               : {workers}")
        print(f"    rate_delay_seconds    : {rate_delay}")
        print(f"    max_retries           : {max_retries}")
        print(f"    seeds_per_selector    : {seeds_per_selector}")
        print(f"    selector_requests     : {request_total}")

    pending = set()
    iterator = iter(work_items)
    max_pending = max(workers * 8, workers)

    def submit_more(executor):
        while not abort_event.is_set() and len(pending) < max_pending:
            try:
                item = next(iterator)
            except StopIteration:
                break
            pending.add(executor.submit(_post_owned_selector, api, url, item, limiter, max_retries, abort_event))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        submit_more(executor)
        while pending:
            finished, pending_remaining = wait(pending, return_when=FIRST_COMPLETED)
            pending = pending_remaining
            for future in finished:
                try:
                    result = future.result()
                except Exception as e:
                    result = {"status": "failed", "name": "(worker)", "error": str(e)}

                status = result.get("status", "failed")
                seed_count = int(result.get("seed_count") or 1)
                counts[status] = counts.get(status, 0) + seed_count
                counts["rate_limited"] += int(result.get("rate_limited") or 0)
                done += seed_count
                requests_done += 1

                if status == "failed":
                    failures.append(result)
                    if verbose or len(failures) <= 20:
                        detail = result.get("error") or "Error"
                        code = result.get("http_status")
                        suffix = f" ({code})" if code else ""
                        print(f"\n{markers['warn']} Owned API{suffix} for {result.get('name')}: {detail}")
                elif status == "auth_failed":
                    failures.append(result)
                    abort_event.set()
                    detail = result.get("error") or "Token Authorization failed"
                    print(f"\n{markers['warn']} Owned API auth failed for {result.get('name')}: {detail}")
                    for pending_future in pending:
                        pending_future.cancel()
                    pending = set()

                _progress(done, total, "Owned API", nocolor)

            submit_more(executor)

    if failures and not verbose and len(failures) > 20:
        print(f"{markers['warn']} Owned API: suppressed {len(failures) - 20} additional failure message(s); re-run with -v to show all")

    print(
        f"{markers['ok']} Owned API: attempted {done}/{total} seed(s) in {requests_done}/{request_total} request(s), "
        f"added {counts['added']}, already existed {counts['exists']}, "
        f"failed {counts['failed'] + counts['auth_failed']}, "
        f"pre-skipped {skipped_existing}, 429 retries {counts['rate_limited']}"
    )

    return {
        "attempted": done,
        "selector_requests": requests_done,
        "selector_request_total": request_total,
        "added": counts["added"],
        "exists": counts["exists"],
        "failed": counts["failed"] + counts["auth_failed"],
        "skipped_existing": skipped_existing,
        "rate_limited": counts["rate_limited"],
    }

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
        session_data = _load_session_data()
    except RuntimeError as e:
        print(f"{markers['warn']} {e}")
        return False

    api = _BloodHoundAPISession(session_data, args, markers, verbose)

    url = f"{api.base_url.rstrip('/')}/api/version"
    headers = {"accept": "application/json", "Prefer": "wait=0"}

    if verbose:
        print(f"{markers['info']} Verifying token via {url}")
        redacted_headers = dict(headers)
        redacted_headers["Authorization"] = "Bearer " + _redact_token(api.token)
        print(f"{markers['info']} Headers:\n{json.dumps(redacted_headers, indent=2)}")

    try:
        resp = api.request("GET", url, headers=headers, timeout=15)
    except requests.RequestException as e:
        print(f"{markers['warn']} Request failed: {e}")
        return False

    if verbose:
        status_marker = markers['ok'] if resp.status_code < 400 else markers['warn']
        print(f"{status_marker} Response status: {resp.status_code}")
        try:
            pretty = json.dumps(resp.json(), indent=2, ensure_ascii=False)
            print(f"{markers['info']} Response JSON:\n{pretty}")
        except ValueError:
            print(f"{markers['info']} Response (non-JSON):\n{resp.text}")

    if resp.status_code != 200:
        print(f"{markers['warn']} {_extract_error_message(resp)}")
        return False

    if verbose:
        print(f"{markers['info']} Using session token: {_redact_token(api.token)}")
        print(f"{markers['info']} Base URL: {api.base_url}")
    else:
        print(f"{markers['ok']} JWT valid")

    clears = getattr(args, "clears", None)
    ntlm = getattr(args, "ntlm", None)

    try:
        _check_file(clears, "Clears file")
        _check_file(ntlm, "NTLM file")
    except RuntimeError as e:
        print(f"{markers['warn']} {e}")
        return False

    pot_stats = _analyze_potfile(clears)
    cracked_map: Dict[str, str] = pot_stats.pop("_cracked_map")
    _print_pot_stats(markers, pot_stats, verbose)

    nt_stats = _analyze_ntlm_file(ntlm)
    _print_nt_stats(markers, nt_stats, verbose)

    if pot_stats["valid_entries"] == 0:
        print(f"{markers['warn']} potfile appears to have no usable NTLM entries (32-hex)")
    if nt_stats["unique_pairs"] == 0:
        print(f"{markers['warn']} ntlm file appears to have no valid (acct, hash) pairs")

    db_uri = getattr(args, "db_uri", None) or DEFAULT_URI
    db_user = getattr(args, "db_user", None) or DEFAULT_USER
    db_pass = getattr(args, "db_pass", None) or DEFAULT_PASS

    if verbose:
        print(f"{markers['info']} Neo4j connection:")
        print(f"    uri={db_uri}")
        print(f"    user={db_user}")
        print(f"    pass={_redact_secret(db_pass)}")

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

        raw_rows: List[Dict[str, str]] = []
        for rec in records:
            nt = rec["nt"]
            pwd = cracked_map.get(nt)
            raw_rows.append({"name": rec["name"], "sam": rec["sam"], "upn": rec["upn"], "nt": nt, "pwd": pwd})

        # Merge rows by account: prefer the row that has a cracked password.
        # This prevents an uncracked hash (e.g. the LM hash from secretsdump
        # output like  user:RID:LM_HASH:NT_HASH:::)  from overwriting the
        # cracked NT hash entry for the same account.
        merged: Dict[str, Dict[str, str]] = {}
        for row in raw_rows:
            key = row["name"].lower()
            existing = merged.get(key)
            if existing is None:
                merged[key] = row
            elif row["pwd"] is not None and existing["pwd"] is None:
                merged[key] = row
        rows = list(merged.values())

        total = len(rows)
        if total == 0:
            print(f"{markers['ok']} Nothing to apply")
        else:
            neo4j_legacy_match = os.getenv("PATCHHOUND_NEO4J_LEGACY_MATCH", "").lower() in ("1", "true", "yes")
            neo4j_update_batch = max(1, int(os.getenv("PATCHHOUND_NEO4J_UPDATE_BATCH", str(NEO4J_UPDATE_BATCH))))

            if verbose:
                print(f"{markers['info']} Applying to Neo4j: {total} candidates (write_temp={write_temp})")
                print(f"    fast_match          : {not neo4j_legacy_match}")
                print(f"    neo4j_update_batch  : {neo4j_update_batch}")

            applied = 0
            done = 0
            unmatched_all = []
            failures = []

            print(f"{markers['ok']} Waiting for Neo4j")

            if neo4j_legacy_match:
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
            else:
                with driver.session() as s:
                    if verbose:
                        print(f"{markers['info']} Building local Neo4j node lookup")
                    index, index_stats = _collect_neo4j_target_index(s)
                    if verbose:
                        print(f"{markers['info']} Neo4j node lookup:")
                        print(f"    total_nodes_indexed : {index_stats['nodes']}")
                        print(f"    users               : {index_stats['users']}")
                        print(f"    azusers             : {index_stats['azusers']}")
                        print(f"    computers           : {index_stats['computers']}")

                    update_rows, unmatched_all = _match_rows_with_neo4j_index(rows, index)
                    update_total = len(update_rows)
                    if verbose:
                        print(f"{markers['info']} Neo4j row matching:")
                        print(f"    account_rows        : {total}")
                        print(f"    matched_nodes       : {update_total}")
                        print(f"    unmatched_rows      : {len(unmatched_all)}")
                    elif unmatched_all:
                        print(f"{markers['info']} Neo4j matched {update_total} node(s); {len(unmatched_all)} account row(s) did not map")

                    if update_total == 0:
                        _progress(total, total, "Applying", nocolor)
                    else:
                        for i in range(0, update_total, neo4j_update_batch):
                            sub = update_rows[i:i+neo4j_update_batch]
                            try:
                                upd = _apply_updates_by_node_id(s, sub, write_temp)
                                applied += upd
                            except Exception as e:
                                failures.append((str(e), sub))
                            finally:
                                done += len(sub)
                                _progress(done, update_total, "Applying", nocolor)

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
                candidates, pass_total, pass_with_sid, sids_with_az = _collect_owned_candidate_sids(s)

            tag_id = getattr(args, "asset_group_tag_id", None)
            if tag_id is None:
                tag_id = int(os.getenv("PATCHHOUND_ASSET_GROUP_TAG_ID",
                             os.getenv("PATCHHOUND_ASSET_GROUP_ID", "2")))
            else:
                tag_id = int(tag_id)

            owned_seeds_per_selector = max(1, int(getattr(args, "owned_seeds_per_selector", None) or os.getenv("PATCHHOUND_OWNED_SEEDS_PER_SELECTOR", "1")))
            default_rate_delay = "0" if owned_seeds_per_selector > 1 else "0.02"
            owned_workers = max(1, int(os.getenv("PATCHHOUND_OWNED_WORKERS", "4")))
            owned_rate_delay = max(0.0, float(os.getenv("PATCHHOUND_OWNED_RATE_DELAY", default_rate_delay)))
            owned_max_retries = max(1, int(os.getenv("PATCHHOUND_OWNED_MAX_RETRIES", "6")))
            owned_skip_existing = os.getenv("PATCHHOUND_OWNED_SKIP_EXISTING", "1").lower() not in ("0", "false", "no")

            owned_result = _append_owned_selectors(
                api,
                tag_id,
                candidates,
                markers,
                verbose,
                workers=owned_workers,
                rate_delay=owned_rate_delay,
                skip_existing=owned_skip_existing,
                max_retries=owned_max_retries,
                seeds_per_selector=owned_seeds_per_selector,
                nocolor=nocolor,
            )

            # final summary (verbose only)
            if verbose:
                ex = candidates[0] if candidates else None
                print(f"{markers['info']} Owned summary:")
                print(f"    users_with_password_true  : {pass_total}")
                print(f"    with_sid                  : {pass_with_sid}")
                print(f"    distinct_sids_sent        : {len(candidates)}")
                print(f"    sids_with_azuser_link     : {sids_with_az}")
                print(f"    asset_group_tag_id        : {tag_id}")
                print(f"    owned_attempted           : {owned_result.get('attempted')}")
                print(f"    owned_added               : {owned_result.get('added')}")
                print(f"    owned_existing_or_conflict: {owned_result.get('exists')}")
                print(f"    owned_pre_skipped         : {owned_result.get('skipped_existing')}")
                print(f"    owned_failed              : {owned_result.get('failed')}")
                print(f"    owned_429_retries         : {owned_result.get('rate_limited')}")
                print(f"    owned_selector_requests   : {owned_result.get('selector_requests')}/{owned_result.get('selector_request_total')}")
                if ex:
                    safe_name = re.sub(r'[^A-Za-z0-9_ ]', '_', ex.get('name', ex['sid']))
                    ex_url = f"{api.base_url.rstrip('/')}/api/v2/asset-group-tags/{tag_id}/selectors"
                    example_payload = {"name": safe_name, "seeds": [{"type": 1, "value": ex['sid']}]}
                    print("    example_request:")
                    print(f"      POST {ex_url}")
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
