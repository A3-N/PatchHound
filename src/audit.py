# src/audit.py
import os
import re
from collections import Counter
from typing import Iterable, List, Tuple

try:
    from neo4j.exceptions import Neo4jError
except Exception:
    Neo4jError = Exception

_RE_POTFILE_LINE = re.compile(r'^[A-Za-z0-9+/=._-]{16,}:(.*)$')
_RE_HEX_WRAP = re.compile(r'^\s*\$HEX\[([0-9A-Fa-f]+)\]\s*$')
_RE_HEX32 = re.compile(r'\b[a-fA-F0-9]{32}\b', re.IGNORECASE)

class AuditContext:
    def __init__(self, cracked, ntlm, bloodhound, uri, user, password, verbose=False, nocolor=False, stats=False):
        self.cracked = cracked
        self.ntlm = ntlm
        self.bloodhound = bloodhound
        self.uri = uri
        self.user = user
        self.password = password
        self.verbose = verbose
        self.nocolor = nocolor
        self.stats = stats

def _decode_hex_pw(pw: str) -> str:
    m = _RE_HEX_WRAP.match(pw)
    if not m:
        return pw
    try:
        b = bytes.fromhex(m.group(1))
        try:
            return b.decode("utf-8")
        except UnicodeDecodeError:
            return b.decode("latin-1")
    except Exception:
        return pw

def _scan_potfile_count(path: str) -> int:
    ok = 0
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                if _RE_POTFILE_LINE.match(raw.rstrip("\n")):
                    ok += 1
    except Exception:
        return 0
    return ok

def _scan_ntlm_unique_count(path: str) -> int:
    uniq = set()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                for h in _RE_HEX32.findall(raw):
                    uniq.add(h.lower())
    except Exception:
        return 0
    return len(uniq)

def _potfile_map(path: str):
    m = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            s = raw.rstrip("\n")
            mm = _RE_POTFILE_LINE.match(s)
            if not mm:
                continue
            hash_part, pwd_raw = s.split(":", 1)
            m[hash_part.strip().lower()] = _decode_hex_pw(pwd_raw)
    return m  # dict: hash -> password

def _canonicalize_account(tokens: List[str]) -> str:
    for t in tokens:
        if "\\" in t:
            return t.strip()
    return tokens[0].strip() if tokens else None

def _ntlm_pairs(path: str) -> List[Tuple[str, str]]:
    pairs = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            hashes = _RE_HEX32.findall(line)
            if not hashes:
                continue
            tokens = [p for p in re.split(r'[:\s,;]+', line) if p]
            acct = _canonicalize_account(tokens)
            if not acct:
                continue
            for h in hashes:
                pairs.append((acct, h.lower()))
    return list({(a, h) for a, h in pairs})

def _passwords_from_bloodhound(session) -> List[str]:
    q = """
    MATCH (u:User)
    WITH coalesce(u.Patchhound_pass, u.PatchHound_pass) AS p
    WHERE p IS NOT NULL
    RETURN p
    """
    return [rec["p"] for rec in session.run(q)]

def _audit_from_bloodhound(session):
    q = """
    MATCH (u:User)
    WITH count(u) AS total,
         count(CASE WHEN coalesce(u.Patchhound_pass, u.PatchHound_pass) IS NOT NULL THEN 1 END) AS pass_count,
         count(CASE WHEN coalesce(u.Patchhound_nt,   u.PatchHound_nt)   IS NOT NULL THEN 1 END) AS nt_count,
         count(CASE WHEN coalesce(u.Patchhound_pass, u.PatchHound_pass) IS NOT NULL
                        AND toUpper(coalesce(u.samaccountname,'')) <> '' THEN 1 END) AS pass_with_sam,
         count(CASE WHEN coalesce(u.Patchhound_nt,   u.PatchHound_nt)   IS NOT NULL
                        AND toUpper(coalesce(u.samaccountname,'')) <> '' THEN 1 END) AS nt_with_sam
    RETURN total, pass_count, nt_count, pass_with_sam, nt_with_sam
    """
    rec = session.run(q).single()
    return {
        "total": rec["total"] if rec else 0,
        "pass_count": rec["pass_count"] if rec else 0,
        "nt_count": rec["nt_count"] if rec else 0,
        "pass_with_sam": rec["pass_with_sam"] if rec else 0,
        "nt_with_sam": rec["nt_with_sam"] if rec else 0,
    }

def _render_table(rows: List[Tuple[str, int]], headers: Tuple[str, str]) -> str:
    left_h, right_h = headers
    left_w = max(len(left_h), *(len(str(r[0])) for r in rows)) if rows else len(left_h)
    right_w = max(len(right_h), *(len(str(r[1])) for r in rows)) if rows else len(right_h)
    border = f"+-{'-'*left_w}-+-{'-'*right_w}-+"
    header = f"| {left_h.ljust(left_w)} | {right_h.rjust(right_w)} |"
    out = [border, header, border]
    for left, right in rows:
        out.append(f"| {str(left).ljust(left_w)} | {str(right).rjust(right_w)} |")
    out.append(border)
    return "\n".join(out)

def _print_length_distribution_weighted(pw_freq: Counter) -> str:
    length_counts = Counter()
    for pwd, cnt in pw_freq.items():
        length_counts[len(pwd or "")] += cnt
    rows = sorted(length_counts.items(), key=lambda x: x[0])
    width_len = max(3, *(len(str(k)) for k, _ in rows)) if rows else 3
    width_cnt = max(5, *(len(str(v)) for _, v in rows)) if rows else 5
    border = f"+-{'-'*width_len}-+-{'-'*width_cnt}-+"
    header = f"| {'len'.ljust(width_len)} | {'count'.rjust(width_cnt)} |"
    out = [border, header, border]
    for k, v in rows:
        out.append(f"| {str(k).ljust(width_len)} | {str(v).rjust(width_cnt)} |")
    out.append(border)
    return "\n".join(out)

def run_audit(driver, ctx, markers):
    m = markers(ctx.nocolor)

    if ctx.bloodhound:
        try:
            with driver.session() as s:
                stats = _audit_from_bloodhound(s)
        except Neo4jError as e:
            print(f"{m['warn']} BloodHound audit failed: {e}")
            return False

        print(f"{m['ok']} BloodHound: Users: {stats['total']}")
        if stats["pass_count"] > 0 or stats["nt_count"] > 0:
            if ctx.verbose:
                print(f"{m['info']} Patchhound data present: passwords={stats['pass_count']}, nt={stats['nt_count']}")
        else:
            print(f"{m['warn']} No Patchhound_pass / Patchhound_nt properties found on User nodes")

        if not ctx.stats:
            return True  # stop here without heavy stats

        try:
            with driver.session() as s:
                pwds = _passwords_from_bloodhound(s)
        except Neo4jError as e:
            print(f"{m['warn']} BloodHound password fetch failed: {e}")
            return False

        if len(pwds) == 0:
            print(f"{m['warn']} No Patchhound_pass values found on User nodes")
            return True

        print(f"{m['ok']} Passwords collected from BloodHound: {len(pwds)}")
        pw_freq = Counter(pwds)

    else:
        if not (ctx.cracked and ctx.ntlm):
            print("usage: PatchHound audit -b | -c POTFILE -n FILE")
            return False

        # Basic existence checks always
        c_ok = _scan_potfile_count(ctx.cracked)
        n_ok = _scan_ntlm_unique_count(ctx.ntlm)
        if c_ok > 0:
            print(f"{m['ok']} Potfile OK: {c_ok} structurally valid line{'s' if c_ok!=1 else ''}")
        else:
            print(f"{m['warn']} Potfile invalid or empty of valid lines")
        if n_ok > 0:
            print(f"{m['ok']} NTLM file OK: {n_ok} unique 32-hex hash{'es' if n_ok!=1 else ''}")
        else:
            print(f"{m['warn']} NTLM file invalid or no 32-hex hashes")

        if not ctx.stats:
            return True  # stop here without heavy stats

        pot_map = _potfile_map(ctx.cracked)     # hash -> password
        pairs = _ntlm_pairs(ctx.ntlm)           # [(account, hash)] dedup per (acct,hash)
        joined = 0
        pw_freq = Counter()
        for acct, nt in pairs:
            pwd = pot_map.get(nt)
            if pwd is not None:
                pw_freq[pwd] += 1
                joined += 1

        if joined == 0:
            print(f"{m['warn']} No overlap between NTLM hashes and potfile")
            return True

        print(f"{m['ok']} Joined accounts to potfile: {joined} account-password mappings")

    # Stats output (only when --stats)
    rows_all = sorted(pw_freq.items(), key=lambda kv: (-kv[1], str(kv[0])))
    top = rows_all[:20]

    print()
    print("Most common passwords (top 20):")
    print(_render_table([(p, c) for p, c in top], headers=("password", "count")))

    print()
    print("Password length distribution:")
    print(_print_length_distribution_weighted(pw_freq))

    return True
