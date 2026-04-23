# src/policy.py
#!/usr/bin/env python3
"""Password policy audit — analyses cracked NTDS data offline."""

import re
import string
import sys
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Set

from src.patch import (
    _analyze_potfile,
    _analyze_ntlm_file,
    _check_file,
    _split_account,
)

# Keywords that flag an account as a service / privileged account.
SVC_KEYWORDS = re.compile(
    r"(svc|admin|sql|backup|adm|dev)", re.IGNORECASE
)



TOP_REUSED_LIMIT = 15
TOP_PATTERNS_LIMIT = 15
MIN_PATTERN_LEN = 3
MAX_PATTERN_LEN = 12
MIN_PATTERN_FREQ = 3     # pattern must appear in at least this many passwords

SPECIAL_CHARS = set(string.punctuation)

# ── Table helper ─────────────────────────────────────────────────────

def _table(headers: List[str], rows: List[List[str]], col_align: List[str] = None):
    """Print an ASCII table. col_align entries: '<' left, '>' right."""
    ncols = len(headers)
    if col_align is None:
        col_align = ["<"] * ncols

    # compute column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def _fmt_row(cells, sep="│"):
        parts = []
        for i, cell in enumerate(cells):
            if col_align[i] == ">":
                parts.append(cell.rjust(widths[i]))
            else:
                parts.append(cell.ljust(widths[i]))
        return f"    {sep} " + f" {sep} ".join(parts) + f" {sep}"

    border_top = "    ┌─" + "─┬─".join("─" * w for w in widths) + "─┐"
    border_mid = "    ├─" + "─┼─".join("─" * w for w in widths) + "─┤"
    border_bot = "    └─" + "─┴─".join("─" * w for w in widths) + "─┘"

    print(border_top)
    print(_fmt_row(headers))
    print(border_mid)
    for row in rows:
        print(_fmt_row(row))
    print(border_bot)


# ── Helpers ──────────────────────────────────────────────────────────

def _pct(part: int, whole: int) -> str:
    if whole == 0:
        return "0.0"
    return f"{100 * part / whole:.1f}"


def _match_svc_keyword(sam: str) -> Optional[str]:
    """Return the first matching service-account keyword, or None."""
    m = SVC_KEYWORDS.search(sam)
    return m.group(1).lower() if m else None


def _extract_patterns(passwords: List[str]) -> List[tuple]:
    """Find the most frequent recurring substrings across passwords.

    Slides a window of length 3..MAX_PATTERN_LEN across every password,
    counts how many *distinct* passwords each substring appears in,
    then prunes substrings that are fully contained inside a longer
    substring with equal or higher frequency.
    """
    # Count in how many distinct passwords each substring appears.
    substr_pw_count: Counter = Counter()
    for pw in passwords:
        pw_lower = pw.lower()
        seen_in_pw: Set[str] = set()
        for length in range(MIN_PATTERN_LEN, min(MAX_PATTERN_LEN, len(pw_lower)) + 1):
            for start in range(len(pw_lower) - length + 1):
                sub = pw_lower[start:start + length]
                # skip substrings that are all digits or all alpha — too generic
                # (we keep mixed / special-char patterns)
                if sub.isdigit() and length <= 3:
                    continue
                if sub.isalpha() and length <= 3:
                    continue
                seen_in_pw.add(sub)
        for sub in seen_in_pw:
            substr_pw_count[sub] += 1

    # Filter by minimum frequency.
    candidates = {s: c for s, c in substr_pw_count.items() if c >= MIN_PATTERN_FREQ}

    # Prune: if a shorter substring is fully contained in a longer one
    # with the same or higher frequency, drop the shorter one.
    to_remove: set = set()
    sorted_subs = sorted(candidates.keys(), key=lambda s: -len(s))
    for i, long in enumerate(sorted_subs):
        for short in sorted_subs[i + 1:]:
            if short in long and candidates[short] <= candidates[long]:
                to_remove.add(short)

    pruned = [(s, c) for s, c in candidates.items() if s not in to_remove]
    pruned.sort(key=lambda x: (-x[1], -len(x[0]), x[0]))
    return pruned[:TOP_PATTERNS_LIMIT]


# ── Core audit ───────────────────────────────────────────────────────

def _build_audit(records: List[Dict], cracked_map: Dict[str, str]):
    """Correlate NTDS records with cracked passwords and compute stats."""

    cracked_accounts: List[Dict[str, str]] = []
    uncracked_count = 0
    empty_count = 0

    for rec in records:
        nt = rec["nt"]
        pwd = cracked_map.get(nt)
        _, sam = _split_account(rec["name"])

        if pwd is None:
            uncracked_count += 1
            continue

        if pwd == "" or pwd.isspace():
            empty_count += 1

        cracked_accounts.append({
            "name": rec["name"],
            "sam": sam,
            "password": pwd,
            "nt": nt,
        })

    # ── password reuse ──────────────────────────────────────────────
    pw_counter: Counter = Counter()
    pw_to_accounts: Dict[str, List[str]] = defaultdict(list)
    for entry in cracked_accounts:
        pw = entry["password"]
        pw_counter[pw] += 1
        pw_to_accounts[pw].append(entry["name"])

    unique_passwords = len(pw_counter)

    # ── length distribution (per-length) ────────────────────────────
    length_dist: Dict[int, int] = defaultdict(int)
    for pw in pw_counter:
        plen = len(pw)
        length_dist[plen] += pw_counter[pw]

    # ── special character analysis ──────────────────────────────────
    has_special_count = 0
    no_special_count = 0
    special_char_freq: Counter = Counter()
    for entry in cracked_accounts:
        pw = entry["password"]
        found_any = False
        for ch in pw:
            if ch in SPECIAL_CHARS:
                special_char_freq[ch] += 1
                found_any = True
        if found_any:
            has_special_count += 1
        else:
            no_special_count += 1

    # ── pattern analysis ────────────────────────────────────────────
    all_passwords = [e["password"] for e in cracked_accounts if e["password"]]
    patterns = _extract_patterns(all_passwords)

    # ── service account matches ─────────────────────────────────────
    svc_hits: List[Dict[str, str]] = []
    for entry in cracked_accounts:
        kw = _match_svc_keyword(entry["sam"])
        if kw:
            svc_hits.append({
                "keyword": kw,
                "account": entry["name"],
                "password": entry["password"],
            })

    return {
        "total_records": len(records),
        "cracked_count": len(cracked_accounts),
        "uncracked_count": uncracked_count,
        "empty_count": empty_count,
        "unique_passwords": unique_passwords,
        "pw_counter": pw_counter,
        "pw_to_accounts": pw_to_accounts,
        "length_dist": length_dist,
        "svc_hits": svc_hits,
        "cracked_accounts": cracked_accounts,
        "has_special_count": has_special_count,
        "no_special_count": no_special_count,
        "special_char_freq": special_char_freq,
        "patterns": patterns,
    }


# ── Pretty-print sections ───────────────────────────────────────────

def _print_overview(markers, audit: dict):
    total = audit["total_records"]
    cracked = audit["cracked_count"]
    uncracked = audit["uncracked_count"]
    empty = audit["empty_count"]
    unique = audit["unique_passwords"]

    print(f"{markers['info']} Overview")
    _table(
        ["Metric", "Count", "%"],
        [
            ["Accounts in NTDS",       str(total),     ""],
            ["Cracked",                 str(cracked),   f"{_pct(cracked, total)}%"],
            ["Not cracked",             str(uncracked), f"{_pct(uncracked, total)}%"],
            ["Empty / blank passwords", str(empty),     f"{_pct(empty, total)}%"],
            ["Unique passwords",        str(unique),    f"{_pct(unique, cracked)}%"],
        ],
        col_align=["<", ">", ">"],
    )


def _print_length_dist(markers, audit: dict):
    dist = audit["length_dist"]
    cracked = audit["cracked_count"]

    print(f"{markers['info']} Password Length Distribution")
    rows = []

    if not dist:
        print("    No cracked passwords to measure.")
        return

    for length in sorted(dist.keys()):
        count = dist[length]
        rows.append([str(length), str(count), f"{_pct(count, cracked)}%"])

    rows.append(["Total", str(cracked), "100%"])
    _table(["Length", "Count", "%"], rows, col_align=[">", ">", ">"])


def _print_special_chars(markers, audit: dict):
    cracked = audit["cracked_count"]
    freq = audit["special_char_freq"]

    print(f"{markers['info']} Special Character Usage")
    if not freq:
        print("    No special characters found in cracked passwords.")
        return

    top_chars = freq.most_common(15)
    rows = []
    for ch, cnt in top_chars:
        display = repr(ch).strip("'")  # readable form
        rows.append([display, str(cnt), f"{_pct(cnt, cracked)}%"])
    _table(["Char", "Occurrences", "% of cracked"], rows, col_align=["<", ">", ">"])


def _print_patterns(markers, audit: dict):
    patterns = audit["patterns"]
    cracked = audit["cracked_count"]

    print(f"{markers['info']} Recurring Patterns (substrings found in {MIN_PATTERN_FREQ}+ passwords)")
    if not patterns:
        print("    No recurring patterns detected.")
        return

    rows = []
    for pattern, count in patterns:
        rows.append([pattern, str(count), f"{_pct(count, cracked)}%"])
    _table(["Pattern", "Passwords", "% of cracked"], rows, col_align=["<", ">", ">"])


def _print_reused(markers, audit: dict):
    pw_counter = audit["pw_counter"]

    reused = [(pw, cnt) for pw, cnt in pw_counter.most_common() if cnt > 1]
    print(f"{markers['info']} Top Reused Passwords")
    if not reused:
        print("    No reused passwords detected.")
    else:
        rows = []
        for pw, cnt in reused[:TOP_REUSED_LIMIT]:
            display = pw if pw else "(empty)"
            if len(display) > 30:
                display = display[:27] + "..."
            rows.append([display, str(cnt)])

        total_reused = sum(cnt for _, cnt in reused)
        distinct_reused = len(reused)
        rows.append([f"Total ({distinct_reused} passwords)", str(total_reused)])
        _table(["Password", "Accounts"], rows, col_align=["<", ">"])

    # ── Shortest & longest passwords (immediately after reused table) ──
    all_pws = [pw for pw in pw_counter if pw and not pw.isspace()]
    if all_pws:
        by_len = sorted(all_pws, key=lambda p: (len(p), p))
        shortest = by_len[:3]
        longest = by_len[-3:][::-1]  # longest first

        ext_rows = []
        for pw in shortest:
            display = pw if len(pw) <= 30 else pw[:27] + "..."
            ext_rows.append(["Shortest", display, str(len(pw))])
        for pw in longest:
            display = pw if len(pw) <= 30 else pw[:27] + "..."
            ext_rows.append(["Longest", display, str(len(pw))])
        _table(["Type", "Password", "Length"], ext_rows, col_align=["<", "<", ">"])


def _print_svc_accounts(markers, audit: dict):
    svc = audit["svc_hits"]

    print(f"{markers['info']} Service / Privileged Accounts  (svc, admin, sql, backup, adm, dev)")
    if not svc:
        print("    No service/privileged accounts found with cracked passwords.")
        return

    rows = []
    for h in sorted(svc, key=lambda x: x["keyword"]):
        pw_display = h["password"] if h["password"] else "(empty)"
        rows.append([h["keyword"], h["account"], pw_display])
    rows.append(["Total", str(len(svc)), ""])
    _table(["Keyword", "Account", "Password"], rows, col_align=["<", "<", "<"])


# ── Entry point ──────────────────────────────────────────────────────

def run(args, markers=None, no_color=False) -> bool:
    nocolor = bool(no_color) if no_color is not None else bool(getattr(args, "no_color", False))
    verbose = bool(getattr(args, "verbose", False))

    if markers is None:
        markers = {"ok": "[+]", "info": "[*]", "warn": "[!]"}

    clears = getattr(args, "clears", None)
    ntlm = getattr(args, "ntlm", None)

    try:
        _check_file(clears, "Clears file")
        _check_file(ntlm, "NTLM file")
    except RuntimeError as e:
        print(f"{markers['warn']} {e}")
        return False

    # ── Parse inputs ────────────────────────────────────────────────
    print(f"{markers['info']} Parsing potfile: {clears}")
    pot_stats = _analyze_potfile(clears)
    cracked_map: Dict[str, str] = pot_stats.pop("_cracked_map")
    print(f"{markers['ok']} Potfile: {pot_stats['valid_entries']} cracked hashes loaded")

    print(f"{markers['info']} Parsing NTDS:    {ntlm}")
    nt_stats = _analyze_ntlm_file(ntlm)
    records = nt_stats.get("_records", [])
    print(f"{markers['ok']} NTDS:    {len(records)} account records loaded")

    if not records:
        print(f"{markers['warn']} No valid NTDS records found — nothing to audit.")
        return False

    # ── Correlate & audit ───────────────────────────────────────────
    # Merge records by account: prefer the entry that has a cracked password,
    # mirroring the same dedup logic used in patch.py.
    merged: Dict[str, Dict[str, str]] = {}
    for rec in records:
        nt = rec["nt"]
        pwd = cracked_map.get(nt)
        key = rec["name"].lower()
        existing = merged.get(key)
        if existing is None:
            merged[key] = rec
        elif pwd is not None and cracked_map.get(existing["nt"]) is None:
            merged[key] = rec
    deduped = list(merged.values())

    audit = _build_audit(deduped, cracked_map)

    # ── Print report ────────────────────────────────────────────────
    _print_overview(markers, audit)
    _print_length_dist(markers, audit)
    _print_reused(markers, audit)
    _print_svc_accounts(markers, audit)
    _print_patterns(markers, audit)
    _print_special_chars(markers, audit)

    print()

    # ── Verbose: dump every cracked account ─────────────────────────
    if verbose:
        print(f"{markers['info']} All Cracked Accounts")
        rows = []
        for entry in sorted(audit["cracked_accounts"], key=lambda x: x["name"].lower()):
            pw = entry["password"] if entry["password"] else "(empty)"
            rows.append([entry["name"], pw])
        _table(["Account", "Password"], rows)

    print(f"{markers['ok']} Audit complete.")
    return True
