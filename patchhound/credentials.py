"""Parse hashcat potfiles and secretsdump-style NTDS records."""

import os
import re

HEX32 = re.compile(r"\b[a-fA-F0-9]{32}\b")
LM_NT_RE = re.compile(r"\b([a-fA-F0-9]{32}):([a-fA-F0-9]{32})\b")
HEX_WRAP = re.compile(r"^\s*\$HEX\[([0-9A-Fa-f]+)\]\s*$")
UPN_RE = re.compile(r"^[^\s@]+@[^\s@]+$")
NTDS_STATUS_RE = re.compile(r"\(\s*status\s*=\s*(enabled|disabled)\s*\)", re.IGNORECASE)

DIAGNOSTIC_SAMPLE_LIMIT = 200


def _remember(items: list[str], value: str):
    if len(items) < DIAGNOSTIC_SAMPLE_LIMIT:
        items.append(value)


def check_file(path: str, what: str):
    if not path:
        raise RuntimeError(f"{what} path is required")
    if not os.path.exists(path):
        raise RuntimeError(f"{what} not found: {path}")
    if not os.path.isfile(path):
        raise RuntimeError(f"{what} is not a file: {path}")


def decode_hex_password(password: str) -> tuple[str, bool, str | None]:
    match = HEX_WRAP.match(password)
    if not match:
        return password, False, None
    try:
        raw = bytes.fromhex(match.group(1))
    except ValueError:
        return password, False, None
    try:
        return raw.decode("utf-8"), True, match.group(0)
    except UnicodeDecodeError:
        return raw.decode("latin-1"), True, match.group(0)


def analyze_potfile(path: str) -> dict[str, object]:
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
    cracked: dict[str, str] = {}

    with open(path, encoding="utf-8", errors="ignore") as handle:
        for raw in handle:
            stats["lines_total"] += 1
            line = raw.rstrip("\r\n")
            stripped = line.strip()

            if not stripped or stripped.startswith("#"):
                _remember(stats["excluded_lines"], f"blank_or_comment | {line}")
                stats["excluded_count"] += 1
                continue

            stats["entries_total"] += 1
            if ":" not in line:
                _remember(stats["excluded_lines"], f"no_colon | {line}")
                stats["excluded_count"] += 1
                continue

            # Whitespace can be the password. Only normalize the hash side.
            nt_hash, password = line.split(":", 1)
            nt_hash = nt_hash.strip().lower()
            if HEX32.fullmatch(nt_hash) is None:
                _remember(stats["excluded_lines"], f"hash_not_32hex | {line}")
                stats["excluded_count"] += 1
                continue

            stats["valid_entries"] += 1
            stats["ntlm32_valid"] += 1

            decoded, was_hex, original = decode_hex_password(password)
            if was_hex:
                stats["hex_wrapped"] += 1
                stats["hex_decoded"] += 1
                _remember(stats["hex_decoded_lines"], f"{nt_hash}:{original}:{decoded}")

            cracked[nt_hash] = decoded

    stats["unique_hashes"] = len(cracked)
    stats["_cracked_map"] = cracked
    return stats


def canonicalize_account(account_prefix: str) -> str | None:
    """Return the account field while preserving valid internal whitespace.

    secretsdump writes ``account:RID:LM:NT``.  The LM/NT match gives us the
    complete prefix, so remove only the final decimal RID instead of splitting
    the account on whitespace.  AD SAM names may legally contain spaces.
    """

    account = account_prefix.strip()
    before_rid, separator, rid = account.rpartition(":")
    if separator and rid.strip().isdigit():
        account = before_rid.strip()
    return account or None


def extract_upn(tokens: list[str]) -> str | None:
    for token in tokens:
        token = token.strip()
        if UPN_RE.fullmatch(token):
            return token
    return None


def split_account(account: str) -> tuple[str | None, str]:
    if "\\" in account:
        domain, sam = account.split("\\", 1)
        return domain, sam
    return None, account


def record_key(domain: str | None, sam: str | None, upn: str | None) -> str:
    if domain and sam:
        return f"downlevel:{domain.casefold()}\\{sam.casefold()}"
    if upn:
        return f"upn:{upn.casefold()}"
    return f"sam:{(sam or '').casefold()}"


def analyze_ntlm_file(path: str) -> dict[str, object]:
    stats = {
        "lines_total": 0,
        "lines_with_hash": 0,
        "hashes_total": 0,
        "unique_hashes": 0,
        "valid_records": 0,
        "current_accounts": 0,
        "excluded_count": 0,
        "excluded_lines": [],
    }
    records_by_account: dict[str, dict[str, str]] = {}
    hashes_seen = set()

    with open(path, encoding="utf-8", errors="ignore") as handle:
        for raw in handle:
            stats["lines_total"] += 1
            line = raw.rstrip("\r\n")
            stripped = line.strip()

            if not stripped or stripped.startswith("#"):
                _remember(stats["excluded_lines"], f"blank_or_comment | {line}")
                stats["excluded_count"] += 1
                continue

            lm_nt_match = LM_NT_RE.search(stripped)
            if not lm_nt_match:
                _remember(stats["excluded_lines"], f"no_lm_nt_pair | {line}")
                stats["excluded_count"] += 1
                continue

            nt_hash = lm_nt_match.group(2).lower()
            stats["lines_with_hash"] += 1
            stats["hashes_total"] += 1

            # The account and optional RID precede the LM:NT pair. Restricting
            # account discovery to that prefix prevents metadata from being
            # mistaken for the account name.
            account_prefix = stripped[: lm_nt_match.start()].rstrip(": \t")
            all_tokens = [part for part in re.split(r"[:\s,;]+", stripped) if part]
            account = canonicalize_account(account_prefix)
            upn = extract_upn(all_tokens)
            status_match = NTDS_STATUS_RE.search(stripped)
            status = status_match.group(1).lower() if status_match else ""

            if not account:
                _remember(stats["excluded_lines"], f"no_account_token | {line}")
                stats["excluded_count"] += 1
                continue

            domain, sam = split_account(account)
            if not domain and UPN_RE.fullmatch(account):
                upn = account
                sam = ""

            normalized_sam = (sam or "").upper()
            normalized_upn = (upn or "").upper()
            account_key = record_key(domain, sam, upn)
            # Input order is authoritative for concatenated NTDS snapshots.
            # Moving an existing key to the end also preserves the true order
            # when an account returns to a previously seen hash.
            records_by_account.pop(account_key, None)
            records_by_account[account_key] = {
                "name": account,
                "domain": domain or "",
                "sam": normalized_sam,
                "upn": normalized_upn,
                "nt": nt_hash,
                "status": status,
            }
            hashes_seen.add(nt_hash)
            stats["valid_records"] += 1

    records = list(records_by_account.values())
    stats["unique_hashes"] = len(hashes_seen)
    stats["current_accounts"] = len(records)
    stats["_records"] = records
    return stats
