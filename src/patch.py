import re
import sys
from collections import defaultdict
from src.pwetty import progress_bar

BATCH_SIZE = 1000
APPLY_STEP = 50

HEX32 = re.compile(r'\b[a-fA-F0-9]{32}\b')
HEX_WRAP = re.compile(r'^\s*\$HEX\[([0-9A-Fa-f]+)\]\s*$')

class PatchContext:
    def __init__(self, potfile, ntlm_path, uri, user, password, verbose=False, nocolor=False):
        self.potfile = potfile
        self.ntlm_path = ntlm_path
        self.uri = uri
        self.user = user
        self.password = password
        self.verbose = verbose
        self.nocolor = nocolor

def _decode_hex_pw(pw):
    m = HEX_WRAP.match(pw)
    if not m:
        return pw, False
    try:
        b = bytes.fromhex(m.group(1))
        try:
            return b.decode("utf-8"), True
        except UnicodeDecodeError:
            return b.decode("latin-1"), True
    except Exception:
        return pw, False

def _load_potfile(path):
    cracked = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            s = raw.strip()
            if not s or s.startswith("#") or ":" not in s:
                continue
            h, pwd = s.split(":", 1)
            h = h.strip().lower()
            decoded, _ = _decode_hex_pw(pwd)
            cracked[h] = decoded
    return cracked

def _canonicalize_account(tokens):
    for t in tokens:
        t = t.strip()
        if "\\" in t:
            return t
    return tokens[0].strip() if tokens else None

def _split_account(acct):
    if "\\" in acct:
        dom, sam = acct.split("\\", 1)
        return dom, sam
    return None, acct

def _load_ntlm_file(path):
    pairs = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            hashes = HEX32.findall(line)
            if not hashes:
                continue
            tokens = [p for p in re.split(r'[:\s,;]+', line) if p]
            acct = _canonicalize_account(tokens)
            if not acct:
                continue
            for h in hashes:
                pairs.append((acct, h.lower()))
    return pairs

def _progress(done, total, prefix, nocolor):
    bar, pct = progress_bar(done, total, nocolor, width=28)
    sys.stdout.write(f"\r{prefix} [{bar}] {done}/{total} ({pct}%)")
    sys.stdout.flush()
    if done >= total:
        sys.stdout.write("\n")
        sys.stdout.flush()

def _pre_match(session, rows):
    q = """
    UNWIND $rows AS r
    OPTIONAL MATCH (u_exact:User {name:r.name})
    WITH r, collect(u_exact) AS exacts
    CALL {
      WITH r, exacts
      OPTIONAL MATCH (u_sam:User)
        WHERE size(exacts)=0 AND toUpper(coalesce(u_sam.samaccountname,'')) = r.sam
      WITH r, exacts, collect(u_sam) AS sam_users
      OPTIONAL MATCH (c:Computer)
        WHERE size(exacts)=0 AND toUpper(coalesce(c.samaccountname,'')) = r.sam
      WITH r, exacts, sam_users, collect(c) AS comps
      RETURN CASE WHEN size(exacts)>0 THEN exacts ELSE sam_users + comps END AS targets
    }
    WITH r, targets
    WITH {r:r, has:size(targets)>0} AS row
    RETURN
      [x IN collect(row) WHERE NOT x.has | x.r] AS missing,
      [x IN collect(row) WHERE x.has | x.r] AS found
    """
    res = session.run(q, rows=rows).single()
    missing = res["missing"] if res and res["missing"] else []
    found = res["found"] if res and res["found"] else []
    return found, missing

def _apply_updates(session, rows, redact):
    q = """
    UNWIND $rows AS r
    OPTIONAL MATCH (u_exact:User {name:r.name})
    WITH r, collect(u_exact) AS exacts
    CALL {
      WITH r, exacts
      OPTIONAL MATCH (u_sam:User)
        WHERE size(exacts)=0 AND toUpper(coalesce(u_sam.samaccountname,'')) = r.sam
      WITH r, exacts, collect(u_sam) AS sam_users
      OPTIONAL MATCH (c:Computer)
        WHERE size(exacts)=0 AND toUpper(coalesce(c.samaccountname,'')) = r.sam
      WITH r, exacts, sam_users, collect(c) AS comps
      RETURN CASE WHEN size(exacts)>0 THEN exacts ELSE sam_users + comps END AS targets
    }
    UNWIND targets AS n
    SET n.Patchhound_has_hash = true
    FOREACH (_ IN CASE WHEN $redact THEN [] ELSE [1] END |
        SET n.Patchhound_nt = r.nt
    )
    FOREACH (_ IN CASE WHEN r.pwd IS NULL THEN [] ELSE [1] END |
        SET n.Patchhound_cracked = true
    )
    FOREACH (_ IN CASE WHEN r.pwd IS NULL THEN [] ELSE [1] END |
        SET n.owned = true,
            n.system_tags = CASE
                WHEN n.system_tags IS NULL THEN ['owned']
                WHEN 'owned' IN n.system_tags THEN n.system_tags
                ELSE n.system_tags + 'owned'
            END
    )
    FOREACH (_ IN CASE WHEN r.pwd IS NULL OR $redact THEN [] ELSE [1] END |
        SET n.Patchhound_pass = r.pwd
    )
    RETURN count(DISTINCT n) AS updated
    """
    res = session.run(q, rows=rows, redact=redact).single()
    return res["updated"] if res and "updated" in res else 0

def run_patches(driver, ctx, markers, redact=False):
    m = markers(ctx.nocolor)

    cracked = _load_potfile(ctx.potfile)
    nt_pairs = _load_ntlm_file(ctx.ntlm_path)

    rows = []
    seen = set()
    for acct, nt in nt_pairs:
        key = (acct.lower(), nt)
        if key in seen:
            continue
        seen.add(key)
        _, sam = _split_account(acct)
        pwd = cracked.get(nt)
        rows.append({
            "name": acct,
            "sam": (sam or "").upper(),
            "nt": nt,
            "pwd": pwd,
        })

    total = len(rows)
    if total == 0:
        print(f"{m['ok']} Nothing to apply")
        return True

    if ctx.verbose:
        print(f"{m['info']} Applying to Neo4j: {total} candidates")

    applied = 0
    done = 0
    unmatched_all = []
    failures = []

    with driver.session() as s:
        for i in range(0, total, BATCH_SIZE):
            chunk = rows[i:i+BATCH_SIZE]
            found, missing = _pre_match(s, chunk)

            if missing:
                unmatched_all.extend(missing)
                done += len(missing)
                _progress(done, total, "Applying", ctx.nocolor)

            if not found:
                continue

            for j in range(0, len(found), APPLY_STEP):
                sub = found[j:j+APPLY_STEP]
                try:
                    upd = _apply_updates(s, sub, redact)
                    applied += upd
                except Exception as e:
                    failures.append((str(e), sub))
                finally:
                    done += len(sub)
                    _progress(done, total, "Applying", ctx.nocolor)

    print(f"{m['ok']} Updated nodes: {applied}")
    if unmatched_all:
        print(f"{m['warn']} Failed to map: {len(unmatched_all)}")
        if ctx.verbose:
            for r in unmatched_all:
                nm = r.get("name") or "(unknown)"
                sm = r.get("sam") or "(none)"
                print(f"{m['info']} {nm} -> no match on User.name or Computer.samaccountname ({sm})")
    if failures:
        print(f"{m['warn']} Write failures: {len(failures)}")
        if ctx.verbose:
            for msg, sub in failures:
                ex_count = len(sub)
                sample = sub[0] if sub else {}
                who = sample.get("name") or sample.get("sam") or "(unknown)"
                print(f"{m['info']} {ex_count} rows failed starting at {who} -> {msg}")

    return True
