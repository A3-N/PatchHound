from src.pwetty import progress_bar
import sys

CLEAN_STEP = 50

class CleanContext:
    def __init__(self, verbose=False, nocolor=False):
        self.verbose = verbose
        self.nocolor = nocolor

def _progress(done, total, prefix, nocolor):
    bar, pct = progress_bar(done, total, nocolor, width=28)
    sys.stdout.write(f"\r{prefix} [{bar}] {done}/{total} ({pct}%)")
    sys.stdout.flush()
    if done >= total:
        sys.stdout.write("\n")
        sys.stdout.flush()

def _collect_ids(session):
    q = """
    MATCH (n)
    WHERE coalesce(n.Patchhound_has_hash,false)=true
    OR coalesce(n.Patchhound_cracked,false)=true
    OR n.Patchhound_nt IS NOT NULL
    OR n.Patchhound_pass IS NOT NULL
    RETURN id(n) AS id
    """
    return [r["id"] for r in session.run(q)]

def _clean_batch(session, ids):
    q = """
    UNWIND $ids AS nid
    MATCH (n) WHERE id(n)=nid
    REMOVE n.Patchhound_has_hash
    REMOVE n.Patchhound_cracked
    REMOVE n.Patchhound_nt
    REMOVE n.Patchhound_pass
    SET n.system_tags = CASE
        WHEN n.system_tags IS NULL THEN NULL
        ELSE [x IN n.system_tags WHERE x <> 'owned']
    END
    REMOVE n.owned
    RETURN count(n) AS cleaned
    """
    res = session.run(q, ids=ids).single()
    return res["cleaned"] if res else 0

def run_clean(driver, ctx, markers):
    m = markers(ctx.nocolor)
    with driver.session() as s:
        ids = _collect_ids(s)
    total = len(ids)
    if total == 0:
        print(f"{m['ok']} Nothing to clean")
        return True
    if ctx.verbose:
        print(f"{m['info']} Cleaning nodes: {total} candidates")

    cleaned = 0
    done = 0
    with driver.session() as s:
        for i in range(0, total, CLEAN_STEP):
            batch = ids[i:i+CLEAN_STEP]
            try:
                cleaned += _clean_batch(s, batch)
            finally:
                done += len(batch)
                _progress(done, total, "Cleaning", ctx.nocolor)

    print(f"{m['ok']} Cleaned nodes: {cleaned}")
    return True
