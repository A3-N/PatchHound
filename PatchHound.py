#!/usr/bin/env python3
import argparse
import os
import sys
import getpass
import re
from src.pwetty import ASCII_ART, markers
from src.conn import DEFAULT_URI, DEFAULT_USER, DEFAULT_PASS
from src.patch import PatchContext, run_patches
from src.clean import CleanContext, run_clean

_RE_POTFILE_LINE = re.compile(r'^[A-Za-z0-9+/=._-]{16,}:[^\r\n]*$')
_RE_HEX_PW = re.compile(r':\s*\$HEX\[([0-9A-Fa-f]+)\]\s*$')
_RE_HEX32 = re.compile(r'\b[a-fA-F0-9]{32}\b', re.IGNORECASE)

def build_parser():
    parser = argparse.ArgumentParser(prog="PatchHound")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("help", help="Show this help")

    patch = subparsers.add_parser("patch", help="Run patch operations")
    patch.add_argument("-c", "--cracked", metavar="POTFILE")
    patch.add_argument("-n", "--ntlm", metavar="FILE")
    patch.add_argument("--nocolor", action="store_true")
    patch.add_argument("-u", "--user")
    patch.add_argument("-p", "--password")
    patch.add_argument("--pass-ask", action="store_true")
    patch.add_argument("--uri")
    patch.add_argument("-r", "--redact", action="store_true")
    patch.add_argument("-v", "--verbose", action="store_true")

    clean = subparsers.add_parser("clean", help="Undo PatchHound changes")
    clean.add_argument("--nocolor", action="store_true")
    clean.add_argument("-u", "--user")
    clean.add_argument("-p", "--password")
    clean.add_argument("--pass-ask", action="store_true")
    clean.add_argument("--uri")
    clean.add_argument("-v", "--verbose", action="store_true")

    audit = subparsers.add_parser("audit", help="Audit graph")
    audit.add_argument("-b", "--bloodhound", action="store_true")
    audit.add_argument("-c", "--cracked", metavar="POTFILE")
    audit.add_argument("-n", "--ntlm", metavar="FILE")
    audit.add_argument("--nocolor", action="store_true")
    audit.add_argument("-u", "--user")
    audit.add_argument("-p", "--password")
    audit.add_argument("--pass-ask", action="store_true")
    audit.add_argument("--uri")
    audit.add_argument("-s", "--stats", action="store_true")
    audit.add_argument("-v", "--verbose", action="store_true")
    return parser

def _decode_hex_from_line(line):
    m = _RE_HEX_PW.search(line.strip())
    if not m:
        return None, None
    hexstr = m.group(1)
    try:
        b = bytes.fromhex(hexstr)
    except Exception:
        return None, False
    try:
        return b.decode("utf-8"), True
    except UnicodeDecodeError:
        try:
            return b.decode("latin-1"), True
        except Exception:
            return None, False

def potfile_scan(potfile_path: str):
    valid_count = 0
    excluded_other = []
    hex_infos = []
    try:
        with open(potfile_path, "r", encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                line = raw.rstrip("\n")
                s = line.strip()
                if not s or s.startswith("#"):
                    excluded_other.append(line)
                    continue
                if _RE_POTFILE_LINE.match(s):
                    valid_count += 1
                    dec_txt, ok = _decode_hex_from_line(s)
                    if ok is not None:
                        hex_infos.append((line, dec_txt, ok))
                else:
                    excluded_other.append(line)
    except Exception:
        return 0, [], []
    return valid_count, excluded_other, hex_infos

def ntlm_scan(path: str):
    hashes = set()
    excluded = []
    total_lines = 0
    with_hash = 0
    total_tokens = 0
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                total_lines += 1
                line = raw.rstrip("\n")
                s = line.strip()
                found = _RE_HEX32.findall(s) if s and not s.startswith("#") else []
                if found:
                    with_hash += 1
                    total_tokens += len(found)
                    for h in found:
                        hashes.add(h.lower())
                else:
                    excluded.append(line)
    except Exception:
        return set(), [], {"total_lines": 0, "lines_with_hash": 0, "lines_without_hash": 0, "total_hash_tokens": 0, "unique_hashes": 0}
    stats = {
        "total_lines": total_lines,
        "lines_with_hash": with_hash,
        "lines_without_hash": total_lines - with_hash,
        "total_hash_tokens": total_tokens,
        "unique_hashes": len(hashes),
    }
    return hashes, excluded, stats

def mask_pass(pw: str) -> str:
    if pw is None:
        return "<none>"
    if pw == "":
        return "<empty>"
    if len(pw) <= 2:
        return "*" * len(pw)
    return pw[0] + ("*" * min(len(pw) - 2, 8)) + pw[-1]

def test_neo4j_auth(uri: str, user: str, password: str, m, verbose: bool) -> bool:
    if verbose:
        print(f"{m['info']} Testing Neo4j authentication")
    try:
        from neo4j import GraphDatabase
    except ModuleNotFoundError:
        print(f"{m['warn']} Neo4j Python driver not installed. Install with: pip install neo4j")
        return False
    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        driver.verify_connectivity()
        with driver.session() as s:
            s.run("RETURN 1").consume()
        driver.close()
        print(f"{m['ok']} Neo4j auth OK")
        return True
    except Exception as e:
        try:
            driver.close()
        except Exception:
            pass
        print(f"{m['warn']} Neo4j auth failed: {e}")
        return False

def run_patch(args):
    m = markers(args.nocolor)
    if not (args.cracked and args.ntlm):
        print("usage: PatchHound patch -c POTFILE -n FILE")
        sys.exit(1)
    conn_uri = args.uri or DEFAULT_URI
    conn_user = args.user or DEFAULT_USER
    conn_pass = args.password or DEFAULT_PASS
    if args.pass_ask:
        conn_pass = getpass.getpass(prompt="Enter Neo4j password: ")
    if args.verbose:
        print(f"{m['info']} Checking potfile: {args.cracked}")
    if not os.path.isfile(args.cracked):
        print(f"{m['warn']} Potfile not found: {args.cracked}")
        sys.exit(1)
    pot_count, pot_excluded, pot_hex_infos = potfile_scan(args.cracked)
    if pot_count == 0:
        print(f"{m['warn']} Potfile invalid: no structurally valid 'hash:password' lines found")
        if args.verbose:
            print(f"{m['info']} EXCLUDED FROM POTFILE")
            if pot_excluded:
                for ex in pot_excluded:
                    print(f"{m['info']} {ex}")
            else:
                print(f"{m['info']} (none)")
            print(f"{m['info']} POTFILE $HEX[...] PASSWORDS")
            if pot_hex_infos:
                for orig, dec, ok in pot_hex_infos:
                    if ok and dec is not None:
                        print(f"{m['info']} {orig}:{dec}")
                    else:
                        print(f"{m['info']} {orig} -> decode failed (manual review)")
            else:
                print(f"{m['info']} (none)")
        sys.exit(1)
    print(f"{m['ok']} Potfile valid: {pot_count} structurally valid line{'s' if pot_count!=1 else ''}")
    if args.verbose:
        print(f"{m['info']} EXCLUDED FROM POTFILE")
        if pot_excluded:
            for ex in pot_excluded:
                print(f"{m['info']} {ex}")
        else:
            print(f"{m['info']} (none)")
        print(f"{m['info']} POTFILE $HEX[...] PASSWORDS")
        if pot_hex_infos:
            for orig, dec, ok in pot_hex_infos:
                if ok and dec is not None:
                    print(f"{m['info']} {orig}:{dec}")
                else:
                    print(f"{m['info']} {orig} -> decode failed (manual review)")
        else:
            print(f"{m['info']} (none)")
        print()
    if args.verbose:
        print(f"{m['info']} Checking NTLM file: {args.ntlm}")
    if not os.path.isfile(args.ntlm):
        print(f"{m['warn']} NTLM file not found: {args.ntlm}")
        sys.exit(1)
    hashes, ntlm_excluded, nt_stats = ntlm_scan(args.ntlm)
    if not hashes:
        print(f"{m['warn']} NTLM file invalid: no NT/NTLM/LM 32-hex hashes found")
        if args.verbose:
            print(f"{m['info']} EXCLUDED FROM NTLM FILE")
            if ntlm_excluded:
                for ex in ntlm_excluded:
                    print(f"{m['info']} {ex}")
            else:
                print(f"{m['info']} (none)")
        sys.exit(1)
    print(f"{m['ok']} NTLM file valid: {len(hashes)} unique 32-hex hash{'es' if len(hashes)!=1 else ''}")
    if args.verbose:
        dups = max(0, nt_stats["total_hash_tokens"] - nt_stats["unique_hashes"])
        print(f"{m['info']} NTLM stats:")
        print(f"{m['info']}   total lines         : {nt_stats['total_lines']}")
        print(f"{m['info']}   lines with ≥1 hash  : {nt_stats['lines_with_hash']}")
        print(f"{m['info']}   lines with 0 hashes : {nt_stats['lines_without_hash']}")
        print(f"{m['info']}   total hash tokens   : {nt_stats['total_hash_tokens']}")
        print(f"{m['info']}   unique hashes       : {nt_stats['unique_hashes']}")
        print(f"{m['info']}   duplicate tokens    : {dups}")
        print(f"{m['info']} EXCLUDED FROM NTLM FILE")
        if ntlm_excluded:
            for ex in ntlm_excluded:
                print(f"{m['info']} {ex}")
        else:
            print(f"{m['info']} (none)")
        print()
        print(f"{m['info']} Neo4j connection:")
        print(f"{m['info']}     URI : {conn_uri}")
        print(f"{m['info']}     User: {conn_user}")
        print(f"{m['info']}     Pass: {mask_pass(conn_pass)}")
        print()
    ok = test_neo4j_auth(conn_uri, conn_user, conn_pass, m, args.verbose)
    if not ok:
        sys.exit(1)
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(conn_uri, auth=(conn_user, conn_pass))
        run_patches(driver, PatchContext(args.cracked, args.ntlm, conn_uri, conn_user, conn_pass, args.verbose, args.nocolor), markers, redact=args.redact)
    finally:
        try:
            driver.close()
        except Exception:
            pass
    print(f"{m['ok']} bye...?")
    sys.exit(0)

def run_clean_cmd(args):
    m = markers(args.nocolor)
    conn_uri = args.uri or DEFAULT_URI
    conn_user = args.user or DEFAULT_USER
    conn_pass = args.password or DEFAULT_PASS
    if args.pass_ask:
        conn_pass = getpass.getpass(prompt="Enter Neo4j password: ")
    if args.verbose:
        print(f"{m['info']} Neo4j connection:")
        print(f"{m['info']}     URI : {conn_uri}")
        print(f"{m['info']}     User: {conn_user}")
        print(f"{m['info']}     Pass: {mask_pass(conn_pass)}")
        print()
    ok = test_neo4j_auth(conn_uri, conn_user, conn_pass, m, args.verbose)
    if not ok:
        sys.exit(1)
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(conn_uri, auth=(conn_user, conn_pass))
        run_clean(driver, CleanContext(args.verbose, args.nocolor), markers)
    finally:
        try:
            driver.close()
        except Exception:
            pass
    print(f"{m['ok']} Cleanup complete")
    print(f"{m['ok']} bye...?")
    sys.exit(0)

from src.audit import AuditContext, run_audit

def run_audit_cmd(args):
    m = markers(args.nocolor)

    def _has_extra_flags(a):
        return any([
            a.stats,
            a.nocolor,
            a.user is not None,
            a.password is not None,
            a.pass_ask,
            a.uri is not None,
        ])

    if not (args.bloodhound or (args.cracked and args.ntlm)):
        print("usage: PatchHound audit -b | -c POTFILE -n FILE [--stats|--nocolor|-u USER|-p PASS|--pass-ask|--uri URI] [-v]")
        sys.exit(1)

    if not _has_extra_flags(args):
        print("usage: PatchHound audit -b | -c POTFILE -n FILE [--stats|--nocolor|-u USER|-p PASS|--pass-ask|--uri URI] [-v]")
        sys.exit(1)


    if not (args.bloodhound or (args.cracked and args.ntlm)):
        print("usage: PatchHound audit -b | -c POTFILE -n FILE")
        sys.exit(1)

    conn_uri = args.uri or DEFAULT_URI
    conn_user = args.user or DEFAULT_USER
    conn_pass = args.password or DEFAULT_PASS
    if args.pass_ask:
        conn_pass = getpass.getpass(prompt="Enter Neo4j password: ")

    if args.bloodhound:
        if args.verbose:
            print(f"{m['info']} Neo4j connection:")
            print(f"{m['info']}     URI : {conn_uri}")
            print(f"{m['info']}     User: {conn_user}")
            print(f"{m['info']}     Pass: {mask_pass(conn_pass)}")
            print()
        ok = test_neo4j_auth(conn_uri, conn_user, conn_pass, m, args.verbose)
        if not ok:
            sys.exit(1)
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(conn_uri, auth=(conn_user, conn_pass))
        try:
            from src.audit import AuditContext, run_audit
            ctx = AuditContext(
                cracked=None, ntlm=None, bloodhound=True,
                uri=conn_uri, user=conn_user, password=conn_pass,
                verbose=args.verbose, nocolor=args.nocolor, stats=args.stats
            )
            run_audit(driver, ctx, markers)
        finally:
            try: driver.close()
            except: pass
    else:
        from src.audit import AuditContext, run_audit
        ctx = AuditContext(
            cracked=args.cracked, ntlm=args.ntlm, bloodhound=False,
            uri=None, user=None, password=None,
            verbose=args.verbose, nocolor=args.nocolor, stats=args.stats
        )
        run_audit(None, ctx, markers)

    print(f"{m['ok']} Audit ready")
    print(f"{m['ok']} (-.-)Zzz...")
    sys.exit(0)

def main():
    argv = sys.argv[1:]
    if "--nocolor" not in argv:
        print(ASCII_ART)
    parser = build_parser()
    if len(argv) == 0:
        parser.print_usage(sys.stderr)
        sys.exit(1)
    if argv[0] == "help":
        parser.print_help(sys.stderr)
        sys.exit(0)
    try:
        args = parser.parse_args()
    except SystemExit:
        raise
    if args.command == "patch":
        run_patch(args)
    elif args.command == "clean":
        run_clean_cmd(args)
    elif args.command == "audit":
        run_audit_cmd(args)
    else:
        parser.print_usage(sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        from src.pwetty import markers
        nocol = ("--nocolor" in sys.argv[1:])
        m = markers(nocol)
        print(f"\n{m['warn']} bye...?")
        sys.exit(130)
