#!/usr/bin/env python3
import argparse
import sys
from src import pwetty
from src.auth import run as auth_run
from src.patch import run as patch_run


def build_parser():
    parser = argparse.ArgumentParser(prog="PatchHound", description="PatchHound - BloodHound credential import & ownership tagging tool", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--no-color", action="store_true", help="Disable color output and skip ASCII art")

    subparsers = parser.add_subparsers(dest="command")

    p_auth = subparsers.add_parser("auth", help="Authenticate to BloodHound CE and store JWT in a temp file", formatter_class=argparse.RawTextHelpFormatter)
    p_auth.add_argument("-u", "--url", default="http://localhost:8080/", help="BloodHound CE base URL (default: http://localhost:8080/)")
    p_auth.add_argument("-U", "--username", default="admin", help="Username (default: admin)")
    p_auth.add_argument("-p", "--password", help="Password (if not set, you will be prompted securely)")
    p_auth.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for this command only")

    p_patch = subparsers.add_parser("patch", help="Validate inputs and prepare to patch graph data using JWT & Neo4j defaults", formatter_class=argparse.RawTextHelpFormatter)
    p_patch.add_argument("-c", "--clears", required=True, help="Path to cleartext credentials file (required)")
    p_patch.add_argument("-n", "--ntlm", help="Path to NTLM hashes file")
    p_patch.add_argument("-k", "--kerberos", help="Path to Kerberos credential file")
    p_patch.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for this command only")
    p_patch.add_argument("-t", "--temp", action="store_true", default=False, help="Also write Patchhound_nt and Patchhound_pass")
    p_patch.add_argument("-o", "--owned", action="store_true", default=False, help="(placeholder) no-op")

    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.no_color:
        print(pwetty.ASCII_ART)
        print()

    m = pwetty.markers(nocolor=args.no_color)

    if args.command == "auth":
        try:
            auth_run(args, markers=m, no_color=args.no_color)
            sys.exit(0)
        except KeyboardInterrupt:
            print(f"\n{m['warn']} CTRL+C detected, exiting cleanly.")
            sys.exit(130)
        except Exception as e:
            print(f"{m['warn']} {e}")
            sys.exit(1)

    elif args.command == "patch":
        try:
            patch_run(args, markers=m, no_color=args.no_color)
            sys.exit(0)
        except KeyboardInterrupt:
            print(f"\n{m['warn']} CTRL+C detected, exiting cleanly.")
            sys.exit(130)
        except Exception as e:
            print(f"{m['warn']} {e}")
            sys.exit(1)

    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        from src import pwetty as _p
        print(f"\n{_p.markers()['warn']} CTRL+C")
        sys.exit(130)
