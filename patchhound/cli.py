#!/usr/bin/env python3
import argparse
import sys
import traceback

from patchhound import pwetty
from patchhound.auth import run as auth_run
from patchhound.patch import run as patch_run
from patchhound.policy import run as policy_run


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def build_parser():
    parser = argparse.ArgumentParser(
        prog="PatchHound",
        description="PatchHound - BloodHound credential import & ownership tagging tool",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument(
        "--no-color", action="store_true", help="Disable color output and skip ASCII art"
    )

    subparsers = parser.add_subparsers(dest="command")

    p_auth = subparsers.add_parser(
        "auth",
        help="Authenticate to BloodHound CE and store JWT in a temp file",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p_auth.add_argument(
        "-u",
        "--url",
        default="http://localhost:8080/",
        help="BloodHound CE base URL (default: http://localhost:8080/)",
    )
    p_auth.add_argument("-U", "--username", default="admin", help="Username (default: admin)")
    p_auth.add_argument(
        "-p", "--password", help="Password (if not set, you will be prompted securely)"
    )
    p_auth.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Enable verbose output",
    )

    p_patch = subparsers.add_parser(
        "patch",
        help="Patch BloodHound graph data from NTDS credentials",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p_patch.add_argument(
        "-c", "--clears", required=True, help="Path to cleartext credentials file (required)"
    )
    p_patch.add_argument("-n", "--ntlm", required=True, help="Path to NTLM hashes file (required)")
    p_patch.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Enable verbose output",
    )
    p_patch.add_argument(
        "-t",
        "--tag",
        action="store_true",
        help="Write persistent Patchhound_nt and Patchhound_pass properties",
    )
    p_patch.add_argument(
        "-o",
        "--owned",
        action="store_true",
        help="Reconcile cracked AD users with the BloodHound Owned tag",
    )
    p_patch.add_argument("--db-uri", help="Neo4j URI (overrides patchhound/conn.py DEFAULT_URI)")
    p_patch.add_argument("--db-user", help="Neo4j user (overrides patchhound/conn.py DEFAULT_USER)")
    p_patch.add_argument(
        "--db-pass", help="Neo4j password (overrides patchhound/conn.py DEFAULT_PASS)"
    )
    p_patch.add_argument(
        "--asset-group-tag-id",
        type=positive_int,
        help="Owned asset-group-tag ID (default: PATCHHOUND_ASSET_GROUP_TAG_ID or 2)",
    )
    p_patch.add_argument(
        "--owned-seeds-per-selector",
        type=positive_int,
        help=(
            "Group this many SID seeds into each Owned selector request "
            "(default: PATCHHOUND_OWNED_SEEDS_PER_SELECTOR or 500)"
        ),
    )

    p_policy = subparsers.add_parser(
        "policy",
        help="Password policy audit — no Neo4j or API needed",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p_policy.add_argument(
        "-c", "--clears", required=True, help="Path to cleartext credentials file (required)"
    )
    p_policy.add_argument("-n", "--ntlm", required=True, help="Path to NTLM hashes file (required)")
    p_policy.add_argument(
        "-e",
        "--enabled",
        action="store_true",
        help="Only include NTDS entries marked (status=Enabled)",
    )
    p_policy.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Enable verbose output (lists every cracked account)",
    )

    return parser, p_auth, p_patch, p_policy


def main():
    parser, p_auth, p_patch, p_policy = build_parser()

    # Intercept empty runs to print comprehensive help
    if len(sys.argv) == 1:
        print(pwetty.ASCII_ART)
        print()
        parser.print_help()
        print("\n")
        p_auth.print_help()
        print("\n")
        p_patch.print_help()
        print("\n")
        p_policy.print_help()
        sys.exit(0)

    # Intercept subcommand runs missing required arguments to just print help instead of erroring
    if len(sys.argv) == 2 and sys.argv[1] == "patch":
        p_patch.print_help()
        sys.exit(0)

    if len(sys.argv) == 2 and sys.argv[1] == "policy":
        p_policy.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if not args.no_color:
        print(pwetty.ASCII_ART)
        print()

    m = pwetty.markers(nocolor=args.no_color)

    runner = {
        "auth": auth_run,
        "patch": patch_run,
        "policy": policy_run,
    }.get(args.command)
    if runner is None:
        parser.print_help()
        sys.exit(0)

    try:
        success = runner(args, markers=m, no_color=args.no_color)
    except KeyboardInterrupt:
        print(f"\n{m['warn']} CTRL+C detected, exiting cleanly.")
        sys.exit(130)
    except Exception as e:
        print(f"{m['warn']} {e}")
        if args.verbose:
            traceback.print_exc(file=sys.stdout)
        sys.exit(1)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
