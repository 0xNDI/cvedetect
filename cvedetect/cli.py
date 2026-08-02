"""Command-line entrypoint.

Authentication arguments mirror impacket's ``smbclient.py`` exactly so existing
muscle memory and toolchains transfer:

    cvedetect [[domain/]username[:password]@]<target> [impacket auth opts]

Examples:
    cvedetect checkpoint.htb/alex.turner:'p@ss'@checkpoint.htb
    cvedetect -hashes :ad3b4...b0f0  user@10.10.10.10
    cvedetect -k user@DC01.corp.local
    cvedetect --list
"""

from __future__ import annotations

import argparse
import contextlib
import sys

from impacket import version
from impacket.examples.utils import parse_target

from . import cvedb, reporter
from .connection import (
    AuthArgs,
    CveDetectError,
    connect,
    get_os_version,
    read_ubr,
    trigger_remote_registry,
)
from .detector import HostInfo, evaluate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        add_help=True,
        description=(
            "Detect Windows local-EoP patch-level CVEs over SMB by reading the OS build "
            "(SMB negotiate) and UBR (RemoteRegistry). Same auth interface as impacket "
            "smbclient.py."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "This is a patch-level heuristic: it relies on the OS version and UBR reported "
            "in the registry and does NOT verify the vulnerable component is present or "
            "unmitigated. All listed CVEs are local Elevation-of-Privilege (CVSS 7.8)."
        ),
    )
    parser.add_argument(
        "target", nargs="?", action="store", help="[[domain/]username[:password]@]<targetName or address>"
    )
    parser.add_argument(
        "-c",
        "--cve",
        action="store",
        default="all",
        help="Comma-separated CVE IDs to check (default: all). Use 'all' for all CVEs.",
    )
    parser.add_argument(
        "-e", "--exploitation", action="store_true", help="Also print exploitation references for vulnerable CVEs."
    )
    parser.add_argument("--list", action="store_true", help="List the CVE database and exit (no connection).")
    parser.add_argument(
        "--no-trigger",
        action="store_true",
        help="Skip the RemoteRegistry wakeup nudge (assume the service is running).",
    )
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")
    parser.add_argument("-ts", action="store_true", help="Add a timestamp to logging output")

    ag = parser.add_argument_group("authentication")
    ag.add_argument("-hashes", action="store", metavar="LMHASH:NTHASH", help="NTLM hashes, format is LMHASH:NTHASH")
    ag.add_argument("-no-pass", action="store_true", help="Don't ask for password (useful with -k)")
    ag.add_argument("-k", action="store_true", help="Use Kerberos authentication (ccache via KRB5CCNAME or CLI creds)")
    ag.add_argument(
        "-aesKey", action="store", metavar="hex key", help="AES key for Kerberos authentication (128 or 256 bits)"
    )

    cg = parser.add_argument_group("connection")
    cg.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help="IP of the domain controller (Kerberos). Defaults to the FQDN in target.",
    )
    cg.add_argument(
        "-target-ip",
        action="store",
        metavar="ip address",
        help="Target IP. Defaults to the address in the target string.",
    )
    cg.add_argument(
        "-port",
        choices=["139", "445"],
        nargs="?",
        default="445",
        metavar="destination port",
        help="SMB destination port (default 445)",
    )
    cg.add_argument(
        "--smb-timeout",
        type=int,
        default=5,
        metavar="seconds",
        help="SMB connection timeout in seconds (default 5)",
    )
    return parser


def resolve_auth(args: argparse.Namespace) -> tuple[str, AuthArgs]:
    domain, username, password, address = parse_target(args.target)

    if args.target_ip is None:
        args.target_ip = address
    if domain is None:
        domain = ""

    if password == "" and username != "" and args.hashes is None and args.no_pass is False and args.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    if args.aesKey is not None:
        args.k = True

    if args.hashes is not None:
        lmhash, nthash = args.hashes.split(":")
    else:
        lmhash, nthash = "", ""

    auth = AuthArgs(
        username=username,
        password=password,
        domain=domain,
        lmhash=lmhash,
        nthash=nthash,
        aes_key=args.aesKey or "",
        kerberos=bool(args.k),
        dc_ip=args.dc_ip,
        target_ip=args.target_ip,
        port=int(args.port),
        smb_timeout=args.smb_timeout,
    )
    return address, auth


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = reporter.make_console()

    if args.ts or args.debug:
        from impacket.examples import logger

        logger.init(args.ts, args.debug)

    reporter.print_banner(console)

    if args.list:
        reporter.print_cve_list(console, cvedb.CVE_DATABASE)
        return 0

    if not args.target:
        console.print("[red]Error: target is required (or use --list).[/]")
        console.print(f"\n{version.BANNER}")
        return 1

    selected, unknown = cvedb.select(args.cve)
    if unknown:
        console.print(f"[yellow]Ignoring unknown CVE id(s): {', '.join(unknown)}[/]")
    if not selected:
        console.print("[red]No known CVEs matched the --cve filter.[/]")
        return 1

    try:
        address, auth = resolve_auth(args)
    except ValueError as e:
        console.print(f"[red]Invalid target: {e}[/]")
        return 1

    try:
        conn = connect(address, auth)
    except CveDetectError as e:
        console.print(f"[red]{e}[/]")
        return 2

    try:
        osv = get_os_version(conn)

        if not args.no_trigger:
            try:
                trigger_remote_registry(conn)
            except CveDetectError as e:
                console.print(f"[yellow]RemoteRegistry wakeup failed: {e}[/]")

        ubr = None
        try:
            ubr = read_ubr(conn, auth)
        except CveDetectError as e:
            console.print(f"[yellow]Could not read UBR: {e}[/]")
            console.print("[yellow]Falling back to OS-build-only assessment (no UBR).[/]")

        host = HostInfo(
            major=osv.major,
            minor=osv.minor,
            build=osv.build,
            ubr=ubr,
            os_string=osv.os_string,
            signing_required=osv.signing_required,
            is_dc=osv.is_dc,
        )
        reporter.print_host(console, host)

        verdicts = [evaluate(c, host) for c in selected]
        reporter.print_verdicts(console, verdicts, host, show_exploitation=args.exploitation)

        # Exit codes: 0 = scan completed (vulns or not), 3 = nothing decided.
        any_decided = any(v.vulnerable is not None for v in verdicts)
        return 0 if any_decided else 3
    finally:
        with contextlib.suppress(Exception):
            conn.logoff()


if __name__ == "__main__":
    sys.exit(main())
