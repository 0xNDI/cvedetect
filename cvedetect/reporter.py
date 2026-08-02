"""Rich-based reporting for CVE detection results.

Default output is intentionally minimal: one line per *vulnerable* CVE only.
Patched / out-of-scope / inconclusive results are silent. Use ``--list`` for the
full reference listing (no connection).
"""

from __future__ import annotations

from rich.console import Console

from .cvedb import Cve
from .detector import HostInfo, Verdict

# The four local-Elevation-of-Privilege CVEs (CVSS 7.8, AV:L/PR:L) vs the
# NetExec network/relay/DC/AD-CS set.
_LOCAL_EOP_IDS = {"CVE-2025-55680", "CVE-2026-42980", "CVE-2026-50343", "CVE-2026-49176"}


def make_console() -> Console:
    return Console(highlight=False)


def print_banner(console: Console) -> None:
    console.print("[bold cyan]cvedetect[/] [dim]— Windows patch-level CVE detection over SMB (heuristic)[/]")


def print_host(console: Console, host: HostInfo) -> None:
    role = " [magenta]DC[/]" if host.is_dc else ""
    console.print(
        f"[bold]Target[/]  {host.os_string}  [dim]({host.version})[/]"
        f"  signing=[magenta]{'required' if host.signing_required else 'optional'}[/]{role}"
    )


def print_verdicts(
    console: Console,
    verdicts: list[Verdict],
    host: HostInfo,
    show_exploitation: bool,
) -> None:
    vuln = [v for v in verdicts if v.vulnerable is True]
    if not vuln:
        console.print("[green]No vulnerable CVEs detected.[/]")
        return

    for v in vuln:
        line = f"[bold red]{v.cve.id:<14}[/] [bold]{v.cve.alias}[/]"
        # Relay-style CVEs change meaning under mandatory SMB signing.
        if host.signing_required and v.cve.signing_message:
            line += f"  [yellow]— {v.cve.signing_message}[/]"
        line += f"  [dim](UBR {v.host_ubr} < {v.threshold})[/]"
        if show_exploitation:
            line += f"  [blue underline]{v.cve.exploitation}[/]"
        console.print(line)


def print_cve_list(console: Console, cves: list[Cve]) -> None:
    """Full reference listing (``--list``): scope, dates, and per-product thresholds."""
    for c in cves:
        scope = []
        if c.dc_only:
            scope.append("DC-only")
        if c.signing_message:
            scope.append("signing-aware")
        scope.append("local EoP" if c.id in _LOCAL_EOP_IDS else "network/relay")
        console.print(f"\n[bold]{c.id}[/] — {c.alias}  [dim]({', '.join(scope)})[/]")
        console.print(f"  [dim]{c.message}[/]")
        console.print(f"  Patch Tuesday {c.patch_tuesday}  ({c.cwe})")
        console.print(f"  MSRC: [blue underline]{c.msrc}[/]")
        console.print("  Affected products (min patched UBR):")
        for p in c.affected_products():
            console.print(f"    • {p}")
