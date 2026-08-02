"""Rich-based reporting for CVE detection results.

Default output is intentionally minimal: one line per *vulnerable* CVE only.
Patched / out-of-scope / inconclusive results are silent. Use ``--list`` for the
full reference listing (no connection). ``--json`` emits machine-readable JSON.
"""

from __future__ import annotations

import json

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
        console.print(f"\n[bold]{c.id}[/] — {c.alias}  [dim]({', '.join(_cve_scope(c))})[/]")
        console.print(f"  [dim]{c.message}[/]")
        console.print(f"  Patch Tuesday {c.patch_tuesday}  ({c.cwe})")
        console.print(f"  MSRC: [blue underline]{c.msrc}[/]")
        console.print("  Affected products (min patched UBR):")
        for p in c.affected_products():
            console.print(f"    • {p}")


def _cve_scope(c: Cve) -> list[str]:
    scope = []
    if c.dc_only:
        scope.append("DC-only")
    if c.signing_message:
        scope.append("signing-aware")
    scope.append("local EoP" if c.id in _LOCAL_EOP_IDS else "network/relay")
    return scope


def scan_result(
    target: str,
    host: HostInfo,
    verdicts: list[Verdict],
    tier: str | None,
    warnings: list[str],
    show_exploitation: bool,
) -> dict:
    """Build the structured scan result consumed by the JSON emitter."""
    detected = [v for v in verdicts if v.vulnerable is True]
    cves = []
    for v in detected:
        # Relay-style CVEs change meaning under mandatory SMB signing.
        message = v.cve.signing_message if (host.signing_required and v.cve.signing_message) else v.cve.message
        entry = {
            "cve": v.cve.id,
            "alias": v.cve.alias,
            "ubr": v.host_ubr,
            "patched_ubr": v.threshold,
            "message": message,
            "dc_only": v.cve.dc_only,
            "msrc": v.cve.msrc,
        }
        if show_exploitation:
            entry["exploitation"] = v.cve.exploitation
        cves.append(entry)
    return {
        "target": target,
        "os": host.os_string,
        "major": host.major,
        "minor": host.minor,
        "build": host.build,
        "ubr": host.ubr,
        "version": host.version,
        "signing_required": host.signing_required,
        "is_dc": host.is_dc,
        "tier": tier,
        "vulnerable": len(cves) > 0,
        "warnings": warnings,
        "cves": cves,
    }


def emit_json(result: dict) -> None:
    """Print a result dict as indented JSON to stdout (no colors / markup)."""
    print(json.dumps(result, indent=2))


def database_json(cves: list[Cve]) -> dict:
    """Serialize the CVE database for ``--list --json``."""
    return {
        "cves": [
            {
                "cve": c.id,
                "alias": c.alias,
                "scope": _cve_scope(c),
                "patch_tuesday": c.patch_tuesday,
                "cwe": c.cwe,
                "message": c.message,
                "dc_only": c.dc_only,
                "has_signing_message": c.signing_message is not None,
                "msrc": c.msrc,
                "affected_products": c.affected_products(),
            }
            for c in cves
        ]
    }
