"""Patch-level vulnerability decision logic.

Mirrors NetExec ``enum_cve`` semantics: a host is *vulnerable* iff
``ubr < min_patched_ubr`` for its product key. Unknown product or
unavailable UBR -> ``None`` (skip), never a positive.
"""

from __future__ import annotations

from dataclasses import dataclass

from .cvedb import Cve, PatchKey

# Builds that share one OS build number across distinct products/timelines.
_AMBIGUOUS_26100 = 26100
_AMBIGUOUS_28000 = 28000


@dataclass(frozen=True)
class HostInfo:
    major: int
    minor: int
    build: int
    ubr: int | None
    os_string: str
    signing_required: bool
    is_dc: bool = False

    @property
    def is_server_2025(self) -> bool:
        # SMB negotiate OS string for Server 2025 reads e.g.
        # "Windows 11 / Server 2025 Build 26100" — it contains "Server 2025".
        return "server 2025" in (self.os_string or "").lower()

    @property
    def is_arm(self) -> bool:
        # Architecture is not reliably exposed over SMB; best-effort only.
        return "arm" in (self.os_string or "").lower()

    @property
    def version(self) -> str:
        ubr = f".{self.ubr}" if self.ubr is not None else ""
        return f"{self.major}.{self.minor}.{self.build}{ubr}"


def host_key(host: HostInfo) -> PatchKey:
    """Compute the disambiguated 4-tuple product key for a host.

    * build 26100 -> split client / Server 2025 (from the OS string).
    * build 28000 -> split x64 / arm (arm only when detectable in OS string).
    * everything else -> ``(major, minor, build, None)``.
    """
    if host.build == _AMBIGUOUS_26100:
        tier = "srv2025" if host.is_server_2025 else "client"
        return (host.major, host.minor, host.build, tier)
    if host.build == _AMBIGUOUS_28000:
        return (host.major, host.minor, host.build, "arm" if host.is_arm else "x64")
    return (host.major, host.minor, host.build, None)


@dataclass(frozen=True)
class Verdict:
    cve: Cve
    vulnerable: bool | None  # True / False / None (inconclusive: skip)
    host_ubr: int | None
    threshold: int | None

    @property
    def status(self) -> str:
        if self.vulnerable is True:
            return "VULNERABLE"
        if self.vulnerable is False:
            return "patched"
        return "inconclusive"


def evaluate(cve: Cve, host: HostInfo) -> Verdict:
    """Decide vulnerability for one CVE against one host."""
    if cve.dc_only and not host.is_dc:
        return Verdict(cve, None, None, None)  # DC-only flaw on a non-DC: out of scope
    if host.ubr is None:
        return Verdict(cve, None, None, None)

    key = host_key(host)
    threshold = cve.threshold(key)
    if threshold is None:
        return Verdict(cve, None, host.ubr, None)  # product out of scope
    return Verdict(cve, host.ubr < threshold, host.ubr, threshold)
