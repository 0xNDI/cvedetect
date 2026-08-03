"""CVE patch-level tables.

Detection is a pure version+UBR comparison, exactly like NetExec's ``enum_cve``:
each CVE maps a Windows product key to the *minimum patched UBR* (Update Build
Revision, the 4th dotted number from ``HKLM\\...\\CurrentVersion!UBR``).

A CVE's UBR threshold is a property of **(product-build, Patch-Tuesday-month)**,
not of the individual flaw: every bug fixed in the same monthly cumulative update
for a given build shares one threshold. The four CVEs below therefore reuse a
small set of per-(build, month) numbers.

Keys are 4-tuples ``(major, minor, build, tier)``. ``tier`` is ``None`` for
unambiguous builds and disambiguates the two real collisions:

* build ``26100`` → ``"client"`` (Win11 24H2) vs ``"srv2025"`` (Server 2025),
  which have divergent UBR timelines (detected from the SMB negotiate OS string).
* build ``28000`` → ``"x64"`` vs ``"arm"`` (Win11 26H1, Jul-2026 CVEs only).
  Architecture is not reliably exposed over SMB, so x64 is assumed and the arm
  threshold is only selected when "arm" appears in the OS string.

These are all local Elevation-of-Privilege (CVSS 7.8, ``AV:L/PR:L``): the check
runs remotely over an authenticated SMB login, but is only actionable once you
hold a low-priv local shell.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Tier = Literal["client", "srv2025", "x64", "arm", None]
PatchKey = tuple[int, int, int, str | None]


@dataclass(frozen=True)
class Cve:
    cve: str
    alias: str
    patch_tuesday: str
    message: str
    cwe: str
    exploitation: str
    msrc: str
    patches: dict[PatchKey, int] = field(default_factory=dict)
    dc_only: bool = False
    signing_message: str | None = None

    @property
    def id(self) -> str:
        return self.cve

    def threshold(self, key: PatchKey) -> int | None:
        """Minimum patched UBR for ``key``, or None if the product is out of scope.

        Falls back to the un-tiered key ``(major, minor, build, None)`` when the
        exact tiered key is absent. This lets lumped data (e.g. NetExec relay CVEs
        where we have one UBR for the 26100 collision) apply to any tier, while
        never masking a real divergence: divergent builds always carry explicit
        tiered keys for both client and Server 2025.
        """
        if key in self.patches:
            return self.patches[key]
        untiered = (key[0], key[1], key[2], None)
        if untiered != key:
            return self.patches.get(untiered)
        return None

    def affected_products(self) -> list[str]:
        """Human-readable list of (product, threshold UBR) the CVE applies to."""
        out: list[str] = []
        for k in sorted(self.patches, key=lambda t: (t[2], t[3] or "")):
            _maj, _min, build, tier = k
            name = _PRODUCT_NAMES.get((build, tier)) or _PRODUCT_NAMES.get(build) or f"build {build}"
            out.append(f"{name} (UBR {self.patches[k]})")
        return out


# Friendly product names for help/listing.
_PRODUCT_NAMES: dict[tuple, str] = {
    (14393, None): "Server 2016 / Win10 1607",
    (17763, None): "Server 2019 / Win10 1809",
    (19044, None): "Win10 21H2",
    (19045, None): "Win10 22H2",
    (20348, None): "Server 2022",
    (22621, None): "Win11 22H2",
    (22631, None): "Win11 23H2",
    (25398, None): "Server 2022 23H2",
    (26100, "client"): "Win11 24H2 client",
    (26100, "srv2025"): "Server 2025",
    (26200, None): "Win11 25H2",
    (28000, "x64"): "Win11 26H1 x64",
    (28000, "arm"): "Win11 26H1 ARM64",
}


def _c(name: str) -> str:
    return f"https://msrc.microsoft.com/update-guide/vulnerability/{name}"


# --- NetExec enum_cve CVEs (relay / DC / AD-CS) --------------------------
# Ported from nxc/modules/enum_cve.py. The 26100 collision is stored un-tiered
# (lumped) where we have no divergent client/Server-2025 data, so the threshold
# fallback applies it to any tier exactly as NetExec does. Certighost (Jul 2026)
# is the exception: we DO have the Server-2025 value (33158), and since it is an
# AD-CS / server-only flaw it is keyed srv2025-only (a Win11 24H2 client is out
# of scope, which NetExec gets wrong by lumping).

_CVE_2025_33073 = Cve(
    cve="CVE-2025-33073",
    alias="NTLM reflection",
    patch_tuesday="2025-09-09",
    message="Relay possible from SMB to any protocol",
    cwe="CWE-287",
    exploitation="https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025",
    msrc=_c("CVE-2025-33073"),
    patches={
        (10, 0, 10240, None): 21034,  # Win10 1507
        (10, 0, 14393, None): 8148,  # Server 2016 / Win10 1607
        (10, 0, 17763, None): 7434,  # Server 2019 / Win10 1809
        (10, 0, 19044, None): 5965,  # Win10 21H2
        (10, 0, 20348, None): 3807,  # Server 2022
        (10, 0, 22621, None): 5472,  # Win11 22H2
        (10, 0, 25398, None): 1665,  # Server 2022 23H2
        (10, 0, 26100, None): 4270,  # Server 2025 / Win11 24H2 (lumped)
    },
    signing_message="can relay SMB to other protocols except SMB",
)

_CVE_2025_58726 = Cve(
    cve="CVE-2025-58726",
    alias="Ghost SPN",
    patch_tuesday="2025-10-14",
    message="Relay possible from SMB using Ghost SPN for Kerberos reflection",
    cwe="CWE-287",
    exploitation="https://www.semperis.com/blog/exploiting-ghost-spns-and-kerberos-reflection-for-smb-server-privilege-elevation/",
    msrc=_c("CVE-2025-58726"),
    patches={
        (6, 0, 6003, None): 23571,  # Server 2008 SP2
        (6, 1, 7601, None): 27974,  # Server 2008 R2 SP1
        (6, 2, 9200, None): 25722,  # Server 2012
        (6, 3, 9600, None): 22824,  # Server 2012 R2
        (10, 0, 10240, None): 21161,  # Win10 1507
        (10, 0, 14393, None): 8519,  # Server 2016 / Win10 1607
        (10, 0, 17763, None): 7919,  # Server 2019 / Win10 1809
        (10, 0, 19044, None): 6456,  # Win10 21H2
        (10, 0, 20348, None): 4294,  # Server 2022
        (10, 0, 22621, None): 6060,  # Win11 22H2
        (10, 0, 25398, None): 1913,  # Server 2022 23H2
        (10, 0, 26100, None): 6899,  # Server 2025 / Win11 24H2 (Oct 2025: both tiers 6899)
        (10, 0, 26200, None): 6899,  # Win11 25H2
    },
    signing_message=(
        "Relay possible from SMB using Ghost SPN (non HOST/CIFS) for Kerberos reflection to other protocols except SMB"
    ),
)

_CVE_2025_54918 = Cve(
    cve="CVE-2025-54918",
    alias="NTLM MIC Bypass",
    patch_tuesday="2025-11-11",
    message="Note that without CVE-2025-33073 only Windows Server 2025 is exploitable",
    cwe="CWE-287",
    exploitation="https://yousofnahya.medium.com/hands-on-exploitation-of-cve-2025-54918-cf376ebb40e1",
    msrc=_c("CVE-2025-54918"),
    dc_only=True,
    patches={
        (6, 0, 6003, None): 23529,
        (6, 1, 7601, None): 27929,
        (6, 2, 9200, None): 25675,
        (6, 3, 9600, None): 22774,
        (10, 0, 10240, None): 21128,
        (10, 0, 14393, None): 8422,
        (10, 0, 17763, None): 7792,
        (10, 0, 19044, None): 6332,
        (10, 0, 22621, None): 5909,
        (10, 0, 22631, None): 5909,
        (10, 0, 26100, None): 6508,  # a 26100 DC is Server 2025 (dc_only gate)
    },
)

_CVE_2025_53779 = Cve(
    cve="CVE-2025-53779",
    alias="BadSuccessor",
    patch_tuesday="2025-01-14",
    message="Escalation to Domain Admin possible via dMSA Kerberos abuse",
    cwe="dMSA",
    exploitation="https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory",
    msrc=_c("CVE-2025-53779"),
    dc_only=True,
    patches={
        (10, 0, 26100, None): 4851,  # Server 2025 DC only
    },
)

_CVE_2024_49019 = Cve(
    cve="CVE-2024-49019",
    alias="ESC15 / EKUwu",
    patch_tuesday="2024-12-10",
    message="If host is an AD CS / CA server, it may be vulnerable to ESC15",
    cwe="AD-CS",
    exploitation="https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc",
    msrc=_c("CVE-2024-49019"),
    patches={
        (6, 0, 6003, None): 22966,
        (6, 1, 7601, None): 27415,
        (6, 2, 9200, None): 25165,
        (6, 3, 9600, None): 22267,
        (10, 0, 14393, None): 7515,
        (10, 0, 17763, None): 6532,
        (10, 0, 20348, None): 2849,
        (10, 0, 25398, None): 1251,
        (10, 0, 26100, None): 2314,  # Server 2025 (lumped)
    },
)

_CVE_2026_54121 = Cve(
    cve="CVE-2026-54121",
    alias="Certighost",
    patch_tuesday="2026-07-14",
    message="If host is an AD CS / CA server, it may be vulnerable to Certighost",
    cwe="AD-CS",
    exploitation="https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26",
    msrc=_c("CVE-2026-54121"),
    patches={
        (6, 2, 9200, None): 26226,  # Server 2012
        (6, 3, 9600, None): 23291,  # Server 2012 R2
        (10, 0, 14393, None): 9339,  # Server 2016
        (10, 0, 17763, None): 9020,  # Server 2019
        (10, 0, 20348, None): 5386,  # Server 2022
        # Server 2025 only (Jul 2026). Win11 24H2 client is out of scope — keyed
        # srv2025 so it is NOT flagged (NetExec lumps 33158 and over-reports).
        (10, 0, 26100, "srv2025"): 33158,
    },
)

# --- Local Elevation-of-Privilege CVEs (the original four) ----------------
_CVE_2025_55680 = Cve(
    cve="CVE-2025-55680",
    alias="Cloud Files Mini Filter (cldflt.sys) TOCTOU EoP",
    patch_tuesday="2025-10-14",
    message="cldflt.sys TOCTOU race -> local EoP to SYSTEM",
    cwe="CWE-367",
    exploitation=_c("CVE-2025-55680"),
    msrc=_c("CVE-2025-55680"),
    patches={
        (10, 0, 17763, None): 7919,
        (10, 0, 19044, None): 6456,
        (10, 0, 19045, None): 6456,
        (10, 0, 20348, None): 4294,
        (10, 0, 22621, None): 6060,
        (10, 0, 22631, None): 6060,
        (10, 0, 25398, None): 1913,
        (10, 0, 26100, "client"): 6899,
        (10, 0, 26100, "srv2025"): 6899,
        (10, 0, 26200, None): 6899,
    },
)

# --- Jun 2026 -------------------------------------------------------------
# Patch Tuesday 2026-06-09. WMI integer-underflow -> kernel EoP.
_CVE_2026_42980 = Cve(
    cve="CVE-2026-42980",
    alias="WMI integer-underflow -> NT Kernel EoP",
    patch_tuesday="2026-06-09",
    message="WMI integer underflow -> local EoP to SYSTEM",
    cwe="CWE-191/122",
    exploitation=_c("CVE-2026-42980"),
    msrc=_c("CVE-2026-42980"),
    patches={
        (10, 0, 14393, None): 9234,
        (10, 0, 17763, None): 8880,
        (10, 0, 19044, None): 7417,
        (10, 0, 19045, None): 7417,
        (10, 0, 20348, None): 5256,
        (10, 0, 22631, None): 7219,
        (10, 0, 26100, "client"): 8655,
        (10, 0, 26100, "srv2025"): 32995,
        (10, 0, 26200, None): 8655,
        (10, 0, 28000, "x64"): 2269,
    },
)

# --- Jul 2026 -------------------------------------------------------------
# Patch Tuesday 2026-07-14. Shared month with Certighost (CVE-2026-54121).
_CVE_2026_50343 = Cve(
    cve="CVE-2026-50343",
    alias="Dark Elevator (InstallService) EoP",
    patch_tuesday="2026-07-14",
    message="InstallService improper link following -> local EoP to SYSTEM",
    cwe="CWE-269",
    exploitation=_c("CVE-2026-50343"),
    msrc=_c("CVE-2026-50343"),
    patches={
        # Does NOT affect 14393.
        (10, 0, 17763, None): 9020,
        (10, 0, 19044, None): 7548,
        (10, 0, 19045, None): 7548,
        (10, 0, 20348, None): 5386,
        (10, 0, 26100, "client"): 8875,
        (10, 0, 26100, "srv2025"): 33158,
        (10, 0, 26200, None): 8875,
        (10, 0, 28000, "x64"): 2269,
        (10, 0, 28000, "arm"): 2525,
    },
)

_CVE_2026_49176 = Cve(
    cve="CVE-2026-49176",
    alias="WalletService link-following EoP",
    patch_tuesday="2026-07-14",
    message="WalletService improper link following -> local EoP to SYSTEM",
    cwe="CWE-59/269",
    exploitation=_c("CVE-2026-49176"),
    msrc=_c("CVE-2026-49176"),
    patches={
        # Same as 50343 PLUS 1607.
        (10, 0, 14393, None): 9339,
        (10, 0, 17763, None): 9020,
        (10, 0, 19044, None): 7548,
        (10, 0, 19045, None): 7548,
        (10, 0, 20348, None): 5386,
        (10, 0, 26100, "client"): 8875,
        (10, 0, 26100, "srv2025"): 33158,
        (10, 0, 26200, None): 8875,
        (10, 0, 28000, "x64"): 2269,
        (10, 0, 28000, "arm"): 2525,
    },
)

# Ordered for stable output: network/relay/DC/AD-CS first, then local EoP.
CVE_DATABASE: list[Cve] = [
    _CVE_2025_33073,
    _CVE_2025_58726,
    _CVE_2025_54918,
    _CVE_2025_53779,
    _CVE_2024_49019,
    _CVE_2026_54121,
    _CVE_2025_55680,
    _CVE_2026_42980,
    _CVE_2026_50343,
    _CVE_2026_49176,
]

CVE_BY_ID: dict[str, Cve] = {c.id.lower(): c for c in CVE_DATABASE}


def select(filter_str: str | None) -> tuple[list[Cve], list[str]]:
    """Return ``(selected, unknown_ids)`` matching ``filter_str``.

    ``filter_str`` is a comma-separated list of CVE IDs, or ``'all'`` / empty for
    every entry. Unknown IDs are reported back in ``unknown_ids``.
    """
    if not filter_str or filter_str.lower() == "all":
        return list(CVE_DATABASE), []
    ids = [s.strip().lower() for s in filter_str.split(",") if s.strip()]
    selected = [CVE_BY_ID[i] for i in ids if i in CVE_BY_ID]
    unknown = [i for i in ids if i not in CVE_BY_ID]
    return selected, unknown
