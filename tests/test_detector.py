"""Unit tests for the detection logic and CVE patch tables.

These lock in (a) the exact minimum-patched-UBR values from the design doc and
(b) the 26100 / Server-2025 vs client disambiguation, which is the whole point of
the tool vs NetExec's enum_cve.
"""

from __future__ import annotations

import pytest

from cvedetect import cvedb
from cvedetect.detector import HostInfo, evaluate, host_key
from cvedetect.reporter import scan_result


def _host(build: int, ubr: int | None, os_string="Windows 10", major=10, minor=0, is_dc=False) -> HostInfo:
    return HostInfo(
        major=major,
        minor=minor,
        build=build,
        ubr=ubr,
        os_string=os_string,
        signing_required=False,
        is_dc=is_dc,
    )


# --- CVE database presence & exact UBR values (from cvedetect.md) ----------


def test_all_cves_present():
    ids = {c.id for c in cvedb.CVE_DATABASE}
    assert ids == {
        # nxc relay / DC / AD-CS set
        "CVE-2025-33073",
        "CVE-2025-58726",
        "CVE-2025-54918",
        "CVE-2025-53779",
        "CVE-2024-49019",
        "CVE-2026-54121",
        # local EoP set
        "CVE-2025-55680",
        "CVE-2026-42980",
        "CVE-2026-50343",
        "CVE-2026-49176",
    }


@pytest.mark.parametrize(
    "cve_id, key, expected",
    [
        # Oct 2025 (CVE-2025-55680)
        ("CVE-2025-55680", (10, 0, 19045, None), 6456),  # Win10 22H2 (added vs enum_cve)
        ("CVE-2025-55680", (10, 0, 22631, None), 6060),  # Win11 23H2 (added vs enum_cve)
        ("CVE-2025-55680", (10, 0, 26100, "srv2025"), 6899),
        ("CVE-2025-55680", (10, 0, 26100, "client"), 6899),
        # Jun 2026 (CVE-2026-42980)
        ("CVE-2026-42980", (10, 0, 14393, None), 9234),
        ("CVE-2026-42980", (10, 0, 26100, "srv2025"), 32995),
        ("CVE-2026-42980", (10, 0, 26100, "client"), 8655),
        ("CVE-2026-42980", (10, 0, 28000, "x64"), 2269),
        # Jul 2026 (CVE-2026-50343) — does NOT affect 14393
        ("CVE-2026-50343", (10, 0, 26100, "srv2025"), 33158),
        ("CVE-2026-50343", (10, 0, 26100, "client"), 8875),
        ("CVE-2026-50343", (10, 0, 28000, "x64"), 2269),
        ("CVE-2026-50343", (10, 0, 28000, "arm"), 2525),
        # Jul 2026 (CVE-2026-49176) — same as 50343 plus 1607
        ("CVE-2026-49176", (10, 0, 14393, None), 9339),
        ("CVE-2026-49176", (10, 0, 26100, "srv2025"), 33158),
        ("CVE-2026-49176", (10, 0, 28000, "arm"), 2525),
    ],
)
def test_threshold_values(cve_id, key, expected):
    cve = cvedb.CVE_BY_ID[cve_id.lower()]
    assert cve.threshold(key) == expected


def test_50343_does_not_affect_14393():
    cve = cvedb.CVE_BY_ID["cve-2026-50343"]
    assert cve.threshold((10, 0, 14393, None)) is None


def test_49176_affects_14393():
    cve = cvedb.CVE_BY_ID["cve-2026-49176"]
    assert cve.threshold((10, 0, 14393, None)) == 9339


# --- host_key disambiguation ---------------------------------------------


def test_key_unambiguous_build():
    assert host_key(_host(20348, 5000)) == (10, 0, 20348, None)


def test_key_26100_server_from_os_string():
    host = _host(26100, 32860, os_string="Windows 11 / Server 2025 Build 26100")
    assert host_key(host) == (10, 0, 26100, "srv2025")


def test_key_26100_client_default():
    host = _host(26100, 7000, os_string="Windows 11 Pro")
    assert host_key(host) == (10, 0, 26100, "client")


def test_key_28000_defaults_x64():
    host = _host(28000, 2269, os_string="Windows 11")
    assert host_key(host) == (10, 0, 28000, "x64")


def test_key_28000_arm_when_in_os_string():
    host = _host(28000, 2525, os_string="Windows 11 ARM64")
    assert host_key(host) == (10, 0, 28000, "arm")


# --- evaluate() ----------------------------------------------------------


def test_vulnerable_when_ubr_below_threshold():
    # Server 2025, UBR 32860 < 33158
    host = _host(26100, 32860, os_string="Windows Server 2025")
    v = evaluate(cvedb.CVE_BY_ID["cve-2026-50343"], host)
    assert v.vulnerable is True
    assert v.threshold == 33158


def test_patched_when_ubr_at_threshold():
    host = _host(26100, 33158, os_string="Windows Server 2025")
    v = evaluate(cvedb.CVE_BY_ID["cve-2026-50343"], host)
    assert v.vulnerable is False  # patched == ubr < threshold is False at equality


def test_patched_when_ubr_above_threshold():
    host = _host(26100, 33159, os_string="Windows Server 2025")
    v = evaluate(cvedb.CVE_BY_ID["cve-2026-50343"], host)
    assert v.vulnerable is False


def test_inconclusive_when_ubr_missing():
    host = _host(26100, None, os_string="Windows Server 2025")
    v = evaluate(cvedb.CVE_BY_ID["cve-2026-50343"], host)
    assert v.vulnerable is None


def test_out_of_scope_product_is_inconclusive():
    # CVE-2026-50343 explicitly does NOT affect build 14393 (Server 2016 / 1607).
    host = _host(14393, 1, os_string="Windows Server 2016")
    v = evaluate(cvedb.CVE_BY_ID["cve-2026-50343"], host)
    assert v.vulnerable is None  # product out of scope -> inconclusive
    assert v.threshold is None


def test_in_scope_server2022_is_vulnerable_when_low_ubr():
    # 20348 (Server 2022) IS in scope for 50343 (threshold 5386); low UBR -> vuln.
    host = _host(20348, 1, os_string="Windows Server 2022")
    v = evaluate(cvedb.CVE_BY_ID["cve-2026-50343"], host)
    assert v.vulnerable is True


# --- THE key disambiguation: same UBR, different verdict per product ------


def test_26100_disambiguation_makes_the_difference():
    """At UBR 32860, Server 2025 is VULNERABLE to Jul-2026 CVEs but a 24H2
    client would be patched. enum_cve lumps them; this tool must not."""
    cve = cvedb.CVE_BY_ID["cve-2026-50343"]

    srv = _host(26100, 32860, os_string="Windows Server 2025")
    cli = _host(26100, 32860, os_string="Windows 11 Pro")

    assert evaluate(cve, srv).vulnerable is True  # 32860 < 33158
    assert evaluate(cve, cli).vulnerable is False  # 32860 > 8875
    # the two thresholds must actually differ for this to matter:
    assert cve.threshold((10, 0, 26100, "srv2025")) != cve.threshold((10, 0, 26100, "client"))


# --- select() filter -----------------------------------------------------


def test_select_all():
    selected, unknown = cvedb.select(None)
    assert len(selected) == 10
    assert unknown == []


def test_select_subset():
    selected, unknown = cvedb.select("CVE-2026-50343, CVE-2026-49176")
    assert {c.id for c in selected} == {"CVE-2026-50343", "CVE-2026-49176"}
    assert unknown == []


def test_select_unknown_reported():
    selected, unknown = cvedb.select("CVE-9999-0001")
    assert selected == []
    assert unknown == ["cve-9999-0001"]


# --- dc_only gate --------------------------------------------------------


def test_dc_only_cve_skipped_on_non_dc():
    # BadSuccessor is dc_only. On a non-DC Server 2025 it must be skipped.
    host = _host(26100, 1, os_string="Windows Server 2025", is_dc=False)
    v = evaluate(cvedb.CVE_BY_ID["cve-2025-53779"], host)
    assert v.vulnerable is None  # out of scope (not a DC)


def test_dc_only_cve_checked_on_dc():
    host = _host(26100, 1, os_string="Windows Server 2025", is_dc=True)
    v = evaluate(cvedb.CVE_BY_ID["cve-2025-53779"], host)
    assert v.vulnerable is True  # UBR 1 < 4851, and it is a DC


def test_non_dc_cve_not_gated_by_dc():
    # Local EoP CVEs are not dc_only; the DC flag must not affect them.
    cve = cvedb.CVE_BY_ID["cve-2026-50343"]
    h_dc = _host(26100, 1, os_string="Windows Server 2025", is_dc=True)
    h_nondc = _host(26100, 1, os_string="Windows Server 2025", is_dc=False)
    assert evaluate(cve, h_dc).vulnerable is True
    assert evaluate(cve, h_nondc).vulnerable is True


# --- threshold fallback (lumped nxc data on the 26100 collision) ---------


def test_threshold_fallback_for_lumped_26100():
    # CVE-2025-33073 stores 26100 un-tiered (4270). A Server 2025 host resolves to
    # the srv2025 tier, which is absent, so the lookup falls back to the lumped
    # value — exactly what NetExec does.
    cve = cvedb.CVE_BY_ID["cve-2025-33073"]
    assert cve.threshold((10, 0, 26100, "srv2025")) == 4270
    assert cve.threshold((10, 0, 26100, "client")) == 4270


def test_certighost_server_only_not_flagged_on_client():
    # Certighost is AD-CS / server-only: srv2025 keyed, no client entry, no lumped
    # entry. A Win11 24H2 client must be inconclusive, NOT vulnerable.
    cve = cvedb.CVE_BY_ID["cve-2026-54121"]
    assert cve.threshold((10, 0, 26100, "srv2025")) == 33158
    assert cve.threshold((10, 0, 26100, "client")) is None

    cli = _host(26100, 1, os_string="Windows 11 Pro", is_dc=False)
    srv = _host(26100, 1, os_string="Windows Server 2025", is_dc=True)
    assert evaluate(cve, cli).vulnerable is None
    assert evaluate(cve, srv).vulnerable is True


# --- signing_message semantics -------------------------------------------


def test_signing_message_fields_present():
    reflection = cvedb.CVE_BY_ID["cve-2025-33073"]
    ghost_spn = cvedb.CVE_BY_ID["cve-2025-58726"]
    assert reflection.signing_message is not None
    assert ghost_spn.signing_message is not None
    # local EoP CVEs have no signing nuance
    assert cvedb.CVE_BY_ID["cve-2026-50343"].signing_message is None


# --- JSON scan_result (--json output structure) -------------------------


def _result(host, selected, show_exploitation=False):
    verdicts = [evaluate(c, host) for c in selected]
    return scan_result(
        target="t",
        host=host,
        verdicts=verdicts,
        tier=host_key(host)[3],
        warnings=[],
        show_exploitation=show_exploitation,
    )


def test_json_includes_detected_cves():
    host = _host(26100, 32860, os_string="Windows Server 2025", is_dc=True)
    res = _result(host, [cvedb.CVE_BY_ID["cve-2026-50343"]])
    assert res["target"] == "t"
    assert res["version"] == "10.0.26100.32860"
    assert res["ubr"] == 32860
    assert res["signing_required"] is False
    assert res["is_dc"] is True
    assert res["tier"] == "srv2025"
    assert res["vulnerable"] is True
    assert len(res["cves"]) == 1
    entry = res["cves"][0]
    assert entry["cve"] == "CVE-2026-50343"
    assert entry["patched_ubr"] == 33158
    assert entry["ubr"] == 32860
    assert entry["dc_only"] is False
    assert "exploitation" not in entry  # only with -e


def test_json_excludes_non_vulnerable():
    # Fully patched Server 2025 -> no vulnerable CVEs.
    host = _host(26100, 99999, os_string="Windows Server 2025", is_dc=True)
    res = _result(host, list(cvedb.CVE_DATABASE))
    assert res["vulnerable"] is False
    assert res["cves"] == []


def test_json_signing_message_used_when_signing_required():
    # A vulnerable NTLM-reflection host with signing required reports the
    # signing-aware message, not the generic one.
    host = _host(26100, 1, os_string="Windows 11 / Server 2025 Build 26100", is_dc=False)
    host_signing = HostInfo(
        major=10,
        minor=0,
        build=26100,
        ubr=1,
        os_string="Windows 11 / Server 2025 Build 26100",
        signing_required=True,
        is_dc=False,
    )
    cve = cvedb.CVE_BY_ID["cve-2025-33073"]
    res_plain = _result(host, [cve])
    res_signing = _result(host_signing, [cve])
    assert res_plain["cves"][0]["message"] == cve.message
    assert res_signing["cves"][0]["message"] == cve.signing_message


def test_json_exploitation_url_only_with_flag():
    host = _host(26100, 32860, os_string="Windows Server 2025", is_dc=True)
    cve = cvedb.CVE_BY_ID["cve-2026-50343"]
    assert "exploitation" not in _result(host, [cve])["cves"][0]
    assert _result(host, [cve], show_exploitation=True)["cves"][0]["exploitation"] == cve.exploitation


def test_json_tier_null_for_unambiguous_build():
    host = _host(20348, 1, os_string="Windows Server 2022")
    res = _result(host, [cvedb.CVE_BY_ID["cve-2025-55680"]])
    assert res["tier"] is None
