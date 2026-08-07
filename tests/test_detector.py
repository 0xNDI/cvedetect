"""Unit tests for the detection logic and CVE patch tables.

These lock in (a) the exact minimum-patched-UBR values from the design doc and
(b) the 26100 / Server-2025 vs client disambiguation, which is the whole point of
the tool vs NetExec's enum_cve.
"""

from __future__ import annotations

import pytest

from cvedetect import cvedb
from cvedetect.connection import _is_service_starting
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
        "CVE-2026-25177",
        "CVE-2026-27912",
        # local EoP set
        "CVE-2025-55680",
        "CVE-2026-42980",
        "CVE-2026-50343",
        "CVE-2026-49176",
    }


@pytest.mark.parametrize(
    "cve_id, key, expected",
    [
        # Sep 2025 (CVE-2025-54918, NTLM MIC Bypass) — DC-only
        ("CVE-2025-54918", (10, 0, 20348, None), 4171),  # Server 2022 (regression: was missing)
        ("CVE-2025-54918", (10, 0, 25398, None), 1849),  # Server 2022 23H2 (added vs enum_cve)
        ("CVE-2025-54918", (10, 0, 26100, None), 6584),  # 24H2 / Server 2025 (corrected 6508 -> 6584)
        # --- KB-audit corrections ---
        # CVE-2025-33073: missing client rows added (Jun 2025 Patch Tuesday)
        ("CVE-2025-33073", (10, 0, 19045, None), 5965),  # Win10 22H2 (was missing)
        ("CVE-2025-33073", (10, 0, 22631, None), 5472),  # Win11 23H2 (was missing)
        # CVE-2025-58726: missing client rows added (Oct 2025 Patch Tuesday)
        ("CVE-2025-58726", (10, 0, 19045, None), 6456),  # Win10 22H2 (was missing)
        ("CVE-2025-58726", (10, 0, 22631, None), 6060),  # Win11 23H2 (was missing)
        # CVE-2025-53779: hotpatch -> standard cumulative (KB5063878)
        ("CVE-2025-53779", (10, 0, 26100, None), 4946),  # Server 2025 (was 4851 hotpatch)
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
        # Apr 2026 (CVE-2026-27912, ResetNightmare) — DC-only, server-only
        ("CVE-2026-27912", (6, 2, 9200, None), 26026),  # Server 2012
        ("CVE-2026-27912", (6, 3, 9600, None), 23132),  # Server 2012 R2
        ("CVE-2026-27912", (10, 0, 14393, None), 9060),  # Server 2016
        ("CVE-2026-27912", (10, 0, 17763, None), 8644),  # Server 2019
        ("CVE-2026-27912", (10, 0, 20348, None), 5020),  # Server 2022
        ("CVE-2026-27912", (10, 0, 25398, None), 2274),  # Server 2022 23H2
        ("CVE-2026-27912", (10, 0, 26100, "srv2025"), 32690),  # Server 2025
        # Mar 2026 (CVE-2026-25177, KerberLoss) — DC-only, server-only
        ("CVE-2026-25177", (6, 2, 9200, None), 25973),  # Server 2012
        ("CVE-2026-25177", (6, 3, 9600, None), 23074),  # Server 2012 R2
        ("CVE-2026-25177", (10, 0, 14393, None), 8957),  # Server 2016
        ("CVE-2026-25177", (10, 0, 17763, None), 8511),  # Server 2019
        ("CVE-2026-25177", (10, 0, 20348, None), 4830),  # Server 2022
        ("CVE-2026-25177", (10, 0, 25398, None), 2207),  # Server 2022 23H2
        ("CVE-2026-25177", (10, 0, 26100, "srv2025"), 32522),  # Server 2025 (was 32463 hotpatch)
    ],
)
def test_threshold_values(cve_id, key, expected):
    cve = cvedb.CVE_BY_ID[cve_id.lower()]
    assert cve.threshold(key) == expected


# --- CVE-2025-54918 regression (Puppy.htb: missing Server 2022 row) ------


def test_54918_detected_on_unpatched_server_2022_dc():
    """Regression for the Puppy.htb discrepancy: CVE-2025-54918 must be detected
    on an unpatched Server 2022 DC (UBR 3453 < 4171). It was previously dropped
    because the build-20348 threshold row was missing from the patch table."""
    cve = cvedb.CVE_BY_ID["cve-2025-54918"]
    host = HostInfo(
        major=10,
        minor=0,
        build=20348,
        ubr=3453,
        os_string="Windows Server 2022 Build 20348",
        signing_required=True,
        is_dc=True,
    )
    assert host_key(host) == (10, 0, 20348, None)
    v = evaluate(cve, host)
    assert v.vulnerable is True
    assert v.threshold == 4171


def test_54918_patched_at_server_2022_threshold():
    cve = cvedb.CVE_BY_ID["cve-2025-54918"]
    host = _host(20348, 4171, os_string="Windows Server 2022", is_dc=True)
    assert evaluate(cve, host).vulnerable is False  # patched at equality (ubr < threshold is False)


def test_54918_24h2_uses_corrected_ubr_6584():
    # The 26100 row was 6508 (inherited from enum_cve); MSRC / KB5065426 = 6584.
    cve = cvedb.CVE_BY_ID["cve-2025-54918"]
    assert cve.threshold((10, 0, 26100, None)) == 6584


def test_50343_does_not_affect_14393():
    cve = cvedb.CVE_BY_ID["cve-2026-50343"]
    assert cve.threshold((10, 0, 14393, None)) is None


def test_49176_affects_14393():
    cve = cvedb.CVE_BY_ID["cve-2026-49176"]
    assert cve.threshold((10, 0, 14393, None)) == 9339


# --- KB audit: hotpatch-vs-standard-cumulative regressions --------------


def test_53779_hotpatch_gap_reported_vulnerable():
    """Regression: the 53779 threshold was the Azure hotpatch (4851 / KB5064010),
    not the standard cumulative (4946 / KB5063878). A Server 2025 DC in the
    4851-4945 gap must be reported VULNERABLE — the old value hid it."""
    cve = cvedb.CVE_BY_ID["cve-2025-53779"]
    assert cve.threshold((10, 0, 26100, None)) == 4946
    host = _host(26100, 4900, os_string="Windows Server 2025", is_dc=True)
    assert evaluate(cve, host).vulnerable is True  # 4900 < 4946 (old 4851 -> falsely patched)


def test_25177_srv2025_uses_standard_cumulative():
    """Regression: the 25177 srv2025 threshold was the hotpatch (32463), not the
    standard cumulative (KB5078740 = 32522). A DC in the gap is vulnerable."""
    cve = cvedb.CVE_BY_ID["cve-2026-25177"]
    assert cve.threshold((10, 0, 26100, "srv2025")) == 32522
    host = _host(26100, 32500, os_string="Windows Server 2025", is_dc=True)
    assert evaluate(cve, host).vulnerable is True  # 32500 < 32522 (old 32463 -> falsely patched)


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
    assert len(selected) == 12
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
    assert v.vulnerable is True  # UBR 1 < 4946, and it is a DC


# --- ResetNightmare (CVE-2026-27912): DC-only, server-only ----------------


def test_resetnightmare_skipped_on_non_dc():
    # DC-only: a non-DC Server 2025 is out of scope regardless of UBR.
    cve = cvedb.CVE_BY_ID["cve-2026-27912"]
    host = _host(26100, 1, os_string="Windows Server 2025", is_dc=False)
    assert evaluate(cve, host).vulnerable is None


def test_resetnightmare_vulnerable_on_unpatched_dc():
    cve = cvedb.CVE_BY_ID["cve-2026-27912"]
    host = _host(26100, 32000, os_string="Windows Server 2025", is_dc=True)
    v = evaluate(cve, host)
    assert v.vulnerable is True  # 32000 < 32690
    assert v.threshold == 32690


def test_resetnightmare_patched_on_dc_at_threshold():
    cve = cvedb.CVE_BY_ID["cve-2026-27912"]
    host = _host(26100, 32690, os_string="Windows Server 2025", is_dc=True)
    assert evaluate(cve, host).vulnerable is False  # patched at equality


def test_resetnightmare_client_out_of_scope_on_26100():
    # 26100 is keyed srv2025 only; a Win11 24H2 client is never in scope (and is
    # also gated out by dc_only). Either way it must be inconclusive.
    cve = cvedb.CVE_BY_ID["cve-2026-27912"]
    assert cve.threshold((10, 0, 26100, "client")) is None


def test_resetnightmare_affects_legacy_servers():
    # Server 2012 / 2012 R2 / 2016 / 2019 are in scope on a DC.
    cve = cvedb.CVE_BY_ID["cve-2026-27912"]
    # (major, minor, build, ubr, threshold)
    cases = [
        (6, 2, 9200, 26025, 26026),   # Server 2012
        (6, 3, 9600, 23131, 23132),   # Server 2012 R2
        (10, 0, 14393, 9059, 9060),   # Server 2016
        (10, 0, 17763, 8643, 8644),   # Server 2019
    ]
    for major, minor, build, ubr, thresh in cases:
        host = _host(build, ubr, os_string="Windows Server", major=major, minor=minor, is_dc=True)
        v = evaluate(cve, host)
        assert v.vulnerable is True, (build, ubr)
        assert v.threshold == thresh, (build, thresh)


# --- KerberLoss (CVE-2026-25177): DC-only, server-only --------------------


def test_kerberloss_skipped_on_non_dc():
    cve = cvedb.CVE_BY_ID["cve-2026-25177"]
    host = _host(26100, 1, os_string="Windows Server 2025", is_dc=False)
    assert evaluate(cve, host).vulnerable is None


def test_kerberloss_vulnerable_on_unpatched_dc():
    cve = cvedb.CVE_BY_ID["cve-2026-25177"]
    host = _host(26100, 32000, os_string="Windows Server 2025", is_dc=True)
    v = evaluate(cve, host)
    assert v.vulnerable is True  # 32000 < 32522
    assert v.threshold == 32522


def test_kerberloss_patched_on_dc_at_threshold():
    cve = cvedb.CVE_BY_ID["cve-2026-25177"]
    host = _host(26100, 32522, os_string="Windows Server 2025", is_dc=True)
    assert evaluate(cve, host).vulnerable is False


def test_kerberloss_client_out_of_scope_on_26100():
    # 26100 is keyed srv2025 only; a Win11 24H2 client is never in scope.
    cve = cvedb.CVE_BY_ID["cve-2026-25177"]
    assert cve.threshold((10, 0, 26100, "client")) is None


def test_kerberloss_affects_legacy_servers():
    # Server 2012 / 2012 R2 / 2016 / 2019 are in scope on a DC.
    cve = cvedb.CVE_BY_ID["cve-2026-25177"]
    # (major, minor, build, ubr, threshold)
    cases = [
        (6, 2, 9200, 25972, 25973),   # Server 2012
        (6, 3, 9600, 23073, 23074),   # Server 2012 R2
        (10, 0, 14393, 8956, 8957),   # Server 2016
        (10, 0, 17763, 8510, 8511),   # Server 2019
    ]
    for major, minor, build, ubr, thresh in cases:
        host = _host(build, ubr, os_string="Windows Server", major=major, minor=minor, is_dc=True)
        v = evaluate(cve, host)
        assert v.vulnerable is True, (build, ubr)
        assert v.threshold == thresh, (build, thresh)


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


# --- winreg retry-decision helper ----------------------------------------


@pytest.mark.parametrize(
    "msg, expected",
    [
        ("STATUS_PIPE_NOT_AVAILABLE", True),  # RemoteRegistry still starting
        ("STATUS_PIPE_BUSY", True),
        ("STATUS_PIPE_NOT_FOUND", True),
        ("STATUS_ACCESS_DENIED", False),  # real error, fail fast
        ("STATUS_OBJECT_NAME_NOT_FOUND", False),  # UBR value missing, fail fast
        ("some transport error", False),
    ],
)
def test_is_service_starting(msg, expected):
    assert _is_service_starting(RuntimeError(msg)) is expected
