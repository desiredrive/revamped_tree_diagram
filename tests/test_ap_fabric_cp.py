"""The control-plane set an AP is configured against, resolved to addresses.

The device replies here are the ones the lab WLC actually returned. The
fabric summary in particular prints its VNID mapping as several tables with
repeated headers, and its rows are indented and do not align into columns --
all three are things a parser gets wrong silently rather than loudly.
"""

import types

import pytest

from checks.base import CheckStatus

AP_CONFIG_GENERAL = """\
Hyperlocation Admin Status                      : Disabled
MLO Capability                                  : Not Capable
Fabric status                                   : Enabled
RLOC                                            : 172.19.1.68
Control plane name                             : default-control-plane
FIPS status                                     : Disabled
"""

FABRIC_SUMMARY = """\
Fabric Status      : Enabled


Control-plane:
Name                                IP-address                                 Key                                 Status
-------------------------------------------------------------------------------------------------------------------------
default-control-plane               172.19.1.64                                66302309625d422d                    Up
default-control-plane               172.19.1.65                                66302309625d422d                    Up
jalejand_San Ange_e9143             172.19.1.100                               861c2cb8541243f4                    Up


Fabric VNID Mapping:
  Name               L2-VNID       L3-VNID       IP Address                                 Subnet                                     Control plane name
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
  172_19_8_0-Guest    8192          0                                                        0.0.0.0                                    default-control-plane


Fabric VNID Mapping:
  Name               L2-VNID       L3-VNID       IP Address                                 Subnet                                     Control plane name
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
  172_19_16_0-Campus    8193          0                                                        0.0.0.0                                    default-control-plane
  172_19_5_0-INFRA_VN    8188          4097          172.19.5.0                                 255.255.255.0                              default-control-plane
"""

WLC = "wlc-jalejand-cisco-com"


def _ctx(ap_ip="172.19.5.10"):
    return types.SimpleNamespace(
        service=object(),
        payload={"mac": "b811.4b0e.2630"},
        state={"ap_wlc_ap_name": "AP-002", "ap_ip": ap_ip},
    )


@pytest.fixture
def patched(monkeypatch):
    """Serve the recorded replies in place of the two device commands."""
    import radkit_cli

    def fake(host, command, service, **kw):
        if "config general" in command:
            return AP_CONFIG_GENERAL
        if "fabric summary" in command:
            return FABRIC_SUMMARY
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(radkit_cli, "get_any_single_output", fake)


def test_resolved_cp_set_is_published(patched):
    """The passing path: both addresses of the group, for the checks below."""
    from checks.ap_wlc import ApWlcFabricControlPlane

    ctx = _ctx()
    r = ApWlcFabricControlPlane(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.OK
    assert ctx.state["ap_cp_set"] == ["172.19.1.64", "172.19.1.65"]
    assert ctx.state["ap_cp_name"] == "default-control-plane"
    assert ctx.state["ap_wlc_rloc"] == "172.19.1.68"
    assert not ctx.state.get("ap_stop")


def test_a_group_resolves_to_every_matching_row_not_the_first(patched):
    """One name is a pair of control planes.

    Taking only the first would check a session to one and report the AP
    registered when the other may be the one that is down.
    """
    from checks.ap_wlc import ApWlcFabricControlPlane

    ctx = _ctx()
    ApWlcFabricControlPlane(WLC, "wlc0").run_ap(ctx)
    assert len(ctx.state["ap_cp_set"]) == 2
    # The other group on the controller must not be swept in.
    assert "172.19.1.100" not in ctx.state["ap_cp_set"]


def test_disabled_fabric_status_stops_the_run(patched, monkeypatch):
    """Not a fabric AP: it registers nowhere and gets no access tunnel."""
    import radkit_cli
    from checks.ap_wlc import ApWlcFabricControlPlane

    monkeypatch.setattr(
        radkit_cli, "get_any_single_output",
        lambda h, c, s, **k: AP_CONFIG_GENERAL.replace(
            "Fabric status                                   : Enabled",
            "Fabric status                                   : Disabled"))
    ctx = _ctx()
    r = ApWlcFabricControlPlane(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.FAIL
    assert "Disabled" in r.message
    assert "fabric-enabled" in ctx.state["ap_stop"]


def test_unresolvable_control_plane_name_stops_the_run(patched, monkeypatch):
    """The AP carries a name the controller does not have configured."""
    import radkit_cli
    from checks.ap_wlc import ApWlcFabricControlPlane

    def fake(host, command, service, **kw):
        if "config general" in command:
            return AP_CONFIG_GENERAL.replace(
                "default-control-plane", "typo-control-plane")
        return FABRIC_SUMMARY

    monkeypatch.setattr(radkit_cli, "get_any_single_output", fake)
    ctx = _ctx()
    r = ApWlcFabricControlPlane(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.FAIL
    assert "typo-control-plane" in r.message
    assert ctx.state.get("ap_stop")


def test_ap_addressed_outside_the_l3vnid_subnet_stops_the_run(patched):
    """The group is real, but this AP does not belong to it."""
    from checks.ap_wlc import ApWlcFabricControlPlane

    ctx = _ctx(ap_ip="172.19.9.10")
    r = ApWlcFabricControlPlane(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.FAIL
    assert "172.19.9.10" in r.message
    assert "172.19.5.0" in r.message
    assert ctx.state.get("ap_stop")


def test_the_three_faults_are_reported_as_distinct_causes(patched, monkeypatch):
    """Each stop says which of the three happened.

    They are different faults -- not a fabric AP, a name that resolves to
    nothing, an AP addressed outside the instance -- and the fix for each is
    different, so one shared message would lose the only thing that matters.
    """
    import radkit_cli
    from checks.ap_wlc import ApWlcFabricControlPlane

    stops = []
    for cfg_sub, ap_ip in (
            (("Enabled", "Disabled"), "172.19.5.10"),
            (("default-control-plane", "typo-cp"), "172.19.5.10"),
            ((None, None), "172.19.9.10")):
        def fake(host, command, service, _sub=cfg_sub, **kw):
            if "config general" in command:
                return (AP_CONFIG_GENERAL.replace(*_sub)
                        if _sub[0] else AP_CONFIG_GENERAL)
            return FABRIC_SUMMARY
        monkeypatch.setattr(radkit_cli, "get_any_single_output", fake)
        ctx = _ctx(ap_ip=ap_ip)
        ApWlcFabricControlPlane(WLC, "wlc0").run_ap(ctx)
        stops.append(ctx.state["ap_stop"])
    assert len(set(stops)) == 3, stops


def test_missing_l3vnid_mapping_stops_the_run(patched, monkeypatch):
    """No 4097 row at all: the controller has no INFRA_VN to place the AP in."""
    import radkit_cli
    from checks.ap_wlc import ApWlcFabricControlPlane

    def fake(host, command, service, **kw):
        if "config general" in command:
            return AP_CONFIG_GENERAL
        return "\n".join(l for l in FABRIC_SUMMARY.splitlines()
                         if "INFRA_VN" not in l)

    monkeypatch.setattr(radkit_cli, "get_any_single_output", fake)
    ctx = _ctx()
    r = ApWlcFabricControlPlane(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.FAIL
    assert "4097" in r.message
    assert ctx.state.get("ap_stop")


def test_a_down_control_plane_warns_and_continues(patched, monkeypatch):
    """A fabric fault, so the manifest's warn-and-continue rule applies.

    The other plane of the pair may still be carrying the registration, so
    the checks below have something real to measure.
    """
    import radkit_cli
    from checks.ap_wlc import ApWlcFabricControlPlane

    def fake(host, command, service, **kw):
        if "config general" in command:
            return AP_CONFIG_GENERAL
        return FABRIC_SUMMARY.replace(
            "172.19.1.65                                66302309625d422d                    Up",
            "172.19.1.65                                66302309625d422d                    Down")

    monkeypatch.setattr(radkit_cli, "get_any_single_output", fake)
    ctx = _ctx()
    r = ApWlcFabricControlPlane(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.WARN
    assert not ctx.state.get("ap_stop")
    assert ctx.state["ap_cp_set"] == ["172.19.1.64", "172.19.1.65"]


def test_ap_not_joined_is_skipped_not_failed(patched):
    """Absent from this controller is ApWlcApState's finding, not this one's."""
    from checks.ap_wlc import ApWlcFabricControlPlane

    ctx = _ctx()
    ctx.state.pop("ap_wlc_ap_name")
    ctx.payload["mac"] = ""
    r = ApWlcFabricControlPlane(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.SKIP
    assert not ctx.state.get("ap_stop")


def test_vnid_rows_are_accumulated_across_repeated_tables():
    """The mapping prints as several tables, each repeating its header.

    Stopping at the end of the first would miss the INFRA_VN row entirely --
    on the lab controller it is in the last table.
    """
    from wirelessmodules.accesspointinfo import parse_wireless_fabric_summary

    summary, unreadable = parse_wireless_fabric_summary(FABRIC_SUMMARY)
    assert unreadable == 0
    assert len(summary["vnids"]) == 3
    assert any(r["name"] == "172_19_5_0-INFRA_VN" for r in summary["vnids"])
    assert len(summary["control_planes"]) == 3


def test_rows_that_overrun_their_column_still_parse():
    """`172_19_10_0-Campus` is wider than its header, shifting every field
    right. Fixed offsets would read the shifted row as garbage."""
    from wirelessmodules.accesspointinfo import parse_wireless_fabric_summary

    text = (
        "Fabric VNID Mapping:\n"
        "  Name               L2-VNID       L3-VNID       IP Address"
        "                                 Subnet"
        "                                     Control plane name\n"
        "  172_19_10_0-Campus    8190          0"
        "                                                        0.0.0.0"
        "                                    default-control-plane\n")
    summary, unreadable = parse_wireless_fabric_summary(text)
    assert unreadable == 0
    assert summary["vnids"][0]["name"] == "172_19_10_0-Campus"
    assert summary["vnids"][0]["l2_vnid"] == "8190"


def test_the_two_tables_are_told_apart_by_shape_not_by_header():
    """A control-plane row ends in a status word; a VNID row carries two
    integer VNIDs. Neither can be read as the other."""
    from wirelessmodules.accesspointinfo import parse_wireless_fabric_summary

    summary, _ = parse_wireless_fabric_summary(FABRIC_SUMMARY)
    for row in summary["control_planes"]:
        assert "l3_vnid" not in row
    for row in summary["vnids"]:
        assert "status" not in row


def test_control_plane_name_with_irregular_spacing_is_read():
    """`Control plane name` prints one space short of its neighbours.

    Genie captures neither it nor RLOC, so this parser is the only reader.
    """
    from wirelessmodules.accesspointinfo import parse_ap_fabric_fields

    fields = parse_ap_fabric_fields(AP_CONFIG_GENERAL)
    assert fields["control_plane_name"] == "default-control-plane"
    assert fields["rloc"] == "172.19.1.68"
    assert fields["fabric_status"] == "Enabled"


def test_a_name_containing_spaces_is_not_truncated():
    """`jalejand_San Ange_e9143` has a space in it, so splitting the row on
    single spaces would make its address unreachable."""
    from wirelessmodules.accesspointinfo import (
        control_planes_named, parse_wireless_fabric_summary)

    summary, _ = parse_wireless_fabric_summary(FABRIC_SUMMARY)
    rows = control_planes_named(summary, "jalejand_San Ange_e9143")
    assert [r["ip_address"] for r in rows] == ["172.19.1.100"]


def test_subnet_comparison_distinguishes_outside_from_uncomparable():
    """"Outside the subnet" is a finding about the AP; an unreadable address
    is a finding about the output. Conflating them would stop the run on a
    parse problem."""
    from wirelessmodules.accesspointinfo import subnet_contains

    assert subnet_contains("172.19.5.10", "172.19.5.0", "255.255.255.0") is True
    assert subnet_contains("172.19.9.10", "172.19.5.0", "255.255.255.0") is False
    assert subnet_contains("", "172.19.5.0", "255.255.255.0") is None
    assert subnet_contains("172.19.5.10", "", "") is None


def test_parsers_are_safe_on_junk():
    from wirelessmodules.accesspointinfo import (
        parse_ap_fabric_fields, parse_wireless_fabric_summary)

    for junk in ("", None, "% Invalid input detected"):
        summary, _ = parse_wireless_fabric_summary(junk)
        assert summary["control_planes"] == []
        assert summary["vnids"] == []
        assert parse_ap_fabric_fields(junk)["rloc"] == ""
