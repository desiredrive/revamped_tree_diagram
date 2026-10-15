"""`show fabric wlan summary` -- the fabric-enabled subset of the WLANs.

A WLAN the AP broadcasts that is absent here is offered by the controller
but has no fabric data path, so a client joining it on a fabric AP will not
forward over the access tunnel. Nothing else in the flow surfaces that.

The sample is verbatim from the lab WLC, pulled 2026-10-14.
"""

from wirelessmodules.accesspointinfo import parse_fabric_wlan_summary

LIVE = """WLCv#show fabric wlan summary
Number of Fabric wlan : 5

WLAN Profile Name                     SSID                           Status
----------------------------------------------------------------------------
17   MX CWA_profile                   MX CWA                           UP
19   MX iPSK_profile                  MX iPSK                          UP
22   MX Open_profile                  MX Open                          UP
23   MX Enterprise_profile            MX Enterprise                    UP
25   MX EWA SDA_profile               MX EWA SDA                       UP
"""


def test_the_count_is_read():
    assert parse_fabric_wlan_summary(LIVE)["count"] == 5


def test_every_row_is_parsed():
    r = parse_fabric_wlan_summary(LIVE)
    assert len(r["wlans"]) == 5
    assert [w["wlan_id"] for w in r["wlans"]] == ["17", "19", "22", "23", "25"]


def test_ssids_containing_spaces_survive():
    """The reason Genie's `show wlan summary` parser is unusable here: a
    whitespace split shifts every field after the first."""
    by = {w["wlan_id"]: w for w in parse_fabric_wlan_summary(LIVE)["wlans"]}
    assert by["17"]["ssid"] == "MX CWA"
    assert by["25"]["ssid"] == "MX EWA SDA"
    assert by["23"]["ssid"] == "MX Enterprise"


def test_profile_names_containing_spaces_survive():
    by = {w["wlan_id"]: w for w in parse_fabric_wlan_summary(LIVE)["wlans"]}
    assert by["25"]["profile_name"] == "MX EWA SDA_profile"
    assert by["17"]["profile_name"] == "MX CWA_profile"


def test_the_status_is_not_swallowed_into_the_ssid():
    for w in parse_fabric_wlan_summary(LIVE)["wlans"]:
        assert w["status"] == "UP"
        assert "UP" not in w["ssid"]


def test_a_down_wlan_keeps_its_status():
    r = parse_fabric_wlan_summary(LIVE.replace(
        "MX Open                          UP",
        "MX Open                          DOWN"))
    by = {w["wlan_id"]: w for w in r["wlans"]}
    assert by["22"]["status"] == "DOWN"
    assert by["22"]["ssid"] == "MX Open"


def test_no_fabric_wlans_parses_empty():
    """A controller with fabric enabled but no fabric WLANs."""
    r = parse_fabric_wlan_summary(
        "Number of Fabric wlan : 0\n\n"
        "WLAN Profile Name                     SSID"
        "                           Status\n"
        "------------------------------------------------------------\n")
    assert r["count"] == 0 and r["wlans"] == []


def test_unparseable_output_is_empty_not_an_error():
    assert parse_fabric_wlan_summary("% Invalid input detected")["wlans"] == []
    assert parse_fabric_wlan_summary("")["wlans"] == []
    assert parse_fabric_wlan_summary(None)["wlans"] == []
