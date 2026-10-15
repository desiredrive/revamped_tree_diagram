"""`show ap wlan summary` and `show wireless tag policy detailed`.

Genie has no parser for either -- checked against the parser index. Both
samples are verbatim from the lab WLC, pulled 2026-10-14.
"""

from wirelessmodules.accesspointinfo import (
    parse_ap_wlan_summary, parse_wireless_tag_policy_detailed)

AP_WLAN = open("/tmp/apwlansum.txt").read() if False else """show ap wlan summary
BSSID           SSID                              WLAN profile name                 AP WLAN State  AP WLAN Uptime    Client Count  AP Name                           IP Address                                Physical Capabilities  AP Mode          CAPWAP Path MTU  Radio Uptime      TxPwr           Channel                                   AP Up time                                            Association Up time
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
3891.b70f.2600  MX Enterprise                     MX Enterprise_profile             Enabled        08:50:00          0             AP-002                            172.19.5.10                               24ghz-HE                Local            1485             08:50:00          *8/8 (2 dBm)    (6)*                                      17 hours 57 minutes 3 seconds                         8 hours 50 minutes 1 second
3891.b70f.2602  MX CWA                            MX CWA_profile                    Enabled        08:50:00          0             AP-002                            172.19.5.10                               24ghz-HE                Local            1485             08:50:00          *8/8 (2 dBm)    (6)*                                      17 hours 57 minutes 3 seconds                         8 hours 50 minutes 1 second
3891.b70f.2608  MX EWA SDA                        MX EWA SDA_profile                Enabled        08:50:00          0             AP-002                            172.19.5.10                               24ghz-HE                Local            1485             08:50:00          *8/8 (2 dBm)    (6)*                                      17 hours 57 minutes 3 seconds                         8 hours 50 minutes 1 second
3891.b70f.2607  MX Enterprise                     MX Enterprise_profile             Disabled       NA                0             AP-002                            172.19.5.10                               5ghz-HE                Local            1485             NA                *8/8 (0 dBm)    (36)*                                     17 hours 57 minutes 3 seconds                         8 hours 50 minutes 1 second
3891.b70f.260f  MX EWA SDA                        MX EWA SDA_profile                Disabled       NA                0             AP-002                            172.19.5.10                               5ghz-HE                Local            1485             NA                *8/8 (0 dBm)    (36)*                                     17 hours 57 minutes 3 seconds                         8 hours 50 minutes 1 second
3891.b70f.9900  MX Open                           MX Open_profile                   Enabled        01:00:00          2             AP-009                            172.19.5.11                               24ghz-HE                Local            1485             01:00:00          *8/8 (2 dBm)    (11)*                                     2 hours                                               1 hour
"""

PTAG = """show wireless tag policy detailed PT_jalej_Insur_Floor17_f95a9

Policy Tag Name : PT_jalej_Insur_Floor17_f95a9
Description     : PolicyTagName PT_jalej_Insur_Floor17_f95a9

Number of WLAN-POLICY maps: 5
WLAN Profile Name                 Policy Name
------------------------------------------------------------------------
MX CWA_profile                    MX CWA_profile
MX Open_profile                   MX Open_profile
MX iPSK_profile                   MX iPSK_profile
MX EWA SDA_profile                MX EWA SDA_profile
MX Enterprise_profile             MX Enterprise_profile
"""


def test_the_bssid_is_not_sheared_by_the_ssid_column():
    """`hdr.find("SSID")` matches inside "BSSID" and put the SSID column at
    offset 1, cutting every BSSID after its first character."""
    rows = parse_ap_wlan_summary(AP_WLAN, ap_name="AP-002")
    assert rows[0]["bssid"] == "3891.b70f.2600"
    assert rows[0]["ssid"] == "MX Enterprise"


def test_the_ap_filter_excludes_other_aps():
    """The command prints every AP on the controller."""
    assert len(parse_ap_wlan_summary(AP_WLAN, ap_name="AP-002")) == 5
    assert len(parse_ap_wlan_summary(AP_WLAN)) == 6
    assert parse_ap_wlan_summary(AP_WLAN, ap_name="AP-009")[0]["ssid"] \
        == "MX Open"


def test_the_operational_state_is_read_per_radio():
    rows = parse_ap_wlan_summary(AP_WLAN, ap_name="AP-002")
    by = {(r["ssid"], r["capabilities"]): r["state"] for r in rows}
    assert by[("MX Enterprise", "24ghz-HE")] == "Enabled"
    assert by[("MX Enterprise", "5ghz-HE")] == "Disabled"


def test_ssids_and_profiles_containing_spaces_survive():
    rows = parse_ap_wlan_summary(AP_WLAN, ap_name="AP-002")
    ssids = {r["ssid"] for r in rows}
    assert "MX EWA SDA" in ssids
    profs = {r["wlan_profile"] for r in rows}
    assert "MX EWA SDA_profile" in profs


def test_the_uptime_columns_are_not_split_on_whitespace():
    """Three columns hold values like "17 hours 57 minutes 3 seconds"."""
    r = parse_ap_wlan_summary(AP_WLAN, ap_name="AP-002")[0]
    assert r["ap_uptime"] == "17 hours 57 minutes 3 seconds"
    assert r["assoc_uptime"] == "8 hours 50 minutes 1 second"


def test_client_count_is_its_own_column():
    rows = parse_ap_wlan_summary(AP_WLAN)
    assert all(r["client_count"] == "0" for r in rows if r["ap_name"] == "AP-002")
    assert [r for r in rows if r["ap_name"] == "AP-009"][0]["client_count"] == "2"


def test_unparseable_ap_wlan_output_is_empty():
    assert parse_ap_wlan_summary("% Invalid input detected") == []
    assert parse_ap_wlan_summary("") == []
    assert parse_ap_wlan_summary(None) == []


def test_the_policy_tag_maps_are_read():
    r = parse_wireless_tag_policy_detailed(PTAG)
    assert r["tag_name"] == "PT_jalej_Insur_Floor17_f95a9"
    assert r["count"] == 5
    assert len(r["maps"]) == 5


def test_policy_tag_profile_names_containing_spaces_survive():
    r = parse_wireless_tag_policy_detailed(PTAG)
    profs = {m["wlan_profile"] for m in r["maps"]}
    assert "MX EWA SDA_profile" in profs
    assert "MX Enterprise_profile" in profs


def test_an_empty_policy_tag_parses_as_no_maps():
    """A tag carrying no WLANs -- the AP wearing it broadcasts nothing."""
    r = parse_wireless_tag_policy_detailed(
        "Policy Tag Name : PT_empty\n\n"
        "Number of WLAN-POLICY maps: 0\n"
        "WLAN Profile Name                 Policy Name\n"
        "------------------------------------------------\n")
    assert r["count"] == 0 and r["maps"] == []
    assert r["tag_name"] == "PT_empty"


def test_unparseable_policy_tag_output_is_empty():
    assert parse_wireless_tag_policy_detailed("% Error")["maps"] == []
    assert parse_wireless_tag_policy_detailed("")["maps"] == []
    assert parse_wireless_tag_policy_detailed(None)["maps"] == []


def test_the_table_ends_where_its_two_column_shape_does():
    """Live capture: the prompt follows the table with no blank line that
    the loop treated as a terminator, so it came through as a sixth WLAN
    profile and was reported as a non-fabric WLAN the tag carries."""
    r = parse_wireless_tag_policy_detailed(PTAG + "WLCv#\nshow mac address-table\n")
    assert len(r["maps"]) == r["count"]
    assert all("#" not in m["wlan_profile"] for m in r["maps"])
