"""The SSIDs the AP actually carries, each with its BSSID.

Gated on the access tunnel being up. All samples are verbatim from the lab
WLC and AP-002, pulled 2026-10-14.
"""

from checks.base import CheckStatus
from checks.ap_wlc import ApWlcSsidMapping

WLAN_SUMMARY = """show wlan summary
Number of WLANs: 5

ID   Profile Name                     SSID                             Status 2.4GHz/5GHz Security
------------------------------------------------------------------------------------------------
17   MX CWA_profile                   MX CWA                           UP     [open],MAC Filtering
19   MX iPSK_profile                  MX iPSK                          UP     [WPA2][PSK][AES]
22   MX Open_profile                  MX Open                          UP     [open]
23   MX Enterprise_profile            MX Enterprise                    UP     [WPA3][AES]
25   MX EWA SDA_profile               MX EWA SDA                       UP     [open],[Web Auth]
"""

AP_WLAN = """show ap wlan summary
BSSID           SSID                              WLAN profile name                 AP WLAN State  AP WLAN Uptime    Client Count  AP Name                           IP Address                                Physical Capabilities  AP Mode          CAPWAP Path MTU  Radio Uptime      TxPwr           Channel                                   AP Up time                                            Association Up time
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
3891.b70f.2600  MX Enterprise                     MX Enterprise_profile             Enabled        08:50:00          0             AP-002                            172.19.5.10                               24ghz-HE                Local            1485             08:50:00          *8/8 (2 dBm)    (6)*                                      17 hours                                              8 hours
3891.b70f.2602  MX CWA                            MX CWA_profile                    Enabled        08:50:00          0             AP-002                            172.19.5.10                               24ghz-HE                Local            1485             08:50:00          *8/8 (2 dBm)    (6)*                                      17 hours                                              8 hours
3891.b70f.2604  MX Open                           MX Open_profile                   Enabled        08:50:00          0             AP-002                            172.19.5.10                               24ghz-HE                Local            1485             08:50:00          *8/8 (2 dBm)    (6)*                                      17 hours                                              8 hours
3891.b70f.2605  MX iPSK                           MX iPSK_profile                   Enabled        08:50:00          0             AP-002                            172.19.5.10                               24ghz-HE                Local            1485             08:50:00          *8/8 (2 dBm)    (6)*                                      17 hours                                              8 hours
3891.b70f.2608  MX EWA SDA                        MX EWA SDA_profile                Enabled        08:50:00          0             AP-002                            172.19.5.10                               24ghz-HE                Local            1485             08:50:00          *8/8 (2 dBm)    (6)*                                      17 hours                                              8 hours
3891.b70f.2607  MX Enterprise                     MX Enterprise_profile             Disabled       NA                0             AP-002                            172.19.5.10                               5ghz-HE                Local            1485             NA                *8/8 (0 dBm)    (36)*                                     17 hours                                              8 hours
3891.b70f.260f  MX EWA SDA                        MX EWA SDA_profile                Disabled       NA                0             AP-002                            172.19.5.10                               5ghz-HE                Local            1485             NA                *8/8 (0 dBm)    (36)*                                     17 hours                                              8 hours
"""

PTAG = """Policy Tag Name : PT_jalej_Insur_Floor17_f95a9

Number of WLAN-POLICY maps: 5
WLAN Profile Name                 Policy Name
------------------------------------------------------------------------
MX CWA_profile                    MX CWA_profile
MX Open_profile                   MX Open_profile
MX iPSK_profile                   MX iPSK_profile
MX EWA SDA_profile                MX EWA SDA_profile
MX Enterprise_profile             MX Enterprise_profile
"""

SLOT = """Administrative State                            : Enabled
Operation State                                 : Registered
  Radio Type                                    : 802.11ax - 5 GHz
  Radio Role                                    : Sniffer
  Radio Role Op                                 : Manual
  Administrative State                          : Enabled
"""

FABRIC_WLAN = """show fabric wlan summary
Number of Fabric wlan : 5

WLAN Profile Name                     SSID                           Status
----------------------------------------------------------------------------
17   MX CWA_profile                   MX CWA                           UP
19   MX iPSK_profile                  MX iPSK                          UP
22   MX Open_profile                  MX Open                          UP
23   MX Enterprise_profile            MX Enterprise                    UP
25   MX EWA SDA_profile               MX EWA SDA                       UP
"""


PTAG_NAME = "PT_jalej_Insur_Floor17_f95a9"


class _Ctx:
    def __init__(self, tunnel=True, ap_name="AP-002", ptag=PTAG_NAME):
        self.service = object()
        self.state = {}
        if tunnel:
            self.state["ap_access_tunnel"] = {"name": "Ac0"}
        if ap_name:
            self.state["ap_wlc_ap_name"] = ap_name
        if ptag:
            # As ApWlcApState leaves it.
            self.state["ap_wlc_tags"] = {"WLCv": {"policy_tag": ptag}}



def _run(summary=WLAN_SUMMARY, ap_wlan=AP_WLAN, fabric=FABRIC_WLAN,
         ptag_detail=PTAG, slot=SLOT, **kw):
    import radkit_cli
    chk, ctx = ApWlcSsidMapping("WLCv", "wlc"), _Ctx(**kw)

    def fake(host, cmd, service):
        if "fabric wlan" in cmd:
            if fabric is None:
                raise RuntimeError("unsupported")
            return fabric
        if "tag policy detailed" in cmd:
            return ptag_detail
        if "config slot" in cmd:
            return slot
        if "ap wlan summary" in cmd:
            return ap_wlan
        if "wlan summary" in cmd:
            return summary
        if "config general" in cmd:
            return f"Policy Tag Name  : {PTAG_NAME}\n"
        raise AssertionError(cmd)

    real = radkit_cli.get_any_single_output
    radkit_cli.get_any_single_output = fake
    try:
        return chk.run_ap(ctx), ctx
    finally:
        radkit_cli.get_any_single_output = real


def test_the_healthy_ap_passes():
    r, _ = _run()
    assert r.status is CheckStatus.OK


def test_every_broadcast_wlan_is_reported_with_its_bssid():
    r, _ = _run()
    assert "3891.b70f.2600" in r.message
    assert "3891.b70f.260f" in r.message
    # The operational state, which the dot11 commands did not carry.
    assert "Enabled" in r.message and "Disabled" in r.message


def test_the_fabric_wlans_are_listed():
    r, _ = _run()
    assert len(r.data["fabric_wlans"]) == 5
    assert "Fabric-enabled WLANs on WLCv: 5" in r.message


def test_a_broadcast_wlan_that_is_not_fabric_enabled_warns():
    """The join the user asked for: the controller offers it and the AP
    carries it, but it has no fabric data path."""
    # Dropped by line number rather than by string: the row's trailing
    # whitespace is part of the verbatim sample and a literal would not match.
    fab = "\n".join(
        ln for ln in FABRIC_WLAN.splitlines()
        if not ln.lstrip().startswith("22 ")
    ).replace("Number of Fabric wlan : 5", "Number of Fabric wlan : 4")
    r, _ = _run(fabric=fab)
    assert r.status is CheckStatus.WARN
    assert r.data["non_fabric_broadcast"] == [22]
    assert "no fabric data path" in r.message
    assert "MX Open" in r.message


def test_a_fabric_wlan_the_ap_does_not_carry_is_not_a_finding():
    """Only the WLANs the AP is actually broadcasting are judged."""
    r, _ = _run()
    assert "non_fabric_broadcast" not in r.data


def test_a_controller_that_refuses_the_fabric_command_still_reports_ssids():
    """An unreadable fabric command must not mask the SSID findings."""
    r, _ = _run(fabric=None)
    assert r.status is CheckStatus.OK
    assert "fabric_wlans" not in r.data
    assert "3891.b70f.2600" in r.message


def test_no_access_tunnel_skips():
    r, _ = _run(tunnel=False)
    assert r.status is CheckStatus.SKIP


def test_no_ap_name_skips():
    r, _ = _run(ap_name=None)
    assert r.status is CheckStatus.SKIP


def test_the_policy_tag_is_reported():
    """Step 3: which policy tag the AP wears."""
    r, _ = _run()
    assert r.data["policy_tag"] == PTAG_NAME
    assert PTAG_NAME in r.message


def test_the_tags_fabric_and_non_fabric_ssids_are_split():
    """Step 4: all five in this tag are fabric-enabled."""
    r, _ = _run()
    assert len(r.data["tag_fabric_profiles"]) == 5
    assert r.data["tag_non_fabric_profiles"] == []
    assert "Fabric SSIDs" in r.message


def test_a_tag_with_no_fabric_wlan_warns():
    """Step 4's warning: the tag carries WLANs, none of them fabric.

    The controller DOES have fabric WLANs -- otherwise step 2 fires too
    and its message ("no fabric-enabled WLANs") contains step 4's as a
    substring, so the assertion would pass without step 4 running at all.
    Here the fabric list holds a WLAN the policy tag does not carry.
    """
    fab = FABRIC_WLAN.replace("MX CWA_profile", "Other_profile", 1)
    fab = "\n".join(
        ln for ln in fab.splitlines()
        if not (ln.lstrip()[:2].isdigit() and "Other_profile" not in ln)
    ).replace("Number of Fabric wlan : 5", "Number of Fabric wlan : 1")
    r, _ = _run(fabric=fab)
    assert r.status is CheckStatus.WARN
    assert f"Policy tag {PTAG_NAME} carries no fabric-enabled WLAN" \
        in r.message
    assert "has no fabric-enabled WLANs" not in r.message


def test_an_empty_policy_tag_warns():
    r, _ = _run(ptag_detail=(
        "Policy Tag Name : PT_empty\n\n"
        "Number of WLAN-POLICY maps: 0\n"
        "WLAN Profile Name                 Policy Name\n"
        "--------------------------------------------\n"))
    assert r.status is CheckStatus.WARN
    assert "carries no WLANs" in r.message


def test_a_controller_with_no_fabric_wlans_warns():
    """Step 2's warning."""
    fab = "\n".join(
        ln for ln in FABRIC_WLAN.splitlines()
        if not ln.lstrip()[:2].isdigit()
    ).replace("Number of Fabric wlan : 5", "Number of Fabric wlan : 0")
    r, _ = _run(fabric=fab)
    assert "no fabric-enabled WLANs" in r.message


def test_the_fabric_split_is_not_judged_when_the_fabric_read_failed():
    """An unreadable fabric command is not evidence the tag lacks fabric
    WLANs -- every profile would fall on the non-fabric side."""
    r, _ = _run(fabric=None)
    assert "no fabric-enabled WLAN" not in r.message
    assert "tag_fabric_profiles" not in r.data
    assert r.status is CheckStatus.OK


def test_the_operational_state_is_per_radio():
    """Step 5: the 5GHz rows are Disabled, the 2.4GHz rows Enabled."""
    r, _ = _run()
    rows = r.data["ap_wlan_rows"]
    by = {(x["ssid"], x["capabilities"]): x["state"] for x in rows}
    assert by[("MX Enterprise", "24ghz-HE")] == "Enabled"
    assert by[("MX Enterprise", "5ghz-HE")] == "Disabled"
    assert "24ghz-HE: 5 of 5 broadcasting" in r.message
    assert "5ghz-HE: 0 of 2 broadcasting" in r.message


def test_a_radio_serving_nothing_is_noted_not_graded():
    """The user settled this: a radio out of client service is a note.

    FRA legitimately assigns Monitor to a flexible radio; TPC and DCA
    never disable one. Either way it is not a fault.
    """
    r, _ = _run()
    assert r.status is CheckStatus.OK
    assert "not a fault" in r.message
    assert "Sniffer" in r.message


def test_the_note_says_whether_rrm_or_a_person_set_the_role():
    r, _ = _run()
    assert "set manually" in r.message
    auto = SLOT.replace("Radio Role Op                                 : Manual",
                        "Radio Role Op                                 : Auto")
    r2, _ = _run(slot=auto)
    assert "RRM/FRA" in r2.message


def test_an_ap_broadcasting_nothing_at_all_still_warns():
    """A radio serving nothing is benign; an AP serving nothing is not."""
    dark = AP_WLAN.replace("Enabled        08:50:00", "Disabled       NA      ")
    r, _ = _run(ap_wlan=dark)
    assert r.status is CheckStatus.WARN
    assert "broadcasting no SSIDs" in r.message
