"""Check 3 of 3: what the AP is actually on air with.

The first two establish what the controller offers and which of those are
fabric-enabled; this one answers what the AP is really beaconing, grouped
into fabric and non-fabric SSIDs.

Every test here drives all three checks in queue order against one ctx,
because they are coupled through `ctx.state` rather than by being one
function body -- a check tested alone cannot show that the key its
neighbour publishes is the one it reads.
"""

from checks.base import CheckStatus
from checks.ap_wlc import (
    ApWlcWlans, ApWlcFabricWlans, ApWlcApBroadcastWlans)
from tests.wlan_fixtures import (
    AP_WLAN, FABRIC_WLAN, PTAG_NAME, SLOT, run_chain)


def _run(**kw):
    (_w, _f, r), ctx = run_chain(
        ApWlcWlans("WLCv", "wlc"),
        ApWlcFabricWlans("WLCv", "wlc"),
        ApWlcApBroadcastWlans("WLCv", "wlc"), **kw)
    return r, ctx


def _fabric_without_open():
    """MX Open (22) dropped from the fabric list: the AP carries it, the
    controller offers it, but it has no fabric data path."""
    return "\n".join(
        ln for ln in FABRIC_WLAN.splitlines()
        if not ln.lstrip().startswith("22 ")
    ).replace("Number of Fabric wlan : 5", "Number of Fabric wlan : 4")


def test_the_healthy_ap_passes():
    r, _ = _run()
    assert r.status is CheckStatus.OK


def test_the_name_says_what_it_is_about():
    """Not the `WLC <aspect>` template: this check is about the AP."""
    assert ApWlcApBroadcastWlans("WLCv", "wlc").name == (
        "AP Broadcasted WLANs (Fabric and Non Fabric) — WLCv")


def test_every_on_air_wlan_is_reported_with_its_bssid():
    """On-air rows keep the full detail: the BSSID is what a capture is
    filtered on, so it has to be there for the SSIDs carrying traffic."""
    r, _ = _run()
    assert "3891.b70f.2600" in r.message


def test_off_air_wlans_are_summarised_per_radio_not_listed():
    """Four Disabled rows on one silent radio say one thing, not four.
    The SSID names stay; the per-BSSID detail does not, because a BSSID
    that carries nothing is not something anyone filters a capture on."""
    r, _ = _run()
    assert "Not on air — 5ghz-HE" in r.message
    assert "MX Enterprise" in r.message.split("Not on air")[1]
    assert "3891.b70f.260f" not in r.message


# --------------------------------------------------------------------------
# The two grouped lists.
# --------------------------------------------------------------------------


def test_the_ssids_are_grouped_into_fabric_and_non_fabric():
    r, _ = _run(fabric=_fabric_without_open())
    assert "On air — fabric SSIDs" in r.message
    assert "On air — non-fabric SSIDs" in r.message
    # MX Open is the one that is not fabric-enabled, so it heads the
    # non-fabric group and nothing else does.
    non = r.message.split("On air — non-fabric SSIDs")[1].split("Not on air")[0]
    assert "MX Open" in non
    assert "MX Enterprise" not in non


def test_every_on_air_row_appears_exactly_once_across_the_groups():
    """Regrouping must not drop or duplicate a live BSSID."""
    r, _ = _run(fabric=_fabric_without_open())
    body = r.message[r.message.index("On air — "):]
    for row in r.data["ap_wlan_rows"]:
        if row["state"].lower() == "enabled":
            assert body.count(row["bssid"]) == 1, row["bssid"]


def test_no_wlan_is_lost_between_the_on_air_and_off_air_groups():
    """Every SSID the AP carries is named somewhere, live or not."""
    r, _ = _run(fabric=_fabric_without_open())
    for row in r.data["ap_wlan_rows"]:
        assert row["ssid"] in r.message, row["ssid"]


def test_each_row_still_carries_its_band():
    """Grouping by fabric membership must not lose the per-radio fact: the
    same WLAN has a different BSSID on each radio."""
    r, _ = _run()
    assert "24ghz-HE" in r.message and "5ghz-HE" in r.message


def test_the_groups_are_not_claimed_when_fabric_membership_was_not_read():
    """The precedent. Every row would fall under Non-fabric, stating as a
    finding something no command ever reported."""
    r, _ = _run(fabric=None)
    assert "On air — non-fabric SSIDs" not in r.message
    assert "not grouped by it" in r.message
    # Falls back to the per-radio listing, which is the honest view here.
    assert "24ghz-HE: 5 of 5 broadcasting" in r.message


def test_the_operational_state_is_per_radio():
    r, _ = _run()
    rows = r.data["ap_wlan_rows"]
    by = {(x["ssid"], x["capabilities"]): x["state"] for x in rows}
    assert by[("MX Enterprise", "24ghz-HE")] == "Enabled"
    assert by[("MX Enterprise", "5ghz-HE")] == "Disabled"
    assert "5 of 7 BSSIDs enabled" in r.message


# --------------------------------------------------------------------------
# Findings.
# --------------------------------------------------------------------------


def test_a_broadcast_wlan_that_is_not_fabric_enabled_warns():
    r, _ = _run(fabric=_fabric_without_open())
    assert r.status is CheckStatus.WARN
    assert r.data["non_fabric_broadcast"] == [22]
    assert "no fabric data path" in r.message
    assert "MX Open" in r.message


def test_a_fabric_wlan_the_ap_does_not_carry_is_not_a_finding():
    r, _ = _run()
    assert "non_fabric_broadcast" not in r.data


def test_an_ap_broadcasting_nothing_at_all_still_warns():
    """A radio serving nothing is benign; an AP serving nothing is not."""
    dark = AP_WLAN.replace("Enabled        08:50:00", "Disabled       NA      ")
    r, _ = _run(ap_wlan=dark)
    assert r.status is CheckStatus.WARN
    assert "broadcasting no SSIDs" in r.message


def test_the_fabric_split_is_not_judged_when_the_fabric_read_failed():
    """An unreadable fabric command is not evidence the tag lacks fabric
    WLANs -- every profile would fall on the non-fabric side."""
    r, _ = _run(fabric=None)
    assert "no fabric-enabled WLAN" not in r.message
    assert "tag_fabric_profiles" not in r.data
    assert r.status is CheckStatus.OK


def test_an_unread_fabric_list_does_not_stop_the_ssids_being_reported():
    """What check 2 SKIPping (rather than FAILing) buys."""
    r, _ = _run(fabric=None)
    assert "3891.b70f.2600" in r.message


# --------------------------------------------------------------------------
# Radios out of client service: reported, never graded.
# --------------------------------------------------------------------------


def test_a_radio_serving_nothing_is_noted_not_graded():
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


# --------------------------------------------------------------------------
# The policy tag: what the AP is entitled to broadcast.
# --------------------------------------------------------------------------


def test_the_policy_tag_is_reported():
    r, _ = _run()
    assert r.data["policy_tag"] == PTAG_NAME
    assert PTAG_NAME in r.message


def test_the_tags_fabric_and_non_fabric_ssids_are_split():
    r, _ = _run()
    assert len(r.data["tag_fabric_profiles"]) == 5
    assert r.data["tag_non_fabric_profiles"] == []


def test_a_tag_with_no_fabric_wlan_warns():
    """The tag carries WLANs, none of them fabric."""
    fab = FABRIC_WLAN.replace("MX CWA_profile", "Other_profile", 1)
    fab = "\n".join(
        ln for ln in fab.splitlines()
        if not (ln.lstrip()[:2].isdigit() and "Other_profile" not in ln)
    ).replace("Number of Fabric wlan : 5", "Number of Fabric wlan : 1")
    r, _ = _run(fabric=fab)
    assert r.status is CheckStatus.WARN
    assert f"Policy tag {PTAG_NAME} carries no fabric-enabled WLAN" \
        in r.message


def test_an_empty_policy_tag_warns():
    r, _ = _run(ptag_detail=(
        "Policy Tag Name : PT_empty\n\n"
        "Number of WLAN-POLICY maps: 0\n"
        "WLAN Profile Name                 Policy Name\n"
        "--------------------------------------------\n"))
    assert r.status is CheckStatus.WARN
    assert "carries no WLANs" in r.message


# --------------------------------------------------------------------------
# The AP node on the canvas.
# --------------------------------------------------------------------------


def test_the_fabric_ssids_on_air_are_tagged_onto_the_ap_node():
    """`tag_nodes`, not `node_tags`: this check runs on the WLC node, so
    `node_tags` would put the AP's SSIDs on the controller."""
    r, _ = _run()
    spec = r.data["tag_nodes"][0]
    assert spec["id"] == "ap"
    assert spec["broadcasting"] is True
    assert "MX CWA" in spec["tags"]


def test_only_fabric_ssids_actually_on_air_are_tagged():
    """A non-fabric SSID, and a fabric one that is Disabled, are both left
    off -- the tag answers "serving the fabric", not "configured for it"."""
    r, _ = _run(fabric=_fabric_without_open())
    tags = r.data["tag_nodes"][0]["tags"]
    assert "MX Open" not in tags          # carried, but not fabric
    assert "MX Enterprise" in tags        # fabric and enabled on 2.4GHz
    for t in tags:
        assert t in {row["ssid"] for row in r.data["ap_wlan_rows"]
                     if row["state"].lower() == "enabled"}


def test_nothing_is_tagged_when_fabric_membership_was_not_read():
    r, _ = _run(fabric=None)
    assert "tag_nodes" not in r.data


def test_nothing_is_tagged_when_the_ap_is_dark():
    dark = AP_WLAN.replace("Enabled        08:50:00", "Disabled       NA      ")
    r, _ = _run(ap_wlan=dark)
    assert "tag_nodes" not in r.data


# --------------------------------------------------------------------------
# Gating.
# --------------------------------------------------------------------------


def test_no_access_tunnel_skips():
    r, _ = _run(tunnel=False)
    assert r.status is CheckStatus.SKIP


def test_no_ap_name_skips():
    r, _ = _run(ap_name=None)
    assert r.status is CheckStatus.SKIP


# --------------------------------------------------------------------------
# The net for the split itself.
#
# Splitting one check into three is a refactor, and the risk in a refactor
# is a validation quietly going missing -- not a wrong answer, but no
# answer. These assert the findings of the old single `ApWlcSsidMapping`
# still fire, without caring which of the three now owns them.
# --------------------------------------------------------------------------


def _messages(**kw):
    rs, _ctx = run_chain(
        ApWlcWlans("WLCv", "wlc"),
        ApWlcFabricWlans("WLCv", "wlc"),
        ApWlcApBroadcastWlans("WLCv", "wlc"), **kw)
    return "\n".join(r.message or "" for r in rs)


def test_the_controllers_wlans_are_still_listed_somewhere():
    assert "MX Enterprise" in _messages()


def test_no_fabric_wlans_on_the_controller_is_still_reported():
    empty = ("Number of Fabric wlan : 0\n\n"
             "WLAN Profile Name                 VNID    Name\n"
             "-----------------------------------------------\n")
    assert "no fabric-enabled WLAN" in _messages(fabric=empty)


def test_a_non_fabric_broadcast_is_still_reported():
    assert "no fabric data path" in _messages(fabric=_fabric_without_open())


def test_the_policy_tag_is_still_reported():
    assert PTAG_NAME in _messages()


def test_the_radio_role_note_is_still_reported():
    assert "not a fault" in _messages()


def test_one_note_per_role_not_per_slot():
    """A C9130 has several 5GHz slots, so matching a dark band on its
    number alone hit all of them and printed the same sentence three times
    for one silent radio."""
    r, _ = _run()
    block = r.message.split("not serving clients")[1]
    sniffer = [ln for ln in block.splitlines() if "Sniffer" in ln]
    assert len(sniffer) == 1, block
