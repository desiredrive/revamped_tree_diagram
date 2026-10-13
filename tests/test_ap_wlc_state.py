"""Manifest step 5 — the AP's own state on its controller, read over CLI.

The device replies here are the ones the lab WLC actually returned, parsed by
Genie, so a change in the parser's shape surfaces as a failing test rather
than as an AP reported absent from a controller it is joined to.
"""

import types

import pytest

from checks.base import CheckStatus


# `show ap summary` for AP-002, as Genie parses it. Note the Ethernet MAC and
# the radio MAC are different addresses on the same AP: the lookup must match
# the first and not the second.
AP_SUMMARY = {
    "ap_neighbor_count": 1,
    "ap_name": {
        "AP-002": {
            "slots_count": 3,
            "ap_model": "C9130AXI-A",
            "ethernet_mac": "b811.4b0e.2630",
            "radio_mac": "3891.b70f.2600",
            "country": "MX",
            "regulatory_domain": "-A",
            "ap_ip_address": "172.19.5.10",
            "state": "Registered",
            "location": "Global/Mexico/San Angel/FL1",
        }
    },
}

AP_CONFIG = {
    "ap_name": {
        "AP-002": {
            "site_tag_name": "ST_jalej_Insurgen_35a54_0",
            "policy_tag_name": "PT_jalej_Insur_Floor17_f95a9",
            "rf_tag_name": "TYPICAL",
            "ap_join_profile": "APJ_MX",
            "flex_profile": "default-flex-profile",
            "ap_mode": "Local",
            "ap_submode": "Not Configured",
            "administrative_state": "Enabled",
            "operation_state": "Registered",
            "primary_cisco_controller_name": "WLCv",
            "primary_cisco_controller_ip_address": "10.31.136.74",
        }
    }
}

WLC = "wlc-jalejand-cisco-com"


def _ctx(mac="b811.4b0e.2630", candidates=((WLC, "10.31.136.74", "wlc0"),)):
    return types.SimpleNamespace(
        service=object(),
        payload={"mac": mac},
        state={"ap_wlc_candidates": list(candidates)},
    )


@pytest.fixture
def patched(monkeypatch):
    """Serve the recorded replies in place of the two device commands."""
    import checks.ap_wlc as mod
    import radkit_cli

    monkeypatch.setattr(radkit_cli, "get_single_output_genie",
                        lambda h, c, s, **k: AP_SUMMARY)
    monkeypatch.setattr(mod, "_ap_config_general",
                        lambda h, n, s: (AP_CONFIG["ap_name"]["AP-002"], None))
    return mod


def test_joined_ap_is_found_and_described(patched):
    from checks.ap_wlc import ApWlcApState

    ctx = _ctx()
    r = ApWlcApState(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.OK
    assert "AP-002" in r.message
    # The half of step 5 the summary cannot answer.
    assert "ST_jalej_Insurgen_35a54_0" in r.message
    assert "PT_jalej_Insur_Floor17_f95a9" in r.message
    assert "APJ_MX" in r.message
    assert "MX" in r.message
    assert ctx.state["ap_wlc_joined_on"] == [WLC]
    assert ctx.state["ap_wlc_ap_name"] == "AP-002"


def test_mac_is_matched_regardless_of_the_form_it_was_typed_in(patched):
    """A MAC typed with colons or in upper case is the same address.

    The user pastes from their notes, not from Genie's output.
    """
    from checks.ap_wlc import ApWlcApState

    for form in ("B8:11:4B:0E:26:30", "b811-4b0e-2630", "B811.4B0E.2630"):
        r = ApWlcApState(WLC, "wlc0").run_ap(_ctx(mac=form))
        assert r.status is CheckStatus.OK, form


def test_radio_mac_does_not_match_the_ethernet_keyed_lookup(patched):
    """The radio MAC is a different address and must not resolve the AP.

    Matching it would make two different inputs look equivalent when the rest
    of the chain can only act on the Ethernet MAC. The warning says which MAC
    was searched so the mistake is self-diagnosing.
    """
    from checks.ap_wlc import ApWlcApState

    r = ApWlcApState(WLC, "wlc0").run_ap(_ctx(mac="3891.b70f.2600"))
    assert r.status is CheckStatus.WARN
    assert "radio MAC" in r.message


def test_absent_ap_warns_and_never_stops_the_chain(patched):
    """Absent from one controller is the normal answer on a multi-WLC site.

    A FAIL here would set ap_stop and discard every edge-side finding after
    it -- which is exactly the evidence that explains why the AP never joined.
    """
    from checks.ap_wlc import ApWlcApState

    ctx = _ctx(mac="dead.beef.0001")
    r = ApWlcApState(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.WARN
    assert not ctx.state.get("ap_stop")
    assert ctx.state["ap_wlc_ap_absent"][WLC] == "dead.beef.0001"


def test_unregistered_state_stops_the_run(patched, monkeypatch):
    """Not Registered ends the flow rather than noting a problem.

    SDA allows one primary controller, so there is no second one the AP could
    be registered on instead. Everything the flow exists to validate is built
    on a CAPWAP session that does not exist, so continuing would report a wall
    of absences that all restate this single fault.
    """
    import copy
    import radkit_cli
    from checks.ap_wlc import ApWlcApState

    downed = copy.deepcopy(AP_SUMMARY)
    downed["ap_name"]["AP-002"]["state"] = "Downloading"
    monkeypatch.setattr(radkit_cli, "get_single_output_genie",
                        lambda h, c, s, **k: downed)
    ctx = _ctx()
    r = ApWlcApState(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.FAIL
    assert "Downloading" in r.message
    # Without this every later check fails on its own missing data.
    assert "not Registered" in ctx.state["ap_stop"]


def test_registered_ap_grades_mac_ip_mode_and_admin(patched, monkeypatch):
    """The five rules that apply once the AP is registered."""
    from checks.ap_wlc import ApWlcApState

    ctx = _ctx()
    # What SISF saw on the edge, which the controller's address is graded on.
    ctx.state["ap_ip"] = "172.19.5.10"
    r = ApWlcApState(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.OK
    # Saved for the radio-MAC LISP and access-tunnel checks still to be built.
    assert ctx.state["ap_wlc_radio_mac"] == "3891.b70f.2600"


def test_controller_ip_disagreeing_with_sisf_is_flagged(patched, monkeypatch):
    """One of the two is stale: the AP moved, or something still points at
    where it used to be."""
    from checks.ap_wlc import ApWlcApState

    ctx = _ctx()
    ctx.state["ap_ip"] = "172.19.5.99"
    ctx.state["ap_ip_source"] = "device-tracking + DHCP snooping"
    r = ApWlcApState(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.WARN
    assert "172.19.5.99" in r.message and "172.19.5.10" in r.message


def test_non_local_mode_and_disabled_admin_are_flagged(patched, monkeypatch):
    """Local/Enabled is what an AP onboards as on a fabric edge."""
    import checks.ap_wlc as mod
    from checks.ap_wlc import ApWlcApState

    monkeypatch.setattr(mod, "_ap_config_general", lambda h, n, s: (
        {"ap_mode": "FlexConnect", "administrative_state": "Disabled"}, None))
    r = ApWlcApState(WLC, "wlc0").run_ap(_ctx())
    assert r.status is CheckStatus.WARN
    assert "FlexConnect" in r.message
    assert "Disabled" in r.message


def test_unreadable_config_still_reports_the_join(patched, monkeypatch):
    """The summary row already proved the AP is joined.

    Failing to read its tags narrows what can be said; it does not reverse
    the finding that the AP reached the controller.
    """
    import checks.ap_wlc as mod
    from checks.ap_wlc import ApWlcApState

    monkeypatch.setattr(mod, "_ap_config_general",
                        lambda h, n, s: (None, "timed out"))
    ctx = _ctx()
    r = ApWlcApState(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.WARN
    assert "is joined to" in r.message
    assert ctx.state["ap_wlc_joined_on"] == [WLC]


def test_verdict_warns_when_no_controller_has_the_ap(patched):
    """Absent everywhere is a fabric fault -- WARN, so the chain continues."""
    from checks.ap_wlc import ApWlcApState, ApWlcApStateVerdict

    ctx = _ctx(mac="dead.beef.0001")
    ApWlcApState(WLC, "wlc0").run_ap(ctx)
    v = ApWlcApStateVerdict().run_ap(ctx)
    assert v.status is CheckStatus.WARN
    assert not ctx.state.get("ap_stop")


def test_verdict_flags_two_controllers_claiming_one_ap(patched):
    """An AP holds one CAPWAP session, so two claims is an anomaly."""
    from checks.ap_wlc import ApWlcApStateVerdict

    ctx = _ctx()
    ctx.state["ap_wlc_joined_on"] = [WLC, "wlc-two"]
    ctx.state["ap_wlc_ap_name"] = "AP-002"
    v = ApWlcApStateVerdict().run_ap(ctx)
    assert v.status is CheckStatus.WARN
    assert "more than one" in v.message


def test_genie_result_that_is_a_mapping_but_not_a_dict_is_accepted():
    """RADKit returns a GenieParseResult: a Mapping, but isinstance(x, dict)
    is False for it. Testing for dict here would discard a good parse and
    report a joined AP as absent."""
    from collections.abc import Mapping

    from checks.ap_wlc import _ap_summary_rows

    class GenieLike(Mapping):
        def __init__(self, d): self._d = d
        def __getitem__(self, k): return self._d[k]
        def __iter__(self): return iter(self._d)
        def __len__(self): return len(self._d)

    assert not isinstance(GenieLike(AP_SUMMARY), dict)
    rows = _ap_summary_rows(GenieLike(AP_SUMMARY))
    assert rows is not None and "AP-002" in rows


def test_controller_with_no_aps_is_distinguished_from_a_bad_parse():
    """"No AP is joined here" is a real answer; an unexpected shape is not."""
    from checks.ap_wlc import _ap_summary_rows

    assert _ap_summary_rows({"ap_neighbor_count": 0}) == {}
    assert _ap_summary_rows({"something_else": 1}) is None
    assert _ap_summary_rows("not parsed at all") is None


def test_registered_ap_draws_the_capwap_control_link(patched):
    """The CAPWAP session is the one part of the AP's state that is not about
    a single node, so it goes on the canvas as an edge."""
    from checks.ap_wlc import ApWlcApState

    r = ApWlcApState(WLC, "wlc0").run_ap(_ctx())
    edges = r.data["add_edges"]
    assert len(edges) == 1
    assert edges[0]["source"] == "ap"
    assert edges[0]["target"] == "wlc0"
    assert edges[0]["label"] == "CAPWAP Control"
    assert edges[0]["capwap"] is True


def test_unregistered_ap_draws_no_link(patched, monkeypatch):
    """There is no tunnel to show when the AP never registered."""
    import copy
    import radkit_cli
    from checks.ap_wlc import ApWlcApState

    downed = copy.deepcopy(AP_SUMMARY)
    downed["ap_name"]["AP-002"]["state"] = "Downloading"
    monkeypatch.setattr(radkit_cli, "get_single_output_genie",
                        lambda h, c, s, **k: downed)
    r = ApWlcApState(WLC, "wlc0").run_ap(_ctx())
    assert "add_edges" not in (r.data or {})
