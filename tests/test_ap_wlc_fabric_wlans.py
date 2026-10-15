"""Check 2 of 3: which of the controller's WLANs are fabric-enabled.

A WLAN can be UP on the controller and still have no fabric data path, and
nothing else in the flow would show that.

The contract this check carries is an ABSENCE: when the controller does not
answer `show fabric wlan summary`, the state key is left unset, and check 3
declines to split fabric from non-fabric rather than calling every SSID
non-fabric on the strength of a command that never ran.
"""

from checks.base import CheckStatus
from checks.ap_wlc import ApWlcWlans, ApWlcFabricWlans
from tests.wlan_fixtures import FABRIC_WLAN, run_chain


def _run(**kw):
    (_w, r), ctx = run_chain(
        ApWlcWlans("WLCv", "wlc"), ApWlcFabricWlans("WLCv", "wlc"), **kw)
    return r, ctx


def _no_fabric_wlans():
    return "\n".join(
        ln for ln in FABRIC_WLAN.splitlines()
        if not ln.lstrip()[:2].isdigit()
    ).replace("Number of Fabric wlan : 5", "Number of Fabric wlan : 0")


def test_the_healthy_controller_passes():
    r, _ = _run()
    assert r.status is CheckStatus.OK


def test_the_fabric_wlans_are_listed():
    r, _ = _run()
    assert len(r.data["fabric_wlans"]) == 5
    assert "Fabric-enabled WLANs on WLCv: 5" in r.message
    assert "17   MX CWA" in r.message


def test_the_fabric_sets_are_published_for_the_broadcast_check():
    r, ctx = _run()
    assert ctx.state["ap_wlc_fabric_wlan_ids"]["WLCv"] == {
        "17", "19", "22", "23", "25"}
    assert "MX CWA_profile" in ctx.state[
        "ap_wlc_fabric_wlan_profiles"]["WLCv"]


def test_a_controller_with_no_fabric_wlans_warns():
    r, _ = _run(fabric=_no_fabric_wlans())
    assert r.status is CheckStatus.WARN
    assert "no fabric-enabled WLANs" in r.message


def test_an_unanswered_command_skips_rather_than_failing():
    """FAIL would set `ap_stop` and silence the AP's own broadcast check
    behind this one. A controller refusing this command is not a reason to
    stop reading what the AP is on air with."""
    r, _ = _run(fabric=None)
    assert r.status is CheckStatus.SKIP
    assert r.status is not CheckStatus.FAIL
    assert r.status is not CheckStatus.WARN


def test_an_unanswered_command_leaves_the_key_ABSENT():
    """The sentinel. Not None, not an empty set -- absent. Setting it to a
    falsy value would read downstream as "nothing is fabric-enabled", which
    is a conclusion drawn from a missing read."""
    _, ctx = _run(fabric=None)
    assert "WLCv" not in (ctx.state.get("ap_wlc_fabric_wlans") or {})
    assert "WLCv" not in (ctx.state.get("ap_wlc_fabric_wlan_ids") or {})


def test_an_empty_fabric_list_is_not_the_same_as_an_unread_one():
    """Zero fabric WLANs IS evidence, and is graded. The key is written."""
    _, ctx = _run(fabric=_no_fabric_wlans())
    assert ctx.state["ap_wlc_fabric_wlan_ids"]["WLCv"] == set()


def test_it_skips_when_the_wlan_list_was_never_read():
    from tests.wlan_fixtures import _Ctx
    import radkit_cli
    from tests.wlan_fixtures import fake_device
    ctx = _Ctx()
    real = radkit_cli.get_any_single_output
    radkit_cli.get_any_single_output = fake_device()
    try:
        r = ApWlcFabricWlans("WLCv", "wlc").run_ap(ctx)
    finally:
        radkit_cli.get_any_single_output = real
    assert r.status is CheckStatus.SKIP
    assert "WLC WLANs" in r.message


def test_no_access_tunnel_skips():
    r, _ = _run(tunnel=False)
    assert r.status is CheckStatus.SKIP


def test_no_ap_name_skips():
    r, _ = _run(ap_name=None)
    assert r.status is CheckStatus.SKIP
