"""Check 1 of 3: every WLAN the controller offers.

The catalogue the other two join against. `show wlan summary` is the only
read carrying BOTH the WLAN id and the profile name, which is what lets the
AP's on-air rows (named by profile) reach the fabric list (named by id).
"""

from checks.base import CheckStatus
from checks.ap_wlc import ApWlcWlans
from tests.wlan_fixtures import WLAN_SUMMARY, run_chain


def _run(**kw):
    (r,), ctx = run_chain(ApWlcWlans("WLCv", "wlc"), **kw)
    return r, ctx


def test_the_healthy_controller_passes():
    r, _ = _run()
    assert r.status is CheckStatus.OK


def test_every_wlan_is_listed_with_its_id_and_security():
    r, _ = _run()
    assert "• WLANs on WLCv: 5" in r.message
    for frag in ("17: MX CWA", "23: MX Enterprise", "[WPA3][AES]"):
        assert frag in r.message
    assert len(r.data["wlans"]) == 5


def test_the_join_maps_are_published_for_the_checks_behind_it():
    """The seam. Checks 2 and 3 read these rather than re-running the
    command, so an unwritten key silently degrades both."""
    _, ctx = _run()
    assert ctx.state["ap_wlc_wlans_by_id"]["WLCv"]["17"]["ssid"] == "MX CWA"
    assert (ctx.state["ap_wlc_wlans_by_prof"]["WLCv"]["MX CWA_profile"]
            ["wlan_id"] == "17")


def test_the_state_is_keyed_by_controller():
    """The flow loops over every Fabric WLC at the site; a flat key would be
    clobbered by the second one."""
    _, ctx = _run()
    assert set(ctx.state["ap_wlc_wlans"]) == {"WLCv"}


def test_no_access_tunnel_skips():
    r, _ = _run(tunnel=False)
    assert r.status is CheckStatus.SKIP


def test_no_ap_name_skips():
    r, _ = _run(ap_name=None)
    assert r.status is CheckStatus.SKIP


def test_a_controller_offering_nothing_is_not_a_finding_here():
    """Deliberately silent: an empty catalogue is already reported by the
    AP broadcasting nothing and by the policy tag carrying nothing. A third
    warning would say it a third time on a third badge."""
    empty = "\n".join(
        ln for ln in WLAN_SUMMARY.splitlines()
        if not ln.lstrip()[:2].isdigit()
    ).replace("Number of WLANs: 5", "Number of WLANs: 0")
    r, _ = _run(summary=empty)
    assert r.status is CheckStatus.OK
    assert r.data["wlans"] == []
