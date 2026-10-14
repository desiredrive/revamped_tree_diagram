"""The two control-plane checks with no edge equivalent.

An edge opens its own LISP session, so neither the WLC locator-set nor
passive-open applies to it. A controller does not: the control plane has to be
configured to accept a passive-open session from the controller's wireless
management address, and both halves of that are invisible from the controller
itself.
"""

import types

import pytest

from checks.base import CheckStatus
from checks.wlc_cp_session import WlcCpSessionState, WlcLocatorSet


WMI = "10.31.136.74"
CP = "border1-sdawest-com"


def _ctx(cp):
    """A context whose control-plane cache is already warm."""
    return types.SimpleNamespace(
        service=object(), payload={},
        state={"_lisp_session_cps": {CP: cp}, "wlc_cp_vnid": "8188"})


def _cp(locators=(WMI,), passive=True):
    cfg = types.SimpleNamespace(
        wlc_locator_ips=list(locators), passive_open_configured=passive)
    return types.SimpleNamespace(
        cp_configuration=lambda *a: None, profiled_device=None,
        specific_lisp_session=lambda *a: None, _cfg=cfg)


def _locator(cp):
    """Bind the configuration the reader would have populated."""
    obj = _cp() if cp is None else cp
    chk = WlcLocatorSet(CP, CP, WMI, "catc", "wlccp-1")
    ctx = _ctx(obj)

    def read(_vnid, _svc):
        obj.cp_configuration = obj._cfg
    obj.cp_configuration = read
    return chk, ctx


def test_a_wmi_outside_the_locator_set_warns():
    """The control plane has no locator to match the registration against."""
    chk, ctx = _locator(_cp(locators=("172.19.1.99",)))
    r = chk.run(ctx)
    assert r.status is CheckStatus.WARN
    assert WMI in r.message
    assert "locator-set" in r.message


def test_passive_open_not_configured_warns():
    """The control plane never opens the session the controller waits for."""
    chk, ctx = _locator(_cp(passive=False))
    r = chk.run(ctx)
    assert r.status is CheckStatus.WARN
    assert "passive-open" in r.message


def test_both_faults_are_reported_together():
    """One run, both remediations: fixing the locator-set alone would leave
    the session down and look like the fix did not work."""
    chk, ctx = _locator(_cp(locators=(), passive=False))
    r = chk.run(ctx)
    assert r.status is CheckStatus.WARN
    assert "locator-set" in r.message and "passive-open" in r.message


def test_a_correctly_configured_control_plane_passes():
    chk, ctx = _locator(_cp())
    assert chk.run(ctx).status is CheckStatus.OK


def test_an_unreadable_control_plane_warns_rather_than_failing():
    """A fabric fault must not stop the run: FAIL would skip every remaining
    AP validation."""
    obj = _cp()

    def boom(_vnid, _svc):
        raise RuntimeError("unreachable")
    obj.cp_configuration = boom
    r = WlcLocatorSet(CP, CP, WMI, "catc", "wlccp-1").run(_ctx(obj))
    assert r.status is CheckStatus.WARN
    assert "RuntimeError" in r.message


# --------------------------------------------------------------------------
# The session, read from the control plane.
# --------------------------------------------------------------------------


def _session(**attrs):
    obj = types.SimpleNamespace()

    def read(_wmi, _svc):
        obj.specific_lisp_session = types.SimpleNamespace(**attrs)
    obj.specific_lisp_session = read
    return obj


def test_an_up_session_passes_and_names_both_ends():
    obj = _session(session_state="Up", peer_addr=WMI, peer_port="4342",
                   local_address="172.19.1.64", local_port="22193",
                   session_type="Default", session_state_time="2d04h")
    r = WlcCpSessionState(CP, CP, WMI, "catc", "wlccp-1").run(_ctx(obj))
    assert r.status is CheckStatus.OK
    assert WMI in r.message and "172.19.1.64" in r.message


def test_a_session_that_never_came_up_warns():
    """The legacy flow reads these attributes through a try/except: a session
    that never came up leaves them unset rather than reporting a down state,
    so their ABSENCE is the finding."""
    chk = WlcCpSessionState(CP, CP, WMI, "catc", "wlccp-1")
    r = chk.run(_ctx(_session()))
    assert r.status is CheckStatus.WARN
    assert "no LISP session up" in r.message


def test_a_down_session_records_its_state_for_later_checks():
    obj = _session(session_state="Down", peer_addr=WMI, peer_port="4342",
                   local_address="172.19.1.64", local_port="0",
                   session_type="Default", session_state_time="00:03:11")
    ctx = _ctx(obj)
    r = WlcCpSessionState(CP, CP, WMI, "catc", "wlccp-1").run(ctx)
    assert r.status is CheckStatus.WARN
    assert ctx.state["wlc_cp_session_states"][CP] == "Down"


def test_nodes_resolve_by_hostname_as_well_as_address():
    """`show wireless fabric summary` names control planes by ADDRESS, and the
    canvas nodes follow it -- but `node_for` looks up by HOSTNAME, which is
    what the device is called once Catalyst Center resolves it. Keyed one way
    only, the reused control-plane checks fall back to the controller's node
    and every per-control-plane finding renders on the wrong device.
    """
    from checks.lisp_session import LispControlPlaneConfiguration
    from checks.wlc_cp_session import wlc_cp_session_checks

    checks = wlc_cp_session_checks(
        wmi=WMI, vnid="8188", radio_mac="3891.b70f.2600",
        # Address and hostname differ, as they do once a control plane is
        # profiled -- the fixture elsewhere uses the address for both.
        control_planes=[("172.19.1.64", CP, "172.19.1.64")],
        catc_name="catc", wlc_hostname="wlc", wlc_node_id="wlc",
        cp_nodes={"172.19.1.64": "wlccp-1"})

    reused = [c for c in checks
              if isinstance(c, LispControlPlaneConfiguration)]
    assert reused and all(c.target_node_id == "wlccp-1" for c in reused)
