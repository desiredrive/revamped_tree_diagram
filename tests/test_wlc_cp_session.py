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


# --------------------------------------------------------------------------
# The authentication key comparison. `ETRConfiguration.etr_map_servers` wants
# `.mapservers` off the EID identification phase's record -- which the
# controller's flow does not have, having no such phase.
# --------------------------------------------------------------------------


def test_the_key_comes_from_the_fabric_summary_not_the_running_config():
    """The controller's key for each control plane is in the `Key` column of
    `show wireless fabric summary`, already plaintext.

    The edge's `LispAuthenticationKey` learns the xTR's key from `etr
    map-server` lines in `show run | section service ethernet`. A C9800 has
    no such lines and answers that command with nothing at all, so it found
    no entry for any control plane and reported:

      The switch has no map-server entry for 172.19.1.64, so there is no key
      to compare against border1-sdawest-com.

    It is not in this chain; the comparison is done against the control
    plane's site key by a check that reads the controller's own source.
    """
    from checks.wlc_cp_session import wlc_cp_session_checks, WlcCpAuthenticationKey
    from checks.lisp_session import LispAuthenticationKey

    checks = wlc_cp_session_checks(
        wmi="10.31.136.74", vnid=8188, radio_mac="3891.b70f.2600",
        control_planes=[("172.19.1.64", "cp1", "10.31.136.64"),
                        ("172.19.1.65", "cp2", "10.31.136.65")],
        catc_name="catc", wlc_hostname="wlc", wlc_node_id="wlc",
        cp_nodes={"172.19.1.64": "apcp-1", "172.19.1.65": "apcp-2"},
        wlc_mgmtip="10.31.136.74",
        keys={"172.19.1.64": "66302309625d422d",
              "172.19.1.65": "66302309625d422d"})

    assert not [c for c in checks if isinstance(c, LispAuthenticationKey)]
    auth = [c for c in checks if isinstance(c, WlcCpAuthenticationKey)]
    assert len(auth) == 2
    assert {c.wlc_key for c in auth} == {"66302309625d422d"}
    assert {c.target_node_id for c in auth} == {"apcp-1", "apcp-2"}


def test_a_control_plane_with_no_key_in_the_summary_skips():
    """Nothing to compare is not a mismatch."""
    from checks.wlc_cp_session import wlc_cp_session_checks, WlcCpAuthenticationKey

    checks = wlc_cp_session_checks(
        wmi="10.31.136.74", vnid=8188, radio_mac="3891.b70f.2600",
        control_planes=[("172.19.1.64", "cp1", "10.31.136.64")],
        catc_name="catc", wlc_hostname="wlc", wlc_node_id="wlc",
        cp_nodes={"172.19.1.64": "apcp-1"}, wlc_mgmtip="10.31.136.74",
        keys={})

    auth = [c for c in checks if isinstance(c, WlcCpAuthenticationKey)][0]
    r = auth.run(types.SimpleNamespace(service=object(), payload={}, state={}))
    assert r.status is CheckStatus.SKIP


def test_the_edge_check_falls_back_to_the_targets_control_planes(monkeypatch):
    """`LispAuthenticationKey` on a flow with no EID identification phase.

    Not used by the controller's chain -- it reads `show run | section
    service ethernet`, which a C9800 does not answer -- but the fallback
    still matters for any other flow that reuses it without that phase: the
    substitute record restricts its grading to the map-servers this EID
    registers to, rather than every instance on the box.
    """
    import checks.lisp_session as m

    seen = {}

    class Cfg:
        def __init__(self, _h): pass
        def site_uci(self, *a): 
            self.authentication_key = (True, "k")
            self.decrypted = True
        def __getattr__(self, _n): return lambda *a, **k: None
    monkeypatch.setattr("routingmodules.lisp.L2LISPControlPlane", Cfg)
    monkeypatch.setattr(m, "_cp_device",
                        lambda ctx, h, c, mgmt=None: types.SimpleNamespace(
                            profiled_device=types.SimpleNamespace(
                                hostname=h, loopback="172.19.1.64")))
    # An ETR with NO eid_properties -- the controller's case exactly.
    monkeypatch.setattr(m, "_profile_xtr",
                        lambda ctx, t: types.SimpleNamespace(
                            profiled_device=types.SimpleNamespace(
                                hostname="wlc")))

    class ETRCfg:
        def __init__(self, _h): pass
        def etr_map_servers(self, props, af, svc):
            seen["mapservers"] = props.mapservers
            self.mapserverconfiguration = []
    monkeypatch.setattr(
        "traffic_flows.lispsessiontroubleshooting.ETRConfiguration", ETRCfg)

    t = m.LispSessionTarget(
        eid="3891.b70f.2600", xtr_hostname="wlc", catc_name="catc",
        iid=8188, af="ethernet",
        control_planes=["172.19.1.64", "172.19.1.65"])
    ctx = types.SimpleNamespace(service=object(), payload={}, state={})
    r = m.LispAuthenticationKey(t, "cp1").run_session(ctx)

    assert "AttributeError" not in (r.message or "")
    assert seen["mapservers"] == [{"map_server": "172.19.1.64"},
                                  {"map_server": "172.19.1.65"}]


# --------------------------------------------------------------------------
# Which device the flow is actually about. Every check keyed on the xTR's
# address reads it off the profiled device; a controller registers from its
# WMI and has no Loopback0 to match on.
# --------------------------------------------------------------------------


def test_the_controller_is_profiled_not_the_edge():
    """`_profile_xtr` falls back to the AP chain's `xtr_mgmtip` when the
    target names no management address -- and that is the EDGE.

    The socket check then matched on the edge's Loopback0 and reported the
    edge's LISP session to the control plane as though it were the
    controller's, with real counters and no retransmissions:

      border2-sdawest-com holds the LISP socket to 172.19.1.68 ...
      172.19.1.65:4342 -> 172.19.1.68:28602, MSS 536
    """
    from checks.wlc_cp_session import wlc_cp_session_checks

    checks = wlc_cp_session_checks(
        wmi="10.31.136.74", vnid=8188, radio_mac="3891.b70f.2600",
        control_planes=[("172.19.1.64", "cp1", "10.31.136.64")],
        catc_name="catc", wlc_hostname="wlc", wlc_node_id="wlc",
        cp_nodes={"172.19.1.64": "apcp-1"}, wlc_mgmtip="10.31.136.74")

    targets = {getattr(c, "target", None) for c in checks}
    targets.discard(None)
    for t in targets:
        assert t.xtr_mgmtip == "10.31.136.74"


def test_the_controllers_rloc_is_the_wmi_not_a_loopback():
    """Even when a profiled device offers one, the WMI wins: that is the
    address the controller registers from."""
    from checks.lisp_session import LispSessionTarget

    t = LispSessionTarget(
        eid="3891.b70f.2600", xtr_hostname="wlc", catc_name="catc",
        iid=8188, af="ethernet", xtr_mgmtip="10.31.136.74",
        xtr_loopback="10.31.136.74")
    etr = types.SimpleNamespace(
        profiled_device=types.SimpleNamespace(loopback="172.19.1.68"))
    ctx = types.SimpleNamespace(state={"xtr_loopback": "172.19.1.68"})

    assert t.rloc(ctx, etr) == "10.31.136.74"


def test_the_edges_socket_check_is_unchanged_when_the_two_sources_differ():
    """The regression guard for routing this through `rloc()`.

    On the edge `rloc()` prefers ctx.state["xtr_loopback"] while the old code
    read profiled_device.loopback. `_profile_xtr` populates that state key
    from the same Catalyst Center read, so they agree in practice -- but if
    they ever diverge, the edge must keep reporting the profiled device's
    address rather than silently switching to a stale one.
    """
    from checks.lisp_session import LispSessionTarget

    t = LispSessionTarget(eid="172.19.5.10", xtr_hostname="Edge2",
                          catc_name="catc", iid=4097, af="ipv4")
    etr = types.SimpleNamespace(
        profiled_device=types.SimpleNamespace(loopback="172.19.1.68"))

    # Agreeing, which is the real case: unchanged either way.
    ctx = types.SimpleNamespace(state={"xtr_loopback": "172.19.1.68"})
    assert t.rloc(ctx, etr) == "172.19.1.68"

    # Unset: falls back to the profiled device, as the old code did.
    ctx = types.SimpleNamespace(state={})
    assert t.rloc(ctx, etr) == "172.19.1.68"


def test_the_path_checks_run_on_the_control_plane_towards_the_wmi():
    """Not on the controller. The near side would read CEF, ACLs and CTS
    policy on a C9800 with IOS-XE switch commands -- the same wrong-device
    mistake the edge readers made against this controller earlier.

    These were omitted from the controller's chain entirely at first, which
    left a border policy blocking registrations invisible while every other
    check on the control plane passed.
    """
    from checks.wlc_cp_session import wlc_cp_session_checks
    from checks.lisp_session import (
        LispSessionAccessLists, LispSessionTrustSec, LispMapServerSelfSession)

    checks = wlc_cp_session_checks(
        wmi="10.31.136.74", vnid=8188, radio_mac="3891.b70f.2600",
        control_planes=[("172.19.1.64", "cp1", "10.31.136.64")],
        catc_name="catc", wlc_hostname="wlc", wlc_node_id="wlc",
        cp_nodes={"172.19.1.64": "apcp-1"}, wlc_mgmtip="10.31.136.74")

    for cls in (LispSessionAccessLists, LispSessionTrustSec):
        found = [c for c in checks if isinstance(c, cls)]
        assert found, f"{cls.__name__} was not queued"
        for c in found:
            assert c.on_cp is True
            # The map-server is the RLOC, and the check's own node is the CP.
            assert c.map_server == "172.19.1.64"
            assert c.target_node_id == "apcp-1"

    assert [c for c in checks if isinstance(c, LispMapServerSelfSession)]


def test_the_near_side_path_checks_are_not_queued_against_the_controller():
    """The controller is not where this flow's path questions are answered.

    Routing and PathMtu read the xTR unconditionally -- `show ip cef`,
    `show ip route` and the IGP -- which are IOS-XE switch commands, and they
    have no control-plane side to run instead. The path from the control
    plane towards the WMI is covered by the ACL and SGT checks above.
    """
    from checks.wlc_cp_session import wlc_cp_session_checks
    from checks.lisp_session import LispSessionRouting, LispSessionPathMtu

    checks = wlc_cp_session_checks(
        wmi="10.31.136.74", vnid=8188, radio_mac="3891.b70f.2600",
        control_planes=[("172.19.1.64", "cp1", "10.31.136.64")],
        catc_name="catc", wlc_hostname="wlc", wlc_node_id="wlc",
        cp_nodes={"172.19.1.64": "apcp-1"}, wlc_mgmtip="10.31.136.74")

    for cls in (LispSessionRouting, LispSessionPathMtu):
        assert not [c for c in checks if isinstance(c, cls)]

    # And no check in the chain reads the near side of a path.
    assert not [c for c in checks if getattr(c, "on_cp", True) is False]
