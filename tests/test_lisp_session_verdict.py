"""Where the LISP session flow stops.

Each per-map-server check reports its own session and continues, so that the
checks explaining *why* it is down still run. That leaves nobody looking at
the whole, which is what the verdict is for: the flow stops after the
troubleshooting, not at the first down session.
"""

import types

import pytest

from checks.base import CheckStatus
from checks.lisp_session import (
    STOP_KEY, LispSessionTarget, LispSessionVerdict, lisp_session_checks)


def _target():
    return LispSessionTarget(
        eid="172.19.5.10", xtr_hostname="Edge2", catc_name="catc",
        iid=4097, af="ipv4", label="the AP's address 172.19.5.10")


def _ctx(states):
    """State keyed the way the flow keys it: private to this target's device."""
    key = _target().key("lisp_session_states")
    return types.SimpleNamespace(
        service=object(), payload={},
        state={key: states} if states is not None else {})


def test_every_session_down_stops_the_flow():
    """Rule: both down at the end of the tshoot session, stop the flow."""
    ctx = _ctx({"172.19.1.64": "Down", "172.19.1.65": "Down"})
    r = LispSessionVerdict(_target()).run_session(ctx)
    assert r.status is CheckStatus.FAIL
    assert ctx.state[_target().key(STOP_KEY)]
    assert "172.19.1.64" in r.message and "172.19.1.65" in r.message


def test_one_session_up_continues():
    """A registration can still leave through the session that is up, so the
    checks below have something real to measure."""
    ctx = _ctx({"172.19.1.64": "Up", "172.19.1.65": "Down"})
    r = LispSessionVerdict(_target()).run_session(ctx)
    assert r.status is CheckStatus.WARN
    assert not ctx.state.get(_target().key(STOP_KEY))
    assert "172.19.1.65" in r.message


def test_all_up_passes():
    ctx = _ctx({"172.19.1.64": "Up", "172.19.1.65": "Up"})
    r = LispSessionVerdict(_target()).run_session(ctx)
    assert r.status is CheckStatus.OK
    assert not ctx.state.get(_target().key(STOP_KEY))


def test_the_stop_comes_after_the_troubleshooting_not_before():
    """The point of the rule. If the flow stopped at the first down session,
    the checks that explain it -- socket, key, routing, MTU, ACLs -- would
    never run."""
    checks = lisp_session_checks(
        _target(),
        map_servers=[("172.19.1.64", "cp1", "172.19.1.64"),
                     ("172.19.1.65", "cp2", "172.19.1.65")])
    assert isinstance(checks[-1], LispSessionVerdict)
    names = [type(c).__name__ for c in checks]
    assert names.index("LispSessionVerdict") == len(names) - 1
    # Both control planes were walked before the verdict is reached.
    assert names.count("LispPerMapServerSession") == 2


def test_states_unread_skip_rather_than_stopping():
    """No session was read at all: that is not the same as every session
    being down, and must not stop a flow on no evidence."""
    for states in ({}, None):
        ctx = _ctx(states)
        r = LispSessionVerdict(_target()).run_session(ctx)
        assert r.status is CheckStatus.SKIP
        assert not ctx.state.get(_target().key(STOP_KEY))


def test_unknown_state_counts_as_not_up():
    """A session whose state could not be read is not evidence of health."""
    ctx = _ctx({"172.19.1.64": "unknown", "172.19.1.65": "Init"})
    r = LispSessionVerdict(_target()).run_session(ctx)
    assert r.status is CheckStatus.FAIL
    assert ctx.state[_target().key(STOP_KEY)]


def test_the_stop_makes_later_session_checks_skip():
    """_SessionCheck honours the stop key, so the flow below reports one
    cause rather than failing repeatedly for it."""
    from checks.lisp_session import LispGlobalSession

    ctx = _ctx({"172.19.1.64": "Down", "172.19.1.65": "Down"})
    LispSessionVerdict(_target()).run_session(ctx)
    later = LispGlobalSession(_target()).run(ctx)
    assert later.status is CheckStatus.SKIP


def test_two_runs_of_the_flow_do_not_share_state():
    """The flow runs more than once in a single AP run: the edge registers
    the AP's address, the controller registers its radio MAC.

    Unscoped, the second run reads the first's profiled device, its session
    states and its stop reason -- and reports the wrong box's fabric as the
    fault. Each of those is silent: the output looks like a finding.
    """
    edge = LispSessionTarget(eid="172.19.5.10", xtr_hostname="Edge2",
                             catc_name="catc", iid=4097, af="ipv4")
    wlc = LispSessionTarget(eid="3891.b70f.2600", xtr_hostname="WLCv",
                            catc_name="catc", iid=8188, af="ethernet")

    assert edge.key("lisp_session_states") != wlc.key("lisp_session_states")
    assert edge.key(STOP_KEY) != wlc.key(STOP_KEY)

    ctx = types.SimpleNamespace(service=object(), payload={}, state={
        edge.key("lisp_session_states"): {"172.19.1.64": "Down",
                                          "172.19.1.65": "Down"},
        wlc.key("lisp_session_states"): {"172.19.1.64": "Up",
                                         "172.19.1.65": "Up"},
    })

    # The edge's sessions are all down, so its flow stops.
    assert LispSessionVerdict(edge).run_session(ctx).status is CheckStatus.FAIL
    # The controller's are up, and must be unaffected by the edge's stop.
    assert LispSessionVerdict(wlc).run_session(ctx).status is CheckStatus.OK
    assert ctx.state.get(edge.key(STOP_KEY))
    assert not ctx.state.get(wlc.key(STOP_KEY))


def _etr_with_peers(peers):
    """An ETR stub whose session table reads like the device's."""
    return types.SimpleNamespace(
        global_lisp_sessions=types.SimpleNamespace(
            peers={p: [{"state": s}] for p, s in peers.items()}),
        profiled_device=types.SimpleNamespace(loopback="172.19.1.68"),
        global_lisp_session=lambda svc: None,
    )


def test_one_walked_cp_down_is_not_every_session_down(monkeypatch):
    """The verdict judges the switch, not the subset of CPs it walked.

    A trigger that fires on ONE down session passes only that control plane,
    so the walked subset is {that CP: Down}. Reading the verdict off it alone
    concluded "every session is down" and stopped the AP flow -- while the
    switch's other two sessions were up and its registrations were still
    getting through. The live run that caught this had 172.19.1.64 and
    172.19.1.100 up with only 172.19.1.65 down, and LISP Session -- Global
    said so three checks earlier.
    """
    import checks.lisp_session as m

    etr = _etr_with_peers({"172.19.1.64": "Up", "172.19.1.65": "Down",
                           "172.19.1.100": "Up"})
    monkeypatch.setattr(m, "_profile_xtr", lambda ctx, t: etr)

    ctx = _ctx({"172.19.1.65": "Down"})          # only the implicated CP
    r = LispSessionVerdict(_target(), map_servers=["172.19.1.65"]).run_session(ctx)

    assert r.status is CheckStatus.WARN
    assert not ctx.state.get(_target().key(STOP_KEY))
    assert "172.19.1.65" in r.message
    assert "2 of 3" in r.message


def test_an_unreadable_switch_falls_back_to_the_walked_subset(monkeypatch):
    """Re-reading the switch is an improvement on the subset, not a
    dependency: if it cannot be read the verdict still reports what the
    per-map-server checks established rather than reporting nothing."""
    import checks.lisp_session as m

    def boom(ctx, t):
        raise RuntimeError("device unreachable")
    monkeypatch.setattr(m, "_profile_xtr", boom)

    ctx = _ctx({"172.19.1.64": "Down", "172.19.1.65": "Down"})
    r = LispSessionVerdict(_target()).run_session(ctx)
    assert r.status is CheckStatus.FAIL
    assert ctx.state[_target().key(STOP_KEY)]


def test_a_walked_cp_absent_from_the_peer_table_still_counts(monkeypatch):
    """A map-server missing from `show lisp session` is not thereby up."""
    import checks.lisp_session as m

    etr = _etr_with_peers({"172.19.1.64": "Up"})
    monkeypatch.setattr(m, "_profile_xtr", lambda ctx, t: etr)

    ctx = _ctx({"172.19.1.65": "Down"})
    r = LispSessionVerdict(_target()).run_session(ctx)
    assert r.status is CheckStatus.WARN
    assert "172.19.1.65" in r.message


def test_every_session_down_does_not_stop_the_flow_at_the_global_check(monkeypatch):
    """All sessions down is when the per-CP checks matter MOST.

    LispGlobalSession used to _stop here, which skipped the fourteen checks
    per control plane that say why none of them came up -- so three sessions
    down produced three checks and a halt, while one session down produced
    the full flow. The worse fault gave less diagnostic output. The verdict
    is the only thing that stops the flow now.
    """
    import checks.lisp_session as m

    etr = _etr_with_peers({"172.19.1.64": "Down", "172.19.1.65": "Down",
                           "172.19.1.100": "Down"})
    monkeypatch.setattr(m, "_profile_xtr", lambda ctx, t: etr)

    t = _target()
    ctx = types.SimpleNamespace(service=object(), payload={}, state={})
    r = m.LispGlobalSession(t).run_session(ctx)

    assert r.status is CheckStatus.WARN
    assert not ctx.state.get(t.key(STOP_KEY))      # the flow continues
    assert "172.19.1.64" in r.message


def test_all_down_still_fans_out_over_every_control_plane():
    """The checks that explain a total outage have to be built for each CP."""
    import checks.lisp_session as m

    t = _target()
    pairs = [("172.19.1.64", "cp1", "172.19.1.64"),
             ("172.19.1.65", "cp2", "172.19.1.65"),
             ("172.19.1.100", "cp3", "172.19.1.100")]
    names = [type(c).__name__ for c in m.lisp_session_checks(t, map_servers=pairs)]

    # Three switch-side, thirteen per CP, one inter-CP each, one verdict.
    assert len(names) == 3 + 13 * 3 + 3 + 1
    assert names.count("LispSessionRouting") == 3
    assert names.count("LispAuthenticationKey") == 3
    assert names[-1] == "LispSessionVerdict"


def test_the_verdict_is_what_stops_a_total_outage(monkeypatch):
    """Still down after the troubleshooting is where the flow ends."""
    import checks.lisp_session as m

    etr = _etr_with_peers({"172.19.1.64": "Down", "172.19.1.65": "Down"})
    monkeypatch.setattr(m, "_profile_xtr", lambda ctx, t: etr)

    ctx = _ctx({"172.19.1.64": "Down", "172.19.1.65": "Down"})
    r = LispSessionVerdict(_target()).run_session(ctx)
    assert r.status is CheckStatus.FAIL
    assert ctx.state[_target().key(STOP_KEY)]


def test_a_control_plane_without_the_instance_warns_rather_than_failing(monkeypatch):
    """`lisp_id` missing means the CP serves no such instance.

    That is a fabric fault -- a statement about the device -- not the tool
    failing to work, so it warns and the remaining control planes are still
    walked. It reached the user as "KeyError: 'lisp_id'", which named the
    parser key and not the condition.
    """
    import checks.lisp_session as m

    monkeypatch.setattr(m, "_cp_device",
                        lambda ctx, h, c, mgmt=None: types.SimpleNamespace(
                            profiled_device=types.SimpleNamespace(hostname=h)))

    class Boom:
        def __init__(self, *a): pass
        def eidStatistics(self, af, svc): raise KeyError("lisp_id")
    monkeypatch.setattr("routingmodules.lisp.LISPInstanceStatus", Boom)

    ctx = types.SimpleNamespace(service=object(), payload={}, state={})
    r = m.LispControlPlaneStatistics(_target(), "cp1").run_session(ctx)

    assert r.status is CheckStatus.WARN
    assert "4097" in r.message
    assert "KeyError" not in r.message


def test_a_blocking_acl_names_the_interface_and_reads_as_prose(monkeypatch):
    """The deny reached the user as a Python tuple, and never said where.

    `_evaluate_acls` returns (flow, detail) pairs for the shared renderer to
    lay out; interpolating them directly printed the repr. The interface is
    per-path rather than per-deny, so it only appears once the renderer's
    `path` argument is used -- which is the first thing a reader needs, since
    an ACL blocking TCP/4342 is actionable only on a named port.
    """
    import checks.lisp_session as m

    etr = types.SimpleNamespace(
        profiled_device=types.SimpleNamespace(
            hostname="Edge2", loopback="172.19.1.68"))
    monkeypatch.setattr(m, "_profile_xtr", lambda ctx, t: etr)
    monkeypatch.setattr(m, "_cef_interfaces",
                        lambda ctx, h, d: ["TenGigabitEthernet1/0/3"])
    monkeypatch.setattr(m, "_evaluate_acls", lambda ctx, h, i, f: (
        ["nolisp"],
        [("172.19.1.68 → 172.19.1.65 TCP/4342", "nolisp, sequence 1")],
        [], []))

    ctx = types.SimpleNamespace(service=object(), payload={}, state={})
    r = m.LispSessionAccessLists(_target(), "172.19.1.65", "cp2").run_session(ctx)

    assert r.status is CheckStatus.WARN
    assert "TenGigabitEthernet1/0/3" in r.message
    assert "nolisp, sequence 1" in r.message
    assert "('" not in r.message            # no tuple repr


def test_the_switch_side_check_is_named_for_the_device_it_reads():
    """"(switch)" read as a different subject rather than the same check run
    from the other end -- and the xTR is not always an edge, since the
    controller runs this flow too."""
    import checks.lisp_session as m

    t = m.LispSessionTarget(eid="172.19.5.10", xtr_hostname="Edge2",
                            catc_name="c", iid=4097, af="ipv4")
    for cls in (m.LispSessionAccessLists, m.LispSessionTrustSec):
        near = cls(t, "172.19.1.65", "cp2", False).name
        far = cls(t, "172.19.1.65", "cp2", True).name
        assert "Edge2" in near and "switch" not in near
        assert "cp2" in far
        assert near != far


# --------------------------------------------------------------------------
# A flow about a device other than the AP chain's edge. The controller
# registers the AP's radio MAC to the same control planes, so the same module
# runs against it -- and every xtr_* state key names the edge.
# --------------------------------------------------------------------------


def _wlc_target():
    return LispSessionTarget(
        eid="3891.b70f.2600", xtr_hostname="wlc-jalejand-cisco-com",
        catc_name="catc", iid=8188, af="ethernet",
        xtr_mgmtip="10.31.136.74", label="the AP's radio MAC")


def test_a_foreign_target_is_profiled_through_catalyst_center(monkeypatch):
    """The shim is composed from the chain's xtr_* keys, so it describes the
    edge and nothing else. Reusing it for the controller would read the edge
    and file its fabric under the controller's name."""
    import checks.lisp_session as m

    built = {}

    class ETR:
        def __init__(self, mgmt, _n): built["mgmt"] = mgmt
        def existing_profiled(self, shim): built["via"] = "shim"
        def device_profiler(self, catc, svc): built["via"] = "catc"
    monkeypatch.setattr(
        "traffic_flows.lispsessiontroubleshooting.ETRDevice", ETR)

    ctx = types.SimpleNamespace(
        service=object(), payload={},
        state={"xtr_mgmtip": "10.31.136.126", "xtr_loopback": "172.19.1.68"})
    m._profile_xtr(ctx, _wlc_target())

    assert built["mgmt"] == "10.31.136.74"      # not the edge
    assert built["via"] == "catc"               # not the edge's shim


def test_the_chains_own_xtr_still_uses_the_cached_shim(monkeypatch):
    """The edge path must not pay a second Catalyst Center roundtrip."""
    import checks.lisp_session as m

    built = {}

    class ETR:
        def __init__(self, mgmt, _n): built["mgmt"] = mgmt
        def existing_profiled(self, shim): built["via"] = "shim"
        def device_profiler(self, catc, svc): built["via"] = "catc"
    monkeypatch.setattr(
        "traffic_flows.lispsessiontroubleshooting.ETRDevice", ETR)
    monkeypatch.setattr(m, "_build_src_xtr_shim",
                        lambda ctx: types.SimpleNamespace(hostname="Edge2"),
                        raising=False)
    import checks.ew_shared
    monkeypatch.setattr(checks.ew_shared, "_build_src_xtr_shim",
                        lambda ctx: types.SimpleNamespace(hostname="Edge2"))

    ctx = types.SimpleNamespace(
        service=object(), payload={},
        state={"xtr_mgmtip": "10.31.136.126", "xtr_loopback": "172.19.1.68"})
    m._profile_xtr(ctx, _target())

    assert built["mgmt"] == "10.31.136.126"
    assert built["via"] == "shim"


def test_a_foreign_target_does_not_borrow_the_edges_rloc():
    """Every check keyed on the RLOC would otherwise answer for the edge."""
    etr = types.SimpleNamespace(
        profiled_device=types.SimpleNamespace(loopback="10.31.136.74"))
    ctx = types.SimpleNamespace(state={"xtr_loopback": "172.19.1.68"})

    assert _wlc_target().rloc(ctx, etr) == "10.31.136.74"
    assert _target().rloc(ctx, etr) == "172.19.1.68"


# --------------------------------------------------------------------------
# `rloc_members` and `domains` are read by the configuration check and were
# never graded: the five checks in `cp_configuration_validation` stop at the
# site and the roles. A control plane that does not distribute its locators,
# or has no domain ID, passed silently while the OK message claimed it
# "allows the locators this switch registers from" -- which nothing had read.
# --------------------------------------------------------------------------


def _cfg_check(monkeypatch, **attrs):
    """The configuration check, with the CP's parsed config stubbed."""
    import checks.lisp_session as m

    monkeypatch.setattr(m, "_cp_device",
                        lambda ctx, h, c, mgmt=None: types.SimpleNamespace(
                            profiled_device=types.SimpleNamespace(hostname=h)))

    class Cfg:
        def __init__(self, _h):
            for k, v in attrs.items():
                setattr(self, k, v)
        def __getattr__(self, _n):
            return lambda *a, **k: None
    monkeypatch.setattr("routingmodules.lisp.L2LISPControlPlane", Cfg)
    monkeypatch.setattr(
        "traffic_flows.lispsessiontroubleshooting.cp_configuration_validation",
        lambda *a: None)

    ctx = types.SimpleNamespace(service=object(), payload={}, state={})
    return m.LispControlPlaneConfiguration(_target(), "cp1").run_session(ctx)


def test_a_fully_configured_control_plane_passes(monkeypatch):
    r = _cfg_check(monkeypatch, rloc_members_distribute=True,
                   domainid=1, multihomingid=0)
    assert r.status is CheckStatus.OK
    assert "Domain ID 1" in r.message


def test_locators_not_distributed_is_reported(monkeypatch):
    """Without it the CP does not advertise its site's locators to its peers,
    so an xTR registering here can be unknown to the rest of the fabric."""
    r = _cfg_check(monkeypatch, rloc_members_distribute=False,
                   domainid=1, multihomingid=0)
    assert r.status is CheckStatus.WARN
    assert "rloc members distribute" in r.message


def test_no_domain_id_is_reported(monkeypatch):
    """Publish and subscribe between map-servers is keyed on it."""
    r = _cfg_check(monkeypatch, rloc_members_distribute=True,
                   domainid=0, multihomingid=0)
    assert r.status is CheckStatus.WARN
    assert "domain ID" in r.message
    assert "Domain ID" not in r.message     # nothing to report


def test_both_faults_are_reported_in_one_run(monkeypatch):
    """Neither is fatal, so the reader gets both rather than the first."""
    r = _cfg_check(monkeypatch, rloc_members_distribute=None, domainid=0)
    assert r.status is CheckStatus.WARN
    assert "rloc members distribute" in r.message and "domain ID" in r.message


def test_a_rejected_registration_warns_rather_than_stopping_the_run(monkeypatch):
    """A site configuration that rejects this registration is a fabric fault.

    It returned FAIL, which stopped the AP run -- while the other control
    planes, and every check below, still had diagnostic value.
    """
    import checks.lisp_session as m

    monkeypatch.setattr(m, "_cp_device",
                        lambda ctx, h, c, mgmt=None: types.SimpleNamespace(
                            profiled_device=types.SimpleNamespace(hostname=h)))

    class Cfg:
        def __init__(self, _h): pass
        def __getattr__(self, _n):
            return lambda *a, **k: None
    monkeypatch.setattr("routingmodules.lisp.L2LISPControlPlane", Cfg)

    def reject(*a):
        raise SystemExit("site_uci is not defined")
    monkeypatch.setattr(
        "traffic_flows.lispsessiontroubleshooting.cp_configuration_validation",
        reject)

    ctx = types.SimpleNamespace(service=object(), payload={}, state={})
    r = m.LispControlPlaneConfiguration(_target(), "cp1").run_session(ctx)

    assert r.status is CheckStatus.WARN
    assert "site_uci" in r.message
