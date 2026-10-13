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
