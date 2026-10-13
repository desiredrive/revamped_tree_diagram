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
    return types.SimpleNamespace(
        service=object(), payload={},
        state={"lisp_session_states": states} if states is not None else {})


def test_every_session_down_stops_the_flow():
    """Rule: both down at the end of the tshoot session, stop the flow."""
    ctx = _ctx({"172.19.1.64": "Down", "172.19.1.65": "Down"})
    r = LispSessionVerdict(_target()).run_session(ctx)
    assert r.status is CheckStatus.FAIL
    assert ctx.state[STOP_KEY]
    assert "172.19.1.64" in r.message and "172.19.1.65" in r.message


def test_one_session_up_continues():
    """A registration can still leave through the session that is up, so the
    checks below have something real to measure."""
    ctx = _ctx({"172.19.1.64": "Up", "172.19.1.65": "Down"})
    r = LispSessionVerdict(_target()).run_session(ctx)
    assert r.status is CheckStatus.WARN
    assert not ctx.state.get(STOP_KEY)
    assert "172.19.1.65" in r.message


def test_all_up_passes():
    ctx = _ctx({"172.19.1.64": "Up", "172.19.1.65": "Up"})
    r = LispSessionVerdict(_target()).run_session(ctx)
    assert r.status is CheckStatus.OK
    assert not ctx.state.get(STOP_KEY)


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
        assert not ctx.state.get(STOP_KEY)


def test_unknown_state_counts_as_not_up():
    """A session whose state could not be read is not evidence of health."""
    ctx = _ctx({"172.19.1.64": "unknown", "172.19.1.65": "Init"})
    r = LispSessionVerdict(_target()).run_session(ctx)
    assert r.status is CheckStatus.FAIL
    assert ctx.state[STOP_KEY]


def test_the_stop_makes_later_session_checks_skip():
    """_SessionCheck honours the stop key, so the flow below reports one
    cause rather than failing repeatedly for it."""
    from checks.lisp_session import LispGlobalSession

    ctx = _ctx({"172.19.1.64": "Down", "172.19.1.65": "Down"})
    LispSessionVerdict(_target()).run_session(ctx)
    later = LispGlobalSession(_target()).run(ctx)
    assert later.status is CheckStatus.SKIP
