"""When the LISP session flow runs.

The session tshoot is a shared subroutine with several entry points, not
something the registration check owns. These tests pin which conditions
start it, because the failure mode is silent: a wrong gate means the flow
never runs and the canvas simply shows nothing where the explanation
should be.
"""

import types

import pytest

from checks.base import CheckStatus


def _ctx(**overrides):
    state = {
        "ap_ip": "172.19.5.10",
        "ap_l3_iid": 4097,
        "xtr_hostname": "Edge2",
        "xtr_mgmtip": "10.31.136.126",
        "catc_name": "catc",
        "ap_cp_targets": {"apcp-1": "cp1", "apcp-2": "cp2"},
        "ap_cp_rlocs": {"cp1": "172.19.1.64", "cp2": "172.19.1.65"},
        "ap_cp_mgmts": {"cp1": "172.19.1.64", "cp2": "172.19.1.65"},
    }
    state.update(overrides)
    return types.SimpleNamespace(service=object(), payload={}, state=state)


@pytest.fixture
def no_sessions_down(monkeypatch):
    from checks.ap_onboarding import ApLispSessionTrigger
    monkeypatch.setattr(ApLispSessionTrigger, "_down_sessions",
                        staticmethod(lambda ctx: []))


@pytest.fixture
def both_sessions_down(monkeypatch):
    from checks.ap_onboarding import ApLispSessionTrigger
    monkeypatch.setattr(
        ApLispSessionTrigger, "_down_sessions",
        staticmethod(lambda ctx: [("172.19.1.64", "Down"),
                                  ("172.19.1.65", "Down")]))


def test_trigger_2_registration_missing_runs_the_flow(no_sessions_down):
    """The original trigger: a CP holds no record for the AP's address."""
    from checks.ap_onboarding import ApLispSessionTrigger

    ctx = _ctx(ap_cp_reg_missing=["cp1"])
    r = ApLispSessionTrigger().run_ap(ctx)
    assert r.status is CheckStatus.WARN
    assert r.data["queue_checks"]
    assert "does not hold a registration" in r.message


def test_trigger_1_session_down_runs_the_flow_with_the_record_still_held(
        both_sessions_down):
    """The gap this closes.

    A registration can stay cached on a control plane whose session has since
    gone down. Gating only on the record going missing leaves that fault
    unexamined until it does -- which may be long after the session broke.
    """
    from checks.ap_onboarding import ApLispSessionTrigger

    ctx = _ctx()                      # nothing missing
    r = ApLispSessionTrigger().run_ap(ctx)
    assert r.status is CheckStatus.WARN
    assert r.data["queue_checks"]
    assert "is not up" in r.message
    assert "still held" in r.message


def test_a_down_session_supplies_its_own_map_servers(both_sessions_down):
    """`pairs` is built from the missing registrations. With none missing it
    would be empty and the per-CP checks would never be built -- the flow
    would run and explain nothing."""
    from checks.ap_onboarding import ApLispSessionTrigger

    ctx = _ctx()
    r = ApLispSessionTrigger().run_ap(ctx)
    names = [type(c).__name__ for c in r.data["queue_checks"]]
    assert names.count("LispPerMapServerSession") == 2


def test_down_peers_are_walked_by_their_rloc(both_sessions_down):
    """The session names its peer by RLOC, which is the address the
    per-map-server command needs."""
    from checks.ap_onboarding import ApLispSessionTrigger

    ctx = _ctx()
    r = ApLispSessionTrigger().run_ap(ctx)
    servers = {getattr(c, "map_server", None) for c in r.data["queue_checks"]}
    assert "172.19.1.64" in servers and "172.19.1.65" in servers


def test_an_unaccounted_peer_is_still_walked(monkeypatch):
    """A session down to something the fabric does not list is itself worth
    the flow -- it must not be silently dropped."""
    from checks.ap_onboarding import ApLispSessionTrigger

    monkeypatch.setattr(
        ApLispSessionTrigger, "_down_sessions",
        staticmethod(lambda ctx: [("10.9.9.9", "Init")]))
    ctx = _ctx()
    r = ApLispSessionTrigger().run_ap(ctx)
    assert r.status is CheckStatus.WARN
    assert "10.9.9.9" in r.message


def test_everything_healthy_skips(no_sessions_down):
    from checks.ap_onboarding import ApLispSessionTrigger

    ctx = _ctx()
    r = ApLispSessionTrigger().run_ap(ctx)
    assert r.status is CheckStatus.SKIP
    assert "every LISP session is up" in r.message


def test_registration_missing_takes_precedence_in_the_message(
        both_sessions_down):
    """Both conditions at once: the missing record is the more specific
    finding, and the session state is reported by the flow itself."""
    from checks.ap_onboarding import ApLispSessionTrigger

    ctx = _ctx(ap_cp_reg_missing=["cp1"])
    r = ApLispSessionTrigger().run_ap(ctx)
    assert "does not hold a registration" in r.message
    # Only the CP actually missing the record is walked, as before.
    names = [type(c).__name__ for c in r.data["queue_checks"]]
    assert names.count("LispPerMapServerSession") == 1


def test_an_unreadable_session_state_does_not_invent_a_fault(monkeypatch):
    """Reporting sessions as down because they could not be read would be a
    false finding. The registration side of the trigger still stands."""
    from checks.ap_onboarding import ApLispSessionTrigger

    def boom(ctx):
        raise RuntimeError("device unreachable")

    # _down_sessions swallows its own errors; this asserts that contract.
    monkeypatch.setattr("checks.lisp_session._profile_xtr",
                        lambda ctx, t: (_ for _ in ()).throw(boom_error()))
    ctx = _ctx()
    r = ApLispSessionTrigger().run_ap(ctx)
    assert r.status is CheckStatus.SKIP


def boom_error():
    return RuntimeError("device unreachable")
