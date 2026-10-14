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


def test_a_peer_outside_the_aps_control_planes_is_named_not_walked(monkeypatch):
    """A fabric edge peers with map-servers this AP never registers to.

    A down session to one of those explains nothing about why THIS EID is
    unregistered, and walking it spends a full per-control-plane pass on a
    device the question does not involve. It is reported so the reading is
    not silently dropped, and the flow does not run for it.
    """
    from checks.ap_onboarding import ApLispSessionTrigger

    monkeypatch.setattr(
        ApLispSessionTrigger, "_down_sessions",
        staticmethod(lambda ctx: [("10.9.9.9", "Init")]))
    ctx = _ctx()
    r = ApLispSessionTrigger().run_ap(ctx)
    assert r.status is CheckStatus.SKIP
    assert "10.9.9.9" in r.message
    assert "not walked" in r.message
    assert "queue_checks" not in (r.data or {})


def test_a_down_peer_that_is_an_aps_control_plane_is_walked(monkeypatch):
    """The other side of the same rule: a CP discovery resolved is walked."""
    from checks.ap_onboarding import ApLispSessionTrigger

    ctx = _ctx()
    rloc = next(iter((ctx.state.get("ap_cp_rlocs") or {}).values()))
    monkeypatch.setattr(
        ApLispSessionTrigger, "_down_sessions",
        staticmethod(lambda ctx: [(rloc, "Down")]))
    r = ApLispSessionTrigger().run_ap(ctx)
    assert r.status is CheckStatus.WARN
    assert r.data["queue_checks"]


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


# --------------------------------------------------------------------------
# Consistency: the trigger that decides whether to run the flow and the check
# that reports session state inside it must read the same fact the same way.
# --------------------------------------------------------------------------


class _Etr:
    """An ETR with the attribute surface the session reader walks."""

    def __init__(self, peers, loopback="172.19.1.68"):
        self.global_lisp_sessions = types.SimpleNamespace(peers=peers)
        self.profiled_device = types.SimpleNamespace(loopback=loopback)


def test_the_trigger_and_the_flow_read_session_state_identically():
    """Duplicated logic in the two places drifts, and the drift is silent:
    the flow runs saying every session is down and then reports them up, or
    declines to run on state it would have called a fault."""
    from checks.lisp_session import peer_session_states

    etr = _Etr({"172.19.1.64": [{"state": "Up"}],
                "172.19.1.65": [{"state": "Down"}]})
    up, down = peer_session_states(etr)
    assert up == [("172.19.1.64", "Up")]
    assert down == [("172.19.1.65", "Down")]


def test_state_is_compared_case_insensitively():
    """LispGlobalSession compared `state == "Up"` exactly while the trigger
    lowercased. A state of "up" counted as down in one and up in the other."""
    from checks.lisp_session import peer_session_states

    up, down = peer_session_states(_Etr({"172.19.1.64": [{"state": "up"}],
                                         "172.19.1.65": [{"state": " Up "}]}))
    assert len(up) == 2 and not down


def test_the_switches_own_rloc_is_not_a_peer():
    from checks.lisp_session import peer_session_states

    etr = _Etr({"172.19.1.68": [{"state": "Down"}],
                "172.19.1.64": [{"state": "Up"}]})
    up, down = peer_session_states(etr)
    assert up == [("172.19.1.64", "Up")]
    assert not down


def test_an_unreadable_row_counts_as_not_up():
    """An unreadable session is not evidence of a healthy one."""
    from checks.lisp_session import peer_session_states

    for rows in ([], [{}], None, "nonsense"):
        up, down = peer_session_states(_Etr({"172.19.1.64": rows}))
        assert not up
        assert down == [("172.19.1.64", "unknown")]


def test_an_etr_with_no_sessions_reads_empty():
    from checks.lisp_session import peer_session_states

    assert peer_session_states(_Etr({})) == ([], [])
    assert peer_session_states(types.SimpleNamespace()) == ([], [])
