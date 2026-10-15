"""Context the edge carries that is deliberately NOT graded.

The user settled both halves on 2026-10-14: `show switch` is "just to
collect", and `show logging` is "collect only, no grading" -- flapping is a
time-series question for the dedicated flapping module, not for a
point-in-time check guessing a threshold from one buffer.

So the load-bearing property of this check is a negative one: it must never
WARN on content, however bad the content looks. Both samples are verbatim
from Edge2, pulled 2026-10-14.
"""

from checks.base import CheckStatus
from checks.ap_radio_registration import ApEdgeCollection

SWITCH = {
    "switch": {
        "mac_address": "6c71.0d40.6b80",
        "mac_persistency_wait_time": "indefinite",
        "stack": {"1": {"role": "active", "state": "ready",
                        "mac_address": "6c71.0d40.6b80",
                        "priority": "15", "hw_ver": "V02"}},
    }
}

LOG = """show logging
Syslog logging: enabled (0 messages dropped, 2 messages rate-limited)
000080: *Oct 14 07:46:40.030: %LINEPROTO-5-UPDOWN: Line protocol on Interface LISP0, changed state to down
000104: *Oct 14 07:46:42.859: %LINEPROTO-5-UPDOWN: Line protocol on Interface LISP0, changed state to up
000162: *Oct 14 07:46:49.456: %ILPOWER-5-DETECT: Interface Te1/0/14: Power Device detected: IEEE PD
000483: Oct 14 16:53:15.351: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: dna] [Source: 10.25.131.16]
000487: Oct 14 16:54:23.055: %LINEPROTO-5-UPDOWN: Line protocol on Interface AccessTunnel0, changed state to up
"""


class _Ctx:
    def __init__(self):
        self.service = object()
        self.state = {"xtr_hostname": "Edge2"}


def _run(log=LOG, switch=SWITCH, raise_log=False, raise_switch=False):
    import radkit_cli
    chk, ctx = ApEdgeCollection(), _Ctx()
    ra, rg = (radkit_cli.get_any_single_output,
              radkit_cli.get_single_output_genie)

    def _any(*a, **k):
        if raise_log:
            raise RuntimeError("device unreachable")
        return log

    def _genie(*a, **k):
        if raise_switch:
            raise RuntimeError("no parser")
        return switch

    radkit_cli.get_any_single_output = _any
    radkit_cli.get_single_output_genie = _genie
    try:
        return chk.run(ctx), ctx
    finally:
        radkit_cli.get_any_single_output = ra
        radkit_cli.get_single_output_genie = rg


def test_the_stack_is_reported():
    r, _ = _run()
    assert r.status is CheckStatus.OK
    assert r.data["stack"]["1"]["role"] == "active"
    assert r.data["stack_mac"] == "6c71.0d40.6b80"
    assert "1: active, ready, priority 15, H/W V02" in r.message


def test_ap_relevant_log_lines_are_kept_and_logins_are_not():
    """The buffer is mostly SSH logins. Keeping those would bury the lines
    that bear on the AP."""
    r, _ = _run()
    kept = "\n".join(r.data["log"])
    assert "AccessTunnel0" in kept
    assert "ILPOWER" in kept          # the AP's access port powering up
    assert "LISP0" in kept
    assert "SEC_LOGIN" not in kept
    assert r.data["log_matches"] == 4


def test_a_broken_stack_member_is_reported_but_not_graded():
    """The load-bearing negative. A member in Version Mismatch is exactly
    what a grading check would WARN on; the user asked for collection, so
    this must stay OK."""
    bad = {"switch": {"mac_address": "6c71.0d40.6b80", "stack": {
        "1": {"role": "active", "state": "ready", "priority": "15",
              "hw_ver": "V02"},
        "2": {"role": "member", "state": "version mismatch", "priority": "1",
              "hw_ver": "V02"}}}}
    r, _ = _run(switch=bad)
    assert r.status is CheckStatus.OK
    assert "version mismatch" in r.message
    assert "⚠" not in r.message


def test_a_flapping_tunnel_is_reported_but_not_graded():
    """Six state changes is a flap by any reading, and this check still must
    not WARN -- flapping belongs to the flapping module."""
    flaps = LOG + "".join(
        f"0005{i:02d}: Oct 14 17:0{i}:11.000: %LINEPROTO-5-UPDOWN: Line "
        f"protocol on Interface AccessTunnel0, changed state to "
        f"{'down' if i % 2 else 'up'}\n" for i in range(6))
    r, _ = _run(log=flaps)
    assert r.status is CheckStatus.OK
    assert "⚠" not in r.message
    assert r.data["log_matches"] == 10


def test_the_kept_log_is_capped_at_the_most_recent_lines():
    """The buffer runs to hundreds of lines; the report wants the recent
    ones. The cap keeps the TAIL, not the head -- the oldest lines are the
    least useful."""
    many = "".join(
        f"0006{i:03d}: Oct 14 18:00:00.000: %LINEPROTO-5-UPDOWN: Line "
        f"protocol on Interface AccessTunnel0, change {i}\n"
        for i in range(100))
    r, _ = _run(log=many)
    assert r.data["log_matches"] == 100
    assert len(r.data["log"]) == ApEdgeCollection._LOG_KEEP
    assert "change 99" in r.data["log"][-1]
    assert "change 0 " not in "\n".join(r.data["log"])


def test_an_unreadable_log_does_not_fail_the_check():
    """Collection only. A device that will not answer is not a finding and
    must not stop the run."""
    r, _ = _run(raise_log=True)
    assert r.status is CheckStatus.OK
    assert r.data["log"] == []
    assert "nothing AP-relevant" in r.message


def test_an_unreadable_stack_does_not_fail_the_check():
    r, _ = _run(raise_switch=True)
    assert r.status is CheckStatus.OK
    assert "not reported by this device" in r.message


def test_it_never_warns_whatever_it_finds():
    """The property the user asked for, asserted directly rather than only
    through the cases above."""
    for kw in ({}, {"raise_log": True}, {"raise_switch": True},
               {"log": "", "switch": {}}):
        r, _ = _run(**kw)
        assert r.status is CheckStatus.OK, kw


def test_it_is_queued_last_of_the_edge_side_reads():
    """Nothing downstream depends on it, and it is the slowest read."""
    import inspect
    import checks.ap_wlc as m
    src = inspect.getsource(m)
    assert src.index("ApAccessTunnelIdb()") < src.index("ApEdgeCollection()")
