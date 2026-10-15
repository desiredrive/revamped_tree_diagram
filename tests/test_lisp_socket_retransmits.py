"""The retransmit threshold on the control plane's LISP socket.

A long-lived TCP session accumulates a few retransmissions in normal
operation. Warning on any non-zero counter made a healthy Border1 socket --
1 retransmission on two of its three sockets -- report that Map-Registers
were being lost, on every run.

The grading block is exercised directly rather than through `run_session`,
which would need the whole CP/ETR profiling chain stubbed to reach it.
"""

import types

from checks.lisp_session import RETRANSMIT_WARN_THRESHOLD


def _grade(sockets):
    """The counter block of LispTcpSocket.run_session, as it runs there."""
    problems, counts = [], []
    for s in sockets:
        local = f"{s.local_host}:{s.local_port}"
        foreign = f"{s.foreign_host}:{s.foreign_port}"
        for attr, label in (
                ("retransmitqueue", "segments waiting in the retransmit queue"),
                ("retransmitcounter", "retransmissions"),
                ("fastretransmitcounter", "fast retransmissions")):
            try:
                n = int(getattr(s, attr, 0) or 0)
            except (TypeError, ValueError):
                n = 0
            if n > RETRANSMIT_WARN_THRESHOLD:
                problems.append(f"{n} {label} on {local} → {foreign}")
            elif n:
                counts.append(f"{n} {label} on {local} → {foreign}")
    return problems, counts


def _sock(retransmitcounter=0, retransmitqueue=0, fastretransmitcounter=0):
    return types.SimpleNamespace(
        local_host="172.19.1.64", local_port=4342,
        foreign_host="10.31.136.74", foreign_port=58161, mss=536,
        retransmitcounter=retransmitcounter,
        retransmitqueue=retransmitqueue,
        fastretransmitcounter=fastretransmitcounter)


def test_the_threshold_is_fifty():
    """Set deliberately: below this, retransmissions are normal."""
    assert RETRANSMIT_WARN_THRESHOLD == 50


def test_a_single_retransmission_is_not_a_finding():
    """The live Border1 socket this threshold exists for. It was warning that
    Map-Registers were being lost on a session that was entirely healthy."""
    problems, counts = _grade([_sock(retransmitcounter=1)])
    assert problems == []
    assert len(counts) == 1 and counts[0].startswith("1 retransmissions")


def test_exactly_the_threshold_is_not_a_finding():
    """`> threshold`, not `>=`: 50 is still under 'more than 50'."""
    problems, _c = _grade([_sock(retransmitcounter=RETRANSMIT_WARN_THRESHOLD)])
    assert problems == []


def test_more_than_the_threshold_is_a_finding():
    problems, counts = _grade(
        [_sock(retransmitcounter=RETRANSMIT_WARN_THRESHOLD + 1)])
    assert len(problems) == 1 and "51 retransmissions" in problems[0]
    assert counts == []


def test_a_clean_socket_reports_nothing_either_way():
    assert _grade([_sock()]) == ([], [])


def test_sub_threshold_counts_are_still_reported_as_context():
    """Not silently dropped: the counters are real, they are just not a
    fault. A check that hid them would be discarding device data."""
    _p, counts = _grade([_sock(retransmitcounter=3, fastretransmitcounter=2)])
    assert len(counts) == 2


def test_each_counter_is_graded_against_the_threshold_separately():
    """Three counters, one threshold each -- a large queue is a finding even
    when the retransmit counter is quiet."""
    problems, counts = _grade(
        [_sock(retransmitqueue=200, retransmitcounter=1)])
    assert len(problems) == 1 and "200 segments" in problems[0]
    assert len(counts) == 1
