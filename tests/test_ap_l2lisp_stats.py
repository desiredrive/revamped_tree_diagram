"""`show l2lisp statistics` read for the AP rather than for a client.

`WirelessL2LispStats` already reads this command and this check reuses its
module and parser. The difference is which half of the output is graded: that
check looks only at error counters and is gated on the wireless CLIENT flow,
so it never runs in an AP chain. Here `Add AP` -- the WLC notification landing
on the edge -- is the point.

Fixture is Edge2's real output, captured 2026-10-14.
"""
from checks.base import CheckStatus
from checks.ap_radio_registration import ApL2LispStatistics
from routingmodules.lisp import parse_show_l2lisp_statistics

LIVE = """Control messages::
==================
WLC notify          Received             Succeeded
----------          --------             ---------
Add AP              1                    1
Add client          0                    0
Delete AP           0                    0
Delete client       0                    0

Errors::
========
Add AP: empty metadata = 0
Add AP: add to access tunnel hash failed = 0
Update AP: idb NOT found = 0
Delete AP: AP mac not found = 0
Update client rbm failed = 0

Reconciliation statistics::
==================
Marked dirty        Cleaned              Deleted
----------          --------             ---------
0                0                    0
Dirty client count in hash = 0

Total client count in hash = 0
Incomplete client count in hash = 0
"""


class _Ctx:
    def __init__(self):
        self.service = object()
        self.state = {"xtr_hostname": "Edge2"}


def _run(raw):
    import routingmodules.lisp as lisp_mod
    chk, ctx = ApL2LispStatistics(), _Ctx()
    real = lisp_mod.get_any_single_output
    lisp_mod.get_any_single_output = lambda *a, **k: raw
    try:
        return chk.run(ctx), ctx
    finally:
        lisp_mod.get_any_single_output = real


def test_the_healthy_edge_passes():
    """Edge2 live: one Add AP received, one succeeded, no error counters."""
    r, _ = _run(LIVE)
    assert r.status is CheckStatus.OK
    assert r.data["add_ap_received"] == 1
    assert r.data["add_ap_succeeded"] == 1
    assert "Add AP: 1 received, 1 succeeded" in r.message


def test_a_shortfall_is_the_finding_this_check_exists_for():
    """Told about an AP and could not act on it -- distinct from never
    having been told, which is a different fault."""
    r, _ = _run(LIVE.replace("Add AP              1                    1",
                             "Add AP              5                    2"))
    assert r.status is CheckStatus.WARN
    assert r.data["add_ap_shortfall"] == 3
    assert "did not complete the operation" in r.message


def test_never_notified_is_reported_differently_from_a_shortfall():
    """Zero received is not a failure of the edge: the controller never told
    it. Reported, but not as the edge's fault."""
    r, _ = _run(LIVE.replace("Add AP              1                    1",
                             "Add AP              0                    0"))
    assert r.data.get("add_ap_never_notified") is True
    assert "add_ap_shortfall" not in r.data
    assert "has not told" in r.message


def test_non_zero_error_counters_warn():
    r, _ = _run(LIVE.replace("Add AP: empty metadata = 0",
                             "Add AP: empty metadata = 4"))
    assert r.status is CheckStatus.WARN
    assert r.data["errors"]["Add AP: empty metadata"] == 4


def test_the_noisy_counters_stay_excluded():
    """Carried over from WirelessL2LispStats, which excludes these two for
    the same reason: they are non-zero on a healthy fabric."""
    r, _ = _run(LIVE.replace("Update client rbm failed = 0",
                             "Update client rbm failed = 9"))
    assert r.status is CheckStatus.OK
    assert r.data["errors"] == {}


def test_it_reuses_the_existing_parser():
    """The module and parser already existed; only the grading is new."""
    p = parse_show_l2lisp_statistics(LIVE)
    assert p["control_messages"]["Add AP"] == {"received": 1, "succeeded": 1}


def test_it_is_queued_after_the_access_tunnel_checks():
    """`Add AP` received-but-not-succeeded is what explains a tunnel that
    was asked for and never appeared, so it follows the tunnel checks."""
    import inspect
    import checks.ap_wlc as m
    src = inspect.getsource(m)
    assert "ApL2LispStatistics()" in src, "the check is never queued"
    assert src.index("ApAccessTunnelStatistics()") < src.index("ApL2LispStatistics()")


# --------------------------------------------------------------------------
# The user's explicit rules for this command (2026-10-14): Add AP and
# Delete AP must each have received == succeeded, every AP error counter must
# be zero, and the metadata toggle is reported but never graded.
# --------------------------------------------------------------------------


def test_delete_ap_must_match_too():
    """Received != succeeded on the teardown half leaves state behind on the
    edge -- a tunnel or hash entry for an AP the controller already let go."""
    r, _ = _run(LIVE.replace("Delete AP           0                    0",
                             "Delete AP           4                    1"))
    assert r.status is CheckStatus.WARN
    assert r.data["delete_ap_mismatch"] is True
    assert "Delete AP: 4 received but 1 succeeded" in r.message


def test_more_succeeded_than_received_is_also_a_mismatch():
    """The rule the user gave is equality, not `received > succeeded`. The
    inverse cannot happen on a healthy box, so it is a finding either way."""
    r, _ = _run(LIVE.replace("Add AP              1                    1",
                             "Add AP              1                    3"))
    assert r.status is CheckStatus.WARN
    assert "1 received but 3 succeeded" in r.message


def test_a_nonzero_ap_error_counter_warns():
    r, _ = _run(LIVE.replace("Update AP: idb NOT found = 0",
                             "Update AP: idb NOT found = 2"))
    assert r.status is CheckStatus.WARN
    assert r.data["ap_errors"] == {"Update AP: idb NOT found": 2}
    assert "Non-zero AP error counters" in r.message


def test_ap_counters_are_separated_from_client_ones():
    """A non-zero client counter is context in an AP chain, not the finding,
    so the two are reported under different headings."""
    raw = LIVE.replace("Delete AP: AP mac not found = 0",
                       "Delete AP: AP mac not found = 1")
    raw = raw.replace("Dirty client count in hash = 0",
                      "Dirty client count in hash = 0")
    r, _ = _run(raw)
    assert set(r.data["ap_errors"]) == {"Delete AP: AP mac not found"}


def test_the_marker_does_not_match_a_word_that_merely_contains_ap():
    """`capwap` and `mapping` both contain `ap`. The split is on whole words
    with the device's trailing colon stripped, not on substring."""
    chk = ApL2LispStatistics()
    for label in ("Capwap tunnel failed", "Mapping lookup failed",
                  "Add client: idb NOT found"):
        assert not any(w.strip(":").lower() == chk._AP_MARKER
                       for w in label.split()), label
    for label in ("Add AP: empty metadata", "Delete AP mac from hash failed",
                  "Add AP"):
        assert any(w.strip(":").lower() == chk._AP_MARKER
                   for w in label.split()), label


def test_the_metadata_toggle_is_reported_but_never_graded():
    """The user settled this: it is a mode flag, not a fault. Zero must not
    turn an otherwise clean read into a finding."""
    # The device prints it under its own `Toggles` header; the
    # parser keys off that header, so the fixture carries it.
    raw = LIVE + "\nToggles\n==================\n"\
                 "Use AP info in WLC metadata: 0\n"
    r, _ = _run(raw)
    assert r.status is CheckStatus.OK
    assert r.data["use_ap_info_in_wlc_metadata"] == 0
    assert "Use AP info in WLC metadata: 0" in r.message
