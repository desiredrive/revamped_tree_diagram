"""The AP's WLC database entry read on the fabric edge.

Every other check in `ap_radio_registration` asks a CONTROL PLANE what it
holds. This one asks the edge what it was told to build -- the edge's half of
the registration, and what the access tunnel is built from.

The fixtures are Edge2's real output, captured 2026-10-14.
"""
import pytest

from checks.base import CheckStatus
from checks.ap_radio_registration import (
    ApFabricEdgeWlcDatabase, _uptime_seconds, WLC_DB_FLAP_SECONDS)

LIVE = """
WLC clients/access-points information for LISP 0 EID-table Vlan 2045 (IID 8188)

Hardware Address: 3891.b70f.2600
Type:             AP
Sources:          1
Tunnel Update:    Signalled
Source MS:        172.19.1.64
RLOC:             172.19.1.68
Up time:          06:53:34
Metadata length:  34
Metadata (hex):   00 01 00 22  00 01 00 0C  AC 13 05 0A  00 00 10 01
                  00 02 00 06  00 00 00 03  00 0C 00 00  00 00 00 00
                  00 00
Metadata:         IPv4 address: 172.19.5.10
                  Client SGT: 0
                  Client association time: 0
"""

NOT_FOUND = """
WLC clients/access-points information for LISP 0 EID-table Vlan 2045 (IID 8188)
"""


class _Ctx:
    def __init__(self, **state):
        self.service = object()
        self.state = {
            "xtr_hostname": "Edge2",
            "ap_wlc_l2_vnid": 8188,
            "ap_wlc_radio_mac": "3891.b70f.2600",
            "ap_wlc_cp_planes": [{"hostname": "Border1"},
                                 {"hostname": "Border2"}],
        }
        self.state.update(state)


def _run(raw, **state):
    """Drive the check with `raw` standing in for the device's reply."""
    import routingmodules.lisp as lisp_mod
    chk = ApFabricEdgeWlcDatabase()
    ctx = _Ctx(**state)

    real = lisp_mod.get_any_single_output
    lisp_mod.get_any_single_output = lambda *a, **k: raw
    try:
        return chk.run(ctx), ctx
    finally:
        lisp_mod.get_any_single_output = real


def test_the_healthy_entry_passes():
    """Edge2's real output: Signalled, Type AP, up nearly seven hours."""
    r, ctx = _run(LIVE)
    assert r.status is CheckStatus.OK
    assert r.data["tunnel_signalled"] is True
    assert r.data["type"] == "AP"
    assert r.data["source_ms"] == "172.19.1.64"
    assert r.data["rloc"] == "172.19.1.68"
    assert r.data["up_time"] == "06:53:34"
    assert not r.data.get("possible_flap")


def test_not_signalled_warns_and_says_the_tunnel_checks_still_run():
    """The user's rule: if not signalled, warn -- and the access-tunnel
    verifications are still done."""
    r, _ = _run(LIVE.replace("Tunnel Update:    Signalled",
                             "Tunnel Update:    Not Signalled"))
    assert r.status is CheckStatus.WARN
    assert r.data["tunnel_signalled"] is False
    assert "access-tunnel" in r.message


def test_a_young_entry_is_flagged_as_a_possible_flap():
    """Under three minutes. The entry is rebuilt on every re-signal, so a
    short uptime on an AP that did not just join means it is flapping."""
    r, _ = _run(LIVE.replace("Up time:          06:53:34",
                             "Up time:          00:01:12"))
    assert r.status is CheckStatus.WARN
    assert r.data["possible_flap"] is True
    assert "flap" in r.message.lower()


def test_the_threshold_is_three_minutes():
    """Just over the line is not a flap; just under it is."""
    over, _ = _run(LIVE.replace("06:53:34", "00:03:01"))
    under, _ = _run(LIVE.replace("06:53:34", "00:02:59"))
    assert not over.data.get("possible_flap")
    assert under.data["possible_flap"] is True
    assert WLC_DB_FLAP_SECONDS == 180


def test_a_missing_entry_warns_and_names_the_session_to_check():
    """The user's rule: if not found at all, trigger the LISP session
    troubleshoot between the edge and the Source MS. The Source MS is a
    field OF the entry, so with no entry the AP's own control planes are
    flagged instead."""
    r, ctx = _run(NOT_FOUND)
    assert r.status is CheckStatus.WARN
    assert r.data["found"] is False
    assert ctx.state["ap_edge_wlc_db_missing"] is True
    assert ctx.state["ap_edge_wlc_session_suspect"] == ["Border1", "Border2"]
    assert "LISP session" in r.message


def test_the_source_ms_is_recorded_for_the_session_flow():
    """When the entry IS there, the Source MS names exactly which control
    plane signalled it -- better than guessing from the discovered set."""
    _, ctx = _run(LIVE)
    assert ctx.state["ap_edge_wlc_source_ms"] == "172.19.1.64"


def test_it_is_queued_after_the_control_planes_and_before_the_session_flow():
    """Order is the point: the control-plane records are what told the edge
    to build this entry, and an absent entry is a reason to walk the session
    flow. Queued between the two."""
    import inspect
    import checks.ap_wlc as m

    src = inspect.getsource(m)
    assert "ApFabricEdgeWlcDatabase()" in src, "the check is never queued"
    assert (src.index("ApRadioMacRegistrationTrigger(hostname, node)")
            < src.index("ApFabricEdgeWlcDatabase()")
            < src.index("ApWlcCpLispSessionTrigger(hostname, node)"))


# --------------------------------------------------------------------------
# The trigger. A missing edge entry is a third reason to walk the edge's LISP
# session flow, alongside a missing registration and a down session -- and
# unlike those, it names no single control plane, so BOTH are walked.
# --------------------------------------------------------------------------


def test_a_missing_edge_entry_is_a_reason_to_walk_the_session_flow():
    """Without this the trigger skips: no registration is missing and no
    session is down, yet the edge was never told about the AP."""
    import inspect
    import checks.ap_onboarding as m

    src = inspect.getsource(m.ApLispSessionTrigger.run_ap)
    assert 'ctx.state.get("ap_edge_wlc_db_missing")' in src
    i = src.index("if not missing and not down")
    gate = src[i:i + 120]
    assert "edge_entry_missing" in gate, (
        "the skip gate does not consider the missing edge entry, so the "
        "flow is skipped in exactly the case this trigger was added for")


def test_both_control_planes_are_walked_not_just_a_flagged_one():
    """The user's rule: if not found, trigger the LISP tshoot flow against
    BOTH CPs. The edge was signalled by none of them, so the fault is not
    attributable to one."""
    import inspect
    import checks.ap_onboarding as m

    src = inspect.getsource(m.ApLispSessionTrigger.run_ap)
    assert "if edge_entry_missing:" in src
    i = src.index("if edge_entry_missing:")
    block = src[i:i + 400]
    assert "for host in suspects:" in block
    assert "already" in block, (
        "a control plane already queued for a missing registration would be "
        "walked twice")
