"""Trigger 3 — a control plane whose session from the CONTROLLER is down.

The controller is an xTR in its own right: it registers the AP's radio MAC
into the L2 instance, to the same control planes the edge registers the AP's
address to. A session down from the controller leaves the radio MAC
unregistered while every edge-side check passes, which is why none of the
edge-side triggers can see this fault.
"""

import types

from checks.base import CheckStatus
from checks.ap_wlc import ApWlcCpLispSessionTrigger


WLC = "wlc-jalejand-cisco-com"


def _ctx(**over):
    state = {
        "ap_wlc_cp_down": [("172.19.1.65", "Down")],
        "ap_wlc_radio_mac": "3891.b70f.2600",
        "ap_wlc_l2_vnid": "8188",
        "ap_wlc_mgmtip": "10.31.136.74",
        # The AP's RLOC (the edge's address) and the controller's WMI are
        # different addresses; the flow must trace from the WMI.
        "ap_wlc_rloc": "172.19.1.68",
        "ap_wlc_wmi": "10.31.136.74",
        "ap_wlc_cp_nodes": {"172.19.1.64": "wlccp-1", "172.19.1.65": "wlccp-2"},
        "catc_name": "mxc-dnac5",
        # The edge, which this flow must not read.
        "xtr_mgmtip": "10.31.136.126",
        "xtr_loopback": "172.19.1.68",
    }
    state.update(over)
    return types.SimpleNamespace(service=object(), payload={}, state=state)


def _run(ctx):
    return ApWlcCpLispSessionTrigger(WLC, "wlc").run_ap(ctx)


def test_a_down_control_plane_queues_the_flow_against_the_controller():
    r = _run(_ctx())
    assert r.status is CheckStatus.WARN
    assert "172.19.1.65" in r.message
    assert "3891.b70f.2600" in r.message
    # Three switch-side + thirteen per CP + one inter-CP + the verdict.
    assert len(r.data["queue_checks"]) == 3 + 13 + 1 + 1


def test_the_flow_reads_the_controller_not_the_edge():
    """Every xtr_* key names the edge. Carrying them into this flow would
    profile the edge and report its fabric under the controller's name."""
    r = _run(_ctx())
    t = r.data["queue_checks"][0].target
    assert t.xtr_mgmtip == "10.31.136.74"
    assert t.xtr_hostname == WLC
    assert t.eid == "3891.b70f.2600"
    assert t.iid == "8188"
    assert t.af == "ethernet"


def test_findings_land_on_the_control_plane_they_are_about():
    """Not all piled onto the controller's own node."""
    r = _run(_ctx())
    per_cp = [c for c in r.data["queue_checks"]
              if c.target_node_id == "wlccp-2"]
    assert len(per_cp) == 14          # thirteen plus the inter-CP check
    switch_side = [c for c in r.data["queue_checks"]
                   if c.target_node_id == "wlc"]
    assert len(switch_side) == 4      # the three plus the verdict


def test_the_node_is_known_before_the_check_runs():
    """check_started routes on target_node_id before run() is called, so a
    check that assigns it while running is announced on the wrong node."""
    for c in _run(_ctx()).data["queue_checks"]:
        assert c.target_node_id in ("wlc", "wlccp-1", "wlccp-2")


def test_every_session_up_skips():
    r = _run(_ctx(ap_wlc_cp_down=[]))
    assert r.status is CheckStatus.SKIP
    assert "queue_checks" not in (r.data or {})


def test_an_unknown_radio_mac_skips_rather_than_guessing():
    """The radio MAC is what the controller registers; without it there is
    no EID to trace and the flow would ask about the wrong address."""
    r = _run(_ctx(ap_wlc_radio_mac=""))
    assert r.status is CheckStatus.SKIP
    assert "radio MAC" in r.message


def test_a_missing_instance_or_address_skips():
    assert _run(_ctx(ap_wlc_l2_vnid=None)).status is CheckStatus.SKIP
    assert _run(_ctx(ap_wlc_mgmtip="")).status is CheckStatus.SKIP


# --------------------------------------------------------------------------
# The address the controller registers FROM.
# --------------------------------------------------------------------------


def test_the_flow_traces_from_the_wmi_not_the_aps_rloc():
    """`ap_wlc_rloc` is the AP's RLOC -- the edge's address -- read from
    `show ap name <ap> config general`. The controller registers the radio MAC
    from its wireless management interface instead.

    Passing the AP's RLOC as the controller's aimed routing, MTU, the TCP
    socket, the ACLs and TrustSec at the edge. Each answered plausibly for the
    wrong box, which is why it reads as a finding rather than an error.
    """
    from checks.ap_wlc import ApWlcCpLispSessionTrigger

    ctx = _ctx()
    ctx.state["ap_wlc_wmi"] = "10.31.136.74"
    ctx.state["ap_wlc_rloc"] = "172.19.1.68"        # the edge's
    r = ApWlcCpLispSessionTrigger("wlc", "wlc-1").run_ap(ctx)

    target = r.data["queue_checks"][0].target
    assert target.xtr_loopback == "10.31.136.74"
    assert target.xtr_loopback != ctx.state["ap_wlc_rloc"]


def test_an_ambiguous_management_interface_skips_rather_than_guessing():
    """`wmi_ip` returns None with zero or several interfaces, mirroring
    lispsessiontroubleshooting.py:1839. Every check below traces from that
    address, so a guess misdirects all of them silently."""
    from checks.ap_wlc import ApWlcCpLispSessionTrigger

    ctx = _ctx()
    ctx.state["ap_wlc_wmi"] = None
    r = ApWlcCpLispSessionTrigger("wlc", "wlc-1").run_ap(ctx)

    assert r.status is CheckStatus.SKIP
    assert "management interface" in r.message
