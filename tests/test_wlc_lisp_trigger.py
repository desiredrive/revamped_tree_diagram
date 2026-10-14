"""Trigger 3 — a control plane whose session from the CONTROLLER is down.

The controller is an xTR in its own right: it registers the AP's radio MAC
into the L2 instance, to the same control planes the edge registers the AP's
address to. A session down from the controller leaves the radio MAC
unregistered while every edge-side check passes, which is why none of the
edge-side triggers can see this fault.

`fabricEnabledWirelessSession` is the flow that answers it, decomposed per
control plane by `checks.wlc_cp_session` so each finding renders on the
control plane it is about. An earlier attempt pointed the EDGE flow at the
controller instead, which failed on the first two readers it reached -- MAC
learning against a radio MAC that is never in a MAC table, then
`show run | section service ethernet`, which a C9800 does not answer.
"""

import types

import pytest

from checks.base import CheckStatus
from checks.ap_wlc import ApWlcCpLispSessionTrigger


WLC = "wlc-jalejand-cisco-com"


def _info():
    """A collected controller: one WMI, an INFRA_VN L2 instance."""
    return types.SimpleNamespace(
        hostname=WLC,
        wmi_information={"interfaces": [{"ipaddress": "10.31.136.74"}]},
        fabric_state={"fabric_vnid_mapping": {"l2_vnid": {
            "8188": {"name": "172_19_5_0-INFRA_VN"}}}},
    )


def _ctx(info=None, **over):
    state = {
        "ap_wlc_cp_down": [("172.19.1.65", "Down")],
        "ap_wlc_radio_mac": "3891.b70f.2600",
        "ap_cp_name": "default-control-plane",
        "catc_name": "mxc-dnac5",
        "fabric_id": "fab-1",
        "ap_wlc_collected": {WLC: _info() if info is None else info},
        "ap_wlc_cp_planes": [("172.19.1.64", "172.19.1.64", "172.19.1.64"),
                             ("172.19.1.65", "172.19.1.65", "172.19.1.65")],
        "ap_wlc_cp_nodes": {"172.19.1.64": "wlccp-1",
                            "172.19.1.65": "wlccp-2"},
    }
    state.update(over)
    return types.SimpleNamespace(service=object(), payload={}, state=state)


def _run(ctx):
    return ApWlcCpLispSessionTrigger(WLC, "wlc").run_ap(ctx)


def test_a_down_control_plane_queues_the_per_cp_flow():
    r = _run(_ctx())
    assert r.status is CheckStatus.WARN
    assert "172.19.1.65" in r.message
    assert "3891.b70f.2600" in r.message
    # Seven checks per control plane, plus one inter-CP check each.
    assert len(r.data["queue_checks"]) == 7 * 2 + 2


def test_every_finding_lands_on_the_control_plane_it_is_about():
    """The whole point of decomposing the legacy flow. Wrapped, it renders as
    one check on the controller and every per-control-plane finding goes to
    the collection logfile instead of the canvas."""
    checks = _run(_ctx()).data["queue_checks"]
    nodes = {c.target_node_id for c in checks}
    assert nodes == {"wlccp-1", "wlccp-2"}
    assert "wlc" not in nodes


def test_the_reused_control_plane_checks_are_keyed_by_address():
    """`show wireless fabric summary` names control planes by address and the
    canvas nodes follow it, while `node_for` looks up by hostname. Keyed one
    way only, the five reused checks fall back to the controller's node."""
    from checks.lisp_session import LispControlPlaneConfiguration

    for c in _run(_ctx()).data["queue_checks"]:
        if isinstance(c, LispControlPlaneConfiguration):
            assert c.target_node_id.startswith("wlccp-")


def test_the_flow_registers_from_the_wireless_management_interface():
    """The WMI is the source RLOC: the controller registers the radio MAC
    from it, and it is the socket every per-control-plane check measures."""
    from checks.wlc_cp_session import WlcLocatorSet

    for c in _run(_ctx()).data["queue_checks"]:
        if isinstance(c, WlcLocatorSet):
            assert c.wmi == "10.31.136.74"
            return
    pytest.fail("no locator-set check was queued")


def test_the_instance_is_the_infra_vn_l2_vnid():
    """An AP onboards in the INFRA_VN. The legacy flow takes the instance from
    a client's fabric attributes; an AP has none, so it comes from the
    controller's own VNID mapping."""
    ctx = _ctx()
    _run(ctx)
    assert ctx.state["wlc_cp_vnid"] == "8188"


def test_the_locator_set_is_checked_before_the_session_state():
    """A locator-set or passive-open fault explains a down session with
    nothing wrong on the controller, so it has to be read first."""
    from checks.wlc_cp_session import WlcCpSessionState, WlcLocatorSet

    names = [type(c).__name__ for c in _run(_ctx()).data["queue_checks"]]
    assert names.index(WlcLocatorSet.__name__) < \
        names.index(WlcCpSessionState.__name__)


def test_an_ambiguous_management_interface_skips_rather_than_guessing():
    """`wmi_ip` returns None with zero or several interfaces. Every check
    below measures from that address, so a guess misdirects all of them
    silently."""
    info = _info()
    info.wmi_information = {"interfaces": []}
    r = _run(_ctx(info=info))
    assert r.status is CheckStatus.SKIP
    assert "management interface" in r.message


def test_no_infra_vn_instance_skips():
    info = _info()
    info.fabric_state = {"fabric_vnid_mapping": {"l2_vnid": {}}}
    r = _run(_ctx(info=info))
    assert r.status is CheckStatus.SKIP
    assert "INFRA_VN" in r.message


def test_no_resolved_control_plane_skips():
    r = _run(_ctx(ap_wlc_cp_planes=[]))
    assert r.status is CheckStatus.SKIP


def test_every_control_plane_up_skips():
    r = _run(_ctx(ap_wlc_cp_down=[]))
    assert r.status is CheckStatus.SKIP


def test_an_unknown_radio_mac_skips():
    r = _run(_ctx(ap_wlc_radio_mac=""))
    assert r.status is CheckStatus.SKIP
    assert "radio MAC" in r.message


def test_uncollected_controller_skips():
    r = _run(_ctx(ap_wlc_collected={}))
    assert r.status is CheckStatus.SKIP


def test_the_node_is_known_before_the_check_runs():
    """The runner routes check_started before run(), so a check that only
    assigns its node while running is announced against the previous default
    and renders on the wrong node until it finishes."""
    assert ApWlcCpLispSessionTrigger(WLC, "wlc-1").target_node_id == "wlc-1"
