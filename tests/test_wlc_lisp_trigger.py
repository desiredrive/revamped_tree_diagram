"""Trigger 3 — a control plane whose session from the CONTROLLER is down.

The controller is an xTR in its own right: it registers the AP's radio MAC
into the L2 instance, to the same control planes the edge registers the AP's
address to. A session down from the controller leaves the radio MAC
unregistered while every edge-side check passes, which is why none of the
edge-side triggers can see this fault.

The flow that answers it is `fabricEnabledWirelessSession`, not the edge's.
It already existed: it takes the WMI as the source RLOC, the map-servers and
their keys from `show wireless fabric summary`, and the instance from the
controller's own VNID mapping. An earlier attempt pointed the EDGE flow at the
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
    }
    state.update(over)
    return types.SimpleNamespace(service=object(), payload={}, state=state)


def _run(ctx, monkeypatch, **kw):
    """Run the trigger with the legacy flow stubbed."""
    seen = {}

    def flow(wlcinfo, fabric_id, step, catc, endpoint, service):
        seen["wlcinfo"] = wlcinfo
        seen["endpoint"] = endpoint
        seen["catc"] = catc
        if "raises" in kw:
            raise kw["raises"]
        return 9, kw.get("cps", [{"ip": "172.19.1.65", "status": "Down"}]), []

    monkeypatch.setattr(
        "traffic_flows.lispsessiontroubleshooting.fabricEnabledWirelessSession",
        flow)
    return ApWlcCpLispSessionTrigger(WLC, "wlc").run_ap(ctx), seen


def test_a_down_control_plane_runs_the_controllers_own_session_flow(monkeypatch):
    r, seen = _run(_ctx(), monkeypatch)
    assert r.status is CheckStatus.WARN
    assert "172.19.1.65" in r.message
    assert "3891.b70f.2600" in r.message
    assert seen["endpoint"].mac == "3891.b70f.2600"


def test_the_flow_registers_from_the_wireless_management_interface(monkeypatch):
    """The WMI is the source RLOC: the controller registers the radio MAC from
    it, and it is the socket every per-control-plane check measures."""
    _r, seen = _run(_ctx(), monkeypatch)
    assert seen["endpoint"].endpointinfo["fabric"]["rloc"] == "10.31.136.74"


def test_the_instance_is_the_infra_vn_l2_vnid(monkeypatch):
    """An AP onboards in the INFRA_VN. The legacy flow takes the instance from
    a client's fabric attributes; an AP has none, so it comes from the
    controller's own VNID mapping."""
    _r, seen = _run(_ctx(), monkeypatch)
    assert seen["endpoint"].endpointinfo["fabric"]["vnid"] == "8188"


def test_an_ambiguous_management_interface_skips_rather_than_guessing(monkeypatch):
    """`wmi_ip` returns None with zero or several interfaces. Every check
    below measures from that address, so a guess misdirects all of them
    silently."""
    info = _info()
    info.wmi_information = {"interfaces": []}
    r, _seen = _run(_ctx(info=info), monkeypatch)
    assert r.status is CheckStatus.SKIP
    assert "management interface" in r.message


def test_no_infra_vn_instance_skips(monkeypatch):
    info = _info()
    info.fabric_state = {"fabric_vnid_mapping": {"l2_vnid": {}}}
    r, _seen = _run(_ctx(info=info), monkeypatch)
    assert r.status is CheckStatus.SKIP
    assert "INFRA_VN" in r.message


def test_every_control_plane_up_skips(monkeypatch):
    r, _seen = _run(_ctx(ap_wlc_cp_down=[]), monkeypatch)
    assert r.status is CheckStatus.SKIP


def test_an_unknown_radio_mac_skips(monkeypatch):
    r, _seen = _run(_ctx(ap_wlc_radio_mac=""), monkeypatch)
    assert r.status is CheckStatus.SKIP
    assert "radio MAC" in r.message


def test_a_fatal_finding_warns_rather_than_stopping_the_run(monkeypatch):
    """The legacy flow calls sys.exit on its own findings. Those are
    statements about the fabric, and the manifest's rule is that a fabric
    fault warns -- a FAIL would skip every remaining AP validation."""
    r, _seen = _run(_ctx(), monkeypatch,
                    raises=SystemExit("Error: LISP Sessions - All Down"))
    assert r.status is CheckStatus.WARN
    assert "All Down" in r.message


def test_an_unreadable_controller_warns(monkeypatch):
    r, _seen = _run(_ctx(), monkeypatch, raises=RuntimeError("unreachable"))
    assert r.status is CheckStatus.WARN
    assert "RuntimeError" in r.message


def test_uncollected_controller_skips(monkeypatch):
    r, _seen = _run(_ctx(ap_wlc_collected={}), monkeypatch)
    assert r.status is CheckStatus.SKIP


def test_the_node_is_known_before_the_check_runs():
    """The runner routes check_started before run(), so a check that only
    assigns its node while running is announced against the previous default
    and renders on the wrong node until it finishes."""
    assert ApWlcCpLispSessionTrigger(WLC, "wlc-1").target_node_id == "wlc-1"
