"""Item 1 — the LISP sessions carrying the AP's registration to its CPs.

The troubleshooter being wrapped was written for a wireless client. These
tests pin the two things that makes fragile: the EID has to be the radio MAC
rather than the Ethernet MAC the rest of the AP chain keys on, and the
endpoint object has to be built rather than collected, because the command
WirelessEndpointMac issues returns nothing for an AP.
"""

import types

import pytest

from checks.base import CheckStatus

WLC = "wlc-jalejand-cisco-com"
RADIO_MAC = "3891.b70f.2600"
ETHERNET_MAC = "b811.4b0e.2630"


class _Info:
    """Stands in for the WirelessControllerInfo ApWlcCollect builds."""

    hostname = WLC
    fabric_state = {
        "fabric_status": "Enabled",
        "control_plane": {"ip_address": {
            "172.19.1.64": {"name": "default-control-plane",
                            "key": "k", "status": "Up"},
            "172.19.1.65": {"name": "default-control-plane",
                            "key": "k", "status": "Up"},
        }},
        "fabric_vnid_mapping": {"l2_vnid": {8188: {"name": "172_19_5_0-INFRA_VN"}}},
    }
    wmi_information = {"interfaces": [{"ipaddress": "10.31.136.74"}]}


def _ctx(**overrides):
    state = {
        "ap_wlc_collected": {WLC: _Info()},
        "ap_wlc_radio_mac": RADIO_MAC,
        "ap_cp_name": "default-control-plane",
        "ap_cp_set": ["172.19.1.64", "172.19.1.65"],
        "ap_wlc_rloc": "172.19.1.68",
        "ap_infra_l2_vnid": 8188,
        "ap_wlc_fabric_status": {WLC: "Enabled"},
        "catc_name": "catc",
    }
    state.update(overrides)
    return types.SimpleNamespace(
        service=object(), payload={"mac": ETHERNET_MAC}, state=state)


@pytest.fixture
def stub(monkeypatch):
    """Capture what the troubleshooter is handed, and control what it returns."""
    import traffic_flows.lispsessiontroubleshooting as mod

    seen = {}

    def fake(wlcinfo, fabric_id, step, catc, endpoint, service):
        seen["wlcinfo"] = wlcinfo
        seen["endpoint"] = endpoint
        seen["catc"] = catc
        return (0, seen.get("planes", [
            {"ip": "172.19.1.64", "status": "Up"},
            {"ip": "172.19.1.65", "status": "Up"},
        ]), {"cp": "info"})

    monkeypatch.setattr(mod, "fabricEnabledWirelessSession", fake)
    return seen


def test_the_eid_is_the_radio_mac_not_the_ethernet_mac(stub):
    """The controller registers the radio MAC; the edge builds its access
    tunnel for that address. Passing the Ethernet MAC would query LISP for an
    EID that was never registered and report the AP missing from a control
    plane that holds it."""
    from checks.ap_wlc import ApWlcCpLispSession

    ApWlcCpLispSession(WLC, "wlc0").run_ap(_ctx())
    assert stub["endpoint"].mac == RADIO_MAC
    assert stub["endpoint"].mac != ETHERNET_MAC


def test_the_endpoint_carries_the_five_fabric_fields(stub):
    """FEWEIDIdentification reads exactly these out of endpointinfo."""
    from checks.ap_wlc import ApWlcCpLispSession

    ApWlcCpLispSession(WLC, "wlc0").run_ap(_ctx())
    fabric = stub["endpoint"].endpointinfo["fabric"]
    assert fabric["status"] == "Enabled"
    assert fabric["rloc"] == "172.19.1.68"
    assert fabric["vnid"] == 8188
    assert fabric["control_plane_name"] == "default-control-plane"
    assert fabric["sgt"] == 0


def test_the_vnid_is_the_l2_vnid(stub):
    """FEWEIDIdentification looks the VNID up in fabric_vnid_mapping.l2_vnid.

    Handing it the L3 VNID (4097) would resolve no name and describe the EID
    as belonging to an instance that is not the one it registers under.
    """
    from checks.ap_wlc import ApWlcCpLispSession

    ApWlcCpLispSession(WLC, "wlc0").run_ap(_ctx())
    vnid = stub["endpoint"].endpointinfo["fabric"]["vnid"]
    assert vnid == 8188
    assert vnid != 4097
    # And it must be a key of the map the module indexes with it.
    assert vnid in _Info.fabric_state["fabric_vnid_mapping"]["l2_vnid"]


def test_the_collected_controller_object_is_reused_not_rebuilt(stub):
    """fabric_state and wmi_information already exist on what ApWlcCollect
    stored; the module indexes straight into them."""
    from checks.ap_wlc import ApWlcCpLispSession

    ctx = _ctx()
    collected = ctx.state["ap_wlc_collected"][WLC]
    ApWlcCpLispSession(WLC, "wlc0").run_ap(ctx)
    assert stub["wlcinfo"] is collected
    assert stub["wlcinfo"].fabric_state["control_plane"]["ip_address"]
    assert stub["wlcinfo"].wmi_information["interfaces"]


def test_sessions_up_pass_and_publish(stub):
    from checks.ap_wlc import ApWlcCpLispSession

    ctx = _ctx()
    r = ApWlcCpLispSession(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.OK
    assert ctx.state["ap_cp_info"] == {"cp": "info"}
    assert len(ctx.state["ap_cp_sessions"]) == 2


def test_a_down_session_warns_and_continues(stub):
    """The manifest's rule, and the module's own behaviour: a down control
    plane is reported and the run goes on, because the other plane of the
    pair may still carry the registration."""
    from checks.ap_wlc import ApWlcCpLispSession

    stub["planes"] = [{"ip": "172.19.1.64", "status": "Up"},
                      {"ip": "172.19.1.65", "status": "Down"}]
    ctx = _ctx()
    r = ApWlcCpLispSession(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.WARN
    assert not ctx.state.get("ap_stop")
    assert "172.19.1.65" in r.message


def test_no_sessions_at_all_warns(stub):
    from checks.ap_wlc import ApWlcCpLispSession

    stub["planes"] = []
    r = ApWlcCpLispSession(WLC, "wlc0").run_ap(_ctx())
    assert r.status is CheckStatus.WARN
    assert "registers nowhere" in r.message


def test_a_raising_troubleshooter_warns_rather_than_killing_the_run(monkeypatch):
    """It is legacy code reached through a thin shim; a failure inside it is
    a tool problem, and the edge-side findings are still worth having."""
    import traffic_flows.lispsessiontroubleshooting as mod
    from checks.ap_wlc import ApWlcCpLispSession

    def boom(*a, **k):
        raise RuntimeError("legacy exploded")

    monkeypatch.setattr(mod, "fabricEnabledWirelessSession", boom)
    ctx = _ctx()
    r = ApWlcCpLispSession(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.WARN
    assert "legacy exploded" in r.message
    assert not ctx.state.get("ap_stop")


@pytest.mark.parametrize("missing", [
    "ap_wlc_radio_mac", "ap_cp_name", "catc_name"])
def test_missing_prerequisites_skip_rather_than_fail(stub, missing):
    """Each is established by an earlier check that reports its own absence.
    Failing again here would report one fault twice."""
    from checks.ap_wlc import ApWlcCpLispSession

    ctx = _ctx(**{missing: ""})
    r = ApWlcCpLispSession(WLC, "wlc0").run_ap(ctx)
    assert r.status is CheckStatus.SKIP


def test_an_ap_is_not_collected_as_a_client():
    """WirelessEndpointMac fills endpointinfo from `show wireless client
    mac-address <mac> detail`, which returns nothing for a radio MAC. The
    adapter must therefore build the object, never collect it."""
    from checks.ap_wlc import _ApEidAttributes

    e = _ApEidAttributes(WLC, RADIO_MAC, "Enabled", "172.19.1.68", 8188,
                         "default-control-plane")
    assert not hasattr(e, "endpoint_info")
    assert e.endpointinfo["fabric"]["vnid"] == 8188
