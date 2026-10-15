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
        # What ApWlcControlPlanes grades and publishes -- the trigger's
        # input. It was `ap_wlc_cp_down` (from ApWlcFabricControlPlane) until
        # that check was found to return early on several faults, leaving the
        # key unwritten and this flow skipping with "every session is up"
        # while the controller had every session down.
        "ap_wlc_control_planes": {WLC: {
            "local": [{"ip_address": "172.19.1.64", "status": "Up"},
                      {"ip_address": "172.19.1.65", "status": "Down"}],
            "multisite": []}},
        "ap_wlc_radio_mac": "3891.b70f.2600",
        "ap_cp_name": "default-control-plane",
        "catc_name": "mxc-dnac5",
        "fabric_id": "fab-1",
        "ap_wlc_collected": {WLC: _info() if info is None else info},
        # (RLOC, hostname, management IP), resolved against the control
        # planes the edge discovered -- the three are genuinely different.
        "ap_wlc_cp_planes": [("172.19.1.64", "cp1", "10.31.136.64"),
                             ("172.19.1.65", "cp2", "10.31.136.65")],
        "ap_wlc_cp_nodes": {"172.19.1.64": "apcp-1", "cp1": "apcp-1",
                            "172.19.1.65": "apcp-2", "cp2": "apcp-2"},
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
    # Nine per control plane, plus one inter-CP check each. The last three
    # of the nine are the control-plane-side path checks -- the CP's own
    # session to the map-server, and the ACL and SGT policy it applies
    # towards the WMI. The controller sits outside the fabric, so its LISP
    # traffic crosses a border; without them a policy blocking registrations
    # there was invisible while every other check on the CP passed.
    assert len(r.data["queue_checks"]) == 9 * 2 + 2


def test_every_finding_lands_on_the_control_plane_it_is_about():
    """The whole point of decomposing the legacy flow. Wrapped, it renders as
    one check on the controller and every per-control-plane finding goes to
    the collection logfile instead of the canvas."""
    checks = _run(_ctx()).data["queue_checks"]
    nodes = {c.target_node_id for c in checks}
    assert nodes == {"apcp-1", "apcp-2"}
    assert "wlc" not in nodes


def test_the_reused_control_plane_checks_land_on_the_edges_nodes():
    """The control planes are the ones `ApCpDiscovery` already drew, so the
    findings join that node rather than a second one for the same device.

    `show wireless fabric summary` names control planes by RLOC while
    `node_for` looks up by hostname, so both key the same node.
    """
    from checks.lisp_session import LispControlPlaneConfiguration

    seen = 0
    for c in _run(_ctx()).data["queue_checks"]:
        if isinstance(c, LispControlPlaneConfiguration):
            assert c.target_node_id.startswith("apcp-")
            seen += 1
    assert seen == 2


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
    r = _run(_ctx(ap_wlc_control_planes={WLC: {
        "local": [{"ip_address": "172.19.1.64", "status": "Up"},
                  {"ip_address": "172.19.1.65", "status": "Up"}],
        "multisite": []}}))
    assert r.status is CheckStatus.SKIP


def test_a_down_multisite_control_plane_does_not_trigger_the_flow():
    """Only site-local sessions decide, as in ApWlcControlPlanes' grading.

    A Multi-Site control plane serves a remote site, so its session being
    down is not what keeps THIS AP from registering -- triggering on it
    would walk a flow with nothing to find.
    """
    r = _run(_ctx(ap_wlc_control_planes={WLC: {
        "local": [{"ip_address": "172.19.1.64", "status": "Up"}],
        "multisite": [{"ip_address": "172.19.1.100", "status": "Down"}]}}))
    assert r.status is CheckStatus.SKIP


def test_no_graded_control_planes_skips_without_claiming_they_are_up():
    """An ungraded controller is unknown, not healthy."""
    r = _run(_ctx(ap_wlc_control_planes={}))
    assert r.status is CheckStatus.SKIP
    assert "no site control plane was graded" in r.message.lower()


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


# --------------------------------------------------------------------------
# Resolving the control planes. `show wireless fabric summary` names them by
# RLOC and nothing else; `ApCpDiscovery` already resolved the same devices to
# hostname, RLOC and management IP, and drew a node for each.
# --------------------------------------------------------------------------


def _fabric_ctx(**over):
    """State as it stands when ApWlcFabricControlPlane runs: the edge's CP
    discovery has published its three maps."""
    state = {
        "ap_cp_targets": {"apcp-1": "cp1", "apcp-2": "cp2"},
        "ap_cp_rlocs": {"cp1": "172.19.1.64", "cp2": "172.19.1.65"},
        "ap_cp_mgmts": {"cp1": "10.31.136.64", "cp2": "10.31.136.65"},
    }
    state.update(over)
    return types.SimpleNamespace(service=object(), payload={}, state=state)


def _resolve(ctx, addresses):
    """The resolution block of ApWlcFabricControlPlane, as it runs there."""
    cp_rlocs = ctx.state.get("ap_cp_rlocs") or {}
    cp_mgmts = ctx.state.get("ap_cp_mgmts") or {}
    cp_targets = ctx.state.get("ap_cp_targets") or {}
    by_rloc = {rloc: host for host, rloc in cp_rlocs.items()}
    node_by_host = {host: nid for nid, host in cp_targets.items()}

    cp_nodes, planes_out, unmatched = {}, [], []
    for addr in addresses:
        host = by_rloc.get(addr)
        if not host:
            unmatched.append(addr)
            continue
        node_id = node_by_host.get(host)
        if node_id:
            cp_nodes[addr] = node_id
            cp_nodes[host] = node_id
        planes_out.append((addr, host, cp_mgmts.get(host) or host))
    return cp_nodes, planes_out, unmatched


def test_the_management_ip_is_never_the_rloc():
    """The fault this fixes. Profiling goes through Catalyst Center by
    management address; no device is managed at the RLOC, so filling the
    triple from the summary killed every per-CP check with "Error Retrieving
    Device Details from Catalyst Center API"."""
    _n, planes, _u = _resolve(_fabric_ctx(), ["172.19.1.64", "172.19.1.65"])
    assert planes == [("172.19.1.64", "cp1", "10.31.136.64"),
                      ("172.19.1.65", "cp2", "10.31.136.65")]
    for rloc, _host, mgmt in planes:
        assert mgmt != rloc


def test_the_edges_nodes_are_reused_rather_than_new_ones_minted():
    """Two nodes for one device splits its findings across the canvas."""
    nodes, _p, _u = _resolve(_fabric_ctx(), ["172.19.1.64", "172.19.1.65"])
    assert set(nodes.values()) == {"apcp-1", "apcp-2"}
    assert not any(n.startswith("wlccp-") for n in nodes.values())


def test_nodes_are_keyed_by_both_rloc_and_hostname():
    """The summary names CPs by RLOC; `node_for` looks them up by hostname."""
    nodes, _p, _u = _resolve(_fabric_ctx(), ["172.19.1.64"])
    assert nodes["172.19.1.64"] == nodes["cp1"] == "apcp-1"


def test_a_control_plane_the_edge_never_saw_is_reported_not_guessed():
    """A different site, or an SDA transit CP. It has no profiled device and
    no node, so inventing a triple for it only reproduces the original
    fault further down."""
    nodes, planes, unmatched = _resolve(
        _fabric_ctx(), ["172.19.1.64", "172.19.1.99"])
    assert unmatched == ["172.19.1.99"]
    assert [p[0] for p in planes] == ["172.19.1.64"]
    assert "172.19.1.99" not in nodes


def _edges(cp_nodes, planes):
    """The edge block of ApWlcFabricControlPlane, as it runs there."""
    return [
        {"source": "wlc", "target": nid, "label": "LISP Session"}
        for nid in (cp_nodes.get(p["ip_address"]) for p in planes)
        if nid]


def test_the_controller_is_linked_to_the_control_planes_it_registers_to():
    """The controller is an xTR in its own right and peers with the same
    control planes the edge does. Without the link its per-control-plane
    findings land on nodes the edge drew for the EDGE's sessions, with
    nothing on the canvas saying the controller peers with them too."""
    nodes, _p, _u = _resolve(_fabric_ctx(), ["172.19.1.64", "172.19.1.65"])
    edges = _edges(nodes, [{"ip_address": "172.19.1.64", "status": "Up"},
                           {"ip_address": "172.19.1.65", "status": "Down"}])
    assert [(e["source"], e["target"]) for e in edges] == [
        ("wlc", "apcp-1"), ("wlc", "apcp-2")]
    # Labelled as the edge's own control-plane links are, so the same
    # relationship reads the same way on the canvas.
    assert {e["label"] for e in edges} == {"LISP Session"}


def test_no_link_is_drawn_to_a_control_plane_with_no_node():
    """An unmatched control plane -- a different site, or an SDA transit CP --
    has no node to draw to. It is named in the message instead."""
    nodes, _p, _u = _resolve(_fabric_ctx(), ["172.19.1.64", "172.19.1.99"])
    edges = _edges(nodes, [{"ip_address": "172.19.1.64", "status": "Up"},
                           {"ip_address": "172.19.1.99", "status": "Up"}])
    assert len(edges) == 1
    assert edges[0]["target"] == "apcp-1"


# --------------------------------------------------------------------------
# A missing registration is the second reason to walk this flow. It does not
# need a session to be down -- a radio MAC absent from every control plane
# while every session is UP is exactly the fault only this flow explains, and
# the verdict that finds it sets `ap_stop`, which would otherwise skip it.
# --------------------------------------------------------------------------


def _all_up():
    return {WLC: {"local": [{"ip_address": "172.19.1.64", "status": "Up"},
                            {"ip_address": "172.19.1.65", "status": "Up"}],
                  "multisite": []}}


def test_a_missing_registration_runs_the_flow_though_every_session_is_up():
    r = _run(_ctx(ap_wlc_control_planes=_all_up(),
                  ap_radio_reg={"cp1": False, "cp2": False}))
    assert r.status is not CheckStatus.SKIP


def test_sessions_up_and_registration_present_still_skips():
    """The flow must not run when there is nothing to explain."""
    r = _run(_ctx(ap_wlc_control_planes=_all_up(),
                  ap_radio_reg={"cp1": True, "cp2": True}))
    assert r.status is CheckStatus.SKIP


def test_the_flow_is_not_suppressed_by_ap_stop():
    """`ap_stop` is set by the verdict that queues this flow.

    Honouring it would suppress the explanation for the fault that raised
    it, which is why this check overrides _ApCheck.run.
    """
    ctx = _ctx(ap_wlc_control_planes=_all_up(),
               ap_radio_reg={"cp1": False, "cp2": False},
               ap_stop="radio MAC registered on no control plane")
    from checks.ap_wlc import ApWlcCpLispSessionTrigger
    r = ApWlcCpLispSessionTrigger(WLC, "wlc").run(ctx)
    assert r.status is not CheckStatus.SKIP


# --------------------------------------------------------------------------
# Resolution happens where the flow is QUEUED, not only where it used to.
#
# The live fault: `ApWlcControlPlanes` was moved ahead of
# `ApWlcFabricControlPlane` so a down session triggers the flow straight away.
# But only the fabric check resolved the (RLOC, hostname, management IP)
# triples, so on every-session-down -- the one run this flow exists for -- the
# trigger it queued skipped with "no control plane was resolved", and the run
# went straight on to radio MAC registration having walked nothing.
# --------------------------------------------------------------------------


def _unresolved_ctx():
    """The live state: three control planes down, the EDGE's discovery maps
    published, but no WLC triples yet."""
    ctx = _ctx(ap_wlc_control_planes={WLC: {
        "local": [{"ip_address": "172.19.1.64", "status": "Down"},
                  {"ip_address": "172.19.1.65", "status": "Down"}],
        "multisite": [{"ip_address": "172.19.1.100", "status": "Down"}]}})
    for key in ("ap_wlc_cp_planes", "ap_wlc_cp_nodes"):
        ctx.state.pop(key, None)
    ctx.state.update({
        "ap_cp_rlocs": {"cp1": "172.19.1.64", "cp2": "172.19.1.65"},
        "ap_cp_mgmts": {"cp1": "10.31.136.64", "cp2": "10.31.136.65"},
        "ap_cp_targets": {"apcp-1": "cp1", "apcp-2": "cp2"},
    })
    return ctx


def test_without_resolution_the_flow_skips():
    """Characterises the fault, so the fix below is shown to be what moves
    it rather than something else in the fixture."""
    r = _run(_unresolved_ctx())
    assert r.status is CheckStatus.SKIP
    assert "no control plane was resolved" in r.message


def test_resolving_the_control_planes_lets_the_whole_flow_run():
    """Nine checks per control plane plus one inter-CP check each."""
    from checks.ap_wlc import resolve_wlc_control_planes

    ctx = _unresolved_ctx()
    graded = ctx.state["ap_wlc_control_planes"][WLC]
    resolve_wlc_control_planes(
        ctx, graded["local"] + graded["multisite"], "wlc")

    r = _run(ctx)
    assert r.status is CheckStatus.WARN
    assert len(r.data["queue_checks"]) == 9 * 2 + 2


def test_the_management_ip_is_resolved_not_taken_from_the_summary():
    """The original fault this resolution exists for: no device is managed at
    the RLOC, so a triple filled from the summary kills every per-CP check
    with "Error Retrieving Device Details from Catalyst Center API"."""
    from checks.ap_wlc import resolve_wlc_control_planes

    ctx = _unresolved_ctx()
    graded = ctx.state["ap_wlc_control_planes"][WLC]
    _n, planes, _u = resolve_wlc_control_planes(
        ctx, graded["local"] + graded["multisite"], "wlc")
    assert planes == [("172.19.1.64", "cp1", "10.31.136.64"),
                      ("172.19.1.65", "cp2", "10.31.136.65")]


def test_a_multisite_control_plane_the_edge_never_saw_is_not_invented():
    """172.19.1.100 serves a remote site: no profiled device, no node. It is
    reported as unmatched rather than given a guessed triple."""
    from checks.ap_wlc import resolve_wlc_control_planes

    ctx = _unresolved_ctx()
    graded = ctx.state["ap_wlc_control_planes"][WLC]
    _n, planes, unmatched = resolve_wlc_control_planes(
        ctx, graded["local"] + graded["multisite"], "wlc")
    assert unmatched == ["172.19.1.100"]
    assert "172.19.1.100" not in [p[0] for p in planes]


def test_the_check_that_queues_the_flow_also_resolves_the_planes():
    """Order-independence, stated as a rule: whichever check queues the flow
    must publish what the flow reads, or the two can be reordered apart
    again."""
    import inspect
    from checks.ap_wlc import ApWlcControlPlanes

    src = inspect.getsource(ApWlcControlPlanes.run_ap)
    assert "resolve_wlc_control_planes(" in src, (
        "ApWlcControlPlanes queues the session flow but does not resolve the "
        "control planes it needs, so the flow skips when it is reached first")
    assert src.index("resolve_wlc_control_planes(") < \
        src.index("ApWlcCpLispSessionTrigger"), \
        "the planes must be resolved before the trigger is queued"
