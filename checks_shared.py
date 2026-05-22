"""Shared helpers used by every checks_* module.

Kept tiny on purpose: just the two utilities that bridge the legacy
sys.exit-based helpers to structured CheckResults, and the SimpleNamespace
shim that lets legacy traffic_flows functions see ctx.state as if it were
the old edge_node_device object.
"""

from types import SimpleNamespace

from checks import CheckResult, CheckStatus, RunContext


def _legacy_fail(e: BaseException, prefix: str) -> CheckResult:
    """Format a legacy-helper failure for the UI.

    The CLI helpers call exit_program() which raises SystemExit with a
    user-friendly "Error: X | Y" string. For those, we show only that string.
    For genuinely unexpected exceptions we include the traceback.
    """
    if isinstance(e, SystemExit):
        return CheckResult(CheckStatus.FAIL, str(e) or f"{prefix} (SystemExit)")
    import traceback
    return CheckResult(
        CheckStatus.FAIL,
        f"{prefix} raised {type(e).__name__}: {e}\n\n"
        f"Traceback:\n{traceback.format_exc()}",
    )


def _build_edge_shim(ctx: RunContext):
    """Compose a SimpleNamespace mirroring the legacy edge_node_device.

    Legacy functions reach into edge_node_device.profiled_device.{hostname,
    mgmtip, dnac, fabric_id, fabric_site_hierarchy, ispubsub, loopback,
    isfabric, edge, l2handoff, iborder} and edge_node_device.{hostname,
    mac, vlan, mac_learning_info, loopback, localsgt, is_infravn, is_ap,
    dhcpparameters_info, lispparameters_info, sisfparameters_info}.
    """
    profiled = SimpleNamespace(
        hostname=ctx.state.get("xtr_hostname"),
        mgmtip=ctx.payload.get("mgmt_ip"),
        dnac=ctx.state.get("catc_name"),
        fabric_id=ctx.state.get("fabric_id"),
        fabric_site_hierarchy=ctx.state.get("fabric_site_hierarchy"),
        ispubsub=ctx.state.get("is_pubsub"),
        loopback=ctx.state.get("xtr_loopback"),
        isfabric=ctx.state.get("xtr_is_fabric"),
        edge=ctx.state.get("edge"),
        l2handoff=ctx.state.get("l2handoff"),
        iborder=ctx.state.get("iborder"),
    )
    return SimpleNamespace(
        profiled_device=profiled,
        hostname=ctx.state.get("xtr_hostname"),
        mac=ctx.payload.get("mac"),
        vlan=ctx.payload.get("vlan"),
        port=ctx.state.get("xtr_port"),
        mac_learning_info=ctx.state.get("mac_learning_info"),
        loopback=ctx.state.get("xtr_loopback"),
        localsgt=ctx.state.get("localsgt"),
        is_infravn=ctx.state.get("is_infravn"),
        is_ap=ctx.state.get("is_ap"),
        dhcpparameters_info=ctx.state.get("dhcpparameters_info"),
        lispparameters_info=ctx.state.get("lispparameters_info"),
        sisfparameters_info=ctx.state.get("sisfparameters_info"),
    )
