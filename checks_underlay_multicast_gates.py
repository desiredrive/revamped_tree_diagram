"""Stage: PIM-global gating checks.

Two presence checks against the running-config that universally invalidate
SDA broadcast-underlay assumptions if either is configured. Applied to FHR,
LHR, and every discovered RP. Default RIB only — VRF scope is irrelevant
because broadcast-underlay always uses the global table for the underlay
group.

  * ``ip pim bidir-enable`` — BiDir alters RPF/DF/mroute semantics; our S,G
    walk and register-tunnel checks become invalid.
  * ``ip pim spt-threshold infinity`` — pins LHR to the shared tree forever;
    SPT walks won't find S,G state and we'd silently mis-diagnose.

Per-host state keys read at run-time (no hard-coded hostnames):
    FHR side: ``umcast_source_hostname``  / node id ``xtr``
    LHR side: ``umcast_dst_hostname``     / node id ``dxtr``
    RP idx N: ``umcast_rp{N}_hostname``   / node id ``umcast_rp{N}``
"""

from checks import Check, CheckResult, CheckStatus, RunContext
import radkit_cli


_BIDIR_PATTERN = "ip pim bidir-enable"
_SPT_INF_PATTERN = "ip pim spt-threshold infinity"
_BANNER_TOKENS = ("#", "show ")


def _grep_running_config(host: str, needle: str, service) -> list[str]:
    """Run ``show run | i <needle>`` and return matching config lines (banners
    and the echoed command stripped). Raises BaseException through to caller
    so the wrapper check can convert it to a FAIL CheckResult."""
    cmd = f"show run | i {needle}"
    op = radkit_cli.get_any_single_output(host, cmd, service)
    if not op:
        return []
    matches = []
    for line in op.splitlines():
        s = line.strip()
        if not s:
            continue
        if any(tok in s for tok in _BANNER_TOKENS):
            continue
        if needle in s:
            matches.append(s)
    return matches


def _wrap_fail(name: str, exc: BaseException) -> CheckResult:
    msg = str(exc) if str(exc) else exc.__class__.__name__
    return CheckResult(
        CheckStatus.FAIL,
        f"{name} raised {exc.__class__.__name__}: {msg}",
    )


class _PimGate(Check):
    """Base for a single-line config-presence gate against one device."""

    needle: str = ""
    failure_explainer: str = ""
    short_label: str = ""

    def __init__(
        self,
        host_state_key: str,
        target_node_id: str,
        role_label: str,
        device_state_key: str | None = None,
    ):
        self.host_state_key = host_state_key
        self.device_state_key = device_state_key
        self.target_node_id = target_node_id
        self.role_label = role_label
        self.name = f"Underlay Mcast ({role_label}): {self.short_label}"

    def _resolve_host(self, ctx: RunContext) -> str | None:
        """Prefer the radkit-known hostname from a profiled device object;
        fall back to the raw state value (which may be a mgmt IP).

        For UnderlayMulticastDevice the radkit-known hostname lives on
        ``.profiled_device.hostname`` — its top-level ``.hostname`` is what
        the caller passed in (often a mgmt IP). For plain ``Device`` objects
        the hostname IS at top level.
        """
        if self.device_state_key:
            dev = ctx.state.get(self.device_state_key)
            if dev is not None:
                profiled = getattr(dev, "profiled_device", None)
                host = getattr(profiled, "hostname", None) or getattr(dev, "hostname", None)
                if host:
                    return host
        return ctx.state.get(self.host_state_key)

    def run(self, ctx: RunContext) -> CheckResult:
        host = self._resolve_host(ctx)
        if not host:
            return CheckResult(
                CheckStatus.SKIP,
                f"Skipped: {self.role_label} hostname not in state.",
            )
        try:
            hits = _grep_running_config(host, self.needle, ctx.service)
        except BaseException as e:
            return _wrap_fail(self.name, e)
        if hits:
            return CheckResult(
                CheckStatus.FAIL,
                f"• Device: {host}\n"
                f"• Role: {self.role_label}\n"
                f"• Found in running-config:\n"
                + "\n".join(f"    {h}" for h in hits)
                + f"\n• {self.failure_explainer}",
            )
        return CheckResult(
            CheckStatus.OK,
            f"• Device: {host}\n"
            f"• Role: {self.role_label}\n"
            f"• `{self.needle}` not present in running-config (default RIB).",
        )


class UmcastBidirGate(_PimGate):
    needle = _BIDIR_PATTERN
    short_label = "PIM BiDir disabled"
    failure_explainer = (
        "PIM BiDir changes RPF / DF election / mroute semantics — there is no "
        "S,G state on shared-tree, no register process, and no SPT switchover. "
        "SDA broadcast-underlay assumes ASM with SPT; with BiDir enabled the "
        "downstream S,G / register / MSDP / SPT-walk checks are invalid. "
        "Remove `ip pim bidir-enable` from the global config."
    )


class UmcastSptInfinityGate(_PimGate):
    needle = _SPT_INF_PATTERN
    short_label = "PIM spt-threshold not infinity"
    failure_explainer = (
        "`ip pim spt-threshold infinity` pins LHRs to the shared tree forever "
        "and prevents SPT switchover for any group (or for the matched ACL). "
        "S,G state will not exist on the LHR and the SPT walk will report "
        "'shared-tree mode' as if it were normal. Remove the global "
        "spt-threshold infinity (or scope it tightly enough to exclude the "
        "broadcast-underlay group)."
    )


def build_pim_gates_for_side(side: str) -> list[Check]:
    """Two gates targeting the FHR (xtr) or LHR (dxtr) device."""
    if side == "fhr":
        return [
            UmcastBidirGate("umcast_source_hostname", "xtr", "FHR",
                            device_state_key="umcast_device"),
            UmcastSptInfinityGate("umcast_source_hostname", "xtr", "FHR",
                                  device_state_key="umcast_device"),
        ]
    if side == "lhr":
        return [
            UmcastBidirGate("umcast_dst_hostname", "dxtr", "LHR",
                            device_state_key="umcast_dst_device"),
            UmcastSptInfinityGate("umcast_dst_hostname", "dxtr", "LHR",
                                  device_state_key="umcast_dst_device"),
        ]
    return []


def build_pim_gates_for_rp(idx: int) -> list[Check]:
    """Two gates targeting RP{idx}; uses the per-RP state shape from
    [[checks_underlay_multicast_rp]] (`umcast_rp{idx}_hostname` already holds
    the radkit-known hostname). Node id is ``urp{idx}`` to match
    ``checks_underlay_multicast_rp._node_id`` — using a different id would
    drop the badges onto a non-existent node."""
    state_key = f"umcast_rp{idx}_hostname"
    node_id = f"urp{idx}"
    role = f"RP{idx}"
    return [
        UmcastBidirGate(state_key, node_id, role),
        UmcastSptInfinityGate(state_key, node_id, role),
    ]
