"""AP Onboarding — Fabric Enabled Wireless.

Traces a fabric-enabled access point onto the wireless fabric: the switchport it
lands on, the address it needs, the CAPWAP join, and the access tunnel that
carries its clients.

Two things about this flow differ from the others:

  * It is gated on the XTR being an **Edge node**. An AP onboards through a
    fabric edge; pointed at a border or a control plane, none of the downstream
    verification means anything, so everything after the gate skips rather than
    reporting misleading results. See `ApEdgeGate` and `_ApCheck`.

  * It distinguishes **platform-independent** (PI) from **platform-dependent**
    (PD) verification. `show mac address-table` is PI -- it says what IOS
    believes. `show platform software fed ... matm macTable` is PD: what the
    hardware was actually programmed with. The two disagree exactly when the
    interesting bugs happen.

PD-eligible objects found along the way are recorded (see `pd_objects`) and
verified in a later pass, once the PI picture is complete.
"""

from checks.base import Check, CheckResult, CheckStatus, RunContext


# Objects whose hardware programming can be verified separately from what IOS
# reports. Collected during the PI pass, verified in the PD pass.
PD_ELIGIBLE = (
    "mac_address",
    "adjacency",
    "route",
    "fib_entry",
    "interface_programming",
    "cts_sgacl_entry",
    "acl_entry",
    "qos_entry",
    "copp_drops",
)


def record_pd_object(ctx: RunContext, kind: str, **attrs) -> None:
    """Queue a PD-eligible object for hardware verification later.

    Called during the PI pass. Deferred rather than verified inline because a PD
    lookup needs identifiers the PI pass discovers (an interface's IF-ID, a
    MAC's VLAN), and because hardware state is worth reading once the software
    picture is settled -- not midway through it.
    """
    if kind not in PD_ELIGIBLE:
        raise ValueError(f"{kind!r} is not a PD-eligible object type")
    ctx.state.setdefault("pd_objects", []).append(dict(kind=kind, **attrs))


class _ApCheck(Check):
    """Base for every AP-onboarding check after the gate.

    An AP onboards through a fabric edge. On any other role the downstream
    verification is not merely inapplicable -- it would be misleading -- so each
    check skips instead. Subclasses implement `run_ap`.
    """

    def run(self, ctx: RunContext) -> CheckResult:
        if not ctx.state.get("edge"):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the XTR is not an Edge node (see XTR Role Classification).",
            )
        return self.run_ap(ctx)

    def run_ap(self, ctx: RunContext) -> CheckResult:
        raise NotImplementedError


class ApEdgeGate(Check):
    """Stop the flow unless the XTR is an Edge node.

    Reads the `edge` flag XtrRoleClassification set. Everything downstream
    subclasses _ApCheck and skips when this fails, so a wrong device produces
    one clear error rather than a wall of unrelated failures.

    Extended-node APs are not covered yet: they onboard through an extended
    node whose upstream is a fabric edge, so the guidance is to run this against
    that edge.
    """

    name = "Edge Node Gate"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if ctx.state.get("edge"):
            return CheckResult(
                CheckStatus.OK,
                "XTR is an Edge node — AP onboarding checks apply.",
            )

        if not ctx.state.get("xtr_is_fabric"):
            return CheckResult(
                CheckStatus.FAIL,
                "This device is not a fabric member, so it cannot be the edge an "
                "AP onboards through. Re-run against the fabric edge the AP is "
                "cabled to.",
            )

        roles = ctx.state.get("xtr_roles") or []
        found = ", ".join(roles) if roles else "no roles reported"
        return CheckResult(
            CheckStatus.FAIL,
            f"AP onboarding requires an Edge node; this device is: {found}. "
            "All further checks are skipped. If the AP is behind an extended "
            "node, that flow is not available yet — re-run against the fabric "
            "edge upstream of it.",
        )
