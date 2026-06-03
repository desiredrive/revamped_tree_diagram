"""Reusable Check objects shared across scenarios.

These are the first checks any flow needs: parameter validation, INFRA_VN
detection, XTR hostname resolution, and Fabric-Enabled Wireless redirect.
They contain no scenario-specific logic and are imported by every chain.
"""

from checks import Check, CheckResult, CheckStatus, RunContext


class ValidateVrfParam(Check):
    """Phase 1 / Check 1 — VRF parameter must be present and non-empty.

    Mirrors dhcp_troubleshooting.py:1881-1886, which exits the program when
    vrf is None. The form already enforces a value, but this check still
    runs server-side so non-form callers (future CLI/API) hit the same gate.
    """

    name = "Validate VRF parameter"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        vrf = (ctx.payload.get("vrf") or "").strip()
        if not vrf:
            return CheckResult(
                CheckStatus.FAIL,
                "VRF parameter is missing. Cannot proceed.",
            )
        ctx.state["vrf"] = vrf
        return CheckResult(CheckStatus.OK, f"VRF = '{vrf}'.")


class DetectInfraVn(Check):
    """Phase 1 / Check 2 — Detect INFRA_VN mode.

    Mirrors dhcp_troubleshooting.py:1889-1909. When vrf == "default", the
    endpoint is an AP or Extended Node and downstream checks take the
    underlay-only path (Phase 12) instead of the LISP overlay path (Phase 9).
    """

    name = "Detect INFRA_VN mode"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        vrf = ctx.state.get("vrf", "")
        is_infravn = vrf.lower() == "default"
        ctx.state["is_infravn"] = is_infravn
        if is_infravn:
            return CheckResult(
                CheckStatus.OK,
                "INFRA_VN mode: endpoint is an AP/Extended Node. "
                "Underlay-only flow will be used.",
                data={"is_infravn": True},
            )
        return CheckResult(
            CheckStatus.OK,
            f"Standard overlay flow (VRF '{vrf}', not INFRA_VN).",
            data={"is_infravn": False},
        )


class ProfileXtrHostname(Check):
    """Phase 1 / Check 3 (partial) — Resolve XTR hostname from RSA inventory.

    Mirrors the find_device() portion of dhcp_troubleshooting.py:1874-1876 →
    device_profiler.Device.find_device(). The full profile_device() (which
    queries Catalyst Center for softwareVersion / fabric role / instanceUuid)
    is wired as separate checks in checks_dhcp.py.
    """

    name = "Profile XTR (hostname lookup)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        mgmtip = ctx.payload.get("mgmt_ip") or ctx.payload.get("device_source_ip")
        if service is None:
            return CheckResult(CheckStatus.FAIL, "No RSA service in run context.")
        if not mgmtip:
            return CheckResult(CheckStatus.FAIL, "No XTR management IP supplied.")

        try:
            inv = service.inventory.filter("host", "^{}$".format(mgmtip))
            names = list(inv.keys())
            if not names:
                return CheckResult(
                    CheckStatus.FAIL,
                    f"Device {mgmtip} is not in RSA inventory.",
                )
            hostname = names[0]
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"RSA inventory lookup failed: {type(e).__name__}: {e}",
            )

        ctx.state["xtr_hostname"] = hostname
        ctx.state["xtr_mgmtip"] = mgmtip
        return CheckResult(
            CheckStatus.OK,
            f"Hostname resolved: {hostname}",
            data={"hostname": hostname, "node_relabel": hostname},
        )


class FewRedirect(Check):
    """Phase 1 / Check 4 (stub) — Redirect to actual XTR when is_few=True.

    Mirrors dhcp_troubleshooting.py:1911-1915 which calls
    wirelessflows.wirelessclientonboarding() to identify the XTR actually
    hosting the AP that hosts the wireless endpoint, and re-runs profiling
    against that device.

    STATUS: stub. When is_few=False, this check returns SKIP cleanly.
    When is_few=True, it returns WARN with a clear "not yet wired" message
    so the validation slot is visible and not silently omitted.
    """

    name = "FEW redirect (Fabric-Enabled Wireless)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if not ctx.payload.get("is_few"):
            return CheckResult(
                CheckStatus.SKIP,
                "Endpoint is not Fabric-Enabled Wireless; no redirect needed.",
            )
        return CheckResult(
            CheckStatus.WARN,
            "FEW redirect is not yet wired in the web path. "
            "Continuing with the XTR you supplied, but if the endpoint is "
            "actually wireless, the real XTR hosting its AP may differ.",
        )
