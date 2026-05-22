"""LISP / RLOC / SISF checks.

Covers CP-loopback discovery, RLOC mapping (PITR/PETR), the LISP-parameters
summary, and SISF device-tracking validation. Runs after the profile module
populates ctx.state with xtr_hostname / loopback / role flags.
"""

from checks import Check, CheckResult, CheckStatus, RunContext
from checks_shared import _legacy_fail
from radkit_cli import get_catc_api, get_any_single_output, get_single_output_genie


def _query_loopback0(ctx: RunContext) -> tuple:
    """Helper used by CP and RLOC checks. Returns (ip, mask, error_message_or_None)."""
    service = ctx.service
    dnac = ctx.state.get("catc_name")
    uuid = ctx.state.get("xtr_uuid")
    api = f"/dna/intent/api/v1/interface/network-device/{uuid}/interface-name?name=Loopback0"
    try:
        raw = get_catc_api(dnac, api, service)
    except Exception as e:
        return None, None, f"Loopback0 API call failed: {type(e).__name__}: {e}"
    if not raw:
        return None, None, f"Catalyst Center returned no response for {api}."
    response = raw.get("response") or {}
    if "Not found" in str(response.get("errorCode", "")):
        return None, None, f"Catalyst Center could not retrieve Loopback0 for device."
    if response.get("status") != "up":
        return None, None, "Loopback0 is administratively/operationally down; unshut the interface."

    for addr in response.get("addresses", []) or []:
        if "IPV4_PRIMARY" in (addr.get("type") or ""):
            try:
                ip = addr["address"]["ipAddress"]["address"]
                mask = addr["address"]["ipMask"]["address"]
            except (KeyError, TypeError):
                continue
            if ip and mask:
                return ip, mask, None
    return None, None, "Loopback0 has no IPV4_PRIMARY address."


class CpLoopback(Check):
    """Phase 1 / Check 9 (conditional) — Loopback0 collection for Control Plane.

    Mirrors device_profiler.cp_loopback():111-145. Only runs when the device's
    fabric role list contains 'Control Plane'.
    """

    name = "Control Plane Loopback0"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        roles = ctx.state.get("xtr_roles") or []
        if not any("Control Plane" in r for r in roles):
            return CheckResult(
                CheckStatus.SKIP,
                "Device is not a Control Plane; Loopback0 CP-specific check skipped.",
            )
        ip, mask, err = _query_loopback0(ctx)
        if err:
            return CheckResult(CheckStatus.FAIL, err)
        ctx.state["xtr_loopback"] = ip
        ctx.state["xtr_loopback_mask"] = mask
        return CheckResult(
            CheckStatus.OK,
            f"Loopback0: {ip}/{mask}",
            data={"loopback": ip, "mask": mask},
        )


class RlocDefinition(Check):
    """Phase 1 / Check 10 (conditional) — RLOC definition for Edge/Border.

    Mirrors device_profiler.rloc_definition():22-109. Pulls Loopback0 and
    cross-references it against `show run | i IPv4-interface|affinity` to
    confirm Loopback0 is the single LISP RLOC.
    """

    name = "RLOC Definition & Loopback0 Status"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        roles = ctx.state.get("xtr_roles") or []
        if not any(r in ("Edge Node", "Border Node") for r in roles):
            return CheckResult(
                CheckStatus.SKIP,
                "Device is not an Edge/Border; RLOC definition not applicable.",
            )
        if ctx.state.get("xtr_reachability") == "Unreachable":
            return CheckResult(
                CheckStatus.SKIP,
                "Device is Unreachable per Catalyst Center; RLOC check skipped.",
            )

        ip, mask, err = _query_loopback0(ctx)
        if err:
            return CheckResult(CheckStatus.FAIL, err)

        hostname = ctx.state.get("xtr_hostname")
        service = ctx.service
        try:
            output = get_any_single_output(
                hostname, "show run | i IPv4-interface|affinity", service
            )
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"show run collection failed: {type(e).__name__}: {e}",
            )
        if output is None:
            return CheckResult(
                CheckStatus.FAIL,
                f"Empty output when profiling RLOC on {hostname}. "
                f"Verify Catalyst Center reports it as 'Managed' and that SSH/Telnet works.",
            )

        import re

        def _grab(pattern: str, text: str) -> str:
            m = re.search(pattern, text)
            return m.group().strip() if m else ""

        rlocs = []
        for line in output.splitlines():
            if "IPv4-interface " not in line:
                continue
            m_iface = re.search(r"(?<=face).*(?=prio)", line)
            if not m_iface:
                continue
            interface = m_iface.group().strip()
            priority = _grab(r"(?<=priority\s)[0-9]+", line)
            weight = _grab(r"(?<=weight\s)[0-9]+", line)
            affinity = []
            if "affinity-id" in line:
                a1 = _grab(r"(?<=affinity-id\s)[0-9]+", line)
                a2 = _grab(r"(?<=,\s)[0-9]+", line)
                if a1:
                    affinity.append(a1)
                if a2:
                    affinity.append(a2)
            rlocs.append({"Interface": interface, "Priority": priority, "Weight": weight, "Affinity": affinity})

        if not rlocs:
            return CheckResult(
                CheckStatus.FAIL,
                f"RLOC interface not found on {hostname}. Verify Loopback0 is configured as RLOC "
                f"under 'locator-set'; check the BorderAffinity attribute.",
            )
        if len(rlocs) > 1:
            for r in rlocs:
                if r["Interface"] != "Loopback0":
                    return CheckResult(
                        CheckStatus.FAIL,
                        f"More than 1 RLOC configured under 'router lisp' on {hostname} — "
                        f"unsupported SD-Access configuration.",
                    )

        ctx.state["xtr_loopback"] = ip
        ctx.state["xtr_loopback_mask"] = mask
        ctx.state["xtr_rloc"] = rlocs[0]
        return CheckResult(
            CheckStatus.OK,
            (
                f"• RLOC interface: {rlocs[0]['Interface']}\n"
                f"• Address: {ip}/{mask}\n"
                f"• Priority: {rlocs[0]['Priority']}\n"
                f"• Weight: {rlocs[0]['Weight']}"
            ),
            data={"loopback": ip, "mask": mask, "rloc": rlocs[0], "node_rloc": ip},
        )


def _ensure_lisp_summary(ctx: RunContext) -> tuple:
    """Lazily fetch & cache `show lisp service ipv4` (genie). Returns (lispsum, error)."""
    cached = ctx.state.get("_lisp_service_ipv4")
    if cached is not None:
        return cached, None
    err_cached = ctx.state.get("_lisp_service_ipv4_err")
    if err_cached:
        return None, err_cached
    try:
        lispsum = get_single_output_genie(
            ctx.state.get("xtr_hostname"), "show lisp service ipv4", ctx.service
        )
    except Exception as e:
        msg = f"`show lisp service ipv4` parse failed: {type(e).__name__}: {e}"
        ctx.state["_lisp_service_ipv4_err"] = msg
        return None, msg
    if not lispsum:
        msg = "Empty/unparseable output from `show lisp service ipv4`."
        ctx.state["_lisp_service_ipv4_err"] = msg
        return None, msg
    ctx.state["_lisp_service_ipv4"] = lispsum
    return lispsum, None


class PitrValidation(Check):
    """Phase 1 / Check 11 (conditional) — PITR address must equal Loopback0.

    Mirrors device_profiler.profile_device():326-335. Pulls `show lisp service
    ipv4` (Genie-parsed) and confirms `proxy_itr_rloc` matches the device's
    Loopback0 address.
    """

    name = "PITR Validation"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        roles = ctx.state.get("xtr_roles") or []
        if not any(r in ("Edge Node", "Border Node") for r in roles):
            return CheckResult(CheckStatus.SKIP, "Not an Edge/Border; PITR check not applicable.")
        if ctx.state.get("xtr_reachability") == "Unreachable":
            return CheckResult(CheckStatus.SKIP, "Device Unreachable; PITR check skipped.")
        loopback = ctx.state.get("xtr_loopback")
        if not loopback:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — Loopback0 was not resolved by an earlier check (CpLoopback / RlocDefinition).",
            )

        lispsum, err = _ensure_lisp_summary(ctx)
        if err:
            return CheckResult(CheckStatus.FAIL, err)

        try:
            pitr = lispsum["lisp_id"][0]["itr"]["proxy_itr_rloc"]
        except (KeyError, IndexError, TypeError) as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not locate proxy_itr_rloc in `show lisp service ipv4`: {e}",
            )

        if pitr != loopback:
            return CheckResult(
                CheckStatus.FAIL,
                f"PITR address {pitr} does not match Loopback0 {loopback}. "
                f"Correct with `proxy-itr <Loopback0-ip>` under `router lisp, service ipv4`.",
            )
        return CheckResult(
            CheckStatus.OK,
            f"PITR matches Loopback0 ({loopback}).",
            data={"pitr": pitr},
        )


class PetrValidation(Check):
    """Phase 1 / Check 12 (conditional) — PETR flag indicates External Border.

    Mirrors device_profiler.profile_device():337-339. The `proxy_etr_router`
    boolean from `show lisp service ipv4` marks the device as an External
    Border (eborder). This is informational — both True and False are valid
    depending on topology — so this check reports OK either way and records
    the eborder flag for downstream consumers.
    """

    name = "PETR Validation"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        roles = ctx.state.get("xtr_roles") or []
        if not any(r in ("Edge Node", "Border Node") for r in roles):
            return CheckResult(CheckStatus.SKIP, "Not an Edge/Border; PETR check not applicable.")
        if ctx.state.get("xtr_reachability") == "Unreachable":
            return CheckResult(CheckStatus.SKIP, "Device Unreachable; PETR check skipped.")

        lispsum, err = _ensure_lisp_summary(ctx)
        if err:
            return CheckResult(CheckStatus.FAIL, err)

        try:
            petr_flag = bool(lispsum["lisp_id"][0]["etr"]["proxy_etr_router"])
        except (KeyError, IndexError, TypeError) as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not locate proxy_etr_router in `show lisp service ipv4`: {e}",
            )

        ctx.state["xtr_is_eborder"] = petr_flag
        return CheckResult(
            CheckStatus.OK,
            f"Device is {'an External Border (eborder)' if petr_flag else 'NOT an External Border'}.",
            data={"is_eborder": petr_flag},
        )

class LispParameters(Check):
    """DHCP — LISP IID / instance / database / map-cache on the XTR."""

    name = "LISP Parameters"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        dhcp_info = ctx.state.get("dhcpparameters_info")
        mac_info = ctx.state.get("mac_learning_info")
        is_infravn = ctx.state.get("is_infravn")

        if not (service and hostname and dhcp_info and mac_info):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — requires dhcpparameters_info / mac_learning_info.",
            )

        vrf = getattr(dhcp_info, "svivrf", None)
        eids = getattr(dhcp_info, "helper_address", None) or []

        try:
            from routingmodules.lisp import L3Device
            lisp_info = L3Device(vrf, hostname)
            lisp_info.lispiid(service)
            lisp_info.instance_properties(service)
            lisp_info.lisp_database_information(service)
            if not is_infravn:
                lisp_info.map_cache(list(eids), service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"LISP parameter collection failed: {type(e).__name__}: {e}",
            )

        ctx.state["lispparameters_info"] = lisp_info
        ctx.state["lisp_iid"] = getattr(lisp_info, "iid", None)

        # Address family — derive from instance_information if present, else
        # fall back to "ipv4" (which is what we collect for L3 today).
        inst = getattr(lisp_info, "instance_information", None)
        af = getattr(inst, "address_family", None) or "ipv4"
        af_label = {"ipv4": "IPv4", "ipv6": "IPv6", "ethernet": "Ethernet"}.get(
            str(af).lower(), str(af)
        )

        # Map-cache crucial info: per-EID state + RLOC count (or use-petrs
        # fallback when LISP-BGP forward-native is in play).
        use_petrs = list(getattr(inst, "usepetrs", []) or [])
        mc_lines = []
        for mc in (getattr(lisp_info, "map_cache_information", []) or []):
            prefix = getattr(mc, "eid_prefix", None) or getattr(mc, "requested_eid", "?")
            rlocs = getattr(mc, "rlocs", []) or []
            petr_encap = getattr(mc, "petr_encap", False)
            sources = getattr(mc, "sources", "") or ""
            if rlocs:
                rloc_ips = ", ".join(r.get("rloc", "?") for r in rlocs)
                mc_lines.append(f"    - {prefix} → {rloc_ips} ({sources})")
            elif petr_encap and use_petrs:
                mc_lines.append(
                    f"    - {prefix} → forward-native, encapsulating to PETR(s) "
                    f"{', '.join(use_petrs)}"
                )
            else:
                mc_lines.append(f"    - {prefix} → no RLOCs ({sources or 'unknown'})")

        mc_block = "\n".join(mc_lines) if mc_lines else "    - (none)"

        body = (
            f"• Instance-ID: {ctx.state['lisp_iid']} (VRF '{vrf or 'default'}')\n"
            f"• Address Family: {af_label}\n"
            f"• Map-Cache:\n{mc_block}"
        )
        return CheckResult(
            CheckStatus.OK,
            body,
            data={"iid": str(ctx.state["lisp_iid"])},
        )


class SisfDeviceTracking(Check):
    """DHCP — SISF device-tracking policies + database on the XTR."""

    name = "SISF - Device Tracking"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        dhcp_info = ctx.state.get("dhcpparameters_info")
        mac_info = ctx.state.get("mac_learning_info")
        lisp_info = ctx.state.get("lispparameters_info")
        is_infravn = ctx.state.get("is_infravn")
        is_pubsub = ctx.state.get("is_pubsub")

        if not (service and hostname and dhcp_info and mac_info and lisp_info):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — requires lispparameters_info / dhcpparameters_info.",
            )

        svi = getattr(dhcp_info, "prefix", None)
        vlan = getattr(mac_info, "vlan", ctx.payload.get("vlan"))

        try:
            from switchingmodules.sisf import SISF
            sisf_info = SISF(hostname)
            sisf_info.device_tracking_policies(vlan, service)
            sisf_info.device_tracking_database_address(svi, service)
            sisf_info.device_tracking_database_history(service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"SISF collection failed: {type(e).__name__}: {e}",
            )

        try:
            from traffic_flows.dhcp_troubleshooting import lisp_parameters_validation_edge
            lisp_parameters_validation_edge(lisp_info, is_pubsub, 0, dhcp_info, sisf_info, is_infravn)
        except BaseException as e:
            return _legacy_fail(e, "lisp_parameters_validation_edge")

        ctx.state["sisfparameters_info"] = sisf_info

        # SVI Status — is the SVI primary IP present in the SISF database?
        dbentries = getattr(sisf_info, "dbentries", []) or []
        svi_status = (
            f"{svi} present in SISF database ({len(dbentries)} entry/entries)"
            if svi and dbentries
            else f"no SISF database entry for SVI {svi or '?'}"
        )

        # VLAN IPDT Policy — names attached to this VLAN.
        policies = getattr(sisf_info, "policies", None) or []
        if policies:
            pol_names = ", ".join(sorted({p.get("policy", "?") for p in policies}))
            ipdt_status = f"VLAN {vlan} → {pol_names}"
        else:
            ipdt_status = f"no device-tracking policy attached to VLAN {vlan}"

        body = (
            f"• SVI Status: {svi_status}\n"
            f"• VLAN IPDT Policy: {ipdt_status}"
        )
        return CheckResult(
            CheckStatus.OK,
            body,
            data={"db_entries": len(dbentries), "policy_count": len(policies)},
        )
