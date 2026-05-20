"""DHCP-specific Check objects.

These checks are exclusive to the DHCP troubleshooting flow. They run after
the common checks in checks_common.py and assume that the XTR hostname has
already been resolved into ctx.state["xtr_hostname"].
"""

from checks import Check, CheckResult, CheckStatus, RunContext
from radkit_cli import get_catc_api, get_any_single_output, get_single_output_genie


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


class ResolveCatcName(Check):
    """Phase 1 / Check 5 — Resolve the Catalyst Center hostname.

    Mirrors the radkit_cli.get_catc_name() call that dhcp_troubleshooting
    performs before any Catalyst Center API request. The form lets the user
    override the auto-detected name (needed when RADKIT Standalone Server is
    in use); if they leave it blank, we fall back to scanning the RADKIT
    inventory for a device with device_type CENTER (or DNAC for older builds).
    """

    name = "Resolve Catalyst Center name"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        if service is None:
            return CheckResult(CheckStatus.FAIL, "No RADKIT service in run context.")

        form_value = (ctx.payload.get("catc_name") or "").strip()
        if form_value:
            try:
                inv = service.inventory.filter("name", "^{}$".format(form_value))
                if not list(inv.keys()):
                    return CheckResult(
                        CheckStatus.FAIL,
                        f"Catalyst Center '{form_value}' is not in RADKIT inventory.",
                    )
            except Exception as e:
                return CheckResult(
                    CheckStatus.FAIL,
                    f"RADKIT inventory lookup failed: {type(e).__name__}: {e}",
                )
            ctx.state["catc_name"] = form_value
            return CheckResult(
                CheckStatus.OK,
                f"Using Catalyst Center '{form_value}' (form-supplied).",
                data={"catc_name": form_value},
            )

        try:
            inv = service.inventory.filter("device_type", "CENTER")
            names = list(inv.keys())
            if not names:
                inv = service.inventory.filter("device_type", "DNAC")
                names = list(inv.keys())
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"RADKIT inventory lookup failed: {type(e).__name__}: {e}",
            )

        if not names:
            return CheckResult(
                CheckStatus.FAIL,
                "No Catalyst Center (device_type CENTER/DNAC) found in RADKIT inventory. "
                "Supply the Catalyst Center name in the form if RADKIT Standalone is in use.",
            )

        catc_name = names[0]
        ctx.state["catc_name"] = catc_name
        return CheckResult(
            CheckStatus.OK,
            f"Catalyst Center auto-detected: '{catc_name}'.",
            data={"catc_name": catc_name},
        )


class ProfileXtrNetworkDevice(Check):
    """Phase 1 / Check 6 — network-device API: softwareVersion, serial, uuid, platform, reachability.

    Mirrors device_profiler.profile_device():234-270, the first half of the
    CatC profile call. Extracts the fields downstream checks need (instanceUuid
    is required for every later /interface/network-device/{uuid} call). The
    original sys.exit()s on missing fields or empty response are converted to
    CheckResult(FAIL, ...) so the chain halts cleanly.
    """

    name = "Profile XTR (network-device API)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        if service is None:
            return CheckResult(CheckStatus.SKIP, "RADKIT service missing in run context.")
        dnac = ctx.state.get("catc_name")
        mgmtip = ctx.state.get("xtr_mgmtip")
        if not dnac:
            return CheckResult(CheckStatus.SKIP, "Catalyst Center name not resolved by an earlier check.")
        if not mgmtip:
            return CheckResult(CheckStatus.SKIP, "XTR management IP not resolved by an earlier check.")

        api = f"/dna/intent/api/v1/network-device/ip-address/{mgmtip}"
        try:
            raw = get_catc_api(dnac, api, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Catalyst Center API call failed: {type(e).__name__}: {e} (API: {api})",
            )
        if raw is None:
            return CheckResult(
                CheckStatus.FAIL,
                f"Catalyst Center returned no response for {api}.",
            )
        response = raw.get("response") if isinstance(raw, dict) else None
        if not response:
            return CheckResult(
                CheckStatus.FAIL,
                f"Catalyst Center could not find network device {mgmtip} (API: {api}).",
            )

        try:
            version = response["softwareVersion"]
            serial = response["serialNumber"]
            uuid = response["instanceUuid"]
            platform = response["platformId"]
            reach = response["reachabilityStatus"]
        except KeyError as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Network-device API response missing field {e} (API: {api}).",
            )

        ctx.state["xtr_catc_hostname"] = response.get("hostname")
        ctx.state["xtr_version"] = version
        ctx.state["xtr_serial"] = serial
        ctx.state["xtr_uuid"] = uuid
        ctx.state["xtr_platform"] = platform
        ctx.state["xtr_reachability"] = reach

        if reach == "Unreachable":
            return CheckResult(
                CheckStatus.WARN,
                f"{platform} (IOS-XE {version}, serial {serial}) is marked Unreachable by Catalyst Center. "
                f"Downstream RLOC/LISP checks will be skipped.",
                data={
                    "platform": platform,
                    "version": version,
                    "serial": serial,
                    "uuid": uuid,
                    "reachability": reach,
                },
            )

        return CheckResult(
            CheckStatus.OK,
            f"{platform} | IOS-XE {version} | serial {serial} | reachability: {reach}",
            data={
                "platform": platform,
                "version": version,
                "serial": serial,
                "uuid": uuid,
                "reachability": reach,
            },
        )


class ProfileXtrFabricDevice(Check):
    """Phase 1 / Check 7 — fabric-device API: roles + siteNameHierarchy.

    Mirrors device_profiler.profile_device():248-292. When the device is not a
    fabric member (status == 'failed' or no siteNameHierarchy), falls back to
    the device-detail API to recover the location string so later checks know
    the site even for Intermediate/Fusion routers.
    """

    name = "Profile XTR (fabric-device API)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        dnac = ctx.state.get("catc_name")
        mgmtip = ctx.state.get("xtr_mgmtip")
        uuid = ctx.state.get("xtr_uuid")
        if not (service and dnac and mgmtip and uuid):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — an earlier check did not populate the required state "
                "(service / catc_name / xtr_mgmtip / xtr_uuid).",
            )

        api = f"/dna/intent/api/v1/business/sda/device?deviceManagementIpAddress={mgmtip}"
        try:
            raw = get_catc_api(dnac, api, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Catalyst Center API call failed: {type(e).__name__}: {e} (API: {api})",
            )
        if not isinstance(raw, dict):
            return CheckResult(
                CheckStatus.FAIL,
                f"Catalyst Center returned no/unparseable response for {api}.",
            )

        site_hierarchy = None
        roles = []
        is_fabric = True

        if raw.get("status") == "failed" or "siteNameHierarchy" not in raw:
            is_fabric = False
            detail_api = f"/dna/intent/api/v1/device-detail?searchBy={uuid}&identifier=uuid"
            try:
                detail_raw = get_catc_api(dnac, detail_api, service)
            except Exception as e:
                return CheckResult(
                    CheckStatus.FAIL,
                    f"device-detail API failed: {type(e).__name__}: {e}",
                )
            detail = (detail_raw or {}).get("response") or {}
            site_hierarchy = detail.get("location")
            if not site_hierarchy:
                return CheckResult(
                    CheckStatus.FAIL,
                    f"Device {mgmtip} is not a fabric device and device-detail returned no location.",
                )
        else:
            site_hierarchy = raw.get("siteNameHierarchy")
            roles = raw.get("roles") or []

        ctx.state["xtr_is_fabric"] = is_fabric
        ctx.state["xtr_roles"] = roles
        ctx.state["xtr_site_hierarchy"] = site_hierarchy

        if not is_fabric:
            return CheckResult(
                CheckStatus.WARN,
                f"Device {mgmtip} is not a fabric device (possibly Intermediate/Fusion). "
                f"Location: {site_hierarchy}. RLOC/LISP checks will be skipped.",
                data={"is_fabric": False, "site_hierarchy": site_hierarchy},
            )

        return CheckResult(
            CheckStatus.OK,
            f"Fabric roles: {', '.join(roles) if roles else '(none)'} | site: {site_hierarchy}",
            data={"is_fabric": True, "roles": roles, "site_hierarchy": site_hierarchy},
        )


class XtrRoleClassification(Check):
    """XTR role classification — sets edge / iborder / l2handoff state flags.

    Mirrors device_profiler.profile_device():353-365 + the LISP route-import
    branch at :341-350. Downstream DHCP checks (MAC learning, forwarding) gate
    on these flags so they must be in state before Group A runs.

    - edge:      'Edge Node' is in xtr_roles
    - iborder:   'Border Node' role AND at least one IID has route-import
                 configured (lisp_route_import.ridb_state)
    - l2handoff: layer2Handoffs count >= 1 on this device in this fabric
    """

    name = "XTR role classification (edge / iborder / l2handoff)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        dnac = ctx.state.get("catc_name")
        hostname = ctx.state.get("xtr_hostname")
        uuid = ctx.state.get("xtr_uuid")
        fabric_id = ctx.state.get("fabric_id")
        roles = ctx.state.get("xtr_roles") or []
        is_fabric = ctx.state.get("xtr_is_fabric")

        if not is_fabric:
            ctx.state["edge"] = False
            ctx.state["iborder"] = False
            ctx.state["l2handoff"] = False
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — device is not a fabric member; no role flags to set.",
            )

        if not (service and dnac and hostname and uuid and fabric_id):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — required state missing (service / catc_name / "
                "xtr_hostname / xtr_uuid / fabric_id).",
            )

        edge = any("Edge Node" in r for r in roles)

        iborder = False
        if any("Border Node" in r for r in roles):
            try:
                from routingmodules.lisp import lisp_route_import
                rdbstate = lisp_route_import("*", hostname).ridb_state(service)
            except Exception as e:
                return CheckResult(
                    CheckStatus.FAIL,
                    f"LISP route-import probe failed: {type(e).__name__}: {e}",
                )
            if rdbstate:
                iborder = any(
                    (entry or {}).get("configured") is True
                    for entry in rdbstate.values()
                )

        l2handoff_api = (
            f"/dna/intent/api/v1/sda/fabricDevices/layer2Handoffs/count"
            f"?fabricId={fabric_id}&networkDeviceId={uuid}"
        )
        try:
            l2_raw = get_catc_api(dnac, l2handoff_api, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"layer2Handoffs/count API failed: {type(e).__name__}: {e}",
            )
        l2_response = (l2_raw or {}).get("response") if isinstance(l2_raw, dict) else None
        count = (l2_response or {}).get("count", 0) if isinstance(l2_response, dict) else 0
        l2handoff = count >= 1

        ctx.state["edge"] = edge
        ctx.state["iborder"] = iborder
        ctx.state["l2handoff"] = l2handoff

        labels = []
        if edge:      labels.append("edge")
        if iborder:   labels.append("iborder")
        if l2handoff: labels.append(f"l2handoff (count={count})")
        summary = ", ".join(labels) if labels else "no XTR roles matched"

        tags = []
        if edge:      tags.append("Edge")
        if iborder:   tags.append("iBorder")
        if l2handoff: tags.append("L2Handoff")

        return CheckResult(
            CheckStatus.OK,
            f"XTR classification: {summary}.",
            data={
                "edge": edge,
                "iborder": iborder,
                "l2handoff": l2handoff,
                "l2handoff_count": count,
                "node_tags": tags,
            },
        )


class FabricSiteLookup(Check):
    """Phase 1 / Check 8 — fabricSites API: pubsub flag + fabric_id + site_id + site_hierarchy.

    Mirrors device_profiler.fabric_sites():147-187. Uses the v1 site API and
    cross-references against fabricSites to find the entry whose siteId is in
    the device's site hierarchy. Skips cleanly when the device is not fabric.
    """

    name = "Fabric site lookup (pubsub / fabric_id)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if not ctx.state.get("xtr_is_fabric", False):
            return CheckResult(
                CheckStatus.SKIP,
                "Device is not a fabric member; fabric site lookup not applicable.",
            )

        service = ctx.service
        dnac = ctx.state.get("catc_name")
        site_hierarchy = ctx.state.get("xtr_site_hierarchy")
        if not (service and dnac and site_hierarchy):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — an earlier check did not populate the required state "
                "(service / catc_name / xtr_site_hierarchy).",
            )

        site_api = f"/dna/intent/api/v1/site?name={site_hierarchy}"
        fabricsite_api = "/dna/intent/api/v1/sda/fabricSites"
        try:
            site_raw = get_catc_api(dnac, site_api, service)
            fabric_raw = get_catc_api(dnac, fabricsite_api, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Catalyst Center API call failed: {type(e).__name__}: {e}",
            )
        if not isinstance(site_raw, dict) or not isinstance(fabric_raw, dict):
            return CheckResult(CheckStatus.FAIL, "Catalyst Center returned unparseable response for site lookup.")
        site_response = site_raw.get("response") or []
        fabric_response = fabric_raw.get("response") or []
        if not isinstance(site_response, list) or not site_response:
            return CheckResult(
                CheckStatus.FAIL,
                f"Site '{site_hierarchy}' not found in Catalyst Center (API: {site_api}).",
            )
        first_site = site_response[0] if isinstance(site_response[0], dict) else {}
        group_hierarchy = first_site.get("siteHierarchy", "")

        fabric_id = site_id = None
        is_pubsub = False
        for entry in fabric_response:
            if not isinstance(entry, dict):
                continue
            if entry.get("siteId") and entry["siteId"] in group_hierarchy:
                is_pubsub = entry.get("isPubSubEnabled", False)
                fabric_id = entry.get("id")
                site_id = entry.get("siteId")
                break

        if fabric_id is None:
            return CheckResult(
                CheckStatus.FAIL,
                f"No fabricSites entry matches site hierarchy '{site_hierarchy}'. "
                f"Review the latest API retrieved in Catalyst Center in the GPS_SDA Collection ({fabricsite_api}).",
            )

        final_api = f"/dna/intent/api/v1/site?siteId={site_id}"
        try:
            final_raw = get_catc_api(dnac, final_api, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Catalyst Center API call failed: {type(e).__name__}: {e} (API: {final_api})",
            )
        final_resp = (final_raw or {}).get("response") or {}
        final_hierarchy = final_resp.get("siteNameHierarchy", site_hierarchy)

        ctx.state["is_pubsub"] = is_pubsub
        ctx.state["fabric_id"] = fabric_id
        ctx.state["fabric_site_id"] = site_id
        ctx.state["fabric_site_hierarchy"] = final_hierarchy

        return CheckResult(
            CheckStatus.OK,
            f"Fabric site: {final_hierarchy} | pubsub: {is_pubsub} | fabric_id: {fabric_id}",
            data={
                "is_pubsub": is_pubsub,
                "fabric_id": fabric_id,
                "fabric_site_id": site_id,
                "fabric_site_hierarchy": final_hierarchy,
            },
        )


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

    name = "RLOC definition (Loopback0 under router lisp)"
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
            f"RLOC: {rlocs[0]['Interface']} ({ip}/{mask}) | priority={rlocs[0]['Priority']} weight={rlocs[0]['Weight']}",
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

    name = "PITR validation (proxy-itr == Loopback0)"
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

    name = "PETR validation (proxy-etr flag)"
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
            f"proxy-etr flag: {petr_flag} → device is "
            f"{'an External Border (eborder)' if petr_flag else 'NOT an External Border'}.",
            data={"is_eborder": petr_flag},
        )


class FewRedirectReal(Check):
    """Phase 1 / Check 13 — Real Fabric-Enabled Wireless redirect.

    Replaces the FewRedirect stub. When is_few=True, calls
    wirelessflows.wirelessclientonboarding() with the resolved fabric_site_id,
    catc_name, and endpoint MAC. The function returns the hostname of the XTR
    actually hosting the wireless endpoint's AP; we override
    ctx.state['xtr_hostname'] and relabel the topology node accordingly.

    NOTE: wirelessclientonboarding() runs many validations internally and uses
    sys.exit() on error — we catch BaseException (covers SystemExit) so the
    chain fails cleanly rather than killing the worker.
    """

    name = "FEW redirect (real)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if not ctx.payload.get("is_few"):
            return CheckResult(
                CheckStatus.SKIP,
                "Endpoint is not Fabric-Enabled Wireless; redirect not needed.",
            )

        fabric_site_id = ctx.state.get("fabric_site_id")
        catc_name = ctx.state.get("catc_name")
        mac = ctx.payload.get("mac")
        service = ctx.service
        if not (fabric_site_id and catc_name and mac and service):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — required state missing (fabric_site_id / catc_name / mac / service).",
            )

        try:
            from traffic_flows.wirelessflows import wirelessclientonboarding
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not import wirelessclientonboarding: {type(e).__name__}: {e}",
            )

        # Pre-flight: confirm at least one WLC is registered to this fabric.
        # wirelessclientonboarding() crashes with IndexError on empty inventory.
        wlc_api = (
            f"/dna/intent/api/v1/sda/fabricDevices?fabricId={fabric_site_id}"
            f"&deviceRoles=WIRELESS_CONTROLLER_NODE"
        )
        try:
            wlc_raw = get_catc_api(catc_name, wlc_api, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"WLC lookup failed: {type(e).__name__}: {e} (API: {wlc_api})",
            )
        wlc_response = (wlc_raw or {}).get("response") if isinstance(wlc_raw, dict) else None
        if not wlc_response:
            return CheckResult(
                CheckStatus.FAIL,
                f"No Wireless LAN Controller is registered to fabric_id {fabric_site_id}. "
                f"Cannot identify the XTR hosting this wireless endpoint. "
                f"Add a WLC to the fabric site in Catalyst Center, or set "
                f"'Fabric Enabled Wireless' to OFF if the endpoint is wired.",
            )

        try:
            _step, new_xtr = wirelessclientonboarding(0, fabric_site_id, catc_name, mac, service)
        except BaseException as e:
            return _legacy_fail(e, "wirelessclientonboarding")

        if not new_xtr:
            return CheckResult(
                CheckStatus.FAIL,
                "wirelessclientonboarding returned no XTR hostname.",
            )

        prior = ctx.state.get("xtr_hostname")
        ctx.state["xtr_hostname"] = new_xtr
        return CheckResult(
            CheckStatus.OK,
            f"Real XTR for wireless endpoint: {new_xtr} (was {prior}).",
            data={"hostname": new_xtr, "node_relabel": new_xtr},
        )


class MacLearning(Check):
    """DHCP — verify the endpoint MAC is learned on the XTR for the given VLAN.

    Mirrors dhcp_troubleshooting.edge_node.maclearning() +
    dhcp_mac_address_validation(). Runs only on fabric edges or L2 handoffs
    (CLI gate at dhcp_troubleshooting.py:1924-1927).

    Resolution outcomes (preserving CLI semantics):
      - port == None  -> FAIL (MAC not in table)
      - port == "Drop"-> FAIL (drop state)
      - port startswith "Ac" -> OK + flags fewendpoint=True (AccessTunnel; FEW
        features bypassed for the rest of the chain)
      - "Tu" or "L2L" in port -> FAIL (endpoint is remote, known via LISP)
      - otherwise -> OK with the learned port
    """

    name = "MAC learning (show mac address-table)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        mac = ctx.payload.get("mac")
        vlan = ctx.payload.get("vlan")

        if not (service and hostname and mac and vlan):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — required state missing (service / xtr_hostname / mac / vlan).",
            )

        is_fabric = ctx.state.get("xtr_is_fabric")
        edge = ctx.state.get("edge")
        l2handoff = ctx.state.get("l2handoff")
        if not (is_fabric and (edge or l2handoff)):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — MAC learning only runs on fabric Edge or L2-handoff devices.",
            )

        try:
            from switchingmodules.maclearning import mac_learning
            info = mac_learning(hostname)
            info.mac_learning_mac(mac, vlan, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"mac_learning_mac raised {type(e).__name__}: {e}",
            )

        port = getattr(info, "port", None)
        m_type = getattr(info, "type", None)
        fewendpoint = False

        if port is None:
            return CheckResult(
                CheckStatus.FAIL,
                f"MAC {mac} not found in the mac-address-table for VLAN {vlan} on {hostname}.",
            )
        if port == "Drop":
            return CheckResult(
                CheckStatus.FAIL,
                f"MAC {mac} on VLAN {vlan} is in DROP state on {hostname}.",
            )
        if isinstance(port, str) and (("Tu" in port) or ("L2L" in port)):
            return CheckResult(
                CheckStatus.FAIL,
                f"MAC {mac} on VLAN {vlan} learned on {port} of {hostname} — endpoint is "
                f"remote (known via LISP). Specify the correct device or update the endpoint's location.",
            )

        if isinstance(port, str) and port.startswith("Ac"):
            fewendpoint = True
            msg = (
                f"MAC {mac} on VLAN {vlan} learned on {port} (AccessTunnel) of {hostname}. "
                f"Fabric-Enabled Wireless interface — FEW-specific features will be bypassed."
            )
        else:
            msg = (
                f"MAC {mac} on VLAN {vlan} learned on {port} of {hostname}. "
                f"Confirm this is the expected port for this endpoint."
            )

        ctx.state["xtr_port"] = port
        ctx.state["xtr_mac_type"] = m_type
        ctx.state["fewendpoint"] = fewendpoint
        ctx.state["mac_learning_info"] = info  # for downstream Checks (auth-session, cdp)

        return CheckResult(
            CheckStatus.OK,
            msg,
            data={"port": port, "type": m_type, "fewendpoint": fewendpoint},
        )


class AuthSessionAndCdp(Check):
    """DHCP — authentication-session + CDP validation on the XTR port.

    Mirrors the auth/CDP block at dhcp_troubleshooting.py:1934-1976:
      1. CDP scan on the learned port (CDPinfo.cdpneighborinterface). If any
         neighbor advertises Cisco + Router + Trans-Bridge → flag is_ap=True.
      2. Run authen_session_for_interface(hostname, port, service) — handles
         AccessTunnel ACRO sessions vs. normal interface template lookup.
      3. Delegate to validate_authentication_sessions() which performs the
         full chain: template/closed-mode/order, live session state, MAB,
         CDP phone detection, PAE, host mode, WOL, VLAN/SGT/dACL.

    validate_authentication_sessions() uses sys.exit() on hard fails; we catch
    BaseException so the chain surfaces them as Check FAILs instead of killing
    the worker. Discrete sub-validations stream into collection_logfile.txt
    via the legacy logging helpers.
    """

    name = "Auth session + CDP (interface)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        from types import SimpleNamespace
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        info = ctx.state.get("mac_learning_info")
        port = ctx.state.get("xtr_port")

        if not (service and hostname and info and port):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — auth-session requires a learned MAC port from the previous Check.",
            )

        # 1. CDP on the learned port
        try:
            from switchingmodules.cdp import CDPinfo
            cdpneighbor = CDPinfo(hostname)
            cdpneighbor.cdpneighborinterface(port, service)
            neighbors = getattr(cdpneighbor, "cdpneighbors", []) or []
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"CDP probe failed on {hostname} {port}: {type(e).__name__}: {e}",
            )

        # 2. AP detection from CDP capabilities (preserves dhcp_troubleshooting.py:1944-1964)
        is_ap = False
        for neighbor in neighbors:
            platform = (neighbor.get("platform") or "").lower()
            capabilities = neighbor.get("capabilities", "") or ""
            if "cisco" in platform and "Router" in capabilities and "Trans-Bridge" in capabilities:
                is_ap = True
                break
        ctx.state["is_ap"] = is_ap

        # 3. Auth session for interface
        try:
            from securitymodules.authenticationsession import authen_session_for_interface
            auth_details = authen_session_for_interface(hostname, port, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"authen_session_for_interface raised {type(e).__name__}: {e}",
            )

        # 4. Delegate to validate_authentication_sessions with a minimal shim
        from device_profiler import Device  # noqa: F401 -- referenced indirectly
        shim = SimpleNamespace(
            hostname=hostname,
            mac_learning_info=info,
            authensessiondetails=auth_details,
            cdpneighborhost=neighbors,
            is_ap=is_ap,
            # profiled_device is consulted by acl_hit_procedure only on dACL hits;
            # provide a minimal stub so attribute access doesn't fail.
            profiled_device=SimpleNamespace(hostname=hostname),
        )

        try:
            from traffic_flows.dhcp_troubleshooting import validate_authentication_sessions
            validate_authentication_sessions(shim, 0, service)
        except BaseException as e:
            return _legacy_fail(e, "validate_authentication_sessions")

        ctx.state["authensessiondetails"] = auth_details
        ctx.state["cdpneighborhost"] = neighbors

        ap_note = " AP detected via CDP." if is_ap else ""
        return CheckResult(
            CheckStatus.OK,
            f"Auth session and CDP validated on {hostname} {port}.{ap_note} "
            f"See collection_logfile.txt for the per-sub-validation breakdown.",
            data={"is_ap": is_ap, "cdp_neighbors": len(neighbors)},
        )


class LocalSgt(Check):
    """DHCP — derive the endpoint's local SGT from the XTR's CEF table.

    Mirrors dhcp_troubleshooting.edge_node.localsgt() (line 71-75) which calls
    local_sgt_determination(loopback, hostname, service). Internally this
    builds an IPCef on the XTR's Loopback0 and pulls the SGT tag the switch
    has bound to that source.

    Side effect (the reason this Check is the trigger for the endpoint
    visualization): once SGT is known, MAC + VLAN + SGT are all available,
    so we emit `add_endpoint` so the frontend can draw the computer node.
    """

    name = "Local SGT (CEF source-tag)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        loopback = ctx.state.get("xtr_loopback")
        mac = ctx.payload.get("mac")
        vlan = ctx.payload.get("vlan")

        if not (service and hostname and loopback):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — local SGT requires xtr_hostname + xtr_loopback + service.",
            )

        try:
            from traffic_flows.dhcp_troubleshooting import local_sgt_determination
            lsgt = local_sgt_determination(loopback, hostname, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"local_sgt_determination raised {type(e).__name__}: {e}",
            )

        ctx.state["localsgt"] = lsgt

        data = {"localsgt": lsgt}
        # Emit the endpoint visualization once MAC/VLAN/SGT are all known.
        if mac and vlan:
            data["add_endpoint"] = {
                "mac": mac,
                "vlan": vlan,
                "sgt": lsgt,
                "port": ctx.state.get("xtr_port"),
                "parent_node_id": "xtr",
            }

        return CheckResult(
            CheckStatus.OK,
            f"Local SGT for {loopback} on {hostname} resolved to {lsgt}.",
            data=data,
        )


class PoolIdentification(Check):
    """DHCP — identify the IP pool bound to the endpoint's VLAN.

    Mirrors dhcp_troubleshooting.py:1978-2020. Two CatC API calls:
      1. /sda/layer2VirtualNetworks?fabricId=…&vlanId=…  → vlanName
      2. /business/sda/virtualnetwork/ippool?siteNameHierarchy=…
         &virtualNetworkName=…&ipPoolName=…                → pool details

    L2-only pools FAIL the run because the downstream DHCP traffic-flow checks
    rely on an Anycast Gateway being present (CLI exit_program at line 2008).
    """

    name = "Pool identification (VLAN → IP pool)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        dnac = ctx.state.get("catc_name")
        fabric_id = ctx.state.get("fabric_id")
        site_hierarchy = ctx.state.get("fabric_site_hierarchy")
        vlan = ctx.payload.get("vlan")
        vrf = ctx.payload.get("vrf")
        is_infravn = ctx.state.get("is_infravn")

        if not (service and dnac and fabric_id and site_hierarchy and vlan):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — pool identification requires service / catc_name / "
                "fabric_id / fabric_site_hierarchy / vlan.",
            )

        l2vn_api = (
            f"/dna/intent/api/v1/sda/layer2VirtualNetworks"
            f"?fabricId={fabric_id}&vlanId={vlan}"
        )
        try:
            l2vn_raw = get_catc_api(dnac, l2vn_api, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"CatC layer2VirtualNetworks call failed: {type(e).__name__}: {e}",
            )

        l2vn_resp = (l2vn_raw or {}).get("response") or []
        if not l2vn_resp:
            return CheckResult(
                CheckStatus.FAIL,
                f"No layer2VirtualNetwork entry for VLAN {vlan} under fabric {fabric_id}. "
                f"Confirm the VLAN is provisioned in this fabric site.",
            )

        vlan_name = l2vn_resp[0].get("vlanName")
        if not vlan_name:
            return CheckResult(
                CheckStatus.FAIL,
                f"layer2VirtualNetworks response has no vlanName for VLAN {vlan}.",
            )

        vn_name = "INFRA_VN" if is_infravn else vrf
        pool_api = (
            f"/dna/intent/api/v1/business/sda/virtualnetwork/ippool"
            f"?siteNameHierarchy={site_hierarchy}"
            f"&virtualNetworkName={vn_name}"
            f"&ipPoolName={vlan_name}"
        )
        try:
            pool_data = get_catc_api(dnac, pool_api, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"CatC virtualnetwork/ippool call failed: {type(e).__name__}: {e}",
            )

        if not pool_data:
            return CheckResult(
                CheckStatus.FAIL,
                f"No pool details returned for VN '{vn_name}', pool '{vlan_name}'.",
            )

        ctx.state["pool_info"] = pool_data
        ctx.state["pool_vlan_name"] = vlan_name

        if pool_data.get("isLayer2OnlyPool") is True:
            return CheckResult(
                CheckStatus.FAIL,
                "Pool is Layer-2 only — DHCP traffic-flow validation requires an "
                "Anycast Gateway. The rest of the chain cannot proceed against this pool.",
                data={"pool": vlan_name, "vn": vn_name, "isLayer2OnlyPool": True},
            )

        ippoolname = pool_data.get("vlanName", pool_data.get("ipPoolName", "Unknown"))
        pooltype = pool_data.get("poolType", pool_data.get("trafficType", "DATA"))
        vlan_id_api = pool_data.get("vlanId", "Unknown")

        return CheckResult(
            CheckStatus.OK,
            f"IP pool '{ippoolname}' (VN '{vn_name}', VLAN {vlan_id_api}) — type '{pooltype}', "
            f"Anycast Gateway.",
            data={
                "pool": ippoolname,
                "vn": vn_name,
                "vlan": vlan_id_api,
                "pool_type": pooltype,
            },
        )


class DhcpParameters(Check):
    """DHCP — collect global DHCP/snooping/relay/SVI parameters on the XTR.

    Collection only. Each sub-validation that dhcp_parameters_validation() runs
    in the CLI is now its own Check below, so the UI shows them one-by-one.
    """

    name = "DHCP parameters collection (service/snooping/relay/SVI)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        vlan = ctx.payload.get("vlan")
        port = ctx.state.get("xtr_port")

        if not (service and hostname and vlan and port):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — required state missing (service / xtr_hostname / vlan / xtr_port).",
            )

        try:
            from switchingmodules.dhcp import DHCPDevice
            info = DHCPDevice(hostname)
            info.service_dhcp(service)
            info.dhcpsnooping(service)
            info.dhcpsnoopingacl(service)
            info.dhcpsnoopingstats(service)
            info.dhcpsnoopingbindings(vlan, service)
            info.dhcprelayconfiguration(service)
            info.svi_configuration(vlan, service)
            info.svi_running_config(vlan, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"DHCP parameter collection failed on {hostname}: {type(e).__name__}: {e}",
            )

        ctx.state["dhcpparameters_info"] = info
        return CheckResult(
            CheckStatus.OK,
            f"Collected DHCP service / snooping / relay / SVI parameters on {hostname} "
            f"for VLAN {vlan} / interface {port}.",
        )


class _DhcpGroup(Check):
    """Base for the 3 DHCP grouped validation Checks.

    Each subclass implements `rules(info, vlan, port)` returning a list of
    (label, ok_bool, message) tuples. The group as a whole FAILs on the first
    rule with ok=False (message becomes the headline); on full pass the message
    is a compact "<n>/<n> rules passed" with per-rule lines in the body for the
    UI panel.
    """

    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        info = ctx.state.get("dhcpparameters_info")
        vlan = ctx.payload.get("vlan")
        port = ctx.state.get("xtr_port")
        if not info or not vlan or not port:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — dhcpparameters_info / vlan / xtr_port not available.",
            )
        try:
            rules = self.rules(info, vlan, port)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"{self.name} raised {type(e).__name__}: {e}",
            )

        lines = []
        first_fail = None
        for label, ok, msg in rules:
            mark = "✓" if ok else "✗"
            lines.append(f"{mark} {label}: {msg}")
            if not ok and first_fail is None:
                first_fail = (label, msg)

        body = "\n".join(lines)
        if first_fail is not None:
            return CheckResult(
                CheckStatus.FAIL,
                f"{first_fail[0]} — {first_fail[1]}\n\n{body}",
            )
        return CheckResult(
            CheckStatus.OK,
            f"{len(rules)}/{len(rules)} rules passed\n\n{body}",
        )

    def rules(self, info, vlan, port):
        raise NotImplementedError


class DhcpSnoopingValidation(_DhcpGroup):
    """Group: service dhcp + DHCP snooping global/VLAN/operational/option82/trust/ACL/stats."""

    name = "DHCP — service & snooping"

    def rules(self, info, vlan, port):
        from traffic_flows.dhcp_troubleshooting import expand_port
        dev = info.device
        results = []

        results.append((
            "service dhcp",
            info.servicedhcp is not False,
            f"enabled on '{dev}'" if info.servicedhcp is not False
            else f"disabled on '{dev}' — configure \"service dhcp\".",
        ))
        results.append((
            "snooping global",
            info.dhcpsnoop_global_enabled is not False,
            f"globally enabled on '{dev}'" if info.dhcpsnoop_global_enabled is not False
            else f"globally disabled on '{dev}' — configure \"ip dhcp snooping\".",
        ))
        in_cfg = int(vlan) in (info.dhcpsnoop_configured_vlans or [])
        results.append((
            "snooping on VLAN",
            in_cfg,
            f"enabled for VLAN {vlan} on '{dev}'" if in_cfg
            else f"disabled for VLAN {vlan} — configure \"ip dhcp snooping vlan {vlan}\".",
        ))
        in_op = int(vlan) in (info.dhcpsnoop_operational_vlans or [])
        results.append((
            "snooping operational",
            in_op,
            f"operational for VLAN {vlan} on '{dev}'" if in_op
            else f"configured but not operational for VLAN {vlan} on '{dev}' — "
                 f"VLAN may be unconfigured/shut or have no STP-forwarding ports.",
        ))
        proxy_on = int(vlan) in (info.dhcpsnoop_operational_vlans_proxy or [])
        results.append((
            "snooping proxy-bridge",
            True,
            f"enabled for VLAN {vlan} on '{dev}'" if proxy_on
            else f"disabled for VLAN {vlan} on '{dev}' (typical — required only for Bridge-Mode VMs / multi-IP).",
        ))
        results.append((
            "option 82 insertion",
            info.option82_insertion is not False,
            f"enabled on '{dev}'" if info.option82_insertion is not False
            else f"disabled on '{dev}' — configure \"ip dhcp snooping information option\".",
        ))
        expanded = expand_port(port)
        trusted = (info.trust_interfaces or [])
        results.append((
            "interface trust",
            expanded not in trusted,
            f"{port} is not snooping-trusted on '{dev}' (expected)" if expanded not in trusted
            else f"{port} is snooping-trusted on '{dev}' — may block Option 82 insertion. "
                 f"Remove with \"no ip dhcp snooping trust\".",
        ))
        results.append((
            "snooping ACL",
            True,
            f"none configured on '{dev}'" if info.dhcpsnoopacl is None
            else f"ACL '{info.dhcpsnoopacl}' present on '{dev}' — review the MAC ACL manually "
                 f"(no automated validation).",
        ))
        stats = getattr(info, "packets_dropped_because", None) or {}
        offenders = {r: c for r, c in stats.items() if c and c > 0}
        if offenders:
            details = ", ".join(f"{r}={c}" for r, c in offenders.items())
            results.append((
                "snooping drops",
                True,
                f"non-zero counters on '{dev}': {details}. Counters are historic — confirm via "
                f"'show ip dhcp snooping statistic details' that they aren't actively incrementing.",
            ))
        else:
            results.append(("snooping drops", True, f"all counters zero on '{dev}'."))

        return results


class DhcpRelayValidation(_DhcpGroup):
    """Group: global DHCP relay information option / vpn / trust-all."""

    name = "DHCP — relay (information option / vpn / trust-all)"

    def rules(self, info, vlan, port):
        dev = info.device
        results = []
        results.append((
            "relay information option",
            info.dhcprelayinformationoption is True,
            f"configured on '{dev}'" if info.dhcprelayinformationoption is True
            else f"not configured on '{dev}' — may prevent Option 82 preservation. "
                 f"Configure \"ip dhcp relay information option\".",
        ))
        results.append((
            "relay information option vpn",
            info.dhcprelayinformationoptionvpn is not True,
            f"not set on '{dev}' (expected)" if info.dhcprelayinformationoptionvpn is not True
            else f"set on '{dev}' — conflicts with LISP-based Option 82. "
                 f"Remove \"ip dhcp relay information option vpn\".",
        ))
        results.append((
            "relay trust-all",
            info.dhcprelayinformationtrustall is not True,
            f"not set on '{dev}' (expected)" if info.dhcprelayinformationtrustall is not True
            else f"set on '{dev}' — prevents Option 82 insertion on any interface. "
                 f"Remove \"ip dhcp relay information option trust-all\".",
        ))
        return results


class SviValidation(_DhcpGroup):
    """Group: SVI operational / primary IP / CEF / helper / helper-VRF / source-interface / same-subnet."""

    name = "SVI — operational / addressing / helpers"

    def rules(self, info, vlan, port):
        from ipaddress import ip_network, ip_address
        dev = info.device
        results = []

        oper_ok = (info.svienabled is not False) and (info.svioperational == 'up')
        results.append((
            "svi operational",
            oper_ok,
            f"VLAN {vlan} SVI up on '{dev}'" if oper_ok
            else f"VLAN {vlan} SVI not operationally enabled on '{dev}' — may be admin-shut "
                 f"or have no STP-forwarding ports.",
        ))
        results.append((
            "svi primary ip",
            info.prefix is not None,
            f"{info.prefix}/{info.mask} on '{dev}'" if info.prefix is not None
            else f"no primary IP on VLAN {vlan} SVI of '{dev}'.",
        ))
        results.append((
            "svi cef",
            info.cef_state is True,
            f"enabled on '{dev}'" if info.cef_state is True
            else f"disabled on VLAN {vlan} SVI of '{dev}' — configure \"ip route-cache same-interface\".",
        ))
        has_helpers = bool(info.helper_address) and len(info.helper_address) > 0
        results.append((
            "helper-address present",
            has_helpers,
            f"{info.helper_address} on '{dev}'" if has_helpers
            else f"no helper-address on VLAN {vlan} SVI — required for Anycast Gateway DHCP.",
        ))
        svivrf = info.svivrf
        bad = [h for h in (info.helper_addresses or []) if h.get('vrf') != svivrf]
        results.append((
            "helper-address vrf",
            not bad,
            f"all helpers in SVI VRF '{svivrf}'" if not bad
            else f"helper {bad[0]['dhcpserverip']} in VRF '{bad[0]['vrf']}' instead of "
                 f"SVI VRF '{svivrf}' on '{dev}'.",
        ))
        si_ok = True
        si_msg = "no conflicting source-interface/vpn-id config."
        expected_vlan = "Vlan" + str(vlan)
        for cmd in (info.ip_dhcp_commands or []):
            if "vpn-id" in cmd:
                si_ok = False
                si_msg = (f"VPN-ID option set on VLAN {vlan} SVI — conflicts with LISP-based "
                          f"Option 82. Remove \"ip dhcp relay information option vpn-id\".")
                break
            if "source-interface" in cmd and expected_vlan not in cmd:
                si_ok = False
                si_msg = (f"non-standard relay source-interface ({cmd!r}). Not supported in "
                          f"SD-Access fabrics. Remove \"ip dhcp relay source-interface\".")
                break
        results.append(("svi relay source/vpn-id", si_ok, si_msg))

        same_subnet_ok = True
        same_subnet_msg = "no helper-address overlaps the SVI subnet."
        if info.prefix and info.mask and info.helper_addresses:
            try:
                svi_net = ip_network(f"{info.prefix}/{info.mask}", strict=False)
                for helper in info.helper_addresses:
                    ip = helper.get('dhcpserverip')
                    if ip and ip_address(ip) in svi_net:
                        same_subnet_ok = False
                        same_subnet_msg = (f"helper '{ip}' is in the same subnet as the SVI ({svi_net}) "
                                           f"on '{dev}'. Same-subnet DHCP servers are not supported in "
                                           f"SD-Access; they must sit inside the fabric under an L2-Only Pool.")
                        break
            except ValueError as e:
                same_subnet_ok = False
                same_subnet_msg = f"could not parse SVI subnet on '{dev}': {e}"
        results.append(("svi same-subnet helper", same_subnet_ok, same_subnet_msg))

        return results


def _build_edge_shim(ctx: RunContext):
    """Compose a SimpleNamespace mirroring the legacy edge_node_device.

    Legacy functions reach into edge_node_device.profiled_device.{hostname,
    mgmtip, dnac, fabric_id, fabric_site_hierarchy, ispubsub, loopback,
    isfabric, edge, l2handoff, iborder} and edge_node_device.{hostname,
    mac, vlan, mac_learning_info, loopback, localsgt, is_infravn, is_ap,
    dhcpparameters_info, lispparameters_info, sisfparameters_info}.
    """
    from types import SimpleNamespace
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


class DhcpSnoopingClientStats(Check):
    """DHCP — collect per-client DHCP snooping stats and infer DORA state.

    Mirrors dhcp_troubleshooting.edge_node.dhcpsnoopingclientstats() (line 110-117).
    Returns the DORA state, which downstream `validate_dhcp_server_compatibility`
    consumes to flag mid-handshake stalls.
    """

    name = "DHCP snooping client stats (DORA state)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        mac = ctx.payload.get("mac")
        dhcp_info = ctx.state.get("dhcpparameters_info")
        if not (service and hostname and mac and dhcp_info):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — requires service / xtr_hostname / mac / dhcpparameters_info.",
            )
        anycastgw = getattr(dhcp_info, "prefix", None)
        helpers = getattr(dhcp_info, "helper_address", None) or []

        try:
            from switchingmodules.dhcp import DHCPDevice
            stats = DHCPDevice(hostname)
            _, dora_state = stats.dhcpsnoopclientstat(mac, anycastgw, helpers, service, 0)
        except BaseException as e:
            return _legacy_fail(e, "dhcpsnoopclientstat")

        ctx.state["dora_state"] = dora_state
        return CheckResult(
            CheckStatus.OK,
            f"DORA state inferred from DHCP snooping client stats: {dora_state}.",
            data={"dora_state": str(dora_state)},
        )


class LocalPolicies(Check):
    """DHCP — RACL / VACL / PACL evaluation in the DHCP path.

    Mirrors dhcp_troubleshooting.edge_node.raclvaclpacl() (line 120-124) +
    the acl_hit_procedure loop at line 2056-2057.
    """

    name = "Local policies (RACL / VACL / PACL)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        vlan = ctx.payload.get("vlan")
        port = ctx.state.get("xtr_port")
        dhcp_info = ctx.state.get("dhcpparameters_info")

        if not (service and hostname and vlan and port and dhcp_info):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — requires dhcpparameters_info / xtr_port / vlan.",
            )

        try:
            from traffic_flows.dhcp_troubleshooting import local_policies, acl_hit_procedure
            acls, vacls = local_policies(dhcp_info, hostname, vlan, port, service, 0)
        except BaseException as e:
            return _legacy_fail(e, "local_policies")

        shim = _build_edge_shim(ctx)
        try:
            for acl in (acls or []):
                acl_hit_procedure(shim, acl, service, 0)
        except BaseException as e:
            return _legacy_fail(e, "acl_hit_procedure")

        ctx.state["edgeacls"] = acls or []
        ctx.state["edgevacls"] = vacls or []
        return CheckResult(
            CheckStatus.OK,
            f"Local policies evaluated on {hostname} (interface {port}, VLAN {vlan}). "
            f"RACLs: {len(acls or [])}, VACLs: {len(vacls or [])}.",
            data={"acl_count": len(acls or []), "vacl_count": len(vacls or [])},
        )


class LispParameters(Check):
    """DHCP — LISP IID / instance / database / map-cache + SISF + edge validation.

    Mirrors dhcp_troubleshooting.edge_node.lispparameters() + sisf_parameters()
    + lisp_parameters_validation_edge() (lines 145-156 and 2066-2071).
    """

    name = "LISP parameters (IID / instance / map-cache + edge validation)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        dhcp_info = ctx.state.get("dhcpparameters_info")
        mac_info = ctx.state.get("mac_learning_info")
        is_infravn = ctx.state.get("is_infravn")
        is_pubsub = ctx.state.get("is_pubsub")

        if not (service and hostname and dhcp_info and mac_info):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — requires dhcpparameters_info / mac_learning_info.",
            )

        vrf = getattr(dhcp_info, "svivrf", None)
        eids = getattr(dhcp_info, "helper_address", None) or []
        svi = getattr(dhcp_info, "prefix", None)
        vlan = getattr(mac_info, "vlan", ctx.payload.get("vlan"))

        try:
            from routingmodules.lisp import L3Device
            lisp_info = L3Device(vrf, hostname)
            lisp_info.lispiid(service)
            lisp_info.instance_properties(service)
            lisp_info.lisp_database_information(service)
            if not is_infravn:
                lisp_info.map_cache(eids, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"LISP parameter collection failed: {type(e).__name__}: {e}",
            )

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

        ctx.state["lispparameters_info"] = lisp_info
        ctx.state["sisfparameters_info"] = sisf_info
        ctx.state["lisp_iid"] = getattr(lisp_info, "iid", None)
        return CheckResult(
            CheckStatus.OK,
            f"LISP IID {ctx.state['lisp_iid']} + SISF validated for {hostname}.",
            data={"iid": str(ctx.state["lisp_iid"])},
        )


class EdgeForwarding(Check):
    """DHCP — recurse Map-Cache → CEF → underlay nexthops/ports on the XTR.

    Branches on is_infravn (CLI lines 2081-2099):
      - INFRA_VN: infra_vn_forwarding() + validate_infra_vn_underlay_nexthops()
      - non-INFRA_VN: process_map_cache_recursion() → forwarding_parameters()
    Stashes loopback/forwarding_prefixes/rlocs/ports for the next Checks.
    """

    name = "Edge node forwarding (map-cache → CEF → underlay)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        dhcp_info = ctx.state.get("dhcpparameters_info")
        lisp_info = ctx.state.get("lispparameters_info")
        is_infravn = ctx.state.get("is_infravn")
        mac = ctx.payload.get("mac")
        vlan = ctx.payload.get("vlan")
        vrf = ctx.payload.get("vrf")
        loopback = ctx.state.get("xtr_loopback")

        if not (service and hostname and dhcp_info and lisp_info and loopback):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — requires dhcpparameters_info / lispparameters_info / xtr_loopback.",
            )

        shim = _build_edge_shim(ctx)
        iid = getattr(lisp_info, "iid", None)

        try:
            if not is_infravn:
                from traffic_flows.dhcp_troubleshooting import (
                    process_map_cache_recursion,
                )
                from routingmodules.lisp import CEFForwardingState
                from traffic_flows.dhcp_troubleshooting import (
                    forwarding_parameters_recursion,
                    underlay_ports,
                )
                _, forwarding_prefixes = process_map_cache_recursion(
                    shim, mac, vlan, service, 0, iid, vrf
                )

                svivrf = getattr(dhcp_info, "svivrf", vrf)
                cefinternallist = CEFForwardingState(svivrf, hostname)
                cefinternallist.cef_resolution(forwarding_prefixes, service, 0)
                final_rlocs = forwarding_parameters_recursion(
                    cefinternallist, ctx.state.get("catc_name"), 0, hostname
                )
                cefinternallist.cef_underlay(final_rlocs, service)
                cefinternallist.underlay_phy(service)
                underlay_ports(cefinternallist.physical_interfaces, hostname, 0)

                ctx.state["forwarding_prefixes"] = forwarding_prefixes
                ctx.state["final_rlocs"] = final_rlocs
                ctx.state["underlay_ports_list"] = cefinternallist.physical_interfaces
                ctx.state["cefinternallist_info"] = cefinternallist
                msg = (
                    f"Map-cache recursion produced {len(forwarding_prefixes)} forwarding prefixes; "
                    f"resolved to {len(final_rlocs)} RLOCs over "
                    f"{len(cefinternallist.physical_interfaces)} underlay ports."
                )
            else:
                from traffic_flows.dhcp_troubleshooting import (
                    process_infra_vn_underlay_recursion,
                    validate_infra_vn_underlay_nexthops,
                )
                helpers = getattr(dhcp_info, "helper_address", None) or []
                localsgt = ctx.state.get("localsgt")
                routes, cefhops, total_phys = process_infra_vn_underlay_recursion(
                    helpers, loopback, localsgt, hostname, service, 0
                )
                validate_infra_vn_underlay_nexthops(cefhops, total_phys, hostname, service, 0)
                ctx.state["upstreamroutes"] = routes
                ctx.state["upstreamcef"] = cefhops
                ctx.state["upstreamphy"] = total_phys
                msg = (
                    f"INFRA_VN underlay recursion: {len(routes)} routes, "
                    f"{len(cefhops)} CEF hops, {len(total_phys)} physical interfaces."
                )
        except BaseException as e:
            return _legacy_fail(e, "Edge forwarding")

        return CheckResult(CheckStatus.OK, msg)


class UnderlayReachability(Check):
    """DHCP — verify reachability between Edge and destination RLOC over the underlay.

    Mirrors dhcp_troubleshooting.py:2101-2113. Skips on INFRA_VN (handled inline
    by validate_infra_vn_underlay_nexthops in EdgeForwarding) and just records
    src/dst for the upcoming border-validation Check.
    """

    name = "Underlay reachability (Edge ↔ destination RLOC)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        loopback = ctx.state.get("xtr_loopback")
        is_infravn = ctx.state.get("is_infravn")
        dhcp_info = ctx.state.get("dhcpparameters_info")

        if not (service and hostname and loopback and dhcp_info):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — requires xtr_hostname / xtr_loopback / dhcpparameters_info.",
            )

        try:
            if not is_infravn:
                from traffic_flows.dhcp_troubleshooting import rloc_reachability
                ports = ctx.state.get("underlay_ports_list") or []
                rlocs = ctx.state.get("final_rlocs") or []
                forwarding_prefixes = ctx.state.get("forwarding_prefixes") or []
                if not forwarding_prefixes:
                    return CheckResult(
                        CheckStatus.FAIL,
                        "No forwarding prefixes available — Edge forwarding did not "
                        "produce a destination RLOC.",
                    )
                rloc_reachability(ports, hostname, service, rlocs, 0)
                srcip = loopback
                dstip = forwarding_prefixes[0]["prefix"]
            else:
                srcip = loopback
                helpers = getattr(dhcp_info, "helper_address", None) or []
                if not helpers:
                    return CheckResult(
                        CheckStatus.FAIL,
                        "INFRA_VN path: no helper-address available for reachability test.",
                    )
                dstip = helpers[0]
        except BaseException as e:
            return _legacy_fail(e, "Underlay reachability")

        ctx.state["dhcp_srcip"] = srcip
        ctx.state["dhcp_dstip"] = dstip
        return CheckResult(
            CheckStatus.OK,
            f"Underlay reachability verified: {srcip} → {dstip}.",
            data={
                "srcip": srcip,
                "dstip": dstip,
                "add_nodes": [{
                    "id": "dhcp-server",
                    "role": "dhcp-server",
                    "label": "DHCP " + dstip,
                    "ip": dstip,
                    "connect_to": "xtr",
                    "edge_label": "helper",
                }],
            },
        )


class UnderlayCdpDiscovery(Check):
    """Underlay — draw a node for each CEF underlay interface using CDP info.

    For every physical interface in `underlay_ports_list` (collected by EdgeForwarding),
    ask the XTR for its CDP neighbor. If a neighbor is found, emit an `add_nodes`
    entry with the neighbor's hostname / platform / port. If no CDP neighbor is
    seen on that interface, emit a generic grey "switch" placeholder so the
    operator still sees the underlay topology fan-out from the XTR.
    """

    name = "Underlay CDP discovery (CEF underlay → neighbors)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        ports = (
            ctx.state.get("underlay_ports_list")
            or ctx.state.get("upstreamphy")
            or []
        )
        if not (service and hostname):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — requires service / xtr_hostname.",
            )
        if not ports:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no underlay ports collected (INFRA_VN path or no CEF nexthops).",
            )

        try:
            from switchingmodules.cdp import CDPinfo
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not import CDPinfo: {type(e).__name__}: {e}",
            )

        from traffic_flows.dhcp_troubleshooting import abbrev_port

        add_nodes = []
        found = 0
        unknown = 0
        for idx, port in enumerate(ports):
            neighbors = []
            try:
                cdp = CDPinfo(hostname)
                cdp.cdpneighborinterface(port, service)
                neighbors = getattr(cdp, "cdpneighbors", []) or []
            except Exception:
                neighbors = []

            node_id = f"underlay-{idx+1}"
            if neighbors:
                n = neighbors[0]
                device_id = n.get("device_id") or f"neighbor-{idx+1}"
                platform = n.get("platform") or ""
                remote = n.get("remoteinterface") or ""
                mgmt = n.get("management_addresses") or ""
                if isinstance(mgmt, dict):
                    mgmt_ip = next(iter(mgmt.keys()), "") if mgmt else ""
                elif isinstance(mgmt, list):
                    mgmt_ip = mgmt[0] if mgmt else ""
                else:
                    mgmt_ip = str(mgmt)
                label_lines = [device_id]
                if platform:
                    label_lines.append(platform)
                if mgmt_ip:
                    label_lines.append(mgmt_ip)
                add_nodes.append({
                    "id": node_id,
                    "role": "underlay-switch",
                    "label": "\n".join(label_lines),
                    "ip": mgmt_ip or None,
                    "cdp_device_id": device_id or None,
                    "connect_to": "xtr",
                    "edge_label": f"{abbrev_port(port)} ↔ {abbrev_port(remote)}" if remote else abbrev_port(port),
                })
                found += 1
            else:
                add_nodes.append({
                    "id": node_id,
                    "role": "underlay-unknown",
                    "label": f"unknown\n({abbrev_port(port)})",
                    "connect_to": "xtr",
                    "edge_label": abbrev_port(port),
                })
                unknown += 1

        ctx.state["underlay_nodes"] = add_nodes
        return CheckResult(
            CheckStatus.OK,
            f"Underlay discovery: {found} CDP neighbor(s) found, {unknown} unknown "
            f"(grey) across {len(ports)} CEF underlay interface(s).",
            data={"add_nodes": add_nodes},
        )


def _border_label(b, idx):
    return (
        getattr(b, "hostname", None)
        or getattr(getattr(b, "profiled_device", None), "hostname", None)
        or getattr(b, "mgmtip", None)
        or f"border{idx+1}"
    )


class BorderDiscovery(Check):
    """Border — lightweight discovery only. Calls CatC to list borders (one fast
    API call), emits `add_nodes` for each border immediately, and queues a
    ControlPlaneListing Check (slower) plus the per-border data-collection +
    validation + ACL chain.
    """

    name = "Border discovery (fabric site)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        dnac = ctx.state.get("catc_name")
        fabric_id = ctx.state.get("fabric_id")

        if not (service and dnac and fabric_id):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — requires catc_name / fabric_id from earlier checks.",
            )

        try:
            from traffic_flows.iptransit import in_site_fabric_borders
            l3_borders = in_site_fabric_borders(0, fabric_id, dnac, service) or []
        except BaseException as e:
            return _legacy_fail(e, "Border discovery")

        ctx.state["l3_borders_raw"] = l3_borders
        ctx.state["border_objects"] = []  # populated by BorderCollect runs

        add_nodes = []
        followups: list[Check] = [ControlPlaneListing()]
        # Per-idx followup registry so BorderCollect can retarget Validate/Acl
        # after deciding (post-profile) whether a border merged into an
        # underlay node by CDP-hostname match.
        border_followups: dict = {}
        ctx.state["border_followups"] = border_followups

        # Draw a border node per discovered border; label = mgmt IP until
        # BorderCollect relabels it with the hostname.
        for idx, b in enumerate(l3_borders):
            bid = f"border-{idx+1}"
            mgmt = b.get("managementIpAddress") or f"border{idx+1}"
            status = (b.get("status") or "").strip().lower()
            add_nodes.append({
                "id": bid,
                "role": "border",
                "label": mgmt,
                "ip": b.get("managementIpAddress") or None,
                "connect_to": "xtr",
                "edge_label": "fabric",
            })
            if status == "reachable":
                collect = BorderCollect(idx=idx, border_id=bid, mgmt=mgmt)
                validate = BorderValidate(idx=idx, border_id=bid, mgmt=mgmt)
                acl = BorderAclCheck(idx=idx, border_id=bid, mgmt=mgmt)
                border_followups[idx] = {"validate": validate, "acl": acl}
                followups.append(collect)
                followups.append(validate)
                followups.append(acl)

        # After all per-border work, run the fabric-wide steps.
        followups.append(MultiBorderValidation())
        followups.append(DhcpServerCompatibility())

        reachable = sum(
            1 for b in l3_borders if (b.get("status") or "").strip().lower() == "reachable"
        )
        return CheckResult(
            CheckStatus.OK,
            f"Discovered {len(l3_borders)} border(s) ({reachable} reachable).",
            data={
                "border_count": len(l3_borders),
                "add_nodes": add_nodes,
                "queue_checks": followups,
            },
        )


class ControlPlaneListing(Check):
    """Control planes — profile each fabric CP (device profiler + LISP ops). This
    is slower than border listing because each CP gets a CLI/RADKIT roundtrip,
    so it's its own Check that runs after the borders have already drawn.
    """

    name = "Control plane listing (profile each fabric CP)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        dnac = ctx.state.get("catc_name")
        fabric_id = ctx.state.get("fabric_id")
        iid = ctx.state.get("lisp_iid")
        if not (service and dnac and fabric_id):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — requires catc_name / fabric_id.",
            )
        try:
            from traffic_flows.iptransit import validate_control_plane_status
            control_planes = validate_control_plane_status(
                fabric_id, iid, dnac, service, 0,
            ) or []
        except BaseException as e:
            return _legacy_fail(e, "Control plane listing")

        ctx.state["control_planes"] = control_planes
        add_nodes = []
        for cp_idx, cp in enumerate(control_planes):
            cphost = (
                getattr(cp, "hostname", None)
                or getattr(getattr(cp, "profiled_device", None), "hostname", None)
                or getattr(cp, "mgmtip", None)
                or f"cp{cp_idx+1}"
            )
            add_nodes.append({
                "id": f"cp-{cp_idx+1}",
                "role": "control-plane",
                "label": cphost,
                "ip": getattr(cp, "mgmtip", None) or None,
                "connect_to": "xtr",
                "edge_label": "LISP",
            })
        return CheckResult(
            CheckStatus.OK,
            f"Profiled {len(control_planes)} control-plane(s).",
            data={"add_nodes": add_nodes},
        )


class BorderCollect(Check):
    """Per-border — calls _fetch_single_border_data for ONE border. The slow part
    (CLI parsing, BGP/CEF/LISP/ACL collection) but scoped to one border so the
    other borders aren't blocked behind it.
    """

    def __init__(self, idx: int, border_id: str, mgmt: str):
        self.idx = idx
        self.target_node_id = border_id
        self.mgmt = mgmt
        self.name = f"Border data collection [{mgmt}]"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        dnac = ctx.state.get("catc_name")
        fabric_id = ctx.state.get("fabric_id")
        vrf = ctx.payload.get("vrf")
        vlan = ctx.payload.get("vlan")
        srcip = ctx.state.get("dhcp_srcip")
        dstip = ctx.state.get("dhcp_dstip")
        iid = ctx.state.get("lisp_iid")
        l3_borders = ctx.state.get("l3_borders_raw") or []
        control_planes = ctx.state.get("control_planes") or []

        if not (service and l3_borders and self.idx < len(l3_borders)):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — border discovery state missing.",
            )

        border_dict = l3_borders[self.idx]
        try:
            from traffic_flows.iptransit import _fetch_single_border_data
            bobj = _fetch_single_border_data(
                border_dict, fabric_id=fabric_id, vrf=vrf, vlanid=vlan,
                srcip=srcip, dstip=dstip, service=service, isdhcp=True,
                iid=iid, catc_name=dnac, control_planes=control_planes, step=0,
            )
        except BaseException as e:
            return _legacy_fail(e, f"Border data collection [{self.mgmt}]")

        if bobj is None:
            return CheckResult(
                CheckStatus.SKIP,
                f"Border '{self.mgmt}' was not reachable — skipping collection.",
            )

        bobjs = ctx.state.setdefault("border_objects", [])
        # Keep the list index-aligned with l3_borders so later checks can find it.
        while len(bobjs) <= self.idx:
            bobjs.append(None)
        bobjs[self.idx] = bobj

        hostname = getattr(
            getattr(bobj, "profiled_device", None), "hostname", None,
        ) or self.mgmt
        catc_hostname = getattr(
            getattr(bobj, "profiled_device", None), "catc_hostname", None,
        )
        btype = getattr(bobj, "type", "") or "unknown"
        # Pull the profiled RLOC (Loopback0) so the node carries the same
        # identity the Edge node shows after its own profiling.
        rloc = getattr(bobj, "rloc", None) or getattr(
            getattr(bobj, "profiled_device", None), "rloc", None,
        )
        # Hostname-based merge: match CatC's `hostname` (real configured
        # hostname / CDP-advertised) against each underlay node's CDP
        # `device_id`. If they match, fold this border node into that underlay
        # node — the underlay was the same physical device all along.
        def _norm(s):
            if not s:
                return ""
            s = str(s).lower()
            # Strip domain suffix so "edge1.sdawest.com" matches "edge1".
            return s.split(".", 1)[0]

        merge_into = None
        match_key = _norm(catc_hostname)
        if match_key:
            for u in (ctx.state.get("underlay_nodes") or []):
                if _norm(u.get("cdp_device_id")) == match_key:
                    merge_into = u.get("id")
                    break

        # Retarget Validate / AclCheck for this border so subsequent check
        # status / messages land on the merged node.
        if merge_into:
            followups = (ctx.state.get("border_followups") or {}).get(self.idx, {})
            for chk in followups.values():
                chk.target_node_id = merge_into

        # Display name on the node: prefer the real CDP/CatC hostname over the
        # RADKIT inventory name.
        display_name = catc_hostname or hostname
        # Tag preserved across the relabel so the Border role stays visible on
        # nodes that were merged with a CDP next-hop.
        tags = ["Border"]
        result_data = {
            "node_relabel": display_name,
            "node_tags": tags,
        }
        if rloc:
            result_data["node_rloc"] = rloc
        if merge_into:
            result_data["merge_into"] = {
                "source": self.target_node_id,
                "target": merge_into,
                "edge_label": "fabric",
            }
        return CheckResult(
            CheckStatus.OK,
            f"Collected data for border '{display_name}' ({self.mgmt}) — type={btype}.",
            data=result_data,
        )


class BorderValidate(Check):
    """Per-border — runs individual_border_validations for ONE border. Wraps the
    full 16-step legacy validation in a single Check so the per-border icon flips
    once all validations have run (or fails fast on sys.exit).
    """

    def __init__(self, idx: int, border_id: str, mgmt: str):
        self.idx = idx
        self.target_node_id = border_id
        self.mgmt = mgmt
        self.name = f"Border validation [{mgmt}]"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        bobjs = ctx.state.get("border_objects") or []
        bobj = bobjs[self.idx] if self.idx < len(bobjs) else None
        if not (service and bobj):
            return CheckResult(
                CheckStatus.SKIP,
                f"Skipped — no hydrated border object for '{self.mgmt}'.",
            )
        try:
            from traffic_flows.iptransit import individual_border_validations
            individual_border_validations(bobj, 0, service)
        except BaseException as e:
            return _legacy_fail(e, f"Border validation [{self.mgmt}]")
        return CheckResult(
            CheckStatus.OK,
            f"Border '{self.mgmt}' passed individual validations (anycast GW, PETR, "
            f"CP logic, VRF, BGP summary/neighbors/policies, advertised prefix, "
            f"source recursion, dest non-LISP, ping, route import, default route, "
            f"overlapping summaries, interface counters, CTS).",
        )


class BorderAclCheck(Check):
    """Per-border — validate egress ACLs on this border for the DHCP relay path."""

    def __init__(self, idx: int, border_id: str, mgmt: str):
        self.idx = idx
        self.target_node_id = border_id
        self.mgmt = mgmt
        self.name = f"Border ACL validation [{mgmt}]"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        bobjs = ctx.state.get("border_objects") or []
        bobj = bobjs[self.idx] if self.idx < len(bobjs) else None
        if not (service and bobj):
            return CheckResult(
                CheckStatus.SKIP,
                f"Skipped — no hydrated border object for '{self.mgmt}'.",
            )
        try:
            from traffic_flows.dhcp_troubleshooting import validate_border_acls
            validate_border_acls([bobj], service, 0)
        except BaseException as e:
            return _legacy_fail(e, f"Border ACL validation [{self.mgmt}]")
        return CheckResult(
            CheckStatus.OK,
            f"No egress ACLs on '{self.mgmt}' that would drop the DHCP relay path.",
        )


class MultiBorderValidation(Check):
    """Fabric-wide — runs multi_border_validation across all hydrated borders."""

    name = "Multi-border validation (overlap, transit consistency)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        bobjs = [b for b in (ctx.state.get("border_objects") or []) if b is not None]
        if not (service and bobjs):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no hydrated border objects available.",
            )
        try:
            from traffic_flows.iptransit import multi_border_validation
            multi_border_validation(bobjs, 0, service)
        except BaseException as e:
            return _legacy_fail(e, "Multi-border validation")
        return CheckResult(
            CheckStatus.OK,
            f"Multi-border validation complete across {len(bobjs)} border(s).",
        )


class DhcpServerCompatibility(Check):
    """Fabric-wide — DHCP server Option-82 compatibility check using DORA state."""

    name = "DHCP server compatibility (Option 82 / DORA)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        border_objects = ctx.state.get("border_objects")
        dora_state = ctx.state.get("dora_state")
        if not (service and border_objects):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — requires border_objects from BorderProfile.",
            )
        try:
            from traffic_flows.dhcp_troubleshooting import validate_dhcp_server_compatibility
            validate_dhcp_server_compatibility(border_objects, dora_state, 0)
        except BaseException as e:
            return _legacy_fail(e, "DHCP server compatibility")
        reach = any(getattr(b, "ping_reachable", False) for b in border_objects)
        return CheckResult(
            CheckStatus.OK,
            f"DHCP server compatibility check complete. DORA state: {dora_state or 'unknown'}; "
            f"at least one border reachable: {reach}.",
        )

