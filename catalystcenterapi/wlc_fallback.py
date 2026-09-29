"""Fabric WLC discovery that survives the /sda/fabricDevices defect.

`/dna/intent/api/v1/sda/fabricDevices?fabricId=<id>&deviceRoles=WIRELESS_CONTROLLER_NODE`
returns `{"response": []}` on some Catalyst Center releases even when a fabric
WLC *is* assigned. Trusting that empty response would report a missing
controller -- sending the operator to add config that already exists.

The CLI works around this by prompting for a management IP on stdin
(catcapi.getFabricWLC). That cannot work in the web path, which runs on a
worker thread with no console, so this rebuilds the answer from two endpoints
that are not affected:

    1. /network-device?family=Wireless Controller   -- every WLC CatC manages
    2. /business/sda/device?deviceManagementIpAddress=<ip>  -- per-device SDA
       record, including the fabric site it belongs to

Stage 2 is what makes the result trustworthy rather than "every controller in
the estate": it is how a managed WLC is tied back to *this* fabric site.
"""

from radkit_cli import get_catc_api

WLC_FAMILY = "Wireless Controller"


def list_managed_wlcs(catc, service) -> list[dict]:
    """Every Wireless Controller in the CatC inventory.

    Returns dicts with hostname/mgmt_ip/uuid. An entry with no management IP is
    dropped: stage 2 is keyed on that address, so it could not be placed in a
    fabric site anyway.
    """
    api = f"/dna/intent/api/v1/network-device?family={WLC_FAMILY.replace(' ', '%20')}"
    raw = get_catc_api(catc, api, service)
    response = (raw or {}).get("response") if isinstance(raw, dict) else None
    if not isinstance(response, list):
        return []

    wlcs = []
    for d in response:
        mgmt_ip = d.get("managementIpAddress")
        if not mgmt_ip:
            continue
        wlcs.append({
            "hostname": d.get("hostname"),
            "mgmt_ip": mgmt_ip,
            "uuid": d.get("id"),
        })
    return wlcs


def get_sda_device(mgmt_ip, catc, service) -> dict | None:
    """The SDA record for one device, or None if CatC has no inventory item.

    The endpoint answers with a `status`/`description` pair rather than an HTTP
    error when the device is not an SDA member, so an absent record is detected
    by the missing site hierarchy rather than by an exception.
    """
    api = ("/dna/intent/api/v1/business/sda/device"
           f"?deviceManagementIpAddress={mgmt_ip}")
    try:
        raw = get_catc_api(catc, api, service)
    except Exception:
        return None
    if not isinstance(raw, dict):
        return None
    # Both spellings appear across releases.
    site = raw.get("siteNameHierarchy") or raw.get("fabricSiteNameHierarchy")
    if not site:
        return None
    return raw


def _site_matches(device_site: str, target_site: str) -> bool:
    """True when an SDA record's site hierarchy is this fabric site.

    Compared case-insensitively and without surrounding whitespace. A device
    deeper in the hierarchy (a building under the fabric site) still belongs to
    it, so a prefix match on a hierarchy boundary counts.
    """
    if not (device_site and target_site):
        return False
    d, t = device_site.strip().lower(), target_site.strip().lower()
    return d == t or d.startswith(t + "/")


def find_fabric_wlcs(catc, service, site_hierarchy):
    """Fabric WLCs for `site_hierarchy`, rebuilt from the two working endpoints.

    Returns (wlcs, reason). `wlcs` is a list of hostname/mgmt_ip dicts. When it
    is empty, `reason` says which stage came up empty -- the two failures need
    different remediation, so they are never collapsed into one message.
    """
    managed = list_managed_wlcs(catc, service)
    if not managed:
        return [], ("Catalyst Center manages no Wireless Controller at all "
                    "(/network-device?family=Wireless Controller returned "
                    "nothing). A Fabric WLC is required for an AP to onboard.")

    matched, unplaced = [], []
    for wlc in managed:
        sda = get_sda_device(wlc["mgmt_ip"], catc, service)
        if sda is None:
            unplaced.append(f"{wlc['hostname'] or '?'} ({wlc['mgmt_ip']})")
            continue
        site = sda.get("siteNameHierarchy") or sda.get("fabricSiteNameHierarchy")
        if _site_matches(site, site_hierarchy):
            matched.append({**wlc, "site": site, "roles": sda.get("roles")})

    if matched:
        return matched, ""

    if len(unplaced) == len(managed):
        return [], (
            f"Catalyst Center manages {len(managed)} Wireless Controller(s) but "
            "has no SDA inventory item for any of them, so none can be tied to a "
            "fabric site: " + ", ".join(unplaced) + ". The site details are "
            "required to continue.")

    return [], (
        f"Catalyst Center manages {len(managed)} Wireless Controller(s), but "
        f"none belongs to this fabric site ({site_hierarchy}). Assign a WLC to "
        "the fabric site in Catalyst Center.")
