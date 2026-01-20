import sys
import ipaddress
from pprint import pformat
import re
from typing import Optional, Union

from device_profiler import Device
from radkit_cli import get_hostname_from_mgmtip, logging_error, logging_info, logging_warning
from routingmodules.lisp import controlplane_eid, l2lisp_info, LISPLocalDB, L2LISPStatistics
from switchingmodules.maclearning import mac_learning
from switchingmodules.sisf import SISF
from traffic_flows.lispsessiontroubleshooting import fabricEnabledWirelessSession, singleETRLISPSessionOnlyFEW
from wirelessmodules.accesspointinfo import AccessPointInfo
from catalystcenterapi.catcapi import getFabricWLC, get_device_from_lo0, get_network_device_byuuid
from wirelessmodules.accesstunnels import AccessTunnel
from wirelessmodules.wirelesscore import WirelessControllerInfo, WirelessEndpointMac, WLANProfile

#Controller Validation - WirelessController class
# Requirements: Controller IP
'''
0) Fabric WLC Information from Catalyst Center
1) Wireless Controller Model and Version
2) HA Status
3) Is EWLC?
4) Wireless Management Interface
5) Wireless Management Trustpoint
6) Is Fabric Enabled?
'''


##Wireless Flows consist in a series of validations related to Fabric Enabled Wireless
''' Planed Modules
AP Join (Vanilla)
AP Join (Fabric Mode)
AP Uptime and Failure status
Wireless Client Fabric Onboarding
Show log parser for AP
Show log parser for Client
Fabric Wireless CP connection (LISP Session)
AP Provisioning state (WLAN broadcasting-oriented)
WLAN Fabric Provisioning State (DHCP; Central, no excessive rate limiters, no VLAN configured, ACLs)
Flex ACL and URL filters (If ACL found on the Wireless Client Onboarding module)
AP Validations (Soft-might fail if SSH is not enabled)
'''

def exit_program(step, process, subprocess, hostname, error, message):
    logging_error(step, process, subprocess, hostname, error)
    logging_info(step, process, subprocess, hostname, message)
    sys.exit("Error: {} | {}".format(error, message))

def is_ipv4(s: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv4Address)
    except ValueError:
        return False

def to_int(value: Union[str, int, float, None]) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        m = re.search(r"-?\d+", value)
        return int(m.group(0)) if m else None
    return None

def extract_control_planes_with_ip(data: dict) -> list[dict]:
    control_planes = []
    for key, value in data.items():
        if is_ipv4(key) and isinstance(value, dict):
            control_planes.append(
                {
                    "ip_address": key,
                    "name": value.get("name"),
                    "status": value.get("status"),
                    "key": value.get("key"),
                }
            )
    return control_planes

def find_l2_vnids_with_l3_vnid(data, target_l3_vnid=4097):
    matches = []
    for l2_vnid, attrs in data.get("l2_vnid", {}).items():
        if attrs.get("l3_vnid") == target_l3_vnid:
            matches.append(
                {
                    "l2_vnid": l2_vnid,
                    "name": attrs.get("name"),
                    "control_plane_name": attrs.get("control_plane_name"),
                    "ip_address": attrs.get("ip_address"),
                    "subnet": attrs.get("subnet"),
                }
            )
    return matches

def warn_if_poor_rf(step, process, subprocess, hostname, mac, rssi_dbm, snr_db, rssi_threshold_dbm=-67, snr_threshold_db=25):
    """
    Logs a warning if RSSI/SNR are below thresholds.
    Typical starting points:
      - RSSI:  -67 dBm (voice/real-time baseline)
      - SNR:   25 dB   (good baseline)
    """
    rssi = to_int(rssi_dbm)
    snr = to_int(snr_db)

    if rssi is None and snr is None:
        return step

    poor_rssi = (rssi is not None) and (rssi < rssi_threshold_dbm)
    poor_snr  = (snr is not None) and (snr < snr_threshold_db)

    if poor_rssi or poor_snr:
        msg1 = "Wireless Endpoint - RF Quality Warning"
        message = (
            f"RF quality is below recommended thresholds for endpoint {mac}: "
            f"RSSI={rssi_dbm} (parsed {rssi} dBm; threshold {rssi_threshold_dbm} dBm), "
            f"SNR={snr_db} (parsed {snr} dB; threshold {snr_threshold_db} dB). "
            f"Remediation: verify client proximity, AP placement, channel utilization/interference, "
            f"and transmit power/RRM settings."
        )
        logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1
    else:
        msg1 = "Wireless Endpoint - RF Quality OK"
        message = (
            f"RF quality is within recommended thresholds for endpoint {mac}: "
            f"RSSI={rssi_dbm} (parsed {rssi} dBm), SNR={snr_db} (parsed {snr} dB)."
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

    return step

def get_endpoint_policies(endpoint_attributes):
    ei = getattr(endpoint_attributes, "endpointinfo", None) or {}
    sm = ei.get("session_manager", {}) or {}
    rp = sm.get("resultant_policies", {}) or {}

    return {
        "URL Redirect ACL": rp.get("URL Redirect ACL"),
        "URL Redirect": rp.get("URL Redirect"),
        "VLAN Name": rp.get("VLAN Name"),
        "VLAN": rp.get("VLAN"),
        "Absolute-Timer": rp.get("Absolute-Timer"),
    }

def flex_profile_has_redirect_acl(flex_profile_obj: dict, acl_name: str) -> bool:
    flex = (flex_profile_obj or {}).get("flex_profile", {}) or {}
    rows = (((flex.get("sections", {}) or {}).get("Policy ACL", {}) or {}).get("rows", []) or [])
    for row in rows:
        if (row.get("acl_name") or "").strip() == (acl_name or "").strip():
            return True
    return False

def wlcInfoValidation(wlcinfo,step):
    process = "wlcValidation"
    subprocess = "[wlcPlatformDetails]"
    hostname = wlcinfo.hostname
    platform = wlcinfo.platform_information['platform']
    version = wlcinfo.platform_information['version']
    uptime = wlcinfo.platform_information['uptime']
    ha_state = wlcinfo.ha_information['hw_mode']
    op_ha_state = wlcinfo.ha_information['oper_red_mode']

    step += 1
    msg1 = "WLC - Platform"
    message = (
        f"Identified Fabric WLC {hostname}, model {platform} on version {version}, "
        f"uptime of {uptime}. Redundancy mode is {ha_state} operating as {op_ha_state}."
    )
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    if wlcinfo.ewlc is False:
        message = "This WLC is not an embedded Wireless LAN Controller for Catalyst switching platforms."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    if wlcinfo.ewlc is True:
        message = "This WLC is an embedded Wireless LAN Controller for Catalyst switching platforms."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    wmi_interface_info = wlcinfo.wmi_information
    try:
        wmi_interface_name = wmi_interface_info['interfaces'][0]['interfacename']
    except IndexError:
        wmi_interface_name = None

    #WMI Availability
    if wmi_interface_name is None:
        error = "WLC - WMI"
        message = f"Wireless Management Interface configuration is missing' recommendation='Use \"wireless management interface\" command to recover"
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        msg1 = "WLC - WMI"
        message = f"Wireless Management Interface configuration is present, interface name: {wmi_interface_name} No action required"
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    wm_trustpoint_info = wlcinfo.trustpoint_information
    wm_trustpoint_name = wm_trustpoint_info['trustpoint_name']
    wm_certificate_info = wm_trustpoint_info['certificate_info']

    # Wireless Management Trustpoint availability
    if wm_trustpoint_name is None:
        error = "WLC - TrustPoint"
        message = "No wireless management trustpoint found on the Wireless LAN Controller; remediation: generate and install a new wireless management certificate (trustpoint)."
        exit_program(step, process, subprocess, hostname, error, message)
    if wm_certificate_info != 'Available':
        error = "WLC - TrustPoint Certificate"
        message = f"Wireless LAN Controller management trustpoint is configured ({wm_trustpoint_name}), but certificate details are unavailable; remediation: generate and install a new certificate."
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        msg1 = "WLC - TrustPoint"
        message = f"Wireless LAN Controller management trustpoint is present ({wm_trustpoint_name}), and certificate details are available."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    # Fabric WLC Enablement:
    fabric_wlc_info = wlcinfo.fabric_state
    fabric_status = fabric_wlc_info['fabric_status']
    fabric_cps = fabric_wlc_info['control_plane']['ip_address']
    fabric_vnids = fabric_wlc_info['fabric_vnid_mapping']

    #Fabric WLC status:
    if fabric_status != 'Enabled':
        error = "WLC - Fabric Enablement"
        message = "Wireless LAN Controller is not enabled for fabric operations; remediation: configure 'wireless fabric':"
        exit_program(step, process, subprocess, hostname, error, message)

    #Fabric CPs configuration:
    parsed_cps = extract_control_planes_with_ip(fabric_cps)
    if len(parsed_cps) == 0:
        error = "WLC - Fabric Control Planes"
        message = "No LISP control planes are defined on the WLC; remediation: configure them under `wireless fabric control-plane`."
        exit_program(step, process, subprocess, hostname, error, message)

    #INFRA_VN Configuration
    infra_vn_vnids = find_l2_vnids_with_l3_vnid(fabric_vnids)
    if len(infra_vn_vnids) == 0:
        error = "WLC - Fabric VNIDs"
        message = "INFRA-VN VNID (L3 4097) is not defined on the WLC; remediation: configure the INFRA-VN L3 VNID."
        exit_program(step, process, subprocess, hostname, error, message)

    else:
        msg1 = "WLC - Fabric Enablement"
        message = (
            f"The WLC is enabled for fabric operation and has the following control plane IPs configured: "
            f"{parsed_cps}. The following L2 VNIDs are used for INFRA_VN (L3 VNID 4097): {infra_vn_vnids}."
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    return parsed_cps, infra_vn_vnids, step

def wlcInfo(fabric_id,step,catc,service):
    wlcmgmtip = getFabricWLC(fabric_id,catc,service,step)
    hostname = get_hostname_from_mgmtip(wlcmgmtip,service)
    wlc_attributes = WirelessControllerInfo(hostname)
    wlc_attributes.initial_commands(service)

    return wlc_attributes

def wlcEndpointValidation(step, wlcname, endpoint_attributes,ewlcflag, service):
    hostname = wlcname
    mac = endpoint_attributes.mac
    process = "wirelessClient"
    subprocess = "[wirelessClient]"
    step += 1
    msg1 = "WLC - Wireless Client"
    message = (
        f"Collecting information for endpoint {mac} on Fabric WLC {hostname}"
    )
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    #0) Is the wireless endpoint under client exclusion list?
    excl = getattr(endpoint_attributes, "exclusionlist", None) or {}

    excl_client = excl.get("client", {}) or {}
    exclusion = excl_client.get("state")

    if exclusion and "Excluded" in exclusion:
        ap = (excl.get("ap", {}) or {}).get("name", "N/A")
        wlan = (excl.get("wlan", {}) or {}).get("wlan_name", "N/A")
        reason = excl_client.get("exclusion_reason", "N/A")
        authentication = excl_client.get("authentication_method", "N/A")

        error = "Wireless Endpoint - Excluded Client"
        message = (
            f"Wireless endpoint {mac} is excluded while attempting to join AP {ap} on WLAN {wlan} "
            f"using {authentication}; exclusion reason: {reason}. Remediation: review WLC logs (show logging) "
            f"to identify the specific exclusion trigger and address the underlying cause."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    #1) Is the wireless endpoint under client list?
    endpointinfo = getattr(endpoint_attributes, "endpointinfo", None) or {}
    wclient = (endpointinfo.get("client", {}) or {}).get("mac_address")

    if wclient is None:
        error = "Wireless Endpoint - Absent Client"
        message = (
            f"Wireless endpoint {mac} was not found on the WLC and is not listed in the exclusion list. "
            f"Remediation: rerun the script while the endpoint is connected and visible as a wireless client. "
            f"If the endpoint still does not appear, investigate join/association failures or missing FlexConnect "
            f"objects on the AP (IPv4/IPv6 ACLs, URL filters, QoS policies, etc.)."
        )
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        msg1 = "Wireless Endpoint - Present Client"
        message = (
            f"Wireless endpoint {mac} is present on the WLC as an active wireless client and is not listed in the "
            f"exclusion list. No remediation is required at this time; proceed with validation of client state, "
            f"policy assignment, and connectivity."
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    #2) Is the wireless endpoint in RUN/WebAuthPending/IP Learn state?
    policymanagerstate = (endpointinfo.get("client", {}) or {}).get("policy_manager_state")
    state = (policymanagerstate or "").strip()
    if 'Assoc' in state:
        error = "Wireless Endpoint - Associating Client"
        message = (
            f"Wireless endpoint {mac} is stuck in the Association state and is not completing authentication"
            f"Remediation: check WLC logs (show logging) and client detail for join/auth failures; verify WLAN security "
            f"(PSK/802.1X), AAA reachability, and policy profile configuration; confirm the AP is operational and has "
            f"RF connectivity"
        )
        exit_program(step, process, subprocess, hostname, error, message)
    elif "Authen" in state:
        error = "Wireless Endpoint - Authenticating Client"
        message = (
            f"Wireless endpoint {mac} is stuck in the Authentication state and is not completing the authentication exchange. "
            f"Remediation: verify WLAN security settings (PSK/802.1X) match the client, confirm AAA/RADIUS servers are reachable "
            f"and returning Access-Accept, review WLC logs (show logging) for authentication errors, and validate any required "
            f"policies applied during authentication."
        )
        exit_program(step, process, subprocess, hostname, error, message)
    elif "IP" in state:
        msg1 = "Wireless Endpoint - IP Learn Client"
        message = (
            f"Wireless endpoint {mac} is currently in IP Learn state; proceeding with validation while the controller completes "
            f"IP addressing and policy application."
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    elif "Web" in state:
        msg1 = "Wireless Endpoint - Web Auth Pending Client"
        message = (
            f"Wireless endpoint {mac} is currently in WebAuth Pending state; proceeding while web authentication/redirect is completed."
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    elif "Run" in state:
        msg1 = "Wireless Endpoint - RUN Client"
        message = (
            f"Wireless endpoint {mac} is in Run state; proceeding with connectivity and policy validation."
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    else:
        msg1 = "Wireless Endpoint - Unknown Policy State"
        message = f"Wireless endpoint {mac} is in an unrecognized Policy Manager state '{state}'; proceeding."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    #RF Parameters
    client = endpointinfo.get("client", {}) or {}
    ap = endpointinfo.get("ap", {}) or {}
    stats = endpointinfo.get("statistics", {}) or {}

    ap_name = ap.get("name")
    ap_mac = ap.get("mac_address")
    bssid = ap.get("bssid")

    protocol = client.get("protocol")
    channel = client.get("channel")
    current_rate = client.get("current_rate")

    rssi_dbm = stats.get("rssi_dbm")
    snr_db = stats.get("snr_db")

    msg1 = "Wireless Endpoint - RF Summary"
    message = (
        f"RF summary for {mac}: AP={ap_name} (ap_mac={ap_mac}, bssid={bssid}), "
        f"protocol={protocol}, channel={channel}, rssi={rssi_dbm} dBm, snr={snr_db} dB, "
        f"current_rate={current_rate}."
    )
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    step = warn_if_poor_rf(step,process,subprocess,hostname,mac,rssi_dbm,snr_db)

    #3) Is the wireless endpoint connected to a fabric ap?
    apcgral = AccessPointInfo(wlcname)
    apcgral.apconfiggeneral(ap_name,service)
    apcgral.fabric_status(ap_name,service)

    apconfigattributes = getattr(apcgral, "apconfiggeneral", None) or {}
    ap_ip = (apconfigattributes.get("ap_name", {}) or {}).get(ap_name).get("ip_address")
    ap_mask = (apconfigattributes.get("ap_name", {}) or {}).get(ap_name).get("ip_netmask")
    ap_ptag = (apconfigattributes.get("ap_name", {}) or {}).get(ap_name).get("policy_tag_name")
    ap_stag = (apconfigattributes.get("ap_name", {}) or {}).get(ap_name).get("site_tag_name")
    ap_rftag = (apconfigattributes.get("ap_name", {}) or {}).get(ap_name).get("rf_tag_name")
    ap_flexprof = (apconfigattributes.get("ap_name", {}) or {}).get(ap_name).get("flex_profile")
    ap_joinprof = (apconfigattributes.get("ap_name", {}) or {}).get(ap_name).get("ap_join_profile")
    ap_mode = (apconfigattributes.get("ap_name", {}) or {}).get(ap_name).get("ap_mode")
    ap_model = (apconfigattributes.get("ap_name", {}) or {}).get(ap_name).get("ap_model")
    ap_version =  (apconfigattributes.get("ap_name", {}) or {}).get(ap_name).get("ios_version")
    ap_uptime = (apconfigattributes.get("ap_name", {}) or {}).get(ap_name).get("ap_up_time")
    ap_capwapuptime = (apconfigattributes.get("ap_name", {}) or {}).get(ap_name).get("ap_capwap_up_time")
    ap_fabric_status = (apconfigattributes.get("ap_name", {}) or {}).get(ap_name).get("fabric_status")
    ap_radio_mac = (apconfigattributes.get("ap_name", {}) or {}).get(ap_name).get("cisco_ap_identifier")
    ap_rloc = apcgral.rloc

        #AP platform / operational summary
    msg1 = "Access Point - Platform Summary"
    message1 = (
        f"AP {ap_name} platform summary: model={ap_model}, mode={ap_mode}, image_version={ap_version}, "
        f"radio_mac={ap_radio_mac}, management_ip={ap_ip}/{ap_mask}, uptime={ap_uptime}, "
        f"capwap_uptime={ap_capwapuptime}."
    )
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message1)

        #AP policy / profiles configuration
    msg2 = "Access Point - Policy and Profiles"
    message2 = (
        f"AP {ap_name} configuration: policy_tag={ap_ptag}, site_tag={ap_stag}, rf_tag={ap_rftag}, "
        f"flex_profile={ap_flexprof}, ap_join_profile={ap_joinprof}."
    )
    logging_info(step, process, subprocess, hostname, msg2+ " | " + message2)

        #AP fabric status
    msg3 = "Access Point - Fabric Status"
    message3 = (
        f"AP {ap_name} fabric status: fabric={ap_fabric_status}, rloc={ap_rloc}."
    )
    logging_info(step, process, subprocess, hostname, msg3 + " | " + message3)

    if (ap_fabric_status or "").strip().lower() == "disabled":
        msg1 = "Access Point - Fabric Disabled"
        message = (
            f"AP {ap_name} fabric status is disabled. "
            f"Remediation: verify fabric enablement for the AP and WLAN, confirm site/policy tags, and validate fabric control-plane reachability."
        )
        logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)

    #4) Is the wireless endpoint connected to a fabric ssid with the correct parameters? (Central Auth, Local SW, no Mobility, no VLAN if not EWLC)
    #Get WLAN Attributes (WLAN/PP/FLEX/FABRIC)
    wlan = endpointinfo.get("wlan", {}) or {}
    wlanid = wlan.get("wlan_id")
    wlanpp = wlan.get("policy_profile")
    wlanflp = wlan.get("flex_profile")

    wlan_set = WLANProfile(wlcname)
    wlan_set.wlanprofile(wlanid,service)
    # Parsed object from parse_show_wlan_id(...)
    wlan_obj = wlan_set.wlanprofile
    wlan = wlan_obj.get("wlan", {}) or {}
    ft = wlan_obj.get("fast_transition", {}) or {}
    security = (wlan_obj.get("security", {}) or {}).get("global", {}) or {}

    msg = "WLAN Profile - Summary"
    message = (
        f"WLAN id={wlan.get('id')}, profile={wlan.get('profile_name')}, ssid={wlan.get('ssid')}, "
        f"status={wlan.get('status')}, auth={security.get('802.11 Authentication')}, "
        f"wmm={wlan.get('wmm')}, okc={wlan.get('okc')}. "
        f"FT={ft.get('support')}"
    )
    logging_info(step, process, subprocess, hostname, msg + " | " + message)

    wlan_set.policyprofile(wlanpp,service)
    # Parsed object from parse_show_wireless policy profile(...)
    pp = wlan_set.policyprofile.get("policy_profile", {})
    sections = (pp.get("sections", {}) or {})

    switching = sections.get("WLAN Switching Policy", {}) or {}
    acl = sections.get("WLAN ACL", {}) or {}
    qos_ssid = sections.get("QOS per SSID", {}) or {}
    qos_client = sections.get("QOS per Client", {}) or {}
    fabric = sections.get("Fabric Profile", {}) or {}
    aaa = sections.get("AAA Policy Params", {}) or {}

    msg1 = "WLAN Policy Profile - Switching and Services"
    message1 = (
        f"Policy profile {pp.get('name')}: vlan={pp.get('vlan')}, WMI_VLAN={pp.get('wireless_management_interface_vlan')}, "
        f"passive_client={pp.get('passive_client')}, static_ip_mobility={pp.get('staticip_mobility')}. "
        f"Flex switching: central_switching={switching.get('Flex Central Switching')}, "
        f"central_authentication={switching.get('Flex Central Authentication')}, "
        f"central_dhcp={switching.get('Flex Central DHCP')}."
    )
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message1)

    msg2 = "WLAN Policy Profile - ACLs and QoS"
    message2 = (
        f"Policy profile {pp.get('name')}: ACLs ipv4={acl.get('IPv4 ACL')}, ipv6={acl.get('IPv6 ACL')}, "
        f"preauth_urlfilter={acl.get('Preauth urlfilter list')}, postauth_urlfilter={acl.get('Postauth urlfilter list')}. "
        f"QoS per SSID ingress={qos_ssid.get('Ingress Service Name')}, egress={qos_ssid.get('Egress Service Name')}; "
        f"QoS per client ingress={qos_client.get('Ingress Service Name')}, egress={qos_client.get('Egress Service Name')}."
    )
    logging_info(step, process, subprocess, hostname, msg2 + " | " + message2)

    msg3 = "WLAN Policy Profile - Fabric and AAA"
    message3 = (
        f"Policy profile {pp.get('name')}: fabric_profile={fabric.get('Profile Name')}; "
        f"AAA override={aaa.get('AAA Override')}, NAC={aaa.get('NAC')} ({aaa.get('NAC Type')}), "
        f"ip_mac_binding={pp.get('ip_mac_binding')}."
    )
    logging_info(step, process, subprocess, hostname, msg3 + " | " + message3)

    #Errors and Alerts
    #Non default VLAN on Policy Profile:
    vlan = pp.get("vlan")
    if ewlcflag is True and vlan not in (None, 1, "1"):
        error = "WLAN Policy Profile - VLAN Validation Failed"
        message = (
            f"Policy profile {pp.get('name')} is configured with VLAN {vlan}. "
            f"This is not supported in the current (non-embedded WLC) context. "
            f"Remediation: set the policy profile VLAN to 1 (default the VLAN configuration, vlan 'default' should not be used):"
        )
        exit_program(step, process, subprocess, hostname, error, message)

    #Fabric Profile
    fabric_profile_name = (fabric.get("Profile Name") or "").strip()

    if not fabric_profile_name or fabric_profile_name.lower() == "not configured":
        error = "WLAN Policy Profile - Missing Fabric Profile"
        message = (
            f"Policy profile {pp.get('name')} does not have a fabric profile attached. "
            f"Remediation: attach the correct fabric profile (VNID/SGT mapping) to this policy profile."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    #No Mobility Tunnels are supported in SD-Access/FEW
    if (pp.get("staticip_mobility") or "").upper() == "ENABLED":
        error = "WLAN Policy Profile - Static IP Mobility Enabled"
        message = (
            f"Policy profile {pp.get('name')} has Static IP Mobility enabled. "
            f"Remediation: disable Static IP Mobility in the policy profile unless this feature is explicitly required "
            f"for the intended roaming design."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    mobility = (pp.get("sections", {}) or {}).get("WLAN Mobility", {}) or {}
    anchor = (mobility.get("Anchor") or "").strip().upper()
    if anchor and anchor != "DISABLED":
        error = "WLAN Policy Profile - Mobility Anchor Not Supported"
        message = (
            f"Policy profile {pp.get('name')} has WLAN mobility anchoring enabled (Anchor={anchor}). "
            f"SDA does not support mobility anchors. Remediation: disable WLAN mobility anchoring for this policy profile."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    #Central SW must be disabled, Central DHCP disabled, Central Authe enabled.
    central_sw = (switching.get("Flex Central Switching") or "").upper()
    central_dhcp = (switching.get("Flex Central DHCP") or "").upper()
    central_auth = (switching.get("Flex Central Authentication") or "").upper()
    invalid = (central_sw != "DISABLED") or (central_dhcp != "DISABLED") or (central_auth != "ENABLED")

    if invalid:
        error = "WLAN Policy Profile - Flex Central Policy Validation Failed"
        message = (
            f"Policy profile {pp.get('name')} has an invalid Flex Central configuration. "
            f"Expected: central switching DISABLED, central DHCP DISABLED, central authentication ENABLED. "
            f"Found: central switching {central_sw or 'N/A'}, central DHCP {central_dhcp or 'N/A'}, "
            f"central authentication {central_auth or 'N/A'}."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    #ACL:
    ipv4_acl = (acl.get("IPv4 ACL") or "").strip()
    ipv6_acl = (acl.get("IPv6 ACL") or "").strip()
    ipv4_used = bool(ipv4_acl) and ipv4_acl.lower() != "not configured"
    ipv6_used = bool(ipv6_acl) and ipv6_acl.lower() != "not configured"

    if ipv4_used or ipv6_used:
        msg1 = "WLAN Policy Profile - ACLs In Use"
        message = (
            f"Policy profile {pp.get('name')} has WLAN ACLs configured "
            f"(ipv4_acl={ipv4_acl or 'N/A'}, ipv6_acl={ipv6_acl or 'N/A'}). "
            f"Verify corresponding ACL objects exist where required and match the intended policy."
        )
        logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)

    # AAA Override
    aaa_override = (aaa.get("AAA Override") or "").strip()

    if aaa_override.upper() != "ENABLED":
        msg1 = "WLAN Policy Profile - AAA Override Not Enabled"
        message = (
            f"Policy profile {pp.get('name')} does not have AAA Override enabled. "
            f"Features that rely on RADIUS/AAA attributes may not function as expected, including dynamic VLAN/VNID "
            f"assignment and web authentication/redirect (CWA). Remediation: enable AAA Override if these features are required."
        )
        logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)

    nac_type = (aaa.get("NAC Type") or "").strip()

    if nac_type.upper() != "ISE NAC":
        msg1 = "WLAN Policy Profile - NAC Type Not Set to ISE NAC"
        message = (
            f"Policy profile {pp.get('name')} is not configured with NAC Type 'ISE NAC' (found '{nac_type or 'Not Configured'}'). "
            f"Endpoints requiring web redirection (CWA) will not be redirected and may transition directly to Run state instead of "
            f"WebAuth Pending. Remediation: configure NAC Type as 'ISE NAC' where web redirection is required."
        )
        logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)

    #QoS and rate-limiters

    qos_client = (pp.get("sections", {}) or {}).get("QOS per Client", {}) or {}
    pc_ingress = (qos_client.get("Ingress Service Name") or "").strip()
    pc_egress = (qos_client.get("Egress Service Name") or "").strip()

    ingress_used = pc_ingress and pc_ingress.lower() != "not configured"
    egress_used = pc_egress and pc_egress.lower() != "not configured"

    if ingress_used or egress_used:
        msg1 = "WLAN Policy Profile - Per-Client QoS In Use"
        message = (
            f"Policy profile {pp.get('name')} has per-client QoS configured "
            f"(ingress={pc_ingress or 'N/A'}, egress={pc_egress or 'N/A'}). "
            f"Verify the QoS policy is intentional and supported for the target deployment, very strict rate-limiters can cause traffic loss and connectivity problems"
        )
        logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)

    #DHCP and IP-MAC binding
    dhcp = (pp.get("sections", {}) or {}).get("DHCP", {}) or {}
    dhcp_required = (dhcp.get("required") or "").strip().upper()

    if dhcp_required == "ENABLED":
        msg1 = "WLAN Policy Profile - DHCP Required Not Supported"
        message = (
            f"Policy profile {pp.get('name')} has 'DHCP required' enabled. "
            f"This setting is not supported in SD-Access or FlexConnect deployments and should be removed. "
            f"Remediation: disable 'DHCP required' under the policy profile DHCP settings."
        )
        logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)

    atf = (pp.get("sections", {}) or {}).get("Airtime-fairness Profile", {}) or {}
    ip_mac_binding = (atf.get("IP mac-binding") or "").strip().upper()

    if ip_mac_binding != "ENABLED":
        msg1 = "WLAN Policy Profile - IP MAC-Binding Disabled"
        message = (
            f"Policy profile {pp.get('name')} has IP mac-binding disabled. "
            f"This can affect IP-to-MAC binding behavior and may impact features that rely on accurate client "
            f"identity/policy enforcement. Remediation: enable IP mac-binding if required for your design. "
            f"Refer to the Catalyst 9800 Wireless Controller configuration guide for IP mac-binding behavior and implications."
        )
        logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)

    #Flex Profile Items
    wlan_set.flexprofile(wlanflp,service)
    flex_profile_obj = wlan_set.flexprofile

    #Extraction of Resultant Policies on the Endpoint side (ACL, URLFilter, SGT, RLOC and VNID)
    endpoint_data = getattr(endpoint_attributes, "endpoint_policies", {}) or {}

    res_policies = endpoint_data.get("resultant_policies", {})
    auth_status = endpoint_data.get("auth_method_status", {})

    method = (auth_status.get("method") or "").upper()

    acl_to_validate = None
    acl_type_label = ""

    # 2. Apply logic: MAB needs URL Redirect ACL, Webauth needs Preauth ACL
    if "MAB" in method:
        acl_to_validate = res_policies.get("URL Redirect ACL")
        acl_type_label = "URL Redirect ACL"
    elif "WEB" in method:
        acl_to_validate = res_policies.get("Preauth ACL")
        acl_type_label = "Preauth ACL"

    # 3. Perform validation against the Flex Profile
    if acl_to_validate:
        if not flex_profile_has_redirect_acl(flex_profile_obj, acl_to_validate):
            error = "Wireless Endpoint - Policy ACL Missing in Flex Profile"
            flex_name = (getattr(flex_profile_obj, "flex_profile", {}) or {}).get("name", "Unknown")

            message = (
                f"Endpoint {mac} is authenticated via {method} and requires the {acl_type_label} '{acl_to_validate}'. "
                f"Finding: This ACL is missing from Flex profile '{flex_name}'. "
                f"Remediation: Add the ACL '{acl_to_validate}' to the Flex profile 'Policy ACL' list. "
                f"For MAB/CWA, ensure it is marked as 'Central Webauth' (ENABLED)."
            )
            exit_program(step, process, subprocess, hostname, error, message)
        else:
            msg1 = f"Wireless Endpoint - {acl_type_label} Validated"
            message = f"The required {acl_type_label} '{acl_to_validate}' for {method} was successfully found in the Flex Profile."
            logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
            step += 1
    elif method:
        # If a method is found but no ACL is assigned to it in the resultant policies
        msg1 = "Wireless Endpoint - No Redirect Policy"
        message = f"Endpoint {mac} is authenticated via {method}, but no redirection ACL (URL Redirect or Preauth) was pushed by the AAA server."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

    # endpoint_attributes.endpointinfo is expected to come from parse_show_wireless_client_detail(...)
    fabric = (endpointinfo.get("fabric", {}) or {})

    fabric_status = (fabric.get("status") or "").strip()
    rloc = fabric.get("rloc")
    vnid = fabric.get("vnid")
    cp_name = fabric.get("control_plane_name")

    msg1 = "Wireless Endpoint - Fabric Status"
    message = (
        f"Endpoint {mac} fabric status: status={fabric_status}, rloc={rloc}, vnid={vnid}, "
        f"control_plane={cp_name}."
    )

    # Log message
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    # Error if fabric is disabled
    if fabric_status.lower() == "disabled":
        error = "Wireless Endpoint - Fabric Disabled"
        message = (
            f"Endpoint {mac} fabric status is disabled. Remediation: verify the WLAN/policy profile is fabric-enabled, "
            f"confirm the AP is fabric-enabled and has an RLOC, and validate fabric control-plane configuration."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    wlan_set.sitetag(ap_stag,service)
    site_tag_obj = wlan_set.stag
    st = (site_tag_obj.get("site_tag", {}) or {})
    msg1 = "Site Tag - Fabric Summary"
    message = (
        f"Site tag '{st.get('name')}': local site '{st.get('local_site')}', "
        f"fabric AP DHCP broadcast '{st.get('fabric_ap_dhcp_broadcast')}', "
        f"fabric multicast group '{st.get('fabric_multicast_group_ipv4')}'."
    )
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    return apconfigattributes, wlan_set, step
    #Return: APConfigGral, FabricStatus, PProfile, FlexProfile, Sitetag Step

def wlcCpQuery(step, eid, vnid, control_planes, control_plane_info, service):
    #1 Identify the EID (MAC or Radio MAC for APs) : EID
    #2 Identify the L2 VNID (vnid)
    #3 Parse through every active CP, select the ones marked as "Up" state and query the EID.
    query_results = []
    for entry in control_planes:
        cp = (entry.get("ip") or "").strip().lower()
        cp_status = (entry.get("status") or "").strip().lower()
        if (cp_status or "").strip().lower() == "up":
            for cp_info in control_plane_info:
                cp_info_hostname = cp_info.profiled_device.hostname
                cp_info_ip = cp_info.profiled_device.loopback
                if str(cp) == str(cp_info_ip):
                    query_result = controlplane_eid(eid,vnid,cp_info_hostname)
                    query_result.ethernet_q(service)
                    query_results.append(query_result)
    step, baseline_etrs = validate_reg_entries(query_results,step)
    return step, baseline_etrs

def validate_reg_entries(reg_entries, step):
    reg_entries = reg_entries or []
    process = "wirelessClientOnboarding"
    subprocess = "[fabricEnabledWireless]"
    # Track first non-empty ETR set seen; all other non-empty must match it
    baseline_etrs = None
    any_empty_etr = False
    all_empty_etr = True

    for entry in reg_entries:
        eid = entry.eid
        iid = entry.iid
        hostname = entry.queriedcp
        # wlcetr must be present and non-empty
        wlcetr = entry.wlcetr or []
        if not isinstance(wlcetr, list) or len(wlcetr) == 0:
            error = "LISP Registration - Missing WLC ETR"
            message = (
                f"EID {eid} (VNID {iid}) is not registered by a Wireless Lan Controller. "
                f"Remediation: focus on the WLC registration process and verify the WLC is registering the endpoint to the map-server."
            )
            exit_program(step, process, subprocess, hostname, error, message)

        # ETRs can be a set/list/str/None depending on your collector
        etrs_raw = entry.etrs
        if etrs_raw is None:
            etrs = set()
        elif isinstance(etrs_raw, set):
            etrs = etrs_raw
        elif isinstance(etrs_raw, list):
            etrs = set(etrs_raw)
        elif isinstance(etrs_raw, str):
            etrs = {etrs_raw}
        else:
            etrs = set()

        # Normalize empties
        etrs = {str(x).strip() for x in etrs if x is not None and str(x).strip()}

        if not etrs:
            any_empty_etr = True
            # per-item empty ETR warning
            msg1 = "LISP Registration - Missing ETR"
            message = (
                f"EID {eid} (VNID {iid}) has no ETRs listed in the control-plane registration output. "
                f"This may indicate the registration has not completed or is not being learned."
            )
            logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)
        else:
            all_empty_etr = False
            if baseline_etrs is None:
                baseline_etrs = etrs
            elif etrs != baseline_etrs:
                error = "LISP Registration - ETR Mismatch"
                message = (
                    f"EID {eid} (VNID {iid}) has inconsistent ETRs across entries. "
                    f"Expected ETRs {sorted(baseline_etrs)}, found {sorted(etrs)}. "
                    f"Remediation: verify duplicate registrations, endpoint mobility events, and that the correct WLC/AP ETR is being used."
                )
                exit_program(step, process, subprocess, hostname, error, message)

        # regbywlc inconsistency: if regbywlc is not true but ETRs are present, it looks like wired registration
        regbywlc = str(entry.regbywlc or "").strip().lower()
        if regbywlc != "true" and etrs:
            error = "LISP Registration - Wired/ETR Inconsistency"
            message = (
                f"EID {eid} (VNID {iid}) is registered by the WLC={entry.regbywlc}, but has ETRs {sorted(etrs)} listed. "
                f"This indicates the endpoint may be registered by another ETR (wired registration) rather than the WLC. "
                f"Remediation: identify the device owning these ETR registrations and correct onboarding/segmentation so the endpoint registers as wireless."
            )
            exit_program(step, process, subprocess, hostname, error, message)

    # All entries have empty ETRs -> hard error
    if reg_entries and all_empty_etr:
        error = "LISP Registration - No ETRs Learned"
        message = (
            "All registration entries have empty ETRs. "
            "Remediation: verify WLC-to-control-plane LISP registration, map-server reachability, and authentication keys."
        )
        exit_program(step, process, subprocess, None, error, message)

    msg1 = "LISP Registration - Validation Passed"
    message = (
        f"LISP registration validation passed for EID {eid} in VNID {iid}: "
        f"registrations are consistent across entries, WLC ETR is present, and ETRs match "
        f"{sorted(baseline_etrs) if baseline_etrs else 'N/A'}."
    )
    logging_info(step, process, subprocess, None, msg1 + " | " + message)

    return step, baseline_etrs

def fabric_edge_etr_validation(step, etr, eid, vnid, catc, service, cps):
    process = "Fabric Enabled Wireless - Edge Node"
    subprocess = "[catalystCenterAPI]"
    #Get UUDI from ETR Lo0:
    device = get_device_from_lo0(etr,catc,service)
    if device is None:
        error = "Catalyst Center Inventory - Device Not Found"
        message = (
            f"Device was not found in Catalyst Center when searching by Loopback0 IP {etr}. "
            f"Remediation: review Inventory device details, verify the management IP/credentials and reachability, "
            f"and confirm Loopback0 is correctly discovered and populated for the device."
        )
        exit_program(step, process, subprocess, catc, error, message)

    if len(device) > 1:
        error = "Catalyst Center Inventory - Duplicate Loopback0"
        message = (
            f"Multiple devices were returned for Loopback0 IP {etr} (count={len(device)}). "
            f"A single fabric edge should exist for a given Loopback0. Remediation: review Catalyst Center Inventory "
            f"for duplicate device entries, stale records, or misconfigured management/loopback addressing."
        )
        exit_program(step, process, subprocess, catc, error, message)

    device_uuid = device[0].get("deviceUUID") if len(device) == 1 else None
    #Get MGMTIP from UUID:
    mgmtip = get_network_device_byuuid(device_uuid, catc,service)

    #Profile XTR:
    sourcextr = Device(mgmtip,catc,step)
    sourcextr.profile_device(service)

    #Get VLAN from VNID
    step = singleETRLISPSessionOnlyFEW(mgmtip,vnid,None,catc,service,step,sourcextr,cps)

    return step, sourcextr

def fabric_edge_mac_validation(step, mac, vnid, rloc, sourcextr, service):
    process = "wirelessClientOnboarding"
    subprocess = "[fabricEnabledWireless]"
    # RLOC Consistency - Inter XTR roaming alert
    #Notified RLOC vs current RLOC.
    edge_rloc = sourcextr.loopback
    endpoint_rloc = rloc
    hostname = sourcextr.hostname
    if (edge_rloc or "").strip() == (endpoint_rloc or "").strip():
        msg1 = "Wireless Endpoint - RLOC Consistency"
        message = (
            f"Endpoint {mac} RLOC matches the fabric edge RLOC ({edge_rloc}); no inter-xTR roaming was detected during "
            f"validations. Proceeding with validations on edge RLOC {edge_rloc}."
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1
    else:
        msg1 = "Wireless Endpoint - Inter-xTR Roam Detected"
        message = (
            f"Endpoint {mac} RLOC reported by the WLC ({endpoint_rloc}) differs from the fabric edge RLOC ({edge_rloc}); "
            f"inter-xTR roaming likely occurred during data collection. Proceeding with validations on edge RLOC {edge_rloc} "
            f"(not the WLC-reported RLOC {endpoint_rloc})."
        )
        logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)

    # LISP DB for WLC Entries
    wireless_endpoint_lispinfo = LISPLocalDB(mac,vnid,hostname)
    wireless_endpoint_lispinfo.lispdbwlcentry(service)

    vlan = wireless_endpoint_lispinfo.vlan

    msg1 = "Fabric Edge - Wireless Client Database"
    message = (
        f"On fabric edge {wireless_endpoint_lispinfo.device}, the wireless client {wireless_endpoint_lispinfo.hardware_address} "
        f"{wireless_endpoint_lispinfo.eid} was found in IID {wireless_endpoint_lispinfo.iid}. "
        f"Metadata indicates the client is associated to an AP using IP {wireless_endpoint_lispinfo.ap_ip_metadata} "
        f"and is operating with SGT {wireless_endpoint_lispinfo.sgt_metadata}."
    )
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    if wireless_endpoint_lispinfo.ap_ip_metadata.strip() == "0.0.0.0":
        msg1 = "Fabric Edge - Missing AP Metadata"
        message = (
            f"On fabric edge {wireless_endpoint_lispinfo.device}, AP metadata could not be derived from the LISP database for "
            f"wireless client {wireless_endpoint_lispinfo.hardware_address} in IID {wireless_endpoint_lispinfo.iid}. The parsed AP IP is 0.0.0.0, "
            f"which suggests the metadata is empty or was miscalculated. The endpoint may not be properly learned on the "
            f"required access-tunnel interface."
        )
        logging_error(step, process, subprocess, hostname, msg1 + " | " + message)

    ap_ip = wireless_endpoint_lispinfo.ap_ip_metadata

    # Access Tunnel Interface Mapping and Physical Recursion
    access_tunnel = AccessTunnel(hostname)
    access_tunnel.accesstunnelbyip(ap_ip,service)

    tunnel_name = access_tunnel.accesstunnelname
    ap_ip =  access_tunnel.accesstunneldstip
    phyport = access_tunnel.accesstunnelphyport[0]

    if not tunnel_name or not ap_ip or not phyport:
        error = "Fabric Edge - Access-Tunnel Not Found"
        message = (
            f"Access-tunnel interface details were not found for endpoint {mac}. "
            f"Remediation: focus on AP access-tunnel creation on the fabric edge (verify the AP is fabric-enabled, "
            f"CAPWAP is up, and the edge has created the AccessTunnel interface for the AP)."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    # Build CDP neighbor summary (if present)
    neighbors = access_tunnel.apcdpneighbor
    neighbor_ips = []
    ap_name = None

    for n in neighbors:
        ap_name = ap_name or n.get("device_id")  # AP name from CDP
        mgmt = (n.get("management_addresses") or {})
        for ip in mgmt.keys():
            neighbor_ips.append(ip)

    neighbor_ips = sorted(set(neighbor_ips))

    msg1 = "Fabric Edge - Access-Tunnel and AP Attachment"
    message = (
        f"Endpoint {mac} is connected through {tunnel_name} on {access_tunnel.hostname}. "
        f"This access-tunnel maps to the AP at {ap_ip} and is physically connected via {phyport}."
    )

    if neighbor_ips:
        if len(neighbor_ips) == 1:
            message += f" CDP confirms neighbor {ap_name or 'AP'} with management IP {neighbor_ips[0]}."
        else:
            message += (
                f" CDP shows {len(neighbor_ips)} management IPs for {ap_name or 'the neighbor'}. "
                f"The downstream device may be an extended node; not listing all neighbors."
            )
    else:
        message += f" No CDP management IP was detected for {ap_name or 'the neighbor'}."

    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    # SISF L2 Entry
    device_tracking_entry = SISF(hostname)
    device_tracking_entry.device_tracking_database_mac_l2(mac,service)

    target_mac = mac.lower()
    target_vlan = vlan

    rows = device_tracking_entry.dbentries
    matches = [r for r in rows if r.get("mac") == target_mac and r.get("vlan_id") == target_vlan]

    if len(matches) == 1:
        intf = matches[0].get("interface")
        msg1 = "Fabric Edge - Device-Tracking Match"
        message = (
            f"Device-tracking captured endpoint {target_mac} on VLAN {target_vlan} via interface {intf}."
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1
    elif len(matches) == 0:
        error = "Fabric Edge - Device-Tracking Missing Endpoint"
        message = (
            f"Device-tracking did not capture endpoint {target_mac} on VLAN {target_vlan}. "
            f"Remediation: verify the endpoint is active, confirm the correct VLAN, and check device-tracking "
            f"and access-tunnel learning on the fabric edge."
        )
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        error = "Fabric Edge - Device-Tracking Duplicate Matches"
        message = (
            f"Multiple device-tracking entries were found for endpoint {target_mac} on VLAN {target_vlan}: "
            f"{[m.get('interface') for m in matches]}. Remediation: investigate duplicate learns or multi-interface "
            f"conditions on the fabric edge."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    # LISP DB Registration
    wireless_endpoint_lispinfo.LISPDBEntry("ethernet",service)
    locators = wireless_endpoint_lispinfo.locators
    mapservers =wireless_endpoint_lispinfo.mapservers
    if not locators:
        error = "LISP Registration - Missing Locators"
        message = (
            f"LISP registration was found for endpoint {mac}, but no locators were returned. "
            f"Remediation: verify the ETR is registering to the control plane and confirm LISP map-register acceptance."
        )
        exit_program(step, process, subprocess, hostname, error, message)
    # Build a concise locator summary
    locator_summary = []
    for l in locators:
        locator_summary.append(
            f"{l.get('rloc')} (priority {l.get('priority')}, weight {l.get('weight')})"
        )
    # Build map-server ack summary
    ms_summary = []
    for ms in mapservers:
        ms_summary.append(f"{ms.get('map_server')} (ack {ms.get('ack')})")

    msg1 = "LISP Registration - EID and Locators"
    message = (
        f"LISP {wireless_endpoint_lispinfo.address_family} registration for endpoint {mac} was found in {wireless_endpoint_lispinfo.eid_table} "
        f"with origin {wireless_endpoint_lispinfo.eid_origin}. Locators: {', '.join(locator_summary)}. "
        f"Map-servers: {', '.join(ms_summary) if ms_summary else 'None reported'}."
    )
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    # CTS Binding Entry (If IP is available)
    mac_table = mac_learning(hostname)
    mac_table.mac_learning_mac(mac,vlan,service)

    port = mac_table.port
    type = mac_table.type

    if not port:
        error = "Fabric Edge - MAC Table Entry Missing"
        message = (
            f"MAC address learning was not found on the fabric edge for endpoint {mac}. "
            f"This is unexpected because LISP database entries and SISF/device-tracking entries are present. "
            f"This can indicate an issue in the interaction between L2SISF and MATM, which is often observed after "
            f"an unexpected reload of an active switch/supervisor or following ISSU procedures. "
            f"Remediation: clear the endpoint entries and re-test. If the issue persists, collect debugs on the fabric edge: "
            f"`debug access-tunnel`, `debug matm all`, `debug l2lisp`, and `debug device-tracking`."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    if (type or "").strip().upper() != "CP_LEARN":
        error = "Fabric Edge - MAC Table Stale/Duplicate Learning"
        message = (
            f"A MAC table entry for endpoint {mac} was found on the local switch, but it was learned via '{type}' "
            f"instead of the expected 'CP_LEARN'. This typically indicates a stale or conflicting MAC learning method "
            f"(for example AAA/MAB, port-security, or a true duplicate MAC in the network). "
            f"Remediation: resolve the conflicting/stale MAC learning condition first; once cleared, the FEW MAC can be "
            f"properly learned on the switch."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    msg1 = "Fabric Edge - MAC Table Validation"
    message = (
        f"MAC address learning is present for endpoint {mac} on port {port} and is learned via CP_LEARN, "
        f"which is consistent with Fabric Enabled Wireless onboarding."
    )
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    return step
#Wireless Client Fabric Onboarding# WirelessClientOnboarding
# Requirements : Endpoint MAC address
'''
** = Requires CatC API Back-to-Back Validation
D0) WLC Information 
D1) Is the wireless endpoint under client list?
D2) Is the wireless endpoint in RUN/WebAuthPending/IP Learn state?
3) Is the wireless endpoint connected to a fabric ap? , how many endpoints connected to the AP? Threshold
D4) Is the wireless endpoint connected to a fabric ssid with the correct parameters? (Central Auth, Local SW, no Mobility, no VLAN if not EWLC) 
D     ** (Provisioned by CatC?, VLAN Mapping)
D5) Is there any preauth, postauth ACL denying the required traffic?
D6) Is there any severe rate-limiter applied to the host? ** Requires manual evaluation
D7) Is the LISP session between WLC and CP in proper state?
D8) Is the properly registered to the correct VNI on the Control Plane?
D9) Is the endpoint seen as metadata/proxy registration on the Control Plane?
D10) Is the endpoint notified to the Fabric RLOC to create a LISP DB entry?
D11) Is the LISP DB entry correct (metadata, AP IP, SGT)
D12) Is the AP IP matching the Access Tunnel interfaces corresponding to the Joined AP? - Soft check, roamming can create false negatives
D13) Is the MAC address entry created on L2 SISF?
N14) If the SGT IP properly passed down to CTS/CEF? 
** PD Verifications **
14) Is the MAC address entry created on MATM? - PD
15) Access Tunnel programming for Active Switch
16) Access Tunnel programming for Member Switch (attached to the AP)
D17) L2 LISP Statistics Collection
18) Access Tunnel historic data Collection
19) L2LISP interface validation (IP on interface, Hardware Programming)
'''

def wirelessclientonboarding(step, fabric_site, catc_name, mac, service):

        #Profiling WLC Parameters
        process = "wirelessClientOnboarding"
        subprocess = "[main]"
        msg1 = "Client Onboarding - Main"
        message = "Identifying the fabric Wireless LAN Controller for the fabric site."
        logging_info(step, process, subprocess, catc_name, msg1 + " | " + message)
        step += 1

        wlc_attributes = wlcInfo(fabric_site,step,catc_name,service)
        cps, vnids, step = wlcInfoValidation(wlc_attributes,step)
        wlcname = wlc_attributes.hostname

        # Profiling Endpoint Attributes
        process = "wirelessClientOnboarding"
        subprocess = "[wirelessClientMAC]"
        msg1 = "Client Onboarding - Association"
        message = "Validating connected endpoint parameters."
        logging_info(step, process, subprocess, catc_name, msg1 + " | " + message)
        step += 1

        endpoint_attributes = WirelessEndpointMac(wlcname, mac)
        endpoint_attributes.endpoint_info(service)
        ewlcflag = wlc_attributes.ewlc

        # Validating Endpoint Attributes
        apconfigattributes, wlan_set, step = wlcEndpointValidation(step,wlcname,endpoint_attributes,ewlcflag,service)
        step +=1

        # Validating LISP Control Plane Parameters
        subprocess = "[fabricEnabledWireless]"
        msg1 = "LISP - Control Plane"
        message = "Validating LISP Control Plane for the wireless Endpoint."
        logging_info(step, process, subprocess, catc_name, msg1 + " | " + message)
        step += 1
        step, control_planes, cp_info = fabricEnabledWirelessSession(wlc_attributes, None, step, catc_name, endpoint_attributes, service)

        # Validating LISP Control Plane Parameters
        msg1 = "LISP - Registration"
        message = "Validating LISP Registration for the wireless Endpoint."
        logging_info(step, process, subprocess, catc_name, msg1 + " | " + message)
        step += 1

        endpointinfo = getattr(endpoint_attributes, "endpointinfo", None) or {}
        fabric = (endpointinfo.get("fabric", {}) or {})
        endpointrloc = fabric.get("rloc")
        endpointvnid = fabric.get("vnid")
        endpointsgt = fabric.get("sgt")
        endpointmac = endpointinfo.get(("client") or {}).get('mac_address')

        step, baseline_etrs = wlcCpQuery(step,endpointmac,endpointvnid,control_planes,cp_info,service)
        baseline_etrs = next(iter(baseline_etrs))

        # Validating LISP Edge Node Parameters
        msg1 = "LISP - WLC Notification"
        message = "Validating LISP Session Parameters on Fabric Edge."
        logging_info(step, process, subprocess, catc_name, msg1 + " | " + message)
        step += 1

        mapservers = []
        for cp in control_planes:
            cp_ip = (cp.get("ip") or "").strip().lower()
            mapservers.append({'map_server' : cp_ip , 'ack': 'Up'})
        step, sourcextr = fabric_edge_etr_validation(step,baseline_etrs,endpointmac,endpointvnid,catc_name,service,mapservers)

        # Validating LISP Edge Node Parameters
        msg1 = "LISP - WLC Notification"
        message = "Validating LISP Local Parameters on Fabric Edge."
        logging_info(step, process, subprocess, catc_name, msg1 + " | " + message)
        step += 1

        step = fabric_edge_mac_validation(step,endpointmac,endpointvnid,endpointrloc,sourcextr,service)

        # Validating LISP Edge Node Parameters
        msg1 = "Endpoint Roaming History"
        message = "Collecting up to the five most recent roaming events."
        logging_info(step, process, subprocess, catc_name, msg1 + " | " + message)
        step += 1

        wirelessroaminghistory = WirelessEndpointMac(wlcname,endpointmac)
        wirelessroaminghistory.fabric_roamming(service)
        events = wirelessroaminghistory.roaminghistory['events']

        msg1 = "Wireless Endpoint - Recent Fabric Association History"
        for i, e in enumerate(events[:5], start=1):
            message = (
                f"Event {i}: AP {e.get('ap_mac')}, assoc {e.get('assoc_time')}, XTR {e.get('xtr_ip')}, "
                f"VNID {e.get('vnid')}, SGT {e.get('sgt')}, MS {e.get('ms_ip')}, "
                f"message '{e.get('message')}', entry {e.get('entry_time')}."
            )
            logging_info(step, process, subprocess, wlcname, msg1 + " | " + message)

        # Validating LISP Edge Node Parameters
        msg1 = "Endpoint L2LISP Statistics"
        message = "Validating the state of L2LISP error counters."
        logging_info(step, process, subprocess, catc_name, msg1 + " | " + message)
        step += 1

        l2lispstatistics = L2LISPStatistics(sourcextr.hostname)
        l2lispstatistics.l2lispstatistics(service)
        l2lisp_stats = l2lispstatistics.l2lispstats
        errors = (l2lisp_stats.get("errors", {}) or {})
        ignore_substrings = (
            "update client rbm failed",
            "idb not found",
        )
        warn_errors = {k: v for k, v in errors.items() if v and not any(s in k.lower() for s in ignore_substrings)}
        if warn_errors:
            msg1 = "Fabric Edge - L2LISP Errors Detected"
            message = (
                    "L2LISP error counters are non-zero for the following items: "
                    + ", ".join(f"{k} ({v})" for k, v in warn_errors.items())
                    + "."
            )
            logging_warning(step, process, subprocess, sourcextr.hostname, msg1 + " | " + message)
        else:
            msg1 = "Fabric Edge - L2LISP Statistics"
            message = "L2LISP error counters are clean; no unexpected errors were detected."
            logging_info(step, process, subprocess, sourcextr.hostname, msg1 + " | " + message)

        return step, sourcextr
        # Add ACL validation on the end - DHCP purposes!  Preauth, Postauth, etc
