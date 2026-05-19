import sys
from device_profiler import Device
from radkit_cli import logging_info, logging_error, get_catc_api, get_hostname_from_mgmtip
from ipverifications import ip_validator_input
import re

def is_version_valid(version_string, minimum_version="2.3.7"):
    version_part = version_string.split('-')[0]
    version_numbers = list(map(int, version_part.split('.')))
    minimum_version_numbers = list(map(int, minimum_version.split('.')))
    if version_numbers < minimum_version_numbers:
        return False  # Reject the version
    return True  # Accept the version

def get_catc_version(catc,service):
    process = 'catalystCenterAPI'
    subprocess = '[catalystCenterVersion]'
    api_url = "/dna/intent/api/v1/dnac-release"
    api_response = get_catc_api(catc, api_url, service)
    version = (api_response['response']['displayVersion'])
    match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', version)
    if match:
        dnac_main_version = match.group(1)
        state = is_version_valid(dnac_main_version)
        if state is True:
            return version
        else:
            error = "Catalyst Center API - Unsupported Version"
            message = "This SD-Access troubleshooting flow requires a Catalyst Center minimum version of 2.3.7, current version is: {}".format(version)
            logging_error(0, process, subprocess, catc, error)
            logging_info(0, process, subprocess, catc, message)
            # raise BDBTaskError("Error: {} | {}".format(error, message))
            sys.exit("Error: {} | {}".format(error, message))

def get_device_from_lo0(lo0_ip,catc,service):
    #Get Device UUID from an IP address existing as Lo0 on a device
    api_url = "/dna/intent/api/v1/interface/ip-address/{}".format(lo0_ip)
    api_response = get_catc_api(catc,api_url,service)
    devices = api_response['response']
    device_list = []
    try:
        for i in devices:
            if (i['portName'] == "Loopback0") and (i['adminStatus'] == 'UP'):
                device_list.append({'portName' : i['portName'], 'deviceUUID' : i['deviceId']})
        if len(device_list) is None:
            return None
        else:
            return device_list
    except (KeyError, AttributeError, IndexError, TypeError):
        return None

def get_device_from_ip(ip,catc,service):
    #Get Device UUID from an IP address existing on the device
    api_url = "/dna/intent/api/v1/interface/ip-address/{}".format(ip)
    api_response = get_catc_api(catc,api_url,service)
    devices = api_response['response']
    device_list = []
    try:
        for i in devices:
            if i['adminStatus'] == 'UP':
                device_list.append({'portName' : i['portName'], 'deviceUUID' : i['deviceId']}, )
        if len(device_list) is None:
            return None
        else:
            return device_list
    except (KeyError, AttributeError, IndexError, TypeError):
        return None

def get_network_device_byuuid(uuid,catc,service):
    # Get Network_Device Management IP by UUID
    api_url = "/dna/intent/api/v1/network-device/{}".format(uuid)
    api_response = get_catc_api(catc,api_url,service)
    response = api_response['response']
    mgmtip = response['managementIpAddress']
    if mgmtip is None:
        return None
    else:
        return mgmtip

def get_network_device_byuuid_detailed(uuid,catc,service):
    # Get Network_Device Management IP by UUID
    api_url = "/dna/intent/api/v1/network-device/{}".format(uuid)
    api_response = get_catc_api(catc,api_url,service)
    response = api_response['response']
    mgmtip = response['managementIpAddress']
    status = response['reachabilityStatus']
    hostname = response['hostname']
    if mgmtip is None:
        return None
    else:
        return mgmtip, status, hostname

def profile_devices_with_ip(step,ip,catc,service):
    #Warning, Do not use with anycast GW IPs! It can take long processing times; restricting the entry for maximum 4 entries
    deviceswithip = get_device_from_ip(ip, catc, service)
    number_of_nodes = 0
    possible_rps = []
    possible_rps_profiled = []
    if deviceswithip is not None:
        if number_of_nodes < 5:
            for uuids in deviceswithip:
                deviceuuid = uuids['deviceUUID']
                rpdevice = get_network_device_byuuid(deviceuuid, catc, service)
                possible_rps.append(rpdevice)
            for rp in possible_rps:
                profiledrp = Device(rp, catc,step)
                profiledrp.profile_device(service)
                possible_rps_profiled.append(profiledrp)
            number_of_nodes += 1
    return possible_rps_profiled

def validate_cp_infabric(cpmgmtip,sitehierarchy,catc,service,step):
    # Identify a Control Plane as Part of a Fabric Site by UUID and managementIP

    process = 'catalystCenterAPI'
    subprocess = '[controlPlaneValidation]'

    api_url = "/dna/intent/api/v1/business/sda/control-plane-device?deviceManagementIpAddress={}".format(cpmgmtip)
    api_response = get_catc_api(catc,api_url,service)
    api_status = api_response['status']
    if api_status == "failed":
        error = "Catalyst Center API - Unable to Collect"
        message = "Could not find the Control Plane with Management IP {} in Catalyst Center, Review the latest API retrieved in Catalyst Center in the GPS_SDA Collection ".format(
            cpmgmtip)
        logging_error(step, process, subprocess, catc, error)
        logging_info(step, process, subprocess, catc, message)
        #raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))

    else:
        cp_name = api_response['deviceName']
        cp_location = api_response['siteNameHierarchy']
    
    #Validating if the device is inside the fabric site: 
    split_string = cp_location.split(sitehierarchy)
    if len(split_string) > 1:
        logging_info(step, process,subprocess, catc,
                      "Device {} located in {} is part of the fabric site {}".format(cp_name,cp_location,sitehierarchy))
        #print ("Device {} located in {} is part of the fabric site {}".format(cp_name,cp_location,sitehierarchy))
        return True
    else:
        error = "Catalyst Center API - Unable to Collect"
        message = "Could not determine if device {} located in {} is part of the fabric site {}. Review the latest API retrieved in Catalyst Center in the GPS_SDA Collection".format(
            cp_name, cp_location, sitehierarchy)
        logging_error(step, process, subprocess, catc, error)
        logging_info(step, process, subprocess, catc, message)
        #raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))

def find_control_plane(cp,dnac,service,step, process,subprocess):
    # Step 1, identify Control Plane
    device = get_device_from_lo0(cp, dnac, service)
    if device is None:
        error = "Catalyst Center API - No Device Found"
        message = "No Control Planes found with Loopback 0 with IP {} in Catalyst Center Inventory, make sure these are in Managed state".format(cp)
        logging_error(step, process, subprocess, dnac, error)
        logging_info(step, process, subprocess, dnac, message)
        # raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))
    # Step 2, identify Management IP for CPs
    control_planes = []
    for match in device:
        response = get_network_device_byuuid_detailed(match['deviceUUID'], dnac, service)
        cpmgmtip = response[0]
        state = response[1]
        hostname = response[2]
        control_plane = {'hostname': hostname,  'mgmtip' : cpmgmtip, 'reachability': state}
        if cpmgmtip is not None:
            control_planes.append(control_plane)
    if len(control_planes) == 1:
        hostname = get_hostname_from_mgmtip(control_planes[0]['mgmtip'],service)
    else:
        error = "Catalyst Center API - Multiple Control Planes"
        message = "Multiple Control Planes sharing the same Loopback 0 with IP {} in Catalyst Center Inventory, unsupported flow".format(cp)
        logging_error(step, process, subprocess, dnac, error)
        logging_info(step, process, subprocess, dnac, message)
        # raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))
    control_plane = control_planes[0]
    control_plane.update({'radkithostname':hostname})
    return control_plane

def getFabricWLC(fabric_id,catc,service,step):
    # Identify a WLC as Part of a Fabric Site by UUID
    process = 'catalystCenterAPI'
    subprocess = '[fabricWLCValidation]'

    api_url = "/dna/intent/api/v1/sda/fabricDevices?fabricId={}&deviceRoles=WIRELESS_CONTROLLER_NODE".format(fabric_id)
    api_response = get_catc_api(catc, api_url, service)
    api_status = api_response['response']

    wlcnetworkdeviceid = None
    api_failed = (api_status == "failed")
    if not api_failed:
        try:
            wlcnetworkdeviceid = api_response['response'][0]['networkDeviceId']
        except (KeyError, IndexError, TypeError):
            wlcnetworkdeviceid = None

    if wlcnetworkdeviceid is None:
        # CatC /sda/fabricDevices is known to return an empty response on some
        # releases even when a fabric WLC is assigned. Fall back to a manual
        # operator-supplied management IP.
        error = "Catalyst Center API - Unable to Collect"
        message = ("Could not find the Fabric WLC for the Fabric Site in Catalyst Center "
                   "(suspected CatC defect on /sda/fabricDevices). Falling back to manual input.")
        logging_error(step, process, subprocess, catc, error)
        logging_info(step, process, subprocess, catc, message)
        mgmtip = ip_validator_input("Enter the Fabric WLC Management IP address > ")
        logging_info(step, process, subprocess, catc,
                     "Operator-provided Fabric WLC Management IP: {}".format(mgmtip))
        return mgmtip

    # Obtaining the WLC name:
    mgmtip = get_network_device_byuuid(wlcnetworkdeviceid,catc,service)
    return mgmtip

def getFabricBorders(fabric_id,catc,service,step):
    process = 'catalystCenterAPI'
    subprocess = '[fabricBorderValidation]'

    api_url = "/dna/intent/api/v1/sda/fabricDevices?fabricId={}&deviceRoles=BORDER_NODE".format(fabric_id)
    api_response = get_catc_api(catc, api_url, service)
    api_status = api_response['response']
    if api_status == "failed":
        error = "Catalyst Center API - Unable to Collect"
        message = "Could not find the Fabric Borders for the Fabric Site in Catalyst Center, Review the latest API retrieved in Catalyst Center in the log file "
        logging_error(step, process, subprocess, catc, error)
        logging_info(step, process, subprocess, catc, message)
        # raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))
    else:
        data = api_response
        layer3_borders = []
        for item in (data.get("response", []) or []):
            bds = item.get("borderDeviceSettings", {}) or {}
            border_types = [t.upper() for t in (bds.get("borderTypes", []) or [])]

            if "LAYER_3" in border_types:
                l3 = bds.get("layer3Settings", {}) or {}
                layer3_borders.append(
                    {
                        "networkDeviceId": item.get("networkDeviceId"),
                        "localAutonomousSystemNumber": l3.get("localAutonomousSystemNumber"),
                        "borderPriority": l3.get("borderPriority"),
                        "importExternalRoutes" : l3.get("importExternalRoutes"),
                        "isDefaultExit" : l3.get("isDefaultExit"),
                    }
                )
        if not layer3_borders:
            error = "External Connectivity - No Layer3 Borders Found"
            message = (
                f"No Layer 3 border nodes were found for fabricId {fabric_id}. "
                f"Remediation: verify external connectivity is configured for the fabric site and that at least one "
                f"border node is provisioned with border type LAYER_3 in Catalyst Center."
            )
            logging_error(step, process, subprocess, catc, error)
            logging_info(step, process, subprocess, catc, message)
            # raise BDBTaskError("Error: {} | {}".format(error, message))
            sys.exit("Error: {} | {}".format(error, message))

    # Obtaining the Borders mgmtip:
    for b in layer3_borders:
        device_id = b.get("networkDeviceId")
        if not device_id:
            continue
        # Example lookup (replace with your actual source/API response)
        # e.g. inv_item = get_device_details(device_id)
        mgmtip,status,hostname = get_network_device_byuuid_detailed(device_id, catc, service)
        b["status"] = status
        b["hostname"] = hostname
        b["managementIpAddress"] = mgmtip

    return layer3_borders

def getFabricCPs(fabric_id,catc,service,step):
    process = 'catalystCenterAPI'
    subprocess = '[fabricBorderValidation]'

    api_url = "/dna/intent/api/v1/sda/fabricDevices?fabricId={}&deviceRoles=CONTROL_PLANE_NODE".format(fabric_id)
    api_response = get_catc_api(catc, api_url, service)
    api_status = api_response['response']
    if api_status == "failed":
        error = "Catalyst Center API - Unable to Collect"
        message = "Could not find the Fabric Control Planes for the Fabric Site in Catalyst Center, Review the latest API retrieved in Catalyst Center in the log file "
        logging_error(step, process, subprocess, catc, error)
        logging_info(step, process, subprocess, catc, message)
        # raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))
    else:
        data = api_response
        # Assuming the dictionary is named 'fabric_devices_data'
        network_device_ids = [device.get("networkDeviceId") for device in data.get("response", [])]
        # network_device_ids will be: ['7c4e530a-f643-4619-a3e2-805f0adc0b4e', '9fa77355-245e-4880-b38d-1daafb549bc0']

    # Assuming 'network_device_ids' is the list extracted in the previous step
    cps = []

    if network_device_ids:
        for dev_id in network_device_ids:
            if dev_id is not None:
                # Replace 'get_mgmt_ip_from_id' with the name of your actual special function
                mgmtip, status, hostname = get_network_device_byuuid_detailed(dev_id, catc, service)
                if mgmtip:
                    cp = {'mgmtip': mgmtip, 'status': status, 'hostname': hostname}
                    cps.append(cp)
    # management_ips now contains the list of IPs retrieved for each valid ID
    return cps

def getL3Handoffs(fabric_id,borderuuid, catc,service,step):
    process = 'catalystCenterAPI'
    subprocess = '[l3HandoffConfiguration]'

    api_url = "/dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/ipTransits?fabricId={}&networkDeviceId={}".format(fabric_id,borderuuid)
    api_response = get_catc_api(catc, api_url, service)
    api_status = api_response['response']
    if api_status == "failed":
        error = "Catalyst Center API - Unable to Collect"
        message = "Could not find the L3 Handoffs for the Fabric Border in Catalyst Center, Review the latest API retrieved in Catalyst Center in the log file "
        logging_error(step, process, subprocess, catc, error)
        logging_info(step, process, subprocess, catc, message)
        # raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))
    else:
        api_data = api_response
        transit_links = []
        for item in (api_data.get("response", []) or []):
            transit_links.append(
                {
                    "networkDeviceId": item.get("networkDeviceId"),
                    "interfaceName": item.get("interfaceName"),
                    "virtualNetworkName": item.get("virtualNetworkName"),
                    "vlanId": item.get("vlanId"),
                    "localIpAddress": item.get("localIpAddress"),
                    "remoteIpAddress": item.get("remoteIpAddress"),
                    "localIpv6Address": item.get("localIpv6Address"),
                    "remoteIpv6Address": item.get("remoteIpv6Address"),
                    "transitNetworkId": item.get("transitNetworkId"),
                }
            )
    return transit_links

def getanycastgateway(fabricid,siteid,vlan,catc,service,step):
    process = 'catalystCenterAPI'
    subprocess = '[anycastGateway]'

    api_url = "/dna/intent/api/v1/sda/anycastGateways?fabricId={}&vlanId={}".format(fabricid,vlan)
    api_response = get_catc_api(catc, api_url, service)
    api_status = api_response['response']
    if api_status == "failed":
        error = "Catalyst Center API - Unable to Collect"
        message = "Could not find the AnycastGateway for the Fabric Site in Catalyst Center, Review the latest API retrieved in Catalyst Center in the log file "
        logging_error(step, process, subprocess, catc, error)
        logging_info(step, process, subprocess, catc, message)
        # raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))

    else:
        payload = api_response  # dict shown above

        data = payload.get("response", [])
        result = data[0] if isinstance(data, list) and data else {}
        ip_pool_name = (result.get("ipPoolName") if isinstance(result, dict) else None)

    #Retrieve IP Pool information
    api_url = "/dna/intent/api/v1/ipam/siteIpAddressPools?siteId={}".format(siteid)
    api_response = get_catc_api(catc, api_url, service)
    api_status = api_response['response']
    if api_status == "failed":
        error = "Catalyst Center API - Unable to Collect"
        message = "Could not find the IP Pools for the Fabric Site in Catalyst Center, Review the latest API retrieved in Catalyst Center in the log file "
        logging_error(step, process, subprocess, catc, error)
        logging_info(step, process, subprocess, catc, message)
        # raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))
    else:
        pools = (api_response.get("response", []) or [])
        matched_pool = next((p for p in pools if (p.get("name") or "").strip() == ip_pool_name), None)
        result["ipPoolDetails"] = matched_pool
    return result
