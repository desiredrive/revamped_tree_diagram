import sys
from device_profiler import Device
from radkit_cli import logging_info, logging_error, get_catc_api, get_hostname_from_mgmtip
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
    print (catc)
    api_response = get_catc_api(catc, api_url, service)
    print (api_response)
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

