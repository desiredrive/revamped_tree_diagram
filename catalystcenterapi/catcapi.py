import sys
import radkit_cli
from device_profiler import Device
from radkit_cli import logging_info,logging_error,logging_warning

def get_device_from_lo0(lo0_ip,catc,service):
    #Get Device UUID from an IP address existing as Lo0 on a device
    api_url = "/dna/intent/api/v1/interface/ip-address/{}".format(lo0_ip)
    api_response = radkit_cli.get_catc_api(catc,api_url,service)
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
    api_response = radkit_cli.get_catc_api(catc,api_url,service)
    devices = api_response['response']
    device_list = []
    try:
        for i in devices:
            if i['adminStatus'] == 'UP':
                device_list.append({'portName' : i['portName'], 'deviceUUID' : i['deviceId']})
        if len(device_list) is None:
            return None
        else:
            return device_list
    except (KeyError, AttributeError, IndexError, TypeError):
        return None

def get_network_device_byuuid(uuid,catc,service):
    # Get Network_Device Management IP by UUID
    api_url = "/dna/intent/api/v1/network-device/{}".format(uuid)
    api_response = radkit_cli.get_catc_api(catc,api_url,service)
    response = api_response['response']
    mgmtip = response['managementIpAddress']
    if mgmtip is None:
        return None
    else:
        return mgmtip

def profile_devices_with_ip(ip,catc,service):
    #Warning, Do not use with anycast IPs! It can take long processing times; restricting the entry for maximum 4 entries
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
                profiledrp = Device(rp, catc)
                profiledrp.profile_device(service)
                possible_rps_profiled.append(profiledrp)
            number_of_nodes += 1
    return possible_rps_profiled

def validate_cp_infabric(cpmgmtip,sitehierarchy,catc,service,step):
    # Identify a Control Plane as Part of a Fabric Site by UUID and managementIP
    api_url = "/dna/intent/api/v1/business/sda/control-plane-device?deviceManagementIpAddress={}".format(cpmgmtip)
    api_response = radkit_cli.get_catc_api(catc,api_url,service)
    api_status = api_response['status']
    if api_status == "failed":
        logging_error(step, "CatalystCenterAPI",None, catc,
                      "WARNING!: Could not find the Control Plane with Management IP {} in Catalyst Center".format(cpmgmtip))
        sys.exit("WARNING!: Could not find the Control Plane with Management IP {} in Catalyst Center".format(cpmgmtip))
    else:
        cp_name = api_response['deviceName']
        cp_location = api_response['siteNameHierarchy']
    
    #Validating if the device is inside the fabric site: 
    split_string = cp_location.split(sitehierarchy)
    if len(split_string) > 1:
        logging_info(step, "CatalystCenterAPI",None, catc,
                      "Device {} located in {} is part of the fabric site {}".format(cp_name,cp_location,sitehierarchy))
        #print ("Device {} located in {} is part of the fabric site {}".format(cp_name,cp_location,sitehierarchy))
        return True
    else:
        logging_error(step, "CatalystCenterAPI",None, catc,
                      "Could not determine if device {} located in {} is part of the fabric site {}".format(cp_name,cp_location,sitehierarchy))
        sys.exit("Could not determine if device {} located in {} is part of the fabric site {}".format(cp_name,cp_location,sitehierarchy))
    