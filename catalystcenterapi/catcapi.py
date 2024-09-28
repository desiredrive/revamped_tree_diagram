from dataclasses import dataclass
import re
import sys
import radkit_cli

#Identify_a_device_from_Loopback0_IP

def get_device_from_lo0(lo0_ip,catc,service):
    api_url = "/dna/intent/api/v1/interface/ip-address/{}".format(lo0_ip)
    api_response = radkit_cli.get_catc_api(catc,api_url,service)
    devices = api_response['response']
    device_list = []
    try:
        for i in devices:
            if (i['portName'] == "Loopback0") and (i['adminStatus'] == 'UP'):
                device_list.append({'portName' : i['portName'], 'deviceUUID' : i['deviceId']})
        if len(device_list) == None:
            return None
        else:
            return device_list
    except:
        return None

#Get Network_Device Management IP by UUID
def get_network_device_byuuid(uuid,catc,service):
    api_url = "/dna/intent/api/v1/network-device/{}".format(uuid)
    api_response = radkit_cli.get_catc_api(catc,api_url,service)
    response = api_response['response']
    mgmtip = response['managementIpAddress']
    if mgmtip == None:
        return None
    else:
        return mgmtip

#Identify a Control Plane as Part of a Fabric Site by UUID and managementIP

def validate_cp_infabric(cpmgmtip,sitehierarchy,catc,service):
    api_url = "/dna/intent/api/v1/business/sda/control-plane-device?deviceManagementIpAddress={}".format(cpmgmtip)
    api_response = radkit_cli.get_catc_api(catc,api_url,service)
    api_status = api_response['status']
    if api_status == "failed":
        sys.exit("WARNING!: Could not find the Control Plane with Management IP {} in Catalyst Center".format(cpmgmtip))
    else:
        cp_name = api_response['deviceName']
        cp_location = api_response['siteNameHierarchy']
    
    #Validating if the device is inside the fabric site: 
    split_string = cp_location.split(sitehierarchy)
    if len(split_string) > 1:
        print ("Device {} located in {} is part of the fabric site {}".format(cp_name,cp_location,sitehierarchy))
        return True
    else:
        sys.exit("Could not determine if device {} located in {} is part of the fabric site {}".format(cp_name,cp_location,sitehierarchy))
    