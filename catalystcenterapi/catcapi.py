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
