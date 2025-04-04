from dataclasses import dataclass
from datetime import datetime
import radkit_client
import sys
import json
import radkit_genie
import logging

from radkit_client.sync import (
    # For the creation of the context.
    create_context,
    #certificate_login,
    access_token_login,
    sso_login,
    # Direct login method.
    direct_login,
)

logging.basicConfig(
    format='%(asctime)s %(levelname)-1s %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S',
    #filename="script_logs.txt"
    )

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def logging_info(step,process,device,message):
   string = "[STEP:{}][{}][{}]: {}".format(step,device,process,message)
   logger.info(string)

def logging_error(step,process,device,message):
    string = "[STEP: {}][{}][{}]: {}".format(step,device,process,message)
    logging.error(string)

def logging_warning(step,process,device,message):
    string = "[STEP: {}][{}][{}]: {}".format(step,device,process,message)
    logging.warning(string)

def main(service: radkit_client.Service):
    """
    :param service: radkit_client.Service object
    """
    
def loggin_file():
    currenttime = datetime.now()
    f = open("collection_logfile.txt", "w")
    f.write("File Created on {}".format(currenttime))
    f.write("\n----------------------------------------------------------------------------------------------------------------------------\n")
    f.close()

def append_to_logging_file(content):
    f = open("collection_logfile.txt", "a")
    f.write(content)
    f.write("\n----------------------------------------------------------------------------------------------------------------------------\n")
    f.close()


def radkit_version(service):
    radkit_version = service.version
    return radkit_version

def radkit_login(email: str, domain: str, serial: str):
    # Connect to the given service, using SSO login.
    client = sso_login(identity=email, domain=domain)
    service = client.service(serial).wait()
    return service

def get_any_single_output(hostname,command: str,service):
    try:
        device_inventory = service.inventory[hostname]
        commands = device_inventory.exec([command]).wait()
        try:
            output = commands.result["{}".format(command)].data
            append_to_logging_file(output)
        except:
            return None
    except ValueError:
        sys.exit("Error when getting the following command: {}".format(command))
    except KeyError as e:
        sys.exit("Error: {} in RADKIT Inventory, Device: {} ".format(e, hostname))
    return output

def get_single_output_genie(hostname, command: str, service):
    #Currently available only for IOS_XE platforms!
    type = 'iosxe'
    try:
        device_inventory = service.inventory[hostname]
        raw = device_inventory.exec(command).wait()
        execution = radkit_genie.parse(raw, os=type)
        try:
            raw_output = raw.result.data
            append_to_logging_file(raw_output)
            output = execution[hostname][command].data
        except:
            return None
    except ValueError:
        sys.exit("Error when getting the following command: {}".format(command))
    except KeyError as e:
        sys.exit("Error: {} in RADKIT Inventory, Device: {} ".format(e, hostname))
    return output

def get_catc_api(dnac, api_url: str,service):
    try:
        device_inventory = service.inventory[dnac]
        try:
            response = device_inventory.http.get(api_url).wait()
            response_js = json.loads(response.content)
            return response_js
        except:
            return None
    except ValueError:
        print ("Error when getting the following API: {}".format(api_url))

def get_catc_name(service):  
        #Find CatC in inventory list
        try:
            device_inventory = service.inventory.filter('device_type', 'CENTER')
            device_name = list(device_inventory.keys())
            #Validation - Does this device exists?
            hostname = device_name[0]
            device_inventory = service.inventory[hostname]
            return (hostname)
        #If the Device does not exist  
        except (IndexError, ValueError):
            sys.exit("Catalyst Center {} not in RADKIT inventory!!") 

def get_hostname_from_mgmtip(mgmtip,service):
        try:
            device_inventory = service.inventory.filter('host', '^{}$'.format(mgmtip))
            device_name = list(device_inventory.keys())
            hostname = device_name[0]
            device_inventory = service.inventory[hostname]
            return (hostname)

        #Does not exist  
        except (IndexError, ValueError):
            sys.exit("Device {} not in RADKIT inventory".format(mgmtip))  