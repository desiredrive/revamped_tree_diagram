from dataclasses import dataclass
from datetime import datetime
import radkit_client
import sys
import radkit_genie
import logging
import threading
import time
import json
import random
#from radkit_client.sync import (
    # For the creation of the context.
    #create_context,
    #certificate_login,
    #access_token_login,
    #sso_login,
    # Direct login method.
    #direct_login,
#)

logging.basicConfig(
    format='%(asctime)s %(levelname)-1s %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S',
    #filename="script_logs.txt"
    )

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def logging_info(step,process,subprocess,device,message):
    if subprocess is None:
        subprocess = ""
    string = "[STEP:{}][{}]{}[{}]: {}".format(step,process,subprocess,device,message)
    append_to_logging_file(string)
    logger.info(string)

def logging_error(step,process,subprocess,device,message):
    if subprocess is None:
        subprocess = ""
    string = "[STEP:{}][{}]{}[{}]: {}".format(step,process,subprocess,device,message)
    append_to_logging_file(string)
    logging.error(string)

def logging_warning(step,process,subprocess,device,message):
    if subprocess is None:
        subprocess = ""
    string = "[STEP:{}][{}]{}[{}]: {}".format(step,process,subprocess,device,message)
    append_to_logging_file(string)
    logging.warning(string)

def main(service: radkit_client.Service):
    """
    :param service: radkit_client.Service object
    """
    
def loggin_file():
    currenttime = datetime.now()
    f = open("collection_logfile.txt", "w")
    f.write("File Created on {}".format(currenttime))
    f.write("----------------------------------------------------------------------------------------------------------------------------\n")
    f.write("\n")
    f.close()

def append_to_logging_file(content):
    f = open("collection_logfile.txt", "a")
    if "STEP" in content:
        f.write("\n")
        f.write(
            "----------------------------------------------------------------------------------------------------------------------------\n")
    f.write(content)
    f.write("\n")
    f.close()


def radkit_version(service):
    radkit_version = service.version
    return radkit_version

#def radkit_login(email: str, domain: str, serial: str):
#    # Connect to the given service, using SSO login.
#    client = sso_login(identity=email, domain=domain)
#    service = client.service(serial).wait()
#    return service

def get_any_single_output(hostname,command: str,service):
    try:
        append_to_logging_file(command)
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
        append_to_logging_file(command)
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

# 1. Define the lock at the top of radkit_cli.py
# This ensures every thread that imports this module shares the same lock.
CATC_API_LOCK = threading.Lock()

def get_catc_api(dnac, api_url: str, service):
    # 2. Wrap the logic in the lock
    with CATC_API_LOCK:
        try:
            device_inventory = service.inventory[dnac]
            attempts = 0

            while attempts < 6:
                try:
                    # Execute the API call
                    response = device_inventory.http.get(api_url).wait()
                    response_js = json.loads(response.content)
                    # Log to file
                    to_file = f"Catalyst Center API: {api_url}\n{json.dumps(response_js, indent=2)}"
                    append_to_logging_file(to_file)

                    # 3. Check for Rate Limit or Concurrency Rejection
                    error_msg = str(response_js.get("error", ""))
                    status_code = response_js.get("bapiExtendedStatusCode", "")

                    if "Rate Limit" in error_msg or status_code == "REJECTED_ABOVE_MAX_CONCURRENCY_LIMIT":
                        attempts += 1  # Fixed the += logic
                        # Wait with jitter to allow the API gateway to breathe
                        time.sleep(3 + random.uniform(1, 3))
                        continue

                    # Success: return the response
                    return response_js

                except Exception as e:
                    # Handle network/parsing errors
                    attempts += 1
                    time.sleep(2)
                    if attempts == 6:
                        return None

            return None

        except Exception as e:
            logging_warning("X", "Catalyst Center API", "[apiError]", dnac, f"Error when getting the following API: {api_url} - {str(e)}")
            print(f"Error when getting the following API: {api_url} - {str(e)}")
            return None

def get_catc_name(service):  
        #Find CatC in inventory list
        try:
            device_inventory = service.inventory.filter('device_type', 'CENTER')
            device_name = list(device_inventory.keys())
            if len(device_name) == 0:
                device_inventory = service.inventory.filter('device_type', 'DNAC')
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