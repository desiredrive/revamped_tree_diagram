from pprint import pformat

from device_profiler import Device
from switchingmodules.maclearning import mac_learning
from radkit_cli import logging_info, logging_error, logging_warning
import sys


"""
DHCP Troubleshooting steps:
MAC learning verification
DHCP snooping configuration
DHCP relay trust configuration
DHCP Snooping trust configuration (must be disabled)
Service DHCP configuration
DHCP information option insertion
DHCP Snooping statistics logs
SVI State in IPDT on FE
Helper Address configuration
Helper Address source interface validation
TrustSec validation for DHCP Inject
Map cache status
LISP Session status
Route recursion on FE
Ping reachability between FE and Border RLOC
Ping reachability between Border Anycast GW to DHCP Server (soft-validation/pings can be blocked by fw or natural anycast gw behavior)
Border punt statistics
Border DHCP snooping configuration
Border anycastgw/SVI validation
Input Queue Drops on FE and Borders
Collection of logs: DHCPsnooping platform state,  identification of which state is pending from DORA, show tech)
"""
class EdgeNodeClassifier:
    def __init__(self, mgmtip):
        self.mgmtip = mgmtip

    def device_profiler(self, catc,service,step):
        devprof = Device(self.mgmtip,catc,step)
        devprof.profile_device(service)
        self.profiled_device = devprof

    def maclearning(self,mac, vlan, service):
        hostname = self.profiled_device.hostname
        mac_learning_info = mac_learning(hostname)
        mac_learning_info.mac_learning_mac(mac,vlan,service)
        self.mac_learning_info = mac_learning_info

def exit_program(step, process, subprocess, hostname, error, message):
    logging_error(step, process, subprocess, hostname, error)
    logging_info(step, process, subprocess, hostname, message)
    sys.exit("Error: {} | {}".format(error, message))

def dhcp_mac_address_validation(mac_learning_info,step):
    process = "dhcpTroubleshooting"
    subprocess = "[macAddressLearning]"

    port = mac_learning_info.port
    type = mac_learning_info.type
    mac = mac_learning_info.mac
    vlan = mac_learning_info.vlan
    hostname = mac_learning_info.hostname


    #If 'port' attribute is set to None, exit the program, no MAC address was found
    if port is None:
        msg1 = "DHCP - Layer 2"
        message = f"DHCP Troubleshooting: MAC Address {mac} on VLAN {vlan} not found on device {hostname}."
        exit_program(step, process, subprocess, hostname, msg1 + " | " + message)
    #If type is 'DROP', exit the program
    elif port == "Drop":
        error = "DHCP - Layer 2"
        message = f"DHCP Troubleshooting: MAC Address {mac} on VLAN {vlan} in DROP state on device {hostname}."
        exit_program(step, process, subprocess, hostname, error, message)
    #If Port is "Ac[0-9]", add "FEW Flag on it"
    elif port is None:
        mac_learning_info.fewendpoint = True
        msg1 = "DHCP - Layer 2"
        message = f"DHCP Troubleshooting: MAC Address {mac} on VLAN {vlan} detected on device {hostname}. As the interface is {port}, Fabric-enabled wireless features will not be validated in this flow."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    #If Port is "Tu[0-9]" or "L2LISP0", end the program, indicate that the entry is remote and cause conflict.
    elif ("Tu" in port) or ("L2L" in port):
        error = "DHCP - Layer 2"
        message = f"DHCP Troubleshooting: MAC Address {mac} on VLAN {vlan} detected on device {hostname}. As the interface is {port}, this indicates the endpoint is not directly connected (known via LISP). Please specify the correct device or update the endpoint's location."
        exit_program(step, process, subprocess, hostname, error, message)
    #Print the interface where the MAC address is located and encourage verifying the interface name
    else:
        subprocess = "[macLearning]"
        msg1 = "DHCP - Layer 2"
        message = f"DHCP Troubleshooting: MAC Address {mac} on VLAN {vlan} detected on device {hostname}. The interface is {port}; please confirm if this is the expected port for this endpoint."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    return mac_learning_info

def dhcp_troubleshooting(step, mgmtip, catc_name, vlan, mac, vrf, service):

        process = "dhcpTroubleshooting"
        subprocess = "[main]"
        msg1 = "DHCP - Main"
        message = f"DHCP Troubleshooting: Initiating flow for MAC address {mac} on VLAN {vlan} in VRF {vrf}."
        logging_info(step, process, subprocess, catc_name, msg1 + " | " + message)
        step += 1

        subprocess = "[deviceProfiler]"
        msg1 = "DHCP - Main"
        message = f"DHCP Troubleshooting: Profiling source device {mgmtip}."
        logging_info(step, process, subprocess, catc_name, msg1 + " | " + message)
        step += 1

        edge_node_device = EdgeNodeClassifier(mgmtip)
        edge_node_device.device_profiler(catc_name, service,step)
        hostname = edge_node_device.profiled_device.hostname
        #print(pformat(vars(edge_node_device.profiled_device), indent=4, width=1, sort_dicts=False))

        subprocess = "[macLearning]"
        msg1 = "DHCP - Layer 2"
        message = f"DHCP Troubleshooting: Verifying MAC learning status for MAC address {mac} on VLAN {vlan}."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

        #Validation can only be executed if the device has the "edge" or "l2 handoff" attribute as true
        if edge_node_device.profiled_device.isfabric is True and edge_node_device.profiled_device.edge is True:
            edge_node_device.maclearning(mac,vlan,service)
        elif edge_node_device.profiled_device.isfabric is True and edge_node_device.profiled_device.l2handoff is True:
            edge_node_device.maclearning(mac, vlan, service)

        #print(pformat(vars(edge_node_device.mac_learning_info), indent=4, width=1, sort_dicts=False))

        #MAC Address validation criteria: dhcp_mac_address_validation(mac_learning_info)
        mac_info = edge_node_device.mac_learning_info
        mac_learning_info = dhcp_mac_address_validation(mac_info,step)



