from pprint import pformat

from asn1crypto.core import Boolean
from re import search

from pysnmp.entity.rfc3413.config import getTargetNames
from device_profiler import Device
from ipverifications import subnetvalidation
from routingmodules.cef import phy_cef_collection, IPCef, physical_recursion
from routingmodules.iprouting import IPRoute
from routingmodules.lisp import L3Device, CEFForwardingState
from securitymodules.accesslists import acl_evaluation, AccessList
from securitymodules.authenticationsession import authen_session_for_interface
from securitymodules.ciscotrustsec import cts_endpoint_info, cts_rules
from switchingmodules.cdp import CDPinfo
from switchingmodules.dhcp import DHCPDevice
from switchingmodules.interfaces import Interfaces
from switchingmodules.maclearning import mac_learning
from radkit_cli import logging_info, logging_error, logging_warning, get_catc_api
import sys
from switchingmodules.sisf import SISF
from switchingmodules.vacl import get_vacl_drop_acls
from traffic_flows.iptransit import border_ip_transit
from traffic_flows.lispsessiontroubleshooting import singleETRProfiling
from traffic_flows.operational_tests import Ping
from traffic_flows.wirelessflows import wirelessclientonboarding

"""
DHCP Troubleshooting steps:
MAC learning verification*
DHCP snooping configuration*
DHCP relay trust configuration*
DHCP Snooping trust configuration (must be disabled)*
Service DHCP configuration*
DHCP information option insertion*
DHCP Snooping statistics logs*
SVI State in IPDT on FE
Helper Address configuration*
Helper Address source interface validation*
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
        self.loopback = devprof.loopback

    def maclearning(self,mac, vlan, service):
        hostname = self.profiled_device.hostname
        self.mac = mac
        self.vlan = vlan
        mac_learning_info = mac_learning(hostname)
        mac_learning_info.mac_learning_mac(mac,vlan,service)
        self.mac_learning_info = mac_learning_info

    def localsgt(self,service):
        hostname = self.profiled_device.hostname
        loopback = self.loopback
        localsgt = local_sgt_determination(loopback,hostname,service)
        self.localsgt = localsgt

    def cdpinfo(self,service):
        maclearninginfo = self.mac_learning_info
        hostname = self.profiled_device.hostname
        self.port = maclearninginfo.port
        cdpneighbor = CDPinfo(hostname)
        cdpneighbor.cdpneighborinterface(self.port,service)
        neighbors_list = (
                             cdpneighbor.get('cdpneighbors', [])
                             if isinstance(cdpneighbor, dict)
                             else getattr(cdpneighbor, 'cdpneighbors', [])
                         ) or []
        self.cdpneighborhost = neighbors_list

    def authenticationsession(self,service):
        maclearninginfo = self.mac_learning_info
        hostname = self.profiled_device.hostname
        port = maclearninginfo.port
        authensessiondetails = authen_session_for_interface(hostname,port,service)
        self.authensessiondetails = authensessiondetails

    def dhcpparameters(self,vlan,service):
        hostname = self.profiled_device.hostname
        dhcpparameters = DHCPDevice(hostname)
        dhcpparameters.service_dhcp(service)
        dhcpparameters.dhcpsnooping(service)
        dhcpparameters.dhcpsnoopingacl(service)
        dhcpparameters.dhcpsnoopingstats(service)
        dhcpparameters.dhcpsnoopingbindings(vlan,service)
        dhcpparameters.dhcprelayconfiguration(service)
        dhcpparameters.svi_configuration(vlan,service)
        dhcpparameters.svi_running_config(vlan,service)
        self.dhcpparameters_info = dhcpparameters

    def dhcpsnoopingclientstats(self, service, step):
        hostname = self.profiled_device.hostname
        mac = self.mac
        anycastgw = self.dhcpparameters_info.prefix
        helpers = self.dhcpparameters_info.helper_address
        dhcpsnoopingclientstatistics = DHCPDevice(hostname)
        # Add 'return' here so the values pass back up to the main script
        return dhcpsnoopingclientstatistics.dhcpsnoopclientstat(mac, anycastgw, helpers, service, step)


    def raclvaclpacl(self,service,step):
        hostname = self.profiled_device.hostname
        acls, vacls = local_policies(self.dhcpparameters_info,hostname,self.vlan,self.port,service,step)
        self.edgeacls = acls
        self.edgevacls = vacls

    def sisf_parameters(self,service):
        hostname = self.profiled_device.hostname
        vlan = self.mac_learning_info.vlan
        svi = self.dhcpparameters_info.prefix
        sisfparameters = SISF(hostname)
        sisfparameters.device_tracking_policies(vlan,service)
        sisfparameters.device_tracking_database_address(svi,service)
        sisfparameters.device_tracking_database_history(service)
        self.sisfparameters_info = sisfparameters

    def lispsession(self,service,step):
        catc_name = self.profiled_device.dnac
        vrf = self.dhcpparameters_info.svivrf
        mac = self.mac_learning_info.mac
        vlan = self.mac_learning_info.vlan
        lisp_session = singleETRProfiling(None,mac,vlan,vrf,catc_name,service,step,self.profiled_device)
        self.lisp_session_info = lisp_session
        return step

    def lispparameters(self,service):
        hostname = self.profiled_device.hostname
        vrf = self.dhcpparameters_info.svivrf
        eids = self.dhcpparameters_info.helper_address
        lispparameters = L3Device(vrf,hostname)
        lispparameters.lispiid(service)
        lispparameters.instance_properties(service)
        lispparameters.lisp_database_information(service)
        if self.is_infravn is False:
            lispparameters.map_cache(eids,service)
        self.lispparameters_info = lispparameters

    def infra_vn_forwarding(self,service,step):
        hostname = self.profiled_device.hostname
        helpers = self.dhcpparameters_info.helper_address
        loopback = self.loopback
        localsgt = self.localsgt
        routes, cefhops, total_phys = process_infra_vn_underlay_recursion(helpers,loopback,localsgt,hostname,service,step)
        self.upstreamroutes = routes
        self.upstreamcef = cefhops
        self.upstreamphy = total_phys

    def forwarding_parameters(self,prefixes,service,step):
        hostname = self.profiled_device.hostname
        vrf = self.dhcpparameters_info.svivrf
        cefinternallist = CEFForwardingState(vrf,hostname)
        cefinternallist.cef_resolution(prefixes,service,step)
        self.cefinternallist_info = cefinternallist
        final_rlocs = forwarding_parameters_recursion(cefinternallist,self.profiled_device.dnac,step,hostname)
        cefinternallist.cef_underlay(final_rlocs,service)
        cefinternallist.underlay_phy(service)
        underlay_ports(cefinternallist.physical_interfaces,hostname,step)
        self.final_rlocs = final_rlocs
        self.underlay_ports = cefinternallist.physical_interfaces

def exit_program(step, process, subprocess, hostname, error, message):
    logging_error(step, process, subprocess, hostname, error)
    logging_info(step, process, subprocess, hostname, message)
    sys.exit("Error: {} | {}".format(error, message))

def expand_port(short_name):
    mapping = {
        'Te': 'TenGigabitEthernet',
        'Gi': 'GigabitEthernet',
        'Fa': 'FastEthernet',
        'Eth': 'Ethernet',
        'Ac' : 'AccessTunnel',
        'Ap' : 'AppGigabitEthernet',
        'Fi': 'FiveGigabitEthernet',
        'Tw': 'TwentyGigabitEthernet',
        'Twe': 'TwentyFiveGigE',
        'Fo': 'FortyGigabitEthernet',
        'Hu': 'HundredGigEthernet',
        # Add more if needed
    }
    for abbr, full in mapping.items():
        if short_name.startswith(abbr):
            return short_name.replace(abbr, full, 1)
    return short_name

def dhcp_mac_address_validation(mac_learning_info,step):
    process = "dhcpTroubleshooting"
    subprocess = "[macAddressLearning]"

    port = getattr(mac_learning_info, "port", None)
    m_type = getattr(mac_learning_info, "type", None)
    mac = getattr(mac_learning_info, "mac", "Unknown")
    vlan = getattr(mac_learning_info, "vlan", "Unknown")
    hostname = getattr(mac_learning_info, "hostname", "Unknown")

    #If 'port' attribute is set to None, exit the program, no MAC address was found
    if port is None:
        error = "DHCP - Layer 2"
        message = f"DHCP Troubleshooting: MAC Address not found on device {hostname}."
        exit_program(step, process, subprocess, hostname, error, message)
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

def dhcp_parameters_validation(dhcpparameters_info,interface,vlan,step):
    process = "dhcpTroubleshooting"
    subprocess = "[dhcpParameters]"
    hostname = dhcpparameters_info.device
    #DHCP validations for SD-Access networks:
    #Service DHCP must be enabled
    if dhcpparameters_info.servicedhcp is False:
        error = "DHCP - DHCP Service"
        message = (
            f"DHCP Troubleshooting: Service DHCP is disabled on device '{hostname}'. "
            f"Enable it by configuring \"service dhcp\"."
        )
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        msg1 = "DHCP - DHCP Service"
        message = f"DHCP Troubleshooting: Service DHCP is enabled on device '{hostname}'"
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    #DHCP Snooping is globally enabled
    if dhcpparameters_info.dhcpsnoop_global_enabled is False:
        error = "DHCP - DHCP Snooping"
        message = (
            f"DHCP Troubleshooting: DHCP Snooping is globally disabled on device '{hostname}'. "
            f"Enable it by configuring \"ip dhcp snooping\"."
        )
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        msg1 = "DHCP - DHCP Snooping"
        message = f"DHCP Troubleshooting: DHCP Snooping is globally enabled on device '{hostname}'."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    #DHCP Snooping is enabled on the VLAN
    if int(vlan) not in dhcpparameters_info.dhcpsnoop_configured_vlans:
        error = "DHCP - DHCP Snooping"
        message = (
            f"DHCP Troubleshooting: DHCP Snooping is disabled for vlan {vlan} on device '{hostname}'."
            f"Enable it by configuring \"ip dhcp snooping vlan {vlan}\"."
        )
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        msg1 = "DHCP - DHCP Snooping"
        message = f"DHCP Troubleshooting: DHCP Snooping is enabled for vlan {vlan} on device '{hostname}'."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    #DHCP Snooping is operational on the VLAN
    if int(vlan) not in dhcpparameters_info.dhcpsnoop_operational_vlans:
        error = "DHCP - DHCP Snooping"
        message = (
            f"DHCP Troubleshooting: DHCP Snooping is configured for vlan {vlan} but not operational on device '{hostname}'."
            f"Verify the status of VLAN {vlan}; it may be unconfigured, shut down, or have no ports in a forwarding state in Spanning Tree."
        )
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        msg1 = "DHCP - DHCP Snooping"
        message = f"DHCP Troubleshooting: DHCP Snooping is configured for vlan {vlan} and operational on device '{hostname}'."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    #DHCP Snooping proxy-bridge for the VLAN
    if int(vlan) not in dhcpparameters_info.dhcpsnoop_configured_vlans:
        msg1 = "DHCP - DHCP Snooping"
        message = (
            f"DHCP Troubleshooting: DHCP Snooping Proxy-Bridge is enabled for VLAN {vlan} on device '{hostname}'. "
            "This setting is typically required only for Bridge-Mode VMs or scenarios involving multiple IP-to-MAC mappings."
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    else:
        msg1 = "DHCP - DHCP Snooping"
        message = (
            f"DHCP Troubleshooting: DHCP Snooping Proxy-Bridge is disabled for VLAN {vlan} on device '{hostname}'. "
            "This setting is typically required only for Bridge-Mode VMs or scenarios involving multiple IP-to-MAC mappings."
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    #DHCP Snooping insertion
    if dhcpparameters_info.option82_insertion is False:
        error = "DHCP - DHCP Snooping"
        message = (
            f"DHCP Troubleshooting: DHCP Snooping Option 82 insertion is disabled on device '{hostname}'."
            f"Enable it by configuring \"ip dhcp snooping information option\"."
        )
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        msg1 = "DHCP - DHCP Snooping"
        message = f"DHCP Troubleshooting: DHCP Snooping Option 82 insertion is enabled on device '{hostname}'."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    #DHCP Snooping on interface:
    expanded_port_name = expand_port(interface)
    trustedinterfaces = dhcpparameters_info.trust_interfaces
    if expanded_port_name in trustedinterfaces:
        error = "DHCP - DHCP Snooping"
        message = (
            f"DHCP Troubleshooting: Interface {interface} is configured as a DHCP Snooping trusted interface on device '{hostname}'. "
            f"This configuration may prevent proper insertion of Option 82. "
            f"To allow Option 82 insertion, remove the trust setting from the interface using \"no ip dhcp snooping trust\"."
        )
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        msg1 = "DHCP - DHCP Snooping"
        message = (
            f"DHCP Troubleshooting: Interface {interface} is not configured as a DHCP Snooping trusted interface on device '{hostname}'. "
            "This is the expected and recommended configuration."
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    #DHCP Snooping ACL
    if dhcpparameters_info.dhcpsnoopacl is not None:
        aclname = dhcpparameters_info.dhcpsnoopacl
        msg1 = "DHCP - DHCP Snooping"
        message = (
            f"DHCP Troubleshooting: Warning: A DHCP Snooping ACL \'{aclname}\' is present on device '{hostname}'. "
            "Please review the MAC ACL configuration to ensure it is not inadvertently blocking traffic from your host. "
            "Note: Automated validation of this ACL is not available."
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    else:
        msg1 = "DHCP - DHCP Snooping"
        message = (
            f"DHCP Troubleshooting: No DHCP Snooping ACLs found on device '{hostname}'. "
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    #DHCP Snooping Statistics:
    dhcpsnoopingstats = getattr(dhcpparameters_info, "packets_dropped_because", None)
    if dhcpsnoopingstats:
        for reason, count in dhcpsnoopingstats.items():
            if count > 0:
                msg1 = "DHCP - DHCP Snooping Statistics"
                message = (
                    f"Non-zero DHCP snooping counter detected for reason '{reason}' (count: {count}). "
                    f"Note: these counters are historic and do not necessarily translate to an ongoing problem. "
                    f"Closely monitor the counters with 'show ip dhcp snooping statistic details' to determine if "
                    f"these values are actively incrementing during the current troubleshooting window."
                )
                logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)

    #DHCP Snooping Bindings [Pending]

    #DHCP Relay Configuration:
    if dhcpparameters_info.dhcprelayinformationoption is not True:
        error = "DHCP - DHCP Relay"
        message = (
            f"DHCP Troubleshooting: The global DHCP Relay information option is not configured on device '{hostname}'. "
            f"This may prevent Option 82 from being preserved during DHCP relay. "
            f'To resolve this, configure the global command: \"ip dhcp relay information option\".'
        )
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        msg1 = "DHCP - DHCP Relay"
        message = (
            f"DHCP Troubleshooting: The global DHCP Relay information option is configured on device '{hostname}'. "
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    if dhcpparameters_info.dhcprelayinformationoptionvpn is True:
        error = "DHCP - DHCP Relay"
        message = (
            "DHCP Troubleshooting: The global DHCP Relay information option is configured for VPN. "
            "This setting conflicts with the LISP-based Option 82 functionality. "
            'To resolve this conflict, remove the global command: \"ip dhcp relay information option vpn\".'
        )
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        msg1 = "DHCP - DHCP Relay"
        message = (
            f"DHCP Troubleshooting: The global DHCP Relay information option is configured for default operation on device '{hostname}'. "
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    if dhcpparameters_info.dhcprelayinformationtrustall is True:
        error = "DHCP - DHCP Relay"
        message = (
            "DHCP Troubleshooting: The global DHCP Relay information option is configured for trust-all. "
            "This will prevent Option-82 insertion into DHCP packets on any interface"
            'To resolve this conflict, remove the global command: \"ip dhcp relay information option trust-all\".'
        )
        exit_program(step, process, subprocess, hostname, error, message)

    #SVI Operational Status:
    if (dhcpparameters_info.svienabled is False) or (dhcpparameters_info.svioperational != 'up'):
        error = "DHCP - SVI & Relay Agent"
        message = (
            f"DHCP Troubleshooting: The SVI for VLAN {vlan} is not in an operationally enabled state on '{hostname}'. "
            f"This may be due to the SVI being administratively shut down or because VLAN {vlan} has no ports in the Spanning Tree forwarding state."
        )
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        msg1 = "DHCP - SVI & Relay Agent"
        message = (
            f"DHCP Troubleshooting: The SVI for VLAN {vlan} is operational enabled state on '{hostname}'. "
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    if dhcpparameters_info.prefix is None:
        error = "DHCP - SVI & Relay Agent"
        message = (
            f"DHCP Troubleshooting: The SVI for VLAN {vlan} does not have a primary IP address assigned on '{hostname}'. "
            f"To resolve this issue, configure a primary IP address on the SVI for VLAN {vlan}."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    if dhcpparameters_info.cef_state is not True:
        error = "DHCP - SVI & Relay Agent"
        message = (
            f"DHCP Troubleshooting: The SVI for VLAN {vlan} does not have CEF enabled on '{hostname}'. "
            f"Enable it by configuring \"ip route-cache same-interface\" under the SVI configuration."
        )
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        msg1 = "DHCP - SVI & Relay Agent"
        message = (
            f"DHCP Troubleshooting: The SVI for VLAN {vlan} has CEF enabled on '{hostname}'. "
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    #SVI Helper Addresses:
    if len(dhcpparameters_info.helper_address) == 0:
        error = "DHCP - SVI & Relay Agent"
        message = (
            f"DHCP Troubleshooting: The SVI for VLAN {vlan} does not have a helper-address configured. "
            f"In typical Anycast Gateway deployments, a helper-address is required for DHCP functionality. "
            f"Please verify the DHCP server relay configuration for VLAN {vlan}."
        )
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        msg1 = "DHCP - SVI & Relay Agent"
        message = (
            f"DHCP Troubleshooting: The SVI for VLAN {vlan} has the following relay-agents configured: {dhcpparameters_info.helper_address}. "
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    #Helpers with the wrong vrf
    svivrf = dhcpparameters_info.svivrf
    non_matching_helpers = [
        h for h in dhcpparameters_info.helper_addresses if h.get('vrf') != svivrf
    ]
    for helper in non_matching_helpers:
        error = "DHCP - SVI & Relay Agent"
        message = (
            f"DHCP Troubleshooting: The SVI for VLAN {vlan} has a helper-address configured with an incorrect VRF assignment. "
            f"The problematic relay address is {helper['dhcpserverip']}, which is configured for VRF '{helper['vrf']}' instead of the expected VRF '{svivrf}'. "
            f"Please update or remove the mismatched VRF on the configured helper-addresses."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    #SVI DHCP Configuration
    svidhcpconfigs = dhcpparameters_info.ip_dhcp_commands
    for svidhcpconfig in svidhcpconfigs:
        if "vpn-id" in svidhcpconfig:
            error = "DHCP - SVI & Relay Agent"
            message = (
                f"DHCP Troubleshooting: The SVI for VLAN {vlan} is configured with the DHCP Relay VPN-ID option. "
                "This setting conflicts with LISP-based Option 82 functionality. "
                'To resolve this conflict, remove the command \"ip dhcp relay information option vpn-id\" from the SVI configuration.'
            )
            exit_program(step, process, subprocess, hostname, error, message)
        if "source-interface" in svidhcpconfig:
            expected_vlan = "Vlan"+str(vlan)
            if expected_vlan not in svidhcpconfig:
                error = "DHCP - SVI & Relay Agent"
                message = (
                    f"DHCP Troubleshooting: The SVI for VLAN {vlan} is configured with a non-standard relay source-interface. "
                    "This configuration is not supported in SD-Access fabrics. "
                    'To resolve this issue, remove the command \"ip dhcp relay source-interface\" from the SVI configuration.'
                )
                exit_program(step, process, subprocess, hostname, error, message)

def acl_hit_procedure(edge_node_device,acl,service,step):
    hostname = edge_node_device.profiled_device.hostname
    process = "fabricEdge"
    subprocess = "aclSecurityValidation"

    # Define the two directions of the DHCP flow
    flows = [
        {
            "description": "DHCP Discover (Client to Server)",
            "params": {
                "sourceip": "0.0.0.0",
                "destinationip": "255.255.255.255",
                "protocol": "udp",
                "srcport": 68,
                "dstport": 67
            }
        },
        {
            "description": "DHCP Offer (Server to Client)",
            "params": {
                "sourceip": "0.0.0.0",  # Note: In a real flow, this would be the Server IP
                "destinationip": "255.255.255.255",
                "protocol": "udp",
                "srcport": 67,
                "dstport": 68
            }
        }
    ]

    for flow in flows:
        flow_desc = flow["description"]
        # Perform the ACL evaluation
        hit = acl_evaluation(service, hostname, acl, False, flow["params"])
        action = hit[1].lower() if len(hit) > 1 else "unknown"

        if action == 'deny':
            error = "ACL Validation - Traffic Denied"
            message = (
                f"Security Policy Violation: ACL '{acl}' on {hostname} is explicitly denying {flow_desc}. "
                f"Traffic flow: {flow['params']}. Remediation: Update the dACL/ACL on the AAA server or "
                f"device configuration to permit DHCP traffic."
            )
            exit_program(step, process, subprocess, hostname, error, message)

        elif action == 'permit':
            msg1 = "ACL Validation - Traffic Permitted"
            message = f"Security Policy Pass: ACL '{acl}' on {hostname} permits {flow_desc}."
            logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
            step += 1

    return step

def racl_hit_procedure(edge_node_device,acl,service,step):
    hostname = edge_node_device.profiled_device.hostname
    process = "fabricEdge"
    subprocess = "aclSecurityValidation"

    # Define the two directions of the DHCP flow
    flows = [
        {
            "description": "DHCP Discover (Client to Server)",
            "params": {
                "sourceip": "0.0.0.0",
                "destinationip": "255.255.255.255",
                "protocol": "udp",
                "srcport": 68,
                "dstport": 67
            }
        },
        {
            "description": "DHCP Offer (Server to Client)",
            "params": {
                "sourceip": "0.0.0.0",  # Note: In a real flow, this would be the Server IP
                "destinationip": "255.255.255.255",
                "protocol": "udp",
                "srcport": 67,
                "dstport": 68
            }
        }
    ]

    for flow in flows:
        flow_desc = flow["description"]
        # Perform the ACL evaluation
        hit = acl_evaluation(service, hostname, acl, False, flow["params"])
        action = hit[1].lower() if len(hit) > 1 else "unknown"

        if action == 'deny':
            error = "ACL Validation - Traffic Denied"
            message = (
                f"Security Policy Violation: RACL/PACL '{acl}' on {hostname} on SVI or Port is explicitly denying {flow_desc}. "
                f"Traffic flow: {flow['params']}. Remediation: Update the ACL on the "
                f"device configuration to permit DHCP traffic."
            )
            exit_program(step, process, subprocess, hostname, error, message)

        elif action == 'permit':
            msg1 = "ACL Validation - Traffic Permitted"
            message = f"Security Policy Pass: RACL/PACL '{acl}' on {hostname} permits {flow_desc}."
            logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
            step += 1

    return step

def vacl_hit_procedure(edge_node_device,acl,service,step):
    hostname = edge_node_device.profiled_device.hostname
    process = "fabricEdge"
    subprocess = "aclSecurityValidation"

    # Define the two directions of the DHCP flow
    flows = [
        {
            "description": "DHCP Discover (Client to Server)",
            "params": {
                "sourceip": "0.0.0.0",
                "destinationip": "255.255.255.255",
                "protocol": "udp",
                "srcport": 68,
                "dstport": 67
            }
        },
        {
            "description": "DHCP Offer (Server to Client)",
            "params": {
                "sourceip": "0.0.0.0",  # Note: In a real flow, this would be the Server IP
                "destinationip": "255.255.255.255",
                "protocol": "udp",
                "srcport": 67,
                "dstport": 68
            }
        }
    ]

    for flow in flows:
        flow_desc = flow["description"]
        # Perform the ACL evaluation
        hit = acl_evaluation(service, hostname, acl, False, flow["params"])
        action = hit[1].lower() if len(hit) > 1 else "unknown"

        if action == 'permit':
            error = "ACL Validation - Traffic Denied"
            message = (
                f"Security Policy Violation: VACL '{acl}' on {hostname} is explicitly denying {flow_desc}. "
                f"Traffic flow: {flow['params']}. Remediation: Update the VACL on the "
                f"device configuration to permit DHCP traffic."
            )
            exit_program(step, process, subprocess, hostname, error, message)

        elif action == 'deny':
            msg1 = "ACL Validation - Traffic Permitted"
            message = f"Security Policy Pass: VACL '{acl}' on {hostname} permits {flow_desc}."
            logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
            step += 1

    return step

def validate_authentication_sessions(edge_node_device,step,service):
    process = "fabricEdge"
    subprocess = "authenticationValidation"
    hostname = getattr(edge_node_device, "hostname", "Unknown") if edge_node_device else "Unknown"
    maclearninginfo = edge_node_device.mac_learning_info
    interface_name = maclearninginfo.port
    target_mac = maclearninginfo.mac

    auth_details = getattr(edge_node_device, "authensessiondetails", None) if edge_node_device else None
    if auth_details is None:
        msg1 = "Auth Session - No Configuration"
        message = f"There is no authentication session state available for interface {interface_name}, which means there is no authentication configured for the host."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        return step + 1

    # --- PART 1: Interface Type (Ac / AccessTunnel) ---
    if interface_name.startswith(("Ac", "AccessTunnel")):
        acro_sessions = getattr(auth_details, "acrosessions", {})
        client_acro = next((s for s in acro_sessions if s.get("mac_address") == target_mac), None)

        if client_acro:
            if client_acro.get("authorized") is False:
                error = "Auth Session - Bridge Mode VM Unauth"
                message = f"Endpoint {target_mac} is a Bridge Mode VM endpoint and has not been authenticated by MAB."
                exit_program(step, process, subprocess, hostname, error, message)
            else:
                msg1 = "Auth Session - ACRO Pass"
                message = f"Endpoint {target_mac} is a validated Bridge Mode VM endpoint (Authorized)."
                logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
                step += 1
        return step

    # --- PART 2: Normal Interface (Template & Session Logic) ---
    interface_dict = getattr(auth_details, "templateinterface", {}).get("interface", {})
    # 2. Try a direct match first (just in case)
    template_info = interface_dict.get(interface_name, {})
    # 3. If no direct match, find the key that contains the same interface numbers
    if not template_info:
        # Extract numbers like '1/0/5' from 'Te1/0/5'
        match_numbers = search(r'\d+(/\d+)+', interface_name)
        if match_numbers:
            target_num = match_numbers.group()  # This is '1/0/5'
            for full_name, data in interface_dict.items():
                # Check if '1/0/5' is in 'TenGigabitEthernet1/0/5'
                if target_num in full_name:
                    template_info = data
                    break
    template_name = template_info.get("method", {}).get("static", {}).get("template_name")

    if not template_name:
        msg1 = "Auth Session - No Template"
        message = f"No authentication template is bound to interface {interface_name}."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        return step + 1

    # 1. Safely get the 'templateconfig' dictionary from the object
    config_dict = getattr(auth_details, "templateconfig", {})
    # 2. Get the specific configuration list for the template name
    # We use (config_dict or {}) in case the attribute exists on the object but is set to None
    config_list = (config_dict or {}).get(template_name, [])

    # Determine Closed vs Open and Order of Operation
    is_closed = any("access-session closed" in cmd for cmd in config_list)

    order = "Unknown"
    for cmd in config_list:
        if "service-policy" in cmd:
            if "1X_MAB" in cmd:
                order = "dot1x then MAB"
            elif "MAB_1X" in cmd:
                order = "MAB then dot1x"

    msg1 = "Auth Session - Template Info"
    message = f"Interface {interface_name} using '{template_name}' ({'Closed' if is_closed else 'Open'} mode). Order: {order}."
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    step += 1

    # Calculate dot1x timeout if Closed and 1X_MAB
    if is_closed and "dot1x then MAB" in order:
        # 1. Safely get the 'dot1xinterfaceparameters' attribute from the object
        # 2. Use 'or {}' in case the attribute exists but is set to None
        # 3. Use .get() to find the 'parameters' key
        dot1x_params = (getattr(auth_details, "dot1xinterfaceparameter", {}) or {}).get("parameters", {})
        supp_timeout = dot1x_params.get("SuppTimeout", 0)
        max_req = dot1x_params.get("MaxReq", 0)
        total_timeout = supp_timeout * max_req
        msg1 = "Auth Session - Timeout Calculation"
        message = f"Calculated dot1x timeout (SuppTimeout x MaxReq): {total_timeout} seconds."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

    # --- PART 3: Live Session Data (authsessionintf) ---
    # 1. Safely get the 'authsessionintf' attribute from the object
    auth_session_data = getattr(auth_details, "authsessionintf", {})


    # 2. Drill down into the nested dictionaries
    # 1. Safely get the data (handles if 'authsessionintf' is a method or a dict)
    raw_attr = getattr(auth_details, "authsessionintf", {})
    auth_session_data = raw_attr() if callable(raw_attr) else raw_attr
    # 2. Get the interfaces dictionary
    interfaces_dict = auth_session_data.get("interfaces", {})
    # 3. Normalize the interface name (extract numbers like '1/0/5')
    # This turns 'Te1/0/5' or 'TenGigabitEthernet1/0/5' into '1/0/5'
    match_numbers = search(r'\d+(/\d+)+', interface_name)
    target_id = match_numbers.group() if match_numbers else interface_name
    # 4. Find the matching interface key in the dictionary
    session_intf = {}
    # Try direct match first
    if interface_name in interfaces_dict:
        session_intf = interfaces_dict[interface_name]
    else:
        # Loop through keys to find the one containing the numbers (e.g., '1/0/5')
        for full_name, data in interfaces_dict.items():
            if target_id in full_name:
                session_intf = data
                break
    # 5. Safely get the client session using the target MAC
    client_session = session_intf.get("mac_address", {}).get(target_mac, {})

    if not client_session:
        msg1 = "Auth Session - No Active Session"
        message = f"No active authentication session found for MAC {target_mac} on interface {interface_name}."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        return step + 1

    # IP Address Check
    if not client_session.get("ipv4_address") or client_session.get("ipv4_address") == "Unknown":
        msg1 = "Auth Session - IP Missing"
        message = f"Endpoint {target_mac} does not have an IP address yet or it is not registered in Device Tracking."
        logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

    # Authorization Check (Error if Closed)
    status = client_session.get("status", "")
    if is_closed and "Authorized" not in status:
        error = "Auth Session - Not Authorized"
        message = f"Endpoint {target_mac} is not Authorized. Closed authentication prevents traffic until authorized."
        exit_program(step, process, subprocess, hostname, error, message)

    # Domain Check
    domain = client_session.get("domain", "").upper()
    if domain == "DATA":
        msg1 = "Auth Session - Domain"
        message = f"Endpoint assigned to DATA domain (standard access VLAN)."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    elif domain == "VOICE":
        msg1 = "Auth Session - Domain"
        message = f"Endpoint assigned to VOICE domain (voice VLAN)."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    step += 1

    # Check for MAB configuration
    if not any(cmd.strip() == "mab" for cmd in config_list):
        msg1 = "Auth Session - MAB Warning"
        message = "MAB authentication is disabled in the template; endpoints will only authenticate using dot1x."
        logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

    cdpneighborlist = getattr(edge_node_device, "cdpneighborhost", []) or []

    if len(cdpneighborlist) > 1:
        msg1 = "Auth Session - CDP Discovery"
        message = "Multiple CDP neighbors exist on this interface; cannot determine the primary device. Skipping phone-specific identification."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1
    elif len(cdpneighborlist) == 1:
        neighbor = cdpneighborlist[0]
        capabilities = neighbor.get('capabilities', '')
        # Check if the neighbor is a phone based on CDP capabilities
        is_phone = "Phone" in str(capabilities)
        if is_phone:
            # Check if the authentication template contains the pre-auth voice vlan 2046
            # 'config_list' is the list of commands from the templateconfig attribute
            has_voice_vlan = any("switchport voice vlan 2046" in cmd for cmd in config_list)
            if has_voice_vlan:
                msg1 = "Auth Session - Voice VLAN Warning"
                message = (
                    f"Neighbor {neighbor.get('device_id')} identified as an IP Phone. "
                    "Some phone models might negatively react to the presence of a pre-auth voice vlan (2046) in the template."
                )
                logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)
                step += 1

    # Check for PAE Authenticator (Required)
    if not any("dot1x pae authenticator" in cmd for cmd in config_list):
        error = "Auth Session - PAE Missing"
        message = "The 'dot1x pae authenticator' setting is missing from the template; this is required for the authentication session to start."
        exit_program(step, process, subprocess, hostname, error, message)

    # Host Mode Check
    host_mode = client_session.get("oper_host_mode", "")
    mode_msgs = {
        "multi-auth": "Multiple endpoints are allowed to be authenticated on this interface.",
        "multi-domain": "A single data and a single voice endpoint are allowed on this interface.",
        "single-host": "Only a single endpoint is allowed on this interface."
    }
    msg1 = "Auth Session - Host Mode"
    message = mode_msgs.get(host_mode, f"Host mode: {host_mode}")
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    step += 1

    # Wake On Lan (Control Direction)
    control_dir = client_session.get("oper_control_dir", "")
    if control_dir == "both":
        msg1 = "Auth Session - WOL"
        message = "Wake On Lan is disabled (control-direction both)."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    elif control_dir == "in":
        msg1 = "Auth Session - WOL"
        message = "Wake On Lan is enabled (control-direction in); egress traffic is permitted without authentication."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    step += 1

    # VLAN, SGT, and dACL Assignment
    vlan_id = client_session.get("local_policies", {}).get("vlan_group", {}).get("vlan")
    if vlan_id:
        msg1 = "Auth Session - VLAN Assignment"
        message = f"Endpoint assigned to VLAN {vlan_id} by the AAA server."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

    server_pol = client_session.get("server_policies", {})
    for p_id, p_val in server_pol.items():
        policy_label = p_val.get("name", "").replace(" ", "")

        # Check for SGT
        if "SGT" in policy_label:
            msg1 = "Auth Session - SGT Assignment"
            message = f"Endpoint assigned SGT {p_val.get('policies')} by the AAA server."
            logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
            step += 1

        # Check for dACL (ACS ACL)
        if "ACSACL" in policy_label:
            dacl_name = p_val.get("policies")
            msg1 = "Auth Session - dACL Detected"
            message = f"A Downloadable ACL (dACL) '{dacl_name}' was found assigned to endpoint {target_mac}. Beginning ACL validation tests for DHCP."
            logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)
            step += 1
            step = acl_hit_procedure(edge_node_device,dacl_name,service,step)

    # Method Status Summary
    methods = client_session.get("method_status", {})
    success_method = next((m_name for m_name, m_val in methods.items() if "Success" in m_val.get("state", "")), "None")
    msg1 = "Auth Session - Summary"
    message = f"Authentication successful via method: {success_method}."
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    step += 1

    return step

def lisp_parameters_validation_edge(lispparameters_info,pubsub_flag,step,dhcpparameters_info,sisf_info, is_infravn):
    process = "lispValidations"
    subprocess = "[lispInstanceID]"
    #LISP validations for SD-Access networks:
    #Instance-ID Configuration relevant for DHCP Flows:
    hostname = lispparameters_info.device
    #Pub-Sub identification, is this fabric pub_sub enabled?
    '''
    if pubsub_flag is not True:
        error = "DHCP - LISP"
        message = (
            "DHCP Troubleshooting: The current fabric implementation is LISP1.0, which is unsupported for this sub-module. "
            "DHCP validations will be skipped."
        )
        exit_program(step, process, subprocess, hostname, error, message)
    '''
    #Instance Configuration and validation.
    vrf = lispparameters_info.vrf
    instance_information = lispparameters_info.instance_information
    iid = instance_information.iid
    if iid is None:
        error = "LISP - Instance-ID"
        message = (
            f"LISP Troubleshooting: No Instance-ID found for VRF '{vrf}' on device '{hostname}'. "
            f"Ensure that a LISP instance is configured for this VRF."
        )
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        msg1 = "LISP - Instance-ID"
        message = (
            f"LISP Troubleshooting: Instance-ID '{instance_information.iid}' was identified for VRF '{vrf}' on device '{hostname}'."
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    #Map-Cache validations (Not operational)
        #Map-Cache limit not over 95%
    if instance_information.mapcache['size']*100/instance_information.mapcache['limit'] > 95:
        error = "LISP - Map-Cache Utilization"
        message = (
            f"LISP Troubleshooting: Map-Cache utilization is at {instance_information.mapcache['size']}, exceeding the 95% threshold ({instance_information.mapcache['limit']}) on device '{hostname}'. "
            "This may prevent new Map-Requests from being triggered."
        )
        logging_warning(step, process, subprocess, hostname, error + " | " + message)

    else:
        msg1 = "LISP - Map-Cache Utilization"
        message = (
            f"LISP Troubleshooting: Map-Cache utilization is at {instance_information.mapcache['size']}, which is within the acceptable threshold ({instance_information.mapcache['limit']}) on device '{hostname}'. "
            "New Map-Requests can be processed normally."
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

        #Map-Cache not in singal suppress state
    if instance_information.mapcache['signal_supress'] is True:
        error = "LISP - Map-Cache , Signal Suppression"
        message = (
            f"LISP Troubleshooting: Signal Suppression is enabled on device '{hostname}'. "
            "This indicates the Map-Cache limit is oversubscribed, and new Map-Requests will be suppressed."
        )
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        msg1 = "LISP - Map-Cache , Signal Suppression"
        message = (
            f"LISP Troubleshooting: Signal Suppression is not enabled on device '{hostname}'. "
            "The Map-Cache is operating within limits, and new Map-Requests will be generated as needed."
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

        #Map-Cache 0/0 exists
    # 1. Safely attempt to retrieve map_cache_information
    map_caches = getattr(lispparameters_info, 'map_cache_information', None)

    # 2. Handle the case where map-cache information is missing
    if map_caches is None:
        # Check if this is an Access Point / INFRA_VN flow
        if is_infravn is True:
            msg1 = "LISP - Map-Cache"
            message = (
                f"LISP Troubleshooting: INFRA_VN (Access Point flow) does not require an upstream map-cache "
                f"for IID {iid} on device '{hostname}', as South-North forwarding is handled by the Underlay IGP."
            )
            logging_info(step, process, subprocess, hostname, f"{msg1} | {message}")
            step += 1
        else:
            # If it's not an AP and data is missing, it's a legitimate error
            error = "LISP - Map-Cache Data Error"
            message = f"LISP Troubleshooting: Failed to retrieve map-cache information for IID {iid} on device '{hostname}'."
            exit_program(step, process, subprocess, hostname, error, message)

    # 3. Proceed with validation if map-cache data is present
    else:
        map_cache_default_present = False
        for map_cache in map_caches:
            eid_prefix = getattr(map_cache, 'eid_prefix', "")
            if eid_prefix == "0.0.0.0/0":
                # Safely check sources (assuming it's a list or string)
                sources = getattr(map_cache, 'sources', [])
                if 'static' in sources:
                    map_cache_default_present = True
                    break  # Found it, no need to keep looping

        if not map_cache_default_present:
            error = "LISP - Map-Cache , Static Default"
            message = (
                f"LISP Troubleshooting: Static Map-Cache entry '0.0.0.0/0' was not found for IID {iid} on device '{hostname}'. "
                f"Please reconfigure the missing map-cache entry using the command: \"map-cache 0.0.0.0/0 map-request\" under IID {iid}."
            )
            exit_program(step, process, subprocess, hostname, error, message)
        else:
            msg1 = "LISP - Map-Cache , Static Default"
            message = f"LISP Troubleshooting: Static Map-Cache entry '0.0.0.0/0' is present for IID {iid} on device '{hostname}'."
            logging_info(step, process, subprocess, hostname, f"{msg1} | {message}")
            step += 1

    #Map Resolvers
    map_resolvers = lispparameters_info.instance_information.mapresolvers
    if len(map_resolvers) == 0:
        error = "LISP - Map-Resolvers"
        message = (
            f"LISP Troubleshooting: No Map-Resolvers found for IID {iid} on device '{hostname}'. "
            "Please reconfigure the missing Map-Resolvers in the LISP configuration."
        )
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        msg1 = "LISP - Map-Resolvers"
        message = (
            f"LISP Troubleshooting: Map-Resolver(s) are configured for IID {iid} on device '{hostname}'. "
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    #VXLAN Encapsulation:
    if lispparameters_info.instance_information.encapsulation != 'vxlan':
        error = "LISP - Encapsulation Mode"
        message = (
            f"LISP Troubleshooting: Encapsulation method '{lispparameters_info.instance_information.encapsulation}' is being used instead of VXLAN on device '{hostname}'. "
            "Please reconfigure the encapsulation to \"vxlan\" in the LISP configuration."
        )
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        msg1 = "LISP - Map-Resolvers"
        message = (
            f"LISP Troubleshooting: Encapsulation method 'vxlan' is correctly configured on device '{hostname}'. "
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)


    #Database Mappings:
    #DynamicEID must be enabled for the endpoint vlan.
    svi_ip = dhcpparameters_info.prefix
    svi_mask = dhcpparameters_info.mask
    svi_subnet = subnetvalidation(svi_ip,svi_mask)
    dynamic_eids = lispparameters_info.instance_local_parameters.dynamic_eids
    svi_subnet_in_dyneid = False
    dynamiceidname = None
    for dynamic_eid in dynamic_eids:
        eid_subnet = dynamic_eid['eid_subnet']
        if str(svi_subnet) == eid_subnet:
            svi_subnet_in_dyneid = True
            dynamiceidname = dynamic_eid['dynamic_eid']
    if svi_subnet_in_dyneid is False:
        error = "LISP - Dynamic EID"
        message = (
            f"LISP Troubleshooting: No Dynamic-EID is configured for subnet {svi_subnet} under IID {iid} on device '{hostname}'. "
            f"Please configure the Dynamic-EID entry under the LISP instance {iid}."
        )
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        msg1 = "LISP - Dynamic EID"
        message = (
            f"LISP Troubleshooting: Dynamic-EID {dynamiceidname} is configured for subnet {svi_subnet} under IID {iid} on device '{hostname}'. "
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    #The SVI must be configured with the LISP mobility parameters
    lisp_mobility_entries = dhcpparameters_info.lisp_mobility_entries
    lisp_mobility_entry_flag = False
    for entry in lisp_mobility_entries:
        if entry == dynamiceidname:
            lisp_mobility_entry_flag = True
    if lisp_mobility_entry_flag is False:
        error = "LISP - SVI Dynamic EID"
        message = (
            f"LISP Troubleshooting: No Dynamic-EID is configured for {svi_subnet} under SVI configuration on device '{hostname}'. "
            f"Please configure the Dynamic-EID entry {dynamiceidname} on the SVI with the command \"lisp mobility {dynamiceidname}\"."
        )
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        msg1 = "LISP - SVI Dynamic EID"
        message = (
            f"LISP Troubleshooting: Dynamic-EID '{dynamiceidname}' is configured for subnet {svi_subnet} under the SVI configuration on device '{hostname}'. "
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    #State of SVI on device-tracking
    sisf_entries = sisf_info.dbentries
    for sisf_entry in sisf_entries:
        state = sisf_entry
        interface = sisf_entry['interface']
        vlan = sisf_entry['vlan_id']
        if state == 'REACHABLE':
            if interface != "Vl"+vlan:
                error = "SISF - SVI Status"
                message = (
                    f"SISF Troubleshooting: The SISF entry for {svi_ip} is associated with a non-SVI interface ({interface}) on device '{hostname}'. "
                    f"This issue may result from an unexpected MAC learning event for the SVI MAC address on the foreign port {interface}. "
                    "To resolve this conflict, remove and reconfigure the SVI."
                )
                exit_program(step, process, subprocess, hostname, error, message)
            else:
                msg1 = "LISP - SVI Status"
                message = (
                    f"SISF Troubleshooting: The SISF entry for {svi_ip} is correctly associated with the SVI interface on device '{hostname}'. "
                    "No MAC learning conflicts or misassociations detected; no action is required."
                )
                logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    #Map-Cache Validation:
    #RLOC Status for each Helper Address:
    map_caches = getattr(lispparameters_info, 'map_cache_information', None)
    # 2. Handle missing map-cache data (specifically for INFRA_VN/APs)
    if map_caches is None:
        if is_infravn is True:
            msg1 = "LISP - Helper-Address RLOC reachability"
            message = (
                f"LISP Troubleshooting: INFRA_VN (Access Point flow) does not require upstream map-cache entries "
                f"for Helper-Addresses in IID {iid} on device '{hostname}', as South-North forwarding is handled by the Underlay."
            )
            logging_info(step, process, subprocess, hostname, f"{msg1} | {message}")
            step += 1
        else:
            error = "LISP - Map-Cache Data Error"
            message = f"LISP Troubleshooting: Failed to retrieve map-cache information for IID {iid} on device '{hostname}'."
            exit_program(step, process, subprocess, hostname, error, message)

    # 3. Proceed with RLOC reachability validation
    else:
        for map_cache in map_caches:
            requested_eid = getattr(map_cache, 'requested_eid', "Unknown")
            rlocs = getattr(map_cache, 'rlocs', [])
            eid_prefix = getattr(map_cache, 'eid_prefix', "")

            # We only validate RLOCs for entries that are NOT the local SVI subnet
            if eid_prefix != svi_subnet:
                any_rloc_up = False

                for rloc in rlocs:
                    # Safely get the state from the RLOC dictionary
                    state = rloc.get('state', '').lower()
                    if state == 'up':
                        any_rloc_up = True
                        break  # One UP RLOC is enough for reachability

                if not any_rloc_up:
                    error = "LISP - Helper-Address RLOC reachability"
                    message = (
                        f"LISP Troubleshooting: All RLOCs associated with the Map-Cache entry for Helper-Address {requested_eid} "
                        f"are DOWN on device '{hostname}'. Please verify RLOC reachability in the routing table. "
                        "Edge nodes must have a /32 route to each RLOC. Refer to the GPS_SDA log file for additional details."
                    )
                    exit_program(step, process, subprocess, hostname, error, message)
                else:
                    msg1 = "LISP - Helper-Address RLOC reachability"
                    message = (
                        f"LISP Troubleshooting: At least one RLOC is in the UP state for the Helper-Address {requested_eid} "
                        f"associated with the endpoint SVI on device '{hostname}'. No RLOC reachability issues detected."
                    )
                    logging_info(step, process, subprocess, hostname, f"{msg1} | {message}")
                    step += 1

        #Stop the flow if extranet parameters are found.
        for map_cache in map_caches:
            rlocs = map_cache.rlocs
            requested_eid = map_cache.requested_eid
            for rloc in rlocs:
                encap_iid = rloc['encap_iid']
                if encap_iid != "-":
                    error = "LISP - Extranet RLOC"
                    message = (
                        f"LISP Troubleshooting: The RLOC used to reach {requested_eid} is associated with Extranet Encapsulation IID {encap_iid} on device '{hostname}'. "
                        "This troubleshooting workflow does not support LISP Extranet configurations."
                    )
                    exit_program(step, process, subprocess, hostname, error, message)
                else:
                    msg1 = "LISP - Helper-Address RLOC reachability"
                    message = (
                        f"LISP Troubleshooting: The RLOC used to reach {requested_eid} is not associated with any Extranet Encapsulation IID on device '{hostname}'. "
                        "LISP Extranet configurations are not present; standard troubleshooting steps apply."
                    )
                    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

def forwarding_parameters_recursion(cefinternallist_info,catc_name,step, hostname):
    process = "overlayValidations"
    subprocess = "[edgeNodeForwarding]"
    cef_prefixes = cefinternallist_info
    final_rlocs = []
    for cef_internal_entries in cef_prefixes.cef_internal_entries:
        nexthop_ips = set(hop["nexthop"] for hop in cef_internal_entries.nexthops)
        expected_rlocs = set(rloc["rloc"] for rloc in cef_internal_entries.expected_rloc)
        if nexthop_ips != expected_rlocs:
            error = "CEF - Forwarding"
            message = (
                f"Forwarding Troubleshooting: Mismatch Between nexthops {nexthop_ips} and expected RLOCs: {expected_rlocs} on device {hostname}"
                f"Consult the GPS SDA Log collection file for more information."
            )
            exit_program(step, process, subprocess, catc_name, error, message)
        else:
            msg1 = "CEF - Forwarding"
            message = (
                f"Forwarding Troubleshooting: Nexthops {sorted(nexthop_ips)} and expected RLOCs {sorted(expected_rlocs)} match on device '{hostname}'. "
                "Forwarding details appears correct."
            )
            logging_info(step, process, subprocess, catc_name, msg1 + " | " + message)
        final_rlocs.append(nexthop_ips)
        # Combine all sets and get unique items
        unique_items = set().union(*final_rlocs)
        unique_list = list(unique_items)
        final_rlocs_list = unique_list
        return final_rlocs_list

def underlay_ports(ports, hostname, step):
    subprocess = "[edgeNodeForwarding]"
    process = "dhcpTroubleshooting"

    # Check if the ports list is empty or None
    if not ports:
        error = "Fabric Edge - Underlay Recursion Failed"
        message = (
            "Finding: No physical outgoing ports were identified for the LISP/VXLAN forwarding path to the DHCP server. "
            "Remediation: Verify CEF recursion to the DHCP server on the fabric edge; ensure a valid RLOC is reachable "
            "and that the underlay routing path to the DHCP server is operational."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    # If ports are found, log the success
    msg1 = "Fabric Edge - DHCP Forwarding Path"
    message = (
        f"Finding: The following physical ports were identified for the LISP/VXLAN forwarding path to the DHCP server: {ports}."
    )
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    return step + 1

def rloc_reachability(ports, hostname, service, rlocs, step):
    subprocess = "[underlayReachability]"
    process = "dhcpTroubleshooting"
    # Underlay Interface Parsing
    # [Object: Interface Information and Counters - interfaceobjects]
    interfaceobjects = []
    mtus = []
    for i in ports:
        nhinterfaceinfo = Interfaces(i, hostname)
        nhinterfaceinfo.show_interface(service)
        interfaceobjects.append(nhinterfaceinfo)
    for i in interfaceobjects:
        phy_cef_collection(i, step)
        # print (pformat(vars(i), indent=4, width =1, sort_dicts=False))
        mtus.append(i.mtu)
        # print ("\n")

    # Minimum MTU calculation
    subprocess = "[mtu]"
    mtus.sort()
    minimum = mtus[0]
    logging_info(step, process, subprocess, hostname,
                 "The lowest MTU between underlay interfaces for device: {} is {}".format(hostname, minimum))
    # print ("The lowest MTU between underlay interfaces for device: {} is {}".format(srcxtr.hostname, minimum))

    for rloc in rlocs:
        # RLOC to RLOC Ping Validation
        # 1) Without MTU
        # print ("RLOC to RLOC results with low MTU")
        normal_ping = Ping(rloc, hostname)
        normal_ping.ping_with_source(None, "Lo0", None, False, service)
        logging_info(step, process, subprocess, hostname,
                     "RLOC to RLOC results with low MTU: {} % Success".format(normal_ping.result))
        # print (pformat(vars(normal_ping), indent=4, width =1, sort_dicts=False))
        # 2) With MTU
        # print ("RLOC to RLOC results with {} MTU".format(minimum))
        mtu_ping = Ping(rloc, hostname)
        mtu_ping.ping_with_source(None, "Lo0", minimum, True, service)
        # print (pformat(vars(mtu_ping), indent=4, width =1, sort_dicts=False))
        logging_info(step, process, subprocess, hostname,
                     "RLOC to RLOC results with {} MTU: {} % Success".format(minimum, normal_ping.result))

        if int(normal_ping.result) <= 70:
            logging_warning(step, process, subprocess, hostname,
                            "WARNING! : Packet Loss from {} to {} is below threshold of 70%, current value is {} % with low MTU".format(
                                 hostname, rloc, normal_ping.result))
            # print ("WARNING! : Packet Loss from {} to {} is below threshold of 70%, current value is {} % with low MTU \n".format(srcxtr.hostname, rloccef.ip, normal_ping.result))
        else:
            logging_info(step, process, subprocess, hostname,
                         "ICMP Connectivity from {} to {} is good at {} % success rate with low MTU".format(hostname,
                                                                                                            rloc,
                                                                                                            normal_ping.result))
            # print ("ICMP Connectivity from {} to {} is good at {} % success rate with low MTU \n".format(srcxtr.hostname, rloccef.ip, normal_ping.result))

        if int(mtu_ping.result) <= 70:
            logging_warning(step, process, subprocess, hostname,
                            "WARNING! : Packet Loss from {} to {} is below threshold of 70%, current value is {} % with {} MTU".format(
                                hostname, rloc, normal_ping.result, minimum))
            # print ("WARNING! : Packet Loss from {} to {} is below threshold of 70%, current value is {} % with {} MTU \n".format(srcxtr.hostname, rloccef.ip, normal_ping.result, minimum))
        else:
            logging_info(step, process, subprocess, hostname,
                         "ICMP Connectivity from {} to {} is good at {} % success rate with {} MTU".format(hostname,
                                                                                                           rloc,
                                                                                                           normal_ping.result,
                                                                                                           minimum))
            # print ("ICMP Connectivity from {} to {} is good at {} % success rate with {} MTU \n".format(srcxtr.hostname, rloccef.ip, normal_ping.result, minimum))

def validate_border_acls(border_objects, service,step):
    process = "externalConnectivity"
    subprocess = "aclValidation"

    for border in border_objects:
        hostname = getattr(border, "hostname", "Unknown")
        # Safely retrieve the list; default to an empty list if missing or None
        acl_names = getattr(border, "egress_acls", []) or []
        if not acl_names:
            msg = f"No egress ACLs identified on border {hostname}."
            logging_info(step, process, subprocess, hostname, msg)
            step += 1
            continue

        # Proceed with ACL validation logic for this border
        for acl in acl_names:
            acl_hit_procedure(border,acl,service,step)
        # ...

    return step

def local_policies(dhcpparameters_info, hostname, vlan_id, port, service, step):
    process = "dhcpPolicies"
    subprocess = "[localPolicies]"

    # 1. Extract configured RACLs (inbound and outbound) from dhcpparameters_info
    inbound = getattr(dhcpparameters_info, "inboundacl", None)
    outbound = getattr(dhcpparameters_info, "outboundacl", None)
    found_racls = [acl for acl in [inbound, outbound] if acl]

    # 2. Extract PACLs if the port is Physical or a Port-Channel
    port_str = str(port)
    if not port_str.startswith(("AccessTunnel", "Ac", "LISP")):
        # Instantiate AccessList and retrieve ACLs for the physical/port-channel interface
        portacls = AccessList(hostname)
        portacls.aclbyinterface(port_str, service)
        # Safely retrieve the list of ACL names
        port_acls_list = getattr(portacls, "aclnames", []) or []
        # Add found PACLs to the RACL list
        if port_acls_list:
            found_racls.extend(port_acls_list)

    # Create a unique list of RACLs + PACLs
    unique_racls = list(dict.fromkeys(found_racls))

    # 3. Get VACLs using the existing function
    vacl_raw = get_vacl_drop_acls(hostname, vlan_id, service)

    # 4. Handle the Implicit Deny marker as a fatal error
    if "VACL_IMPLICIT_DENY_ACTIVE" in vacl_raw:
        error = "VACL Validation - Implicit Deny Active"
        message = (
            f"The VLAN Access Map applied to VLAN {vlan_id} does not contain a final "
            f"'action forward' sequence. This results in an implicit deny for all unmatched traffic, "
            f"which will block DHCP. Remediation: Add a final sequence to the VLAN access-map "
            f"with 'action forward' to permit remaining traffic."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    # 5. Filter out the marker and reverse the VACL list for evaluation
    unique_vacls = [acl for acl in vacl_raw if acl != "VACL_IMPLICIT_DENY_ACTIVE"]
    unique_vacls.reverse()

    # Return both lists separately
    return unique_racls, unique_vacls

def process_map_cache_recursion(edge_node_device, mac, vlan, service, step, iid, vrf):
    """
    Analyzes LISP map-cache entries for helper addresses.
    Triggers LISP and Border troubleshooting flows for unresolved entries.
    Returns the updated step and a list of valid forwarding_prefixes.
    """
    process = "dhcpTroubleshooting"
    subprocess = "[edgeNodeForwarding]"
    forwarding_prefixes = []
    # Safely retrieve the profiled_device object, defaulting to None if missing or if edge_node_device is None
    sourcextr = getattr(edge_node_device, "profiled_device", None) if edge_node_device else None
    mgmtip = (getattr(sourcextr, "mgmtip", "Unknown") or "Unknown") if sourcextr else "Unknown"
    catc_name = (getattr(sourcextr, "dnac", "Unknown") or "Unknown") if sourcextr else "Unknown"
    hostname = (getattr(edge_node_device, "hostname", "Unknown") or "Unknown") if sourcextr else "Unknown"
    fabric_id  = (getattr(sourcextr, "fabric_id", "Unknown") or "Unknown") if sourcextr else "Unknown"
    srcip = getattr(sourcextr, "loopback", None) if sourcextr else None
    map_caches = (getattr(getattr(edge_node_device, "lispparameters_info", None), "map_cache_information", []) or [])
    # Helper for shared object access

    for map_cache in map_caches:
        # Safely get the attributes
        source_type = str(getattr(map_cache, "sources", "")).lower()
        helper_address = getattr(map_cache, "requested_eid", "Unknown")
        eid_prefix = getattr(map_cache, "eid_prefix", None)
        rlocs = getattr(map_cache, "rlocs", []) or []

        # --- Scenario 1: Data-Signal Detected ---
        if "data-signal" in source_type:
            msg1 = "LISP Map-Cache - Data-Signal Detected"
            message = (
                f"Finding: Map-cache for helper address {helper_address} is in 'data-signal' state. "
                f"Action: Triggering LISP session flow to investigate Control Plane connectivity."
            )
            logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)
            step += 1

            # Trigger the LISP session flow
            step = singleETRProfiling(mgmtip, mac, vlan, None, catc_name, service, step, sourcextr)
            continue

            # --- Scenario 2: Default Route Recursion with No RLOCs ---
        elif eid_prefix == "0.0.0.0/0" and not rlocs:
            msg1 = "LISP Map-Cache - Default Route Recursion"
            message = (
                f"Finding: Map-cache for destination {helper_address} resolves to the default route (0.0.0.0/0) "
                f"but contains no valid RLOCs. Action: Initiating LISP troubleshooting and Border validation."
            )
            logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
            step += 1

            # 1. Trigger LISP Troubleshooting Session
            step = singleETRProfiling(mgmtip, mac, vlan, vrf, catc_name, service, step, sourcextr)
            # 2. Trigger Border Validation Functions (using helper_address as dstip)
            border_objects, step = border_ip_transit(step, catc_name, fabric_id, vrf, vlan, srcip, helper_address,
                                                     service, True, iid)
            continue

            # --- Scenario 3: Valid/Standard Source ---
        # Purge RLOCs not in "up" state
        new_rlocs = [rloc for rloc in rlocs if rloc.get('state') == 'up']

        if new_rlocs:
            prefixes = {
                'prefix': helper_address,
                'expectedrlocs': new_rlocs
            }
            forwarding_prefixes.append(prefixes)
        else:
            msg1 = "LISP Map-Cache - No Active RLOCs"
            message = f"Finding: Map-cache for {helper_address} found, but no RLOCs are in the 'up' state."
            logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)
            step += 1

    return step, forwarding_prefixes

def validate_dhcp_server_compatibility(border_objects, dora_state, step):
    """
    Final validation to check if the DHCP server supports Option 82
    when reachability is confirmed but DORA fails at the start.
    """
    process = "dhcpTroubleshooting"
    subprocess = "[serverCompatibility]"
    hostname = "Fabric-Wide"

    # Check if at least one border successfully pinged the DHCP server
    # (Assuming border_objects have a 'ping_reachable' attribute from your border_ip_transit logic)
    reachability_confirmed = any(getattr(border, 'ping_reachable', False) for border in border_objects)

    if dora_state == "STUCK at DISCOVER" and reachability_confirmed:
        msg1 = "DHCP - Option 82 & Server Trust"
        message = (
            "CRITICAL REVIEW REQUIRED: The DHCP process is STUCK at DISCOVER, but the Border nodes "
            "have confirmed IP reachability to the DHCP server. In SD-Access, the Fabric Edge "
            "inserts Option 82 (Relay Agent Information). If the DHCP server is not configured to "
            "honor or trust Option 82, it will silently drop the DISCOVER or strip the option from the OFFER."
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

        # List of well-known servers with specific Option 82 requirements
        compat_list = (
            "\nManual Verification Steps for DHCP Servers:\n"
            "1. Microsoft Windows Server: Ensure 'Relay Agent Information' is enabled and the 'Trust' bit is considered.\n"
            "2. Infoblox: Must be configured to 'Trust Relay Agent Option' and 'Echo back Option 82'.\n"
            "3. BlueCat: Check if the 'Relay Agent Info' deployment option is active for the specific subnet.\n"
            "4. Cisco Prime/CNR: Verify that the server is not configured to drop packets with existing Option 82 information.\n"
            "5. ISC DHCP (Linux): Ensure 'stash-agent-options' is enabled and the server is configured to permit agent options."
        )
        logging_info(step, process, subprocess, hostname, compat_list)

    elif dora_state == "STUCK at DISCOVER" and not reachability_confirmed:
        logging_info(step, process, subprocess, hostname, "DHCP - Server Reachability | Borders cannot reach the DHCP server. Fix routing/ACLs before checking Option 82.")

    return step + 1

def local_sgt_determination(loopback,hostname,service):
    localsgt = IPCef(loopback,None,hostname)
    localsgt.sgtfromcef(service)
    lsgt = getattr(localsgt, 'sgt', 0)

    return lsgt

def process_infra_vn_underlay_recursion(destinations, loopback0, localsgt, hostname, service, step):
    """
    Validates underlay recursion for INFRA_VN by collecting routing and CEF
    information for DHCP server destinations in the default VRF.
    """
    routes = []
    total_phys = []
    cefhops = []

    for destination in destinations:
        # 1. Collect IP Route Information
        iprouteobject = IPRoute(destination, 'default', hostname)
        iprouteobject.iproute_prefix_soft(service, step)
        routes.append(iprouteobject)

        # 2. Collect CEF Information
        ipcefobject = IPCef(destination, 'default', hostname)
        ipcefobject.get_cef_internal(service)
        cefhops.append(ipcefobject)

    seen_prefixes = set()
    unique_cefhops = []
    for hop in cefhops:
        prefix = getattr(hop, 'prefix', None) if not isinstance(hop, dict) else hop.get('prefix')
        if prefix and prefix not in seen_prefixes:
            unique_cefhops.append(hop)
            seen_prefixes.add(prefix)
    # Update the original list with unique entries
    cefhops = unique_cefhops

    # 3. Validation of proper physical interface recursion
    for cef_obj in unique_cefhops:
        # Perform physical recursion check
        phy_result = physical_recursion(cef_obj, hostname)
        phy_result.get_physical_interfaces(service, step)

        if phy_result:
            # Safely retrieve the physical interfaces list
            phy_list = getattr(phy_result, 'total_phys', [])

            # Define a small helper to flatten nested structures
            def extract_interfaces(item):
                if isinstance(item, list):
                    for subitem in item:
                        yield from extract_interfaces(subitem)
                elif isinstance(item, dict):
                    # Grab the key (interface name) from Genie dicts
                    yield next(iter(item))
                elif isinstance(item, str) and item.strip():
                    yield item

            # Use the helper to extend the master list
            total_phys.extend(list(extract_interfaces(phy_list)))

    total_phys = list(set([p for p in total_phys if isinstance(p, str)]))

    access_lists = []
    for phy in total_phys:
        acls_obj = AccessList(hostname)
        acls_obj.aclbyinterface(phy, service)
        found_acls = getattr(acls_obj, 'aclnames', None)

        if found_acls:
            if isinstance(found_acls, list):
                valid_acls = [acl for acl in found_acls if acl]
                access_lists.extend(valid_acls)
            else:
                access_lists.append(found_acls)

    access_lists = list(set([acl for acl in access_lists if acl]))
    #Validation of SGACL enforcement status, SGACL presence, SGT/DSGT rule, rbacl, etc.
    cts_objects = []
    for phy in total_phys:
        ctsobject = cts_endpoint_info(loopback0,None,hostname)
        ctsobject.interface = phy
        ctsobject.cts_enforcement(None,phy,service)
        cts_objects.append(ctsobject)

    evaluation_flag = False
    if cts_objects:
        # 1. Check if ALL items have globalenforcement: True
        # We use a helper to handle both object attributes and dictionary keys
        all_global = all(
            (obj.globalenforcement if hasattr(obj, 'globalenforcement') else obj.get('globalenforcement', False))
            for obj in cts_objects
        )

        # 2. Check if at least ONE item has ctsportenabled: True
        any_port_enabled = any(
            (obj.ctsportenabled if hasattr(obj, 'ctsportenabled') else obj.get('ctsportenabled', False))
            for obj in cts_objects
        )

        # 3. Final Evaluation
        if all_global and any_port_enabled:
            evaluation_flag = True

    #If evaluation is needed, get localsgt from endpointdevice and dgst from unique CEF hops
    finalacls = []
    if evaluation_flag is True:
        dsgts = []
        for hop in cefhops:
            ip = getattr(hop, 'ip', None) if not isinstance(hop, dict) else hop.get('ip')
            dsgtobject = IPCef(ip, None, hostname)
            dsgtobject.sgtfromcef(service)
            dsgt = getattr(dsgtobject, 'sgt', 0)
            dsgts.append(dsgt)
        dsgts = list(set(dsgts))
        rbacls = []
        for dsgt in dsgts:
            rules = cts_rules(hostname)
            rules.cts_rbac_permissions(localsgt,dsgt,service)
            rbacl = getattr(rules, 'rawrbacl', None)
            isrbacl = getattr(rules, 'isdownloaded', False)
            rbacldict  = {
                'isdownloaded' : isrbacl,
                'rbacl' : rbacl,
            }
            rbacls.append(rbacldict)

        process = "DHCP Underlay"
        subprocess = "[aclRBACLPolicy]"
        # Define the two directions of the DHCP flow
        flows = [
            {
                "description": "DHCP Discover (Client to Server)",
                "params": {
                    "sourceip": "0.0.0.0",
                    "destinationip": "255.255.255.255",
                    "protocol": "udp",
                    "srcport": 68,
                    "dstport": 67
                }
            }
        ]
        for rbacl in rbacls:
            acl = rbacl['rbacl']
            for flow in flows:
                flow_desc = flow["description"]
                # Perform the ACL evaluation
                hit = acl_evaluation(service, hostname, acl, True, flow["params"])
                action = hit[1].lower() if len(hit) > 1 else "unknown"

                if action == 'deny':
                    error = "RACL Validation - Traffic Denied"
                    message = (
                        f"Security Policy Violation: RBACL '{acl}' on {hostname} on TrustSec is denying {flow_desc}. "
                        f"Traffic flow: {flow['params']}. Remediation: Update the ACL on the "
                        f"device configuration to permit DHCP traffic."
                    )
                    exit_program(step, process, subprocess, hostname, error, message)

                elif action == 'permit':
                    msg1 = "RACL Validation - Traffic Permitted"
                    message = f"Security Policy Pass: RBACL '{acl}' on {hostname} permits {flow_desc}."
                    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
                    step += 1
        for acl in access_lists:
            for flow in flows:
                flow_desc = flow["description"]
                # Perform the ACL evaluation
                hit = acl_evaluation(service, hostname, acl, False, flow["params"])
                action = hit[1].lower() if len(hit) > 1 else "unknown"

                if action == 'deny':
                    error = "RACL Validation - Traffic Denied"
                    message = (
                        f"Security Policy Violation: RACL/PACL '{acl}' on {hostname} is denying {flow_desc}. "
                        f"Traffic flow: {flow['params']}. Remediation: Update the ACL on the "
                        f"device configuration to permit DHCP traffic."
                    )
                    exit_program(step, process, subprocess, hostname, error, message)

                elif action == 'permit':
                    msg1 = "RACL Validation - Traffic Permitted"
                    message = f"Security Policy Pass: RACL/PACL '{acl}' on {hostname} permits {flow_desc}."
                    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
                    step += 1

    return routes,cefhops,total_phys

def validate_infra_vn_underlay_nexthops(cefhops, total_phys, hostname, service, step):
    """
    Validates that INFRA_VN South-North routing uses valid physical/logical
    underlay paths and not overlay/tunnel interfaces.
    """
    process = 'DHCP Troubleshooting - INFRA-VN'
    subprocess = "[edgeNodeForwarding]"
    invalid_keywords = ["lisp", "tunnel", "accesstunnel", "drop", "null", "loopback"]
    valid_nexthop_found = False

    msg1_pos = "DHCP - Underlay Validation"
    msg1_err = "DHCP - Underlay Error"

    for cef_obj in cefhops:
        prefix = getattr(cef_obj, 'prefix', 'Unknown') if not isinstance(cef_obj, dict) else cef_obj.get('prefix',
                                                                                                         'Unknown')
        # 1. Check if ismpls is True
        ismpls = getattr(cef_obj, 'ismpls', False) if not isinstance(cef_obj, dict) else cef_obj.get('ismpls', False)
        if ismpls:
            error = msg1_err
            message = (
                f"Invalid path detected for prefix {prefix}: ismpls is set to True. "
                "MPLS is not a valid nexthop for INFRA_VN South-North routing."
            )
            exit_program(step, process, subprocess, hostname, error, message)

        # 2. Extract nexthops
        nexthops = getattr(cef_obj, 'nexthops', []) if not isinstance(cef_obj, dict) else cef_obj.get('nexthops', [])

        for nh in nexthops:
            oif = nh.get('oif', '')

            # Handle if oif is a dictionary (e.g., {'Loopback0': {}}) or a string
            if isinstance(oif, dict):
                oif_name = next(iter(oif)).lower()
            else:
                oif_name = str(oif).lower()

            # 3. Check for invalid OIF keywords (case-insensitive)
            is_invalid = any(keyword in oif_name for keyword in invalid_keywords)

            if is_invalid:
                error = msg1_err
                message = (
                    f"Invalid Outgoing Interface (oif) '{oif}' detected for prefix {prefix}. "
                    "LISP, Loopback, Tunnel, AccessTunnel, drop, and Null are not valid nexthops for INFRA_VN South-North routing."
                )
                exit_program(step, process, subprocess, hostname, error, message)

            # Mark that we found at least one valid physical/logical path
            valid_nexthop_found = True

    # 4. Final check: Ensure at least one valid path exists
    if not valid_nexthop_found:
        error = msg1_err
        message = "Validation Failed: Not a single valid physical underlay nexthop was found for INFRA_VN South-North routing."
        exit_program(step, process, subprocess, hostname, error, message)

    # 5. Positive Logging if all checks pass
    message = (
        "DHCP Troubleshooting: All nexthops for INFRA_VN South-North routing are valid physical or "
        "logical underlay paths. No overlay or tunnel recursion detected."
    )
    logging_info(step, process, subprocess, hostname, f"{msg1_pos} | {message}")
    step += 1

    #Physical Interface Counters
    mtu_values = []
    if not total_phys:
        error = "DHCP - Underlay Interface Error"
        message = (
            f"No physical interfaces were identified for the underlay path on device '{hostname}'. "
            "This usually indicates a failure in CEF recursion or missing routing information. "
            "Validation cannot proceed."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    for interface in total_phys:
        # 1. Instantiate and collect interface data
        intf_obj = Interfaces(interface, hostname)
        intf_obj.show_interface(service)

        # 2. Collect MTU for later analysis
        # Safely get MTU and convert to int for comparison
        raw_mtu = getattr(intf_obj, 'mtu', None)
        if raw_mtu:
            try:
                mtu_values.append(int(raw_mtu))
            except (ValueError, TypeError):
                pass

        # 3. Check for Errors and Drops
        # We map the attribute names from your class to readable labels
        counter_map = {
            "Input Queue Drops": getattr(intf_obj, 'iiqdrops', 0),
            "Output Drops": getattr(intf_obj, 'outputdrops', 0),
            "Giants": getattr(intf_obj, 'giants', 0),
            "Runts": getattr(intf_obj, 'runts', 0),
            "CRC Errors": getattr(intf_obj, 'crcerrors', 0)
        }

        # Identify any counter > 0
        active_issues = [f"{label} ({val})" for label, val in counter_map.items() if val and val > 0]

        if active_issues:
            msg1 = "DHCP - Interface Performance Warning"
            message = (
                f"Interface {interface} on {hostname} is reporting increments in error counters: "
                f"{', '.join(active_issues)}. This could lead to DHCP packet drops in the underlay."
            )
            logging_warning(step, process, subprocess, hostname, f"{msg1} | {message}")
            step += 1

        # 4. Check Line/Oper State (Bonus safety check)
        if getattr(intf_obj, 'linestate', '').lower() != 'up' or getattr(intf_obj, 'operstate', '').lower() != 'up':
            msg1 = "DHCP - Interface State Warning"
            message = f"Interface {interface} on {hostname} is not in a fully 'UP' state. Verify physical connectivity."
            logging_warning(step, process, subprocess, hostname, f"{msg1} | {message}")
            step += 1

    return step

def dhcp_troubleshooting(step, mgmtip, catc_name, vlan, mac, vrf, is_few: bool, service):

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

        #INFRA_VN Validation
        edge_node_device.is_infravn = False
        if vrf is None:
            subprocess = "[vrfValidation]"
            error = "DHCP - VRF Error"
            message = "VRF cannot be None. If INFRA_VN is required for Access Point or Extended Nodde troubleshooting, please use 'default' as the VRF name."
            # Using exit_program as this is a terminal error for the flow
            exit_program(step, process, subprocess, hostname, error, message)

        # 2. Check if VRF is 'default' or 'Default'
        elif str(vrf).lower() == "default":
            edge_node_device.is_infravn = True
            subprocess = "[vrfValidation]"
            msg1 = "DHCP - VRF"
            message = (
                "No VRF has been provided, assuming Default VRF for INFRA_VN validations "
                "(Access Points and Extended Nodes). Access Point troubleshooting flow is only "
                "supported if it is directly connected to the Edge Node and CDP is enabled."
            )
            logging_info(step, process, subprocess, hostname, f"{msg1} | {message}")
            step += 1
            # Stability Warning Log
            subprocess = "[accessPointStability]"
            msg1 = "DHCP - Warning"
            message = (
                "DHCP Flow for access points requires the endpoint to be as stable as it can "
                "in the MAC address table and other LISP forwarding tables, estabilize it's "
                "flapping as much as possible, otherwise you might need to run this script multiple times."
            )
            logging_info(step, process, subprocess, hostname, f"{msg1} | {message}")
            step += 1

        if is_few is True:
            fabric_site_id = edge_node_device.profiled_device.fabric_id
            step, new_sourcextr = wirelessclientonboarding(step, fabric_site_id, catc_name, mac,service)
            edge_node_device.profiled_device = new_sourcextr
            hostname = edge_node_device.profiled_device.hostname

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


        mac_info = edge_node_device.mac_learning_info
        mac_learning_info = dhcp_mac_address_validation(mac_info,step)
        #print(pformat(vars(mac_learning_info), indent=4, width=1, sort_dicts=False))

        # Authentication Session Validation
        subprocess = "[authenticationSession]"
        msg1 = "DHCP - Authentication"
        message = f"DHCP Troubleshooting: Verifying authentication parameters for MAC address {mac} on VLAN {vlan}."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

        edge_node_device.is_ap = False
        edge_node_device.cdpinfo(service)

        cdp_neighbors = getattr(edge_node_device, 'cdpneighborhost', [])
        if isinstance(cdp_neighbors, list):
            for neighbor in cdp_neighbors:
                # Extracting data from the neighbor dictionary
                platform = neighbor.get('platform', '').lower()
                capabilities = neighbor.get('capabilities', '')
                neighbor_id = neighbor.get('device_id', 'Unknown')
                # Check for Cisco AP signature
                if 'cisco' in platform and 'Router' in capabilities and 'Trans-Bridge' in capabilities:
                    # 4. Set the flag on the object to True
                    edge_node_device.is_ap = True
                    subprocess = "[cdpAnalysis]"
                    msg1 = "DHCP - CDP Neighbor"
                    local_port = getattr(edge_node_device, 'port', 'Unknown Port')
                    message = (
                        f"Cisco Access Point detected on interface {local_port} "
                        f"(Neighbor ID: {neighbor_id}). 'is_ap' flag set to True."
                    )
                    logging_info(step, process, subprocess, hostname, f"{msg1} | {message}")
                    step += 1
                    break

        edge_node_device.authenticationsession(service)
        step = validate_authentication_sessions(edge_node_device,step,service)

        #Local SGT Identification
        subprocess = "[localSGT]"
        msg1 = "DHCP - Local SGT"
        message = f"DHCP Troubleshooting: Determining Local SGT for device: {hostname}"
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

        edge_node_device.localsgt(service)

        #Pool Identification (AnycastGW or L2 Only)
        subprocess = "[poolIdentification]"
        msg1 = "DHCP - CatalystCenter API"
        message = f"DHCP Troubleshooting: Retrieving pool details for VLAN {vlan}."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

        fabric_id = edge_node_device.profiled_device.fabric_id
        url = "/dna/intent/api/v1/sda/layer2VirtualNetworks?fabricId="+fabric_id+"&vlanId="+str(vlan)
        pool_information = get_catc_api(catc_name, url,service)['response'][0]
        siteNameHierarchy = edge_node_device.profiled_device.fabric_site_hierarchy
        vlanName = pool_information['vlanName']
        if edge_node_device.is_infravn is True:
            vn_name = 'INFRA_VN'
        else:
            vn_name = vrf
        pool_details = (
            f"/dna/intent/api/v1/business/sda/virtualnetwork/ippool"
            f"?siteNameHierarchy={siteNameHierarchy}"
            f"&virtualNetworkName={vn_name}"
            f"&ipPoolName={vlanName}"
        )
        pool_information_detail = get_catc_api(catc_name, pool_details, service)
        edge_node_device.pool_info = pool_information_detail
        pool_data = edge_node_device.pool_info
        if pool_data.get('isLayer2OnlyPool') is True:
            error = "DHCP - Pool Identification"
            message = (
                "DHCP Troubleshooting: DHCP traffic flow information is not available for Layer 2-only pools."
            )
            exit_program(step, process, subprocess, catc_name, error, message)
        else:
            ippoolname = pool_data.get('vlanName', pool_data.get('ipPoolName', 'Unknown'))
            pooltype = pool_data.get('poolType', pool_data.get('trafficType', 'DATA'))
            vlan_id_api = pool_data.get('vlanId', 'Unknown')

            msg1 = "DHCP - Pool Identification"
            message = (
                f"DHCP Troubleshooting: IP pool '{ippoolname}' is assigned to VLAN {vlan_id_api}. "
                f"The pool type is '{pooltype}', and it is configured as an Anycast Gateway."
            )
            logging_info(step, process, subprocess, catc_name, f"{msg1} | {message}")
            step += 1

        #DHCP Configuration
        subprocess = "[dhcpParameters]"
        msg1 = "DHCP - DHCP Service, Relay and Snooping"
        message = f"DHCP Troubleshooting: Initiating verification of global DHCP parameters for VLAN {vlan}."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

        edge_node_device.dhcpparameters(vlan,service)
        dhcp_info = edge_node_device.dhcpparameters_info
        #print(pformat(vars(dhcp_info), indent=4, width=1, sort_dicts=False))
        sourceintf = mac_learning_info.port
        dhcp_parameters_validation(dhcp_info,sourceintf,vlan,step)

        #DHCP Configuration
        subprocess = "[dhcpParameters]"
        msg1 = "DHCP - DHCPSnooping Statistics"
        message = "Evaluating DHCP transaction logs to determine the specific DORA stage reached by the endpoint."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

        # DHCP Configuration
        subprocess = "[dhcpParameters]"
        msg1 = "DHCP - DHCPSnooping Statistics"
        message = "Evaluating DHCP transaction logs to determine the specific DORA stage reached by the endpoint."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

        step, dora_state = edge_node_device.dhcpsnoopingclientstats(service,step)

        #Local Policies (ACL, VACL, PACL)
        #DHCP Configuration
        subprocess = "[localPoliicies]"
        msg1 = "DHCP - Local Policies"
        message = "Evaluating RACL, VACL and PACLs present in the path to the DHCP Client."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

        edge_node_device.raclvaclpacl(service,step)
        acls = getattr(edge_node_device, 'edgeacls', []) or []
        vacls = getattr(edge_node_device, 'edgevacls', []) or []
        for acl in acls:
            acl_hit_procedure(edge_node_device,acl,service,step)

        #LISP Control and Data Plane validation to DHCP Server
        subprocess = "[layer3Parameters]"
        msg1 = "DHCP - LISP IID, Control Plane and Forwarding"
        message = f"DHCP Troubleshooting: Initiating verification of global DHCP parameters for VLAN {vlan}."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

        pub_sub_flag = edge_node_device.profiled_device.ispubsub
        edge_node_device.lispparameters(service)
        edge_node_device.sisf_parameters(service)
        lisp_info = edge_node_device.lispparameters_info
        sisf_info = edge_node_device.sisfparameters_info
        lisp_parameters_validation_edge(lisp_info,pub_sub_flag,step,dhcp_info,sisf_info,edge_node_device.is_infravn)
        iid = lisp_info.iid

        # Recursion to CEF (LISP)
        subprocess = "[edgeNodeForwarding]"
        msg1 = "DHCP - CEF, Route Recursion and RLOC Reachability"
        message = "DHCP Troubleshooting: Recursing Map-Cache information into CEF"
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

        if edge_node_device.is_infravn is False:
            step, forwarding_prefixes = process_map_cache_recursion(edge_node_device,mac,vlan,service,step,iid,vrf)

        #Recursion to CEF Underlay
        subprocess = "[edgeNodeForwarding]"
        msg1 = "DHCP - Underlay Route Recursion and RLOC Reachability"
        message = f"DHCP Troubleshooting: Recursing CEF Route on the Underlay"
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1
        if edge_node_device.is_infravn is False:
            edge_node_device.forwarding_parameters(forwarding_prefixes,service,step)
            rlocs = edge_node_device.final_rlocs
            ports = edge_node_device.underlay_ports
        else:
            edge_node_device.infra_vn_forwarding(service,step)
            step +=1
            upstreamhops = edge_node_device.upstreamcef
            upstreamphy = edge_node_device.upstreamphy
            validate_infra_vn_underlay_nexthops(upstreamhops,upstreamphy,hostname,service,step)

        #Connectivity Tests
        subprocess = "[underlayReachability]"
        msg1 = "DHCP - Underlay Reachability"
        message = f"DHCP Troubleshooting: Verifying reachability between Edge and destination RLOC"
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1
        if edge_node_device.is_infravn is False:
            rloc_reachability(ports,hostname,service,rlocs,step)
            srcip = edge_node_device.loopback
            dstip = forwarding_prefixes[0]['prefix']
        else:
            srcip = edge_node_device.loopback
            dstip = edge_node_device.dhcpparameters_info.helper_address[0]

        subprocess = "[borderValidation]"
        msg1 = "DHCP - Border Validations"
        message = f"DHCP Troubleshooting: Running Border Validation modules for DHCP operation"
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

        #Border Troubleshooting
        border_objects, step = border_ip_transit(step,catc_name,fabric_id,vrf,vlan,srcip,dstip,service,True,iid)

        subprocess = "[borderValidation]"
        msg1 = "DHCP - Border ACL Validations"
        message = f"DHCP Troubleshooting: Running Border ACL Validations for DHCP Traffic"
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

        validate_border_acls(border_objects, service, step)
        #validate_dhcp_server_compatibility(border_objects,dora_state,step)






