from pprint import pformat

from device_profiler import Device
from ipverifications import subnetvalidation
from routingmodules.lisp import L3Device, CEFForwardingState
from switchingmodules.dhcp import DHCPDevice
from switchingmodules.maclearning import mac_learning
from radkit_cli import logging_info, logging_error, logging_warning, get_catc_api
import sys

from switchingmodules.sisf import SISF
from traffic_flows.lispsessiontroubleshooting import singleETRProfiling

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

    def maclearning(self,mac, vlan, service):
        hostname = self.profiled_device.hostname
        mac_learning_info = mac_learning(hostname)
        mac_learning_info.mac_learning_mac(mac,vlan,service)
        self.mac_learning_info = mac_learning_info

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
        lispparameters.map_cache(eids,service)
        self.lispparameters_info = lispparameters

    def forwarding_parameters(self,prefixes,service,step):
        hostname = self.profiled_device.hostname
        vrf = self.dhcpparameters_info.svivrf
        cefinternallist = CEFForwardingState(vrf,hostname)
        cefinternallist.cef_resolution(prefixes,service,step)
        self.cefinternallist_info = cefinternallist
        final_rlocs = forwarding_parameters_recursion(cefinternallist,self.profiled_device.dnac,step)
        cefinternallist.cef_underlay(final_rlocs,service)
        self.cef




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

    port = mac_learning_info.port
    type = mac_learning_info.type
    mac = mac_learning_info.mac
    vlan = mac_learning_info.vlan
    hostname = mac_learning_info.hostname

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
    dhcpsnoopingstats = dhcpparameters_info.packets_dropped_because
    if dhcpsnoopingstats is not None:
        for reason, count in dhcpsnoopingstats.items():
            if count != 0:
                error = "DHCP - DHCP Snooping"
                message = (
                    f"DHCP Troubleshooting: Warning: DHCP Snooping counters detected for reason {reason}, count: {count}"
                )
                logging_warning(step, process, subprocess, hostname, error + " | " + message)

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

def lisp_parameters_validation_edge(lispparameters_info,pubsub_flag,step,dhcpparameters_info,sisf_info):
    process = "lispValidations"
    subprocess = "[lispInstanceID]"
    #LISP validations for SD-Access networks:
    #Instance-ID Configuration relevant for DHCP Flows:
    hostname = lispparameters_info.device
    #Pub-Sub identification, is this fabric pub_sub enabled?
    if pubsub_flag is not True:
        error = "DHCP - LISP"
        message = (
            "DHCP Troubleshooting: The current fabric implementation is LISP1.0, which is unsupported for this sub-module. "
            "DHCP validations will be skipped."
        )
        exit_program(step, process, subprocess, hostname, error, message)

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
    map_caches = lispparameters_info.map_cache_information
    map_cache_default_present = False
    for map_cache in map_caches:
        eid_prefix = map_cache.eid_prefix
        if eid_prefix == "0.0.0.0/0":
            sources = map_cache.sources
            if 'static' in sources:
                    map_cache_default_present = True
    if map_cache_default_present is False:
        error = "LISP - Map-Cache , Static Default"
        message = (
            f"LISP Troubleshooting: Static Map-Cache entry '0.0.0.0/0' was not found for IID {iid} on device '{hostname}'. "
            f"Please reconfigure the missing map-cache entry using the command: \"map-cache 0.0.0.0/0 map-request\" under IID {iid}."
        )
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        msg1 = "LISP - Map-Cache , Static Default"
        message = (
            f"LISP Troubleshooting: Static Map-Cache entry '0.0.0.0/0' is present for IID {iid} on device '{hostname}'. "
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

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
    for map_cache in map_caches:
        requested_eid = map_cache.requested_eid
        rlocs = map_cache.rlocs
        eid_prefix = map_cache.eid_prefix
        no_active_rlocs = True
        if eid_prefix != svi_subnet:
            for rloc in rlocs:
                state = rloc['state']
                if state == 'up':
                    no_active_rlocs = True
            if no_active_rlocs is False:
                error = "LISP - Helper-Address RLOC reachability"
                message = (
                    f"LISP Troubleshooting: All RLOCs associated with the Map-Cache entry for Helper-Address {requested_eid} are down on device '{hostname}'. "
                    "Please verify RLOC reachability in the routing table. Edge nodes must have a /32 route to each RLOC. Refer to the GPS_SDA log file for additional details."
                )
                exit_program(step, process, subprocess, hostname, error, message)
            else:
                msg1 = "LISP - Helper-Address RLOC reachability"
                message = (
                    f"LISP Troubleshooting: At least one RLOC is in the UP state for each Helper-Address associated with the endpoint SVI on device '{hostname}'. "
                    "No RLOC reachability issues detected."
                )
                logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

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

def forwarding_parameters_recursion(cefinternallist_info,catc_name,step):
    process = "overlayValidations"
    subprocess = "[edgeNodeForwarding]"
    cef_prefixes = cefinternallist_info
    final_rlocs = []
    for cef_internal_entries in cef_prefixes.cef_internal_entries:
        nexthop_ips = set(hop["nexthop"] for hop in cef_internal_entries["nexthops"])
        expected_rlocs = set(rloc["rloc"] for rloc in cef_internal_entries["expected_rloc"])
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
                "Forwarding configuration appears correct."
            )
            logging_info(step, process, subprocess, catc_name, msg1 + " | " + message)
        final_rlocs.append(nexthop_ips)
        # Combine all sets and get unique items
        unique_items = set().union(*final_rlocs)
        unique_list = list(unique_items)
        final_rlocs_list = unique_list
        return final_rlocs_list

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

        #MAC Address validation criteria: dhcp_mac_address_validation(mac_learning_info)
        mac_info = edge_node_device.mac_learning_info
        mac_learning_info = dhcp_mac_address_validation(mac_info,step)
        #print(pformat(vars(mac_learning_info), indent=4, width=1, sort_dicts=False))

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
        pool_details = (
            f"/dna/intent/api/v1/business/sda/virtualnetwork/ippool"
            f"?siteNameHierarchy={siteNameHierarchy}"
            f"&virtualNetworkName={vrf}"
            f"&ipPoolName={vlanName}"
        )
        pool_information_detail = get_catc_api(catc_name,pool_details,service)
        edge_node_device.pool_info = pool_information_detail

        if edge_node_device.pool_info['isLayer2OnlyPool'] is True:
            error = "DHCP - Pool Identification"
            message = (
                "DHCP Troubleshooting: DHCP traffic flow information is not available for Layer 2-only pools."
            )
            exit_program(step, process, subprocess, catc_name, error, message)
        else:
            ippoolname = edge_node_device.pool_info['vlanName']
            pooltype = edge_node_device.pool_info['trafficType']

            msg1 = "DHCP - Pool Identification"
            message = (
                f"DHCP Troubleshooting: IP pool '{ippoolname}' is assigned to VLAN {vlan}. "
                f"The pool type is '{pooltype}', and it is configured as an Anycast Gateway."
            )
            logging_info(step, process, subprocess, catc_name, msg1 + " | " + message)

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

        #LISP SESSION Validation
        '''
        #Layer 3 Verifications:
        subprocess = "[lispSession]"
        msg1 = "DHCP - LISP Session Validations"
        message = f"DHCP Troubleshooting: Checking the status of the LISP session."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

        step = edge_node_device.lispsession(service,step)
        print (step)
        '''

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
        lisp_parameters_validation_edge(lisp_info,pub_sub_flag,step,dhcp_info,sisf_info)

        #Recursion to CEF (LISP)
        subprocess = "[edgeNodeForwarding]"
        msg1 = "DHCP - CEF, Route Recursion and RLOC Reachability"
        message = f"DHCP Troubleshooting: Recursing Map-Cache information into CEF"
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

        map_caches = edge_node_device.lispparameters_info.map_cache_information
        #Sanitize map-caches to remove repeated ones, also purge RLOCs not in "up" state
        forwarding_prefixes = []
        for map_cache in map_caches:
            helper_address = map_cache.requested_eid
            rlocs = map_cache.rlocs
            new_rlocs = [rloc for rloc in rlocs if rloc.get('state') == 'up']
            prefixes = {
                'prefix' : helper_address,
                'expectedrlocs' : new_rlocs
            }
            if len(new_rlocs) != 0:
                forwarding_prefixes.append(prefixes)

        edge_node_device.forwarding_parameters(forwarding_prefixes,service,step)

        #Recursion to CEF Underlay
        subprocess = "[edgeNodeForwarding]"
        msg1 = "DHCP - Underlay Route Recursion and RLOC Reachability"
        message = f"DHCP Troubleshooting: Recursing CEF Route on the Underlay"
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1



