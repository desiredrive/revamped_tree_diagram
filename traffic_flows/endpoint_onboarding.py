import sys
import ipaddress
from pprint import pformat
from device_profiler import Device
from switchingmodules.interfaces import Interfaces


class EndpointOnboarding:
    def __init__(self, macaddress, interface, mgmtip):
        self.mgmtip = mgmtip
        self.macaddress = macaddress
        self.interface = interface

    def device_profiler(self, catc,service):
        devprof = Device(self.mgmtip,catc)
        devprof.profile_device(service)
        self.profiled_device = devprof

    def existing_profiled(self, profiled_device):
        self.profiled_device = profiled_device

    def interfacecounters(self,interface,service):
        hostname = self.profiled_device.hostname
        print("Collecting Interface information for {} : {} ...".format(interface,hostname))
        interfaceinfo = Interfaces(interface,hostname)
        interfaceinfo.show_interface(service)
        self.interfaceinfo = interfaceinfo

def endpoint_troubleshooting(mgmtip,macaddress,interface,vlan,catc_name,service):
    '''
    Main Local Verifications
    What is the expected MAC address of the device?
    In which interface is the device supposed to be?
    Is the interface experiencing any errors (down, crcs, runts, overruns, giants, iqds)
    What is the load interval for this interface?
    Is the interface receiving any input traffic?
    Is the interface an access or a trunk?
    Is the endpoint possibly a phone? (CDP, LLDP)
    Is there any MAC learning happening on the port? (If so, in which VLAN?, potential multiple entries in different VLANs)
        If not:
            Is the port STP FWD for that unique port? (Access Only?
                If not, STP troubleshooting module
    Is the port generating  STP TCNs abnormally?
    Is the port authenticated? (Get information from authentication: Domain, multi/single/multidomain, hostname, method
        If not authenticated - AAA troubleshooting flow.
    Is the MAC in which state?
        If Dynamic = it matches the required port?
        If Static = is there a static entry? it matches the required port?
        If Drop = Static entry validation or authentication
        If CP_Learn = It must be remote
    Is the endpoint located on the required VLAN? (If VLAN = 1, check VLAN assignment methods (static, dynamic, templated), attempt to calculate, otherwise ask for the VLAN
    VLAN calculation is needed, it must conclude
    Match interface switchport parameters
    Is the MAC added to the L2 IPDT Table?
        Is it on the table? matching the same original port? In the required state?
    Verify IPDT counter or messages for such MAC
    Is this device part of L2 or L3 pool? - API
    If L2 pool, consider ARP table, otherwise only consider IPDT.
    Is the device static IP or DHCP?
        Always start with the idea that it is static - check ARP table (VRF from VLAN (L3 Pool))
        Validate IPDT limits (getting the limits from each policy on the VLAN)
        Then check consistency with IPDT (parsing against MAC address).
    If L3: asume DHCPsnooping states, otherwise ARP is the only way.

    '''

    print("Starting Endpoint/Host Onboarding Flows!...\n")
    endpointhoinfo = EndpointOnboarding(macaddress,interface,mgmtip)
    endpointhoinfo.device_profiler(catc_name, service)
    hostname = endpointhoinfo.profiled_device.hostname
    interface = endpointhoinfo.interface
    # Interface Counters and Status
    endpointhoinfo.interfacecounters(interface,service)
    if endpointhoinfo.interfaceinfo.connected is not True:
        sys.exit("WARNING!: Interface {} is not in Connected state on device {}, please discard any physical layer problem before proceeding any further\n".format(interface,hostname))
    else:
        print("Interface {} is in Connected state on device {}".format(interface,hostname))

    return endpointhoinfo



def endpointhoinfoprint(endpointhoinfo):
    hostname = endpointhoinfo.profiled_device.hostname
    interface = endpointhoinfo.interface
    print ("Device Information {}:\n".format(hostname))
    print(pformat(vars(endpointhoinfo.profiled_device), indent=4, width=1, sort_dicts=False))
    print ("Information about interface {} on device {}:\n".format(interface, hostname))
    print(pformat(vars(endpointhoinfo.interfaceinfo), indent=4, width=1, sort_dicts=False))