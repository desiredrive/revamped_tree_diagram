import sys
import ipaddress
import radkit_cli
from pprint import pformat

from catalystcenterapi.catcapi import (
    get_device_from_lo0,
    get_network_device_byuuid,
    validate_cp_infabric
)
from ipverifications import (
    mac_address_validator,
    ipsubnet_validator_no_return,
    issubnetbroadcast
)
from device_profiler import device
from routingmodules.lisp import L2LISPInterface, L2LISPConfiguration
from routingmodules.multicastrouting import (
    MulticastConfiguration
)
from routingmodules.pim import (
    PimConfiguration
)
#Order of operations for verifying multicast
def text():
    '''
    Main Local Verifications
    *)Which traffic are you troubleshooting?
    *) Is it L2 Only VN?
    -) Is IGMP snooping enabled? - This controls IGMP verifications
    *) Is 17.6 or higher?
    *) Multicast Routing global enablement
    *) PIM enabled in Loopback0 Interfaces
    MAYBE....) Multicast enabled in upstream interfaces (what are upstream interfaces?) (the ones used by the upstream protocol)
        - This requires per-protocol enablement and neighbor validation; for now: OSPF and ISIS
    *) PIM neighbor validations
    *) PIM enablement on L2 interfaces
    *) PIM DR election (Lo0 must be DR)
    *) L2LISP validations (already made)
    * Determining Multicast Group for the required L2 Instance
    -) Determining RP to the required group
    -) Determining RP source interface = warning if lo0 is not the source
    -) Determining RP reachability and Tunnel encap (and decap if eligible)
    -) Determining if SSM is enabled using the default group 232.0.0.0/8
    -) *,G Creation based on L2LISP interface availability
    -) S,G Creation based on traffic:
        what constitutes traffic? - BUM traffic traversing L2 interfaces in the L2LISP domain/VLAN
            - STP verification
            - AcX exclusion
    -) L2LISP ACL (Parse if the required traffic is blocked or allowed by the L2LISP ACL 17.3 and 17.6)
    -) Multicast Limits and Counts
    -) PIM drops

LHR Validations:

-) Main validations
-) FHR Routes exist already? - Jump to SPT/SG Validations
-) PIM Rules (Rule 1,Rule 2,
-) *,G Creation and RPF
-) *,G Counters
-) *,G Flags (Rule 8)
-) MFIB equivalents
-) Identification of RPF interface
-) Identification of potential CDP neighbor (optional); mapping nexthop interface with L3 information
-) Identification of RPF neighbor (Lo0 to Device name to Radkit Inventory)
-) Identification of RPF upstream interface (CDP and L3)
-) Carrying RP information, how many RPs do exist? Are there more than 1? How can we tell.?
-) DO intermediate nodes exist?


RP Validations:
-) PIM Rules (3, 4, 5=Prunning, 6=Maintenance, 7=FHR Prunning)
-) Main Validations
-) Identification of the RP
-) Is the RP inside the fabric?
-) Is the RP consistent across fabric nodes?
-) MSDP Peer if any (RP more than 1)
-) MSDP SA Cache States
-) MSDP RPF Counters
-) MSDP Next Hop Resolution
-) Telnet for MSDP Validation
-) *,G Definition
-) *,G OILs (and matching with downstream device)
-) *,G Counters
-) S,G Flags (Rule 8)
-) S,G Validation (is registered-module)
-) S,G IIF validation
-) S,G OIL download to *,G Validaiton
-) Is RP joining the downstream Int or FHR?

FHR Validations
-) Main Validations
-) Is it the FHR?
-) Registration Validation (Stuck in Register?, PIM Tunnel, Recahability, Reg Counters)
-) S,G Validation
-) S,G Counters
-) S,G OIL State
-) S,G Counters
-) MFIB Equivalents
-) Is it SPT already?
'''
    return None

def multicast_ranges(mcast_group):
    mcastflag = False
    llmcastflag = False
    mcastflag: bool = ipaddress.ip_address(mcast_group) in ipaddress.ip_network("224.0.0.0/4")
    if mcastflag is True:
        llmcastflag = ipaddress.ip_address(mcast_group) in ipaddress.ip_network("224.0.0.0/24")
        return mcastflag, llmcastflag
    return mcastflag,llmcastflag

def is_l2_flooding(destination, ttl, isl2only: bool, overlaymcast: bool):
    isl2flood = False
    # Subnet_string in correct format:
    # Step 1: Is the prefix an IP subnet?
    is_subnet = ipsubnet_validator_no_return(destination)
    if is_subnet is True:
        subnetstring = destination.split("/")
        if len(subnetstring) == 2:
            prefix = subnetstring[0]
            mask = subnetstring[1]
        else:
            prefix = destination
            mask = "32"

        if prefix == '255.255.255.255':
            isl2flood = True
            return isl2flood
        else:
            # Step 2: Is the prefix a Multicast IP?
            mcast_result = multicast_ranges(prefix)
            mcasttype = mcast_result[0]
            linklocalmcast = mcast_result[1]
            # If the destination IP is a multicast group then:
            if mcasttype is True:
                # If the destination IP is part of 224.0.0.0/24 it is flooded regardles of the TTL
                if linklocalmcast is True:
                    isl2flood = True
                    return isl2flood
                else:
                    # If the destination IP is part of non-link local multicast range, TTL must be evaluated
                    # If TTL of the traffic is 1, it can only be flooded
                    if ttl == 1:
                        isl2flood = True
                        return isl2flood
                    else:
                        # If TTL of the traffic is not 1, it can only be flooded if the pool is L2 only (or if Overlay Multicast is NOT enabled)
                        if isl2only is True:
                            isl2flood = True
                            return isl2flood
                        elif overlaymcast is False:
                            isl2flood = True
                            return isl2flood
                        # If the TTL is not 1, and the pool is not L2 only or if Overlay Multicast is enabled, traffic cannot be flooded.
                        else:
                            isl2flood = False
                            return isl2flood
            else:
                # Step 3 If the Prefix is an IP directed Brodacast
                if mask == "32":
                    print("Host Routes (Mask 32) have no broadcast address, not flooding")
                    return isl2flood
                elif mask == "31":
                    print("Host Routes (Mask 30) have no broadcast address not flooding")
                    return isl2flood
                else:
                    is_ipdb = issubnetbroadcast(destination)
                    isl2flood = is_ipdb
                    return isl2flood
    else:
        mac_info = mac_address_validator(destination)
        flood_types = ['Broadcast', 'Multicast']
        if any(x in mac_info[1] for x in flood_types):
            isl2flood = True
        return isl2flood

def loopback0_pim_status(interface_list,hostname):
    for i in interface_list:
        interfacename = i['interface_name']
        if interfacename == 'Loopback0':
            if i['oper_status'] != 'up':
                print("Loopback0 not in UP state in device {}".format(hostname))
                return False
            elif i['enabled'] is not True:
                print("Loopback0 not in PIM enabled state in device {}".format(hostname))
                return False
            elif i['pim_mode'] == 'dense':
                print("Loopback0  is configured for DENSE mode! Configure it for sparse-mode {}".format(hostname))
                return False
            else:
                print("Loopback0 is configured for PIM Sparse (or sparse-dense) in device: {}".format(hostname))
                return True

class UnderlayMulticastDevice:
    def __init__(self,vrf, mgmtip):
        self.mgmtip = mgmtip
        self.vrf = vrf

    def device_profiler(self, catc,service):
        devprof = device(self.mgmtip,catc)
        devprof.profile_device(service)
        self.profiled_device = devprof

    def existing_profiled(self, profiled_device):
        self.profiled_device = profiled_device

    def multicast_enablement(self,service):
        hostname = self.profiled_device.hostname
        print("Verifying Global Underlay Multicast Status for device: {} ...\n".format(hostname))
        mcaststatus = MulticastConfiguration(None, hostname)
        mcaststatus.multicast_enabled(service)
        self.mcastconfig = mcaststatus

    def pim_interfaces (self, service):
        hostname = self.profiled_device.hostname
        print("Retrieving PIM interfaces for device: {} ...\n".format(hostname))
        pimintfstatus = PimConfiguration(None, hostname)
        pimintfstatus.pim_interfaces(service)
        self.piminterfaces = pimintfstatus

    def islo0up(self,intflist):
        hostname = self.profiled_device.hostname
        print("Validating Loopback0 PIM configuration for device: {} ...\n".format(hostname))
        self.islo0pimenabled = loopback0_pim_status(intflist,hostname)

    def pim_neighbors(self,service):
        hostname = self.profiled_device.hostname
        print("Retrieving PIM Neighbors for device: {} ...\n".format(hostname))
        pimneighbors = PimConfiguration(None, hostname)
        pimneighbors.pim_neighbors(service)
        self.pimneighbors = pimneighbors

    def l2lispinterface(self,vlan, service):
        hostname = self.profiled_device.hostname
        #L2LISP interface Status:
        print("Validating L2LISP Interface Parameters for device: {} ...\n".format(hostname))
        l2lispinterfacestatus = L2LISPInterface(vlan,hostname)
        l2lispinterfacestatus.l2lispinterfacestatus(service)
        self.l2lispinterfacestatus = l2lispinterfacestatus

    def broadcast_underlay_properties(self,iid,service):
        hostname = self.profiled_device.hostname
        print("Verifying L2Flooding Configuration for instance {} in device: {} ...\n".format(iid,hostname))
        l2floodingproperties = L2LISPConfiguration(iid, hostname)
        l2floodingproperties.l2flooding_configuration(service)
        self.l2floodingproperties = l2floodingproperties

    def rp_identification(self,group, service):
        hostname = self.profiled_device.hostname
        print("Verifying RP information in device: {} ...\n".format(hostname))
        rpinformation = PimConfiguration(None,hostname)
        rpinformation.pim_rp(group,service)
        self.rpinformation = rpinformation

    def rpf_to_rp(self,rp,service):
        hostname = self.profiled_device.hostname
        print("Verifying RPF information for RP {} in device: {} ...\n".format(rp, hostname))
        rpfinformation = PimConfiguration(None,hostname)
        rpfinformation.pim_rpf_neighbor(rp,service)
        self.rpfinformation = rpfinformation


