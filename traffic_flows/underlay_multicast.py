import sys
import ipaddress
from pprint import pformat

from catalystcenterapi.catcapi import profile_devices_with_ip
from ipverifications import (
    mac_address_validator,
    ipsubnet_validator_no_return,
    issubnetbroadcast,
    inside_subnet,
)
from device_profiler import Device
from routingmodules.igmp import IGMP
from routingmodules.lisp import L2LISPInterface, L2LISPConfiguration
from routingmodules.multicastrouting import (
    MulticastConfiguration, MulticastRoutes
)
from routingmodules.pim import (
    PimConfiguration
)
from securitymodules.accesslists import AccessList, is_acl_denying_dst
from switchingmodules.cdp import CDPinfo
from switchingmodules.interfaces import Interfaces

#Order of operations for verifying multicast
'''
LHR Validations:

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

'''

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

def anyinterface_pim_status(inputinterface,interface_list,hostname):
    for i in interface_list:
        interfacename = i['interface_name']
        if interfacename == inputinterface:
            if i['oper_status'] != 'up':
                print("{} not in UP state in device {}\n".format(inputinterface,hostname))
                return False
            elif i['enabled'] is not True:
                print("{} not in PIM enabled state in device {}\n".format(inputinterface,hostname))
                return False
            elif i['pim_mode'] == 'dense':
                print("{}  is configured for DENSE mode! Configure it for sparse-mode {}\n".format(inputinterface,hostname))
                return False
            else:
                print("{} is configured for PIM Sparse (or sparse-dense) in device: {}\n".format(inputinterface,hostname))
                return True

class UnderlayMulticastDevice:
    def __init__(self,vrf, mgmtip,step):
        self.mgmtip = mgmtip
        self.vrf = vrf
        self.step = step

    def device_profiler(self, catc,service):
        devprof = Device(self.mgmtip,catc,self.step)
        devprof.profile_device(service)
        self.profiled_device = devprof

    def existing_profiled(self, profiled_device):
        self.profiled_device = profiled_device

    def multicast_enablement(self,service):
        hostname = self.profiled_device.hostname
        print("Verifying Global Underlay Multicast Status for device: {} ...".format(hostname))
        mcaststatus = MulticastConfiguration(self.vrf, hostname)
        mcaststatus.multicast_enabled(service)
        self.mcastconfig = mcaststatus

    def pim_interfaces (self, service):
        hostname = self.profiled_device.hostname
        print("Retrieving PIM interfaces for device: {} ...".format(hostname))
        pimintfstatus = PimConfiguration(self.vrf, hostname)
        pimintfstatus.pim_interfaces(service)
        self.piminterfaces = pimintfstatus

    def pim_neighbors(self,service):
        hostname = self.profiled_device.hostname
        print("Retrieving PIM Neighbors for device: {} ...".format(hostname))
        pimneighbors = PimConfiguration(self.vrf, hostname)
        pimneighbors.pim_neighbors(service)
        self.pimneighbors = pimneighbors

    def l2lispinterface(self,vlan, service):
        hostname = self.profiled_device.hostname
        #L2LISP interface Status:
        print("Validating L2LISP Interface Parameters for device: {} ...".format(hostname))
        l2lispinterfacestatus = L2LISPInterface(vlan,hostname)
        l2lispinterfacestatus.l2lispinterfacestatus(service)
        self.l2lispinterfacestatus = l2lispinterfacestatus

    def broadcast_underlay_properties(self,iid,service):
        hostname = self.profiled_device.hostname
        self.iid = iid
        print("Verifying L2Flooding Configuration for instance {} in device: {} ...".format(iid,hostname))
        l2floodingproperties = L2LISPConfiguration(iid, hostname)
        l2floodingproperties.l2flooding_configuration(service)
        self.l2floodingproperties = l2floodingproperties

    def rp_identification(self,group, service):
        hostname = self.profiled_device.hostname
        print("Verifying RP information in device: {} ...".format(hostname))
        rpinformation = PimConfiguration(self.vrf,hostname)
        rpinformation.pim_rp(group,service)
        self.rpinformation = rpinformation

    def rpf_to_rp(self,rp,service):
        hostname = self.profiled_device.hostname
        self.rp = rp
        print("Verifying RPF information for RP {} in device: {} ...".format(rp, hostname))
        rpfinformation = PimConfiguration(self.vrf,hostname)
        rpfinformation.pim_rpf_neighbor(rp,service)
        self.rpfinformation = rpfinformation

    def ssm_underlay_group(self,service):
        hostname = self.profiled_device.hostname
        print("Verifying SSM configuration in device: {} ...".format(hostname))
        ssminformation = PimConfiguration(self.vrf,hostname)
        ssminformation.pim_ssm_range(service)
        self.ssminformation = ssminformation
        #Verifying if the Underlay Group is within the SSM group
        l2floodinggroup = self.l2floodingproperties.broadcastunderlay
        ssmacl = ssminformation.ssmacl
        ssmstatus = ssminformation.ssmenabled
        self.isssmgroup = False
        if ssmstatus is True:
            if ssmacl is None:
                ssmrange = ssminformation.ssmrange
                self.isssmgroup = inside_subnet(ssmrange,l2floodinggroup)
            else:
                acl = AccessList(hostname)
                acl.aclbyidname(ssmacl,service)
                acltype = acl.acltype
                aclaces = acl.aces
                acl = {
                    'acltype' : acltype,
                    'aces' : aclaces
                }
                self.isssmgroup = not(is_acl_denying_dst(acl,l2floodinggroup))
        else:
            self.isssmgroup = False

    def multicast_range(self,service):
        hostname = self.profiled_device.hostname
        print("Verifying if multicast range is allowing the L2 Flooding Group".format(hostname))
        mcastrangeinfo = MulticastConfiguration(self.vrf,hostname)
        mcastrangeinfo.multicast_ranges(service)
        self.mcastrangestatus = mcastrangeinfo.mcastrange
        mcastrangeacl = mcastrangeinfo.mcastrangeacl
        l2floodinggroup = self.l2floodingproperties.broadcastunderlay
        self.mcastrangeinfo = mcastrangeinfo
        self.isblockedbymcastrange = False
        if self.mcastrangestatus is False:
            self.isblockedbymcastrange = False
        else:
            acl = AccessList(hostname)
            acl.aclbyidname(mcastrangeacl, service)
            acltype = acl.acltype
            aclaces = acl.aces
            acl = {
                'acltype' : acltype,
                'aces' : aclaces
            }
            self.isblockedbymcastrange = is_acl_denying_dst(acl,l2floodinggroup)

    def pim_statistics(self,service):
        hostname = self.profiled_device.hostname
        print ("Collecting Global PIM statistics on this node: {}".format(hostname))
        pimstatistics = PimConfiguration(None,hostname)
        pimstatistics.ip_pim_statistics(service)
        self.pimstatistics = pimstatistics
        if pimstatistics.pimchecksum_errors != 0:
            print ("WARNING!: PIM Checksum Errors found on device: {} verify if these are increasing with \"show ip traffic\" ".format(hostname))
        if pimstatistics.pimformat_errors != 0:
            print("WARNING!: PIM Format Errors found on device: {} verify if these are increasing with \"show ip traffic\" ".format(hostname))
        if pimstatistics.pimqueuedrops != 0:
            print("WARNING!: PIM Queue Drops found on device: {} verify if these are increasing with \"show ip traffic\" ".format(hostname))

    def igmp_verifications(self,service):
        hostname = self.profiled_device.hostname
        print("Verifying IGMP Configuration of L2LISP interface on device: {} ...".format(hostname))
        interface = self.l2lispinterfacestatus.l2lispfinalinterface
        igmpinterfaces = IGMP(None,hostname)
        igmpinterfaces.igmp_groups_interface_interface(interface,service)
        self.igmpinterfaceinfo = igmpinterfaces

    def local_star_g(self,service):
        hostname = self.profiled_device.hostname
        print("Verifying *,G multicast route on this node: {} ...".format(hostname))
        l2floodinggroup = self.l2floodingproperties.broadcastunderlay
        source = '255.255.255.255'
        stargmroute = MulticastRoutes(None,hostname)
        stargmroute.mroute_get(l2floodinggroup,source,service)
        starginfo = stargmroute.mrouteinfo
        self.stargmroute = None
        for source in starginfo:
            if source['source'] == "*":
                print ("*,G Mroute Found!\n")
                self.stargmroute = source

    def anypiminterface(self,interface,intflist):
        hostname = self.profiled_device.hostname
        print("Validating {} PIM configuration for device: {} ...".format(interface,hostname))
        self.isinterfacepimenabled = anyinterface_pim_status(interface,intflist,hostname)

    def floodingacls(self, interface, service):
        hostname = self.profiled_device.hostname
        print("Retrieving ACLs on Interface: {} for device: {} ...".format(interface, hostname))
        if interface == 'L2LISP0':
            acls = AccessList(hostname)
            acls.aclbyinterface(interface,service)
            accesslists = acls.aclnames
            aclcontents = []
            if len(accesslists) != 0:
                for acl in accesslists:
                    acls.aclbyidname(acl,service)
                    aces = acls.aces
                    aclname = acls.aclname
                    acltype = acls.acltype
                    aclaftype = acls.aclaftype
                    aclinfo = {
                        'aclname' : aclname,
                        'acltype' : acltype,
                        'aclaftype' : aclaftype,
                        'aces': aces
                    }
                    aclcontents.append(aclinfo)
            self.l2floodacls = aclcontents
        if interface == 'Tunnel0':
            acls = AccessList(hostname)
            aclcontents = []
            aclnames = ['SDA-fabric-in','SDA-fabric-out']
            for i in aclnames:
                acls.aclbyidname(i,service)
                aces = acls.aces
                aclname = acls.aclname
                acltype = acls.acltype
                aclaftype = acls.aclaftype
                aclinfo = {
                    'aclname': aclname,
                    'acltype': acltype,
                    'aclaftype': aclaftype,
                    'aces': aces
                }
                aclcontents.append(aclinfo)
            self.l2floodacls = aclcontents

def single_device_underlay_profiling(mgmtip,vlan,l2lispiid,catc_name,service,step):
    '''
    Main Local Verifications
    *)Which traffic are you troubleshooting?
    *) Is it L2 Only VN?
    -) Is IGMP snooping enabled? - This controls IGMP verifications
    *) Is 17.6 or higher?
    *) Multicast Routing global enablement
    -) Multicast Limits and Counts (Pending
    *) PIM enabled in Loopback0 Interfaces
    MAYBE....) Multicast enabled in upstream interfaces (what are upstream interfaces?) (the ones used by the upstream protocol)
        - This requires per-protocol enablement and neighbor validation; for now: OSPF and ISIS
    *) PIM neighbor validations
    *) PIM enablement on L2 interfaces
    *) PIM DR election (Lo0 must be DR)
    *) L2LISP validations (already made)
    * Determining Multicast Group for the required L2 Instance
    *) Determining RP to the required group
    *) Determining RP source interface = warning if lo0 is not the source
    *) Determining RP reachability and Tunnel encap (and decap if eligible)
    *) Determining if SSM is enabled using the default group 232.0.0.0/8
    *) PIM drops
    *) *,G Creation based on L2LISP interface availability
    *) L2LISP ACL (Parse if the required traffic is blocked or allowed by the L2LISP ACL 17.3 and 17.6)
    '''

    print("Starting Underlay Multicast Flows!...\n")
    # Starting Underlay Multicast Flows!
    # Underlay Multicast Validations for FHR:
    umcastdevice = UnderlayMulticastDevice(None, mgmtip,step)
    umcastdevice.device_profiler(catc_name, service)
    hostname = umcastdevice.profiled_device.hostname
    #print("Profiled device {}:\n".format(hostname))
    #print(pformat(vars(umcastdevice.profiled_device), indent=4, width=1, sort_dicts=False))
    # Global Multicast Enablement
    umcastdevice.multicast_enablement(service)
    if umcastdevice.mcastconfig.multicastenabled is False:
        sys.exit("WARNING!: Device {} does not have Multicast Enabled in the Global RIB!\n".format(hostname))
    else:
        print("Global Multicast Routing is enabled on device {}:\n".format(hostname))
        #print(pformat(vars(umcastdevice.mcastconfig), indent=4, width=1, sort_dicts=False))
    # PIM Interfaces of a Device:
    umcastdevice.pim_interfaces(service)
    interface_list = umcastdevice.piminterfaces.piminterfaces
    umcastdevice.anypiminterface('Loopback0',interface_list)
    if umcastdevice.isinterfacepimenabled is not True:
        sys.exit("WARNING!: Device {} does not have Loopback0 as PIM enabled\n".format(hostname))
    # PIM Neighbors
    umcastdevice.pim_neighbors(service)
    pimneighborlist = umcastdevice.pimneighbors.pimneighbors
    pimneighborcount = umcastdevice.pimneighbors.neighborcount
    if pimneighborcount == 0:
        sys.exit("WARNING!: Device {} does not have PIM neighbors! verify PIM configuration\n".format(hostname))
    # Identify the L2LISP Interface and Validate it's PIM status
    umcastdevice.l2lispinterface(vlan, service)
    # Retrieve L2Flooding Configuration.
    umcastdevice.broadcast_underlay_properties(l2lispiid, service)
    underlay_group = umcastdevice.l2floodingproperties.broadcastunderlay
    if underlay_group is None:
        sys.exit("WARNING!: Broadcast Underlay Group not found on device: {}, verify if broadcast-underlay is configured under the L2LISP instance {}\n".format(hostname,l2lispiid))
    else:
        print("Broadcast Underlay Group is {} for L2LISP ID {} found on device: {}\n".format(underlay_group,l2lispiid,hostname))
    # SSM Configuration and Validation
    # Underlay Multicast Group should be ASM:
    umcastdevice.ssm_underlay_group(service)
    ssminfo = umcastdevice.ssminformation
    if ssminfo.ssmenabled is True:
        print("SSM Multicast is Enabled on device: {}\n".format(hostname))
    else:
        print("WARNING!: SSM Multicast is NOT Enabled on device: {}, configure \"ip pim ssm default\" on the device\n".format(hostname))
    isssmgroup = umcastdevice.isssmgroup
    if isssmgroup is True:
        sys.exit("WARNING!: SSM Multicast range is covering the Underlay Multicast Group: {} on device: {}".format(underlay_group, hostname))
    # Retrieve RP information:
    umcastdevice.rp_identification(underlay_group, service)
    rp = umcastdevice.rpinformation.rp
    if rp is None:
        sys.exit("WARNING!: Device {} does not have PIM RP! verify PIM RP configuration\n".format(hostname))
    pingstatus = umcastdevice.rpinformation.pingstatus
    if int(pingstatus.result) <= 70:
        print("WARNING! : Packet Loss from {} to RP {} is below threshold of 70%, current value is {} % \n".format(
            hostname, rp, pingstatus))
        print("WARNING! : PIM registers to RP {} might fail!\n".format(rp))
    else:
        print(
            "ICMP Connectivity from {} to RP {} is good at {} % success rate\n".format(hostname, rp, pingstatus.result))
    # RP Validations:
    # Is the PIM Tunnel Status UP?
    try:
        maintunnel = umcastdevice.rpinformation.maintunnel
        tunnels = umcastdevice.rpinformation.pimtunnels
        tunnel_state = None
        for tunnel in tunnels:
            if tunnel['tunnel_interface'] == maintunnel:
                tunnel_state = tunnel['tunnel_state']
                # Matching Register Source as Loopback0:
                devicelo0 = umcastdevice.profiled_device.loopback
                registersource = tunnel['tunnel_source']
                if devicelo0 == registersource:
                    print ("Loopback0 is being used as register-source to register to RP {} on device: {}\n".format(rp, hostname))
                else:
                    print ("WARNING!: Loopback0 is NOT the register-source to reach RP {} on device: {}, current source IP is: {}\n".format(rp,hostname,registersource))
        if tunnel_state == 'UP':
            print("PIM Encapsulation {} to RP {} is in UP state in device {}\n".format(maintunnel, rp, hostname))
        else:
            print("PIM Encapsulation to RP {} is NOT in UP state in device {}, are there any routes to the RP?\n".format(rp, hostname))
            print("RIB route to the PIM RP {}:\n".format(rp))
            print(pformat(vars(umcastdevice.rpinformation.rproute), indent=4, width=1, sort_dicts=False))
            print("CEF route to the PIM RP {}:\n".format(rp))
            print(pformat(vars(umcastdevice.rpinformation.rpcef), indent=4, width=1, sort_dicts=False))
            sys.exit("")
    except (KeyError, ValueError, IndexError) as e:
        print("PIM Encapsulation to RP {} is NOT in UP state in device {}, are there any routes to the RP?\n".format(rp, hostname))
        print("RIB route to the PIM RP {}:\n".format(rp))
        print(pformat(vars(umcastdevice.rpinformation.rproute), indent=4, width=1, sort_dicts=False))
        print("CEF route to the PIM RP {}:\n".format(rp))
        print(pformat(vars(umcastdevice.rpinformation.rpcef), indent=4, width=1, sort_dicts=False))
        sys.exit("")
    # RPF Information:
    umcastdevice.rpf_to_rp(rp,service)
    rpffailurestatus = umcastdevice.rpfinformation.rpffailure
    if rpffailurestatus is False:
        rpf = umcastdevice.rpfinformation.rpfip
        rpfinterface = umcastdevice.rpfinformation.rpfinterface
        print ("RPF Interface to the RP {} is: {} on device: {}; Attempting CDP resolution...\n".format(rp,rpfinterface,hostname))
        cdpneighbors = CDPinfo(hostname)
        cdpneighbors.cdpneighborinterface(rpfinterface,service)
        print ("CDP neighbors for interface {} that matches RPF IP {} on device: {}:\n".format(rpfinterface, rpf, hostname))
        rpfcdpneighbor = None
        if cdpneighbors.numberofneighbors != 0:
            print(pformat(vars(cdpneighbors), indent=4, width=1, sort_dicts=False))
            print ("\n")
            for i in cdpneighbors.cdpneighbors:
                try:
                    management_addresses = i['management_addresses']
                    for j in management_addresses:
                        if j == rpf:
                            rpfcdpneighbor = i
                except (KeyError, ValueError, IndexError) as e:
                    print("WARNING:! No CDP neighbor found for RPF IP {}\n".format(rpf))
        if rpfcdpneighbor is not None:
            print (rpfcdpneighbor)
    else:
        print ("RPF Not Found for RP {} on device: {}; Verifying Route!\n".format(rp,hostname))
        #If RPF resolution fails; verify the route to the upstream RP:
        cef_hops = umcastdevice.rpinformation.rpcef.nexthops
        pimneighbinterfaces=[]
        for i in pimneighborlist:
            interface = i['interface']
            pimneighbinterfaces.append(interface)
        for i in cef_hops:
            interfacename = i['oif']
            if any(x in interfacename for x in pimneighbinterfaces):
                sys.exit("Nexthop Interface {} has a PIM neighbor\n It is possible that long DNS resolution times can prevent RPF command from resolving, try disabling local DNS resolution\n Otherwise, verify if any other multicast or PIM configuration is preventing RPF resolution\n".format(interfacename))
            else:
                print ("WARNING!: Interface {} has no PIM neighbor!\n".format(interfacename))
                #Verifying if the CEF next hop is configured with PIM sparse-mode
                pimintfstatus = False
                for j in interface_list:
                    piminterface = j['interface_name']
                    if interfacename == piminterface:
                        pimintfstatus = True
                if pimintfstatus is False:
                    sys.exit("Elected RPF interface should be {} but it is not PIM enabled!\n".format(interfacename))
                if pimintfstatus is True:
                    sys.exit("Elected RPF interface should be {} and it is enabled for PIM, but no PIM neighbor is found!\n".format(interfacename))

    #Underlay Multicast Group not denied by Multicast Group Range:
    umcastdevice.multicast_range(service)
    mcastrangeinfo = umcastdevice.mcastrangeinfo
    mcastrangestatus = umcastdevice.isblockedbymcastrange
    if mcastrangestatus is False:
        print("Multicast Range allowing the L2 Flooding Group {} on device: {}\n".format(underlay_group,hostname))
    else:
        sys.exit("WARNING!: Multicast Range configuration is denying the Underlay Multicast Group: {} on device: {}\n".format(underlay_group,hostname))

    #PIM Statistics:
    umcastdevice.pim_statistics(service)
    #L2LISP IGMP interfaces
    umcastdevice.igmp_verifications(service)
    #Is L2LISP enabled for IGMP?
    try:
        if umcastdevice.igmpinterfaceinfo.enable is not True:
            sys.exit("WARNING!: IGMP is not enabled on L2LISP interface: {} on device: {}, this is an unknown condition\n".format(umcastdevice.igmpinterfaceinfo.igmpinterface, hostname))
        if umcastdevice.igmpinterfaceinfo.dr_this_system is not True:
            sys.exit("WARNING!: IGMP is enabled on L2LISP interface: {} but it is not the PIM DR on device: {}, this is an unknown condition\n".format(umcastdevice.igmpinterfaceinfo.igmpinterface, hostname))
        if umcastdevice.igmpinterfaceinfo.query_this_system is not True:
            sys.exit("WARNING!: IGMP is enabled on L2LISP interface: {} but it is not the IGMP Querier on device: {}, this is an unknown condition\n".format(umcastdevice.igmpinterfaceinfo.igmpinterface, hostname))
        igmpgroupinterfaces = umcastdevice.igmpinterfaceinfo.joined_group
        joining_underlay_group = False
        for groups in igmpgroupinterfaces:
            if groups in underlay_group:
                joining_underlay_group = True
        if joining_underlay_group is False:
            sys.exit("WARNING!: IGMP is enabled on L2LISP interface: {} but it is not joining the Underlay Group {} on device : {}, this is an unknown condition, use show ip igmp groups command to validate\n".format(umcastdevice.igmpinterfaceinfo.igmpinterface, underlay_group,hostname))
    except (KeyError,AttributeError,TypeError):
        sys.exit("WARNING!: IGMP is not working as expected on L2LISP interface: {} on device: {}, this is an unknown condition\n".format(umcastdevice.igmpinterfaceinfo.igmpinterface, hostname))
    #StarG Mroute:
    umcastdevice.local_star_g(service)
    starginfo = umcastdevice.stargmroute
    if starginfo is None:
        sys.exit("WARNING!: *,G mroute NOT found for group {} on device: {} , confirm if this mroute is not being created due to mroute limits or other multicast configuration\n".format(underlay_group, hostname))
    else:
        print("Found *,G mroute for group {} on device: {} , verifying it's state\n".format(underlay_group,hostname))
        flags = starginfo['flags']
        flagsmatch = ['S','J','C']
        if all(x in flags for x in flagsmatch):
            print ("Flags are SJCF\n")
        else:
            print ("WARNING!: *,G Mroute Flags are not SJCF (Sparse-Mode, Join SPT and Connected)\n")
        #IIF Verification: It is already implicit on previous checks
        #OIL Verification: Is the L2LISP or Tunnel interface listed on the OIL?
        l2lispinterface = None
        if umcastdevice.l2lispinterfacestatus.l2lispparenttype == 'L2LISP0':
            l2lispinterface = umcastdevice.l2lispinterfacestatus.l2lispsubinterfacestatus.interface
        if umcastdevice.l2lispinterfacestatus.l2lispparenttype == 'Tunnel':
            l2lispinterface = umcastdevice.l2lispinterfacestatus.l2lispparenstatus.interface
        oils = starginfo['outgoinginterfacelist']
        oilfound = False
        for i in oils:
            if i['interface'] == l2lispinterface:
                print ("Interface {} found in the OIL for the *,G Mroute on device: {}\n".format(l2lispinterface,hostname))
                oilfound = True
        if oilfound is not True:
            print("WARNING!: L2LISP/Tunnel interface not found as OIL for the *,G Mroute on device: {}, verifying L2LISP PIM interface status".format(l2lispinterface,hostname))
            oilpimstatus = anyinterface_pim_status(l2lispinterface,interface_list,hostname)
            if oilpimstatus is not True:
                sys.exit("WARNING!: Device {} does not have {} as PIM enabled\n".format(hostname,l2lispinterface))
            else:
                sys.exit("WARNING!: Device {} does not have {} as OIL for the *,G Mroute, even if it is PIM enabled".format(hostname,l2lispinterface))
    #L2LISPACL
    if umcastdevice.l2lispinterfacestatus.l2lispparenttype == 'L2LISP0':
        print ("Collecting information about L2LISP0 ACL\n")
        umcastdevice.floodingacls('L2LISP0',service)
    if umcastdevice.l2lispinterfacestatus.l2lispparenttype == 'Tunnel':
        print ("VCollecting information about L2LISP Special ACL \n")
        umcastdevice.floodingacls('Tunnel',service)

    return umcastdevice

def underlaymcast_object_print(umcastdevice):
    hostname = umcastdevice.profiled_device.hostname
    vlan = umcastdevice.l2lispinterfacestatus.stpstatus.vlan
    l2lispiid = umcastdevice.iid
    rp = umcastdevice.rp
    print ("Device Information {}:\n".format(hostname))
    print(pformat(vars(umcastdevice.profiled_device), indent=4, width=1, sort_dicts=False))
    print ("Multicast Global Configuration for device {}:\n".format(hostname))
    print(pformat(vars(umcastdevice.mcastconfig), indent=4, width=1, sort_dicts=False))
    print ("PIM Interface Information for device {}:\n".format(hostname))
    print(pformat(vars(umcastdevice.piminterfaces), indent=4, width=1, sort_dicts=False))
    print("PIM Neighbors Information for device {}:\n".format(hostname))
    print(pformat(vars(umcastdevice.pimneighbors), indent=4, width=1, sort_dicts=False))
    print("L2LISP Interface Information for device {}:\n".format(hostname))
    print(pformat(vars(umcastdevice.l2lispinterfacestatus), indent=4, width=1, sort_dicts=False))
    print("Spanning Tree Information for VLAN {} on device {}:\n".format(vlan, hostname))
    print(pformat(vars(umcastdevice.l2lispinterfacestatus.stpstatus), indent=4, width=1, sort_dicts=False))
    print("VLAN {} information for device {}:\n".format(vlan, hostname))
    print(pformat(vars(umcastdevice.l2lispinterfacestatus.vlanstatus), indent=4, width=1, sort_dicts=False))
    if umcastdevice.l2lispinterfacestatus.l2lispparenttype == 'L2LISP0':
        print("L2LISP Parent Interface Information on device {}:\n".format(hostname))
        print(pformat(vars(umcastdevice.l2lispinterfacestatus.l2lispparenstatus), indent=4, width=1,sort_dicts=False))
        print("L2LISP Sub-Interface Information on device {}:\n".format(hostname))
        print(pformat(vars(umcastdevice.l2lispinterfacestatus.l2lispsubinterfacestatus), indent=4, width=1,sort_dicts=False))
    if umcastdevice.l2lispinterfacestatus.l2lispparenttype == 'Tunnel':
        print("L2LISP Parent Interface Information on device {}:\n".format(hostname))
        print(pformat(vars(umcastdevice.l2lispinterfacestatus.l2lispparenstatus), indent=4, width=1,sort_dicts=False))
    print("L2LISP Flooding Configuration for Instance-ID {} on device {}:\n".format(l2lispiid, hostname))
    print(pformat(vars(umcastdevice.l2floodingproperties), indent=4, width=1, sort_dicts=False))
    print("SSM Information on device {}:\n".format(hostname))
    print(pformat(vars(umcastdevice.ssminformation), indent=4, width=1, sort_dicts=False))
    print("Information about RP {} on device {}:\n".format(rp, hostname))
    print(pformat(vars(umcastdevice.rpinformation), indent=4, width=1, sort_dicts=False))
    print("RIB route to the PIM RP {}:\n".format(rp))
    print(pformat(vars(umcastdevice.rpinformation.rproute), indent=4, width=1, sort_dicts=False))
    print("CEF route to the PIM RP {}:\n".format(rp))
    print(pformat(vars(umcastdevice.rpinformation.rpcef), indent=4, width=1, sort_dicts=False))
    print("RPF information for PIM RP {}: \n".format(rp))
    print(pformat(vars(umcastdevice.rpfinformation), indent=4, width=1, sort_dicts=False))
    print("Multicast Range Information on device {}: \n".format(hostname))
    print(pformat(vars(umcastdevice.mcastrangeinfo), indent=4, width=1, sort_dicts=False))
    print("PIM Statistics on device {}: \n".format(hostname))
    print(pformat(vars(umcastdevice.pimstatistics), indent=4, width=1, sort_dicts=False))
    print("IGMP Information of L2LISP Interface {} {}: \n".format(umcastdevice.l2lispinterfacestatus.l2lispfinalinterface,hostname))
    print(pformat(vars(umcastdevice.igmpinterfaceinfo), indent=4, width=1, sort_dicts=False))
    print("*,G Mroute Information on device {}: \n".format(hostname))
    print(umcastdevice.stargmroute)
    print("L2Flood ACL Information on device {}: \n".format(hostname))
    print(umcastdevice.l2floodacls)

def fhr_lhr_validations(fhrdevice,lhrdevice,catc,service):
    # FHR and LHR consistency:
    # Same RP?
    fhr_rpinfo = fhrdevice.rpinformation
    lhr_rpinfo = lhrdevice.rpinformation
    if fhr_rpinfo.rp == lhr_rpinfo.rp:
        samerp = True
    else:
        samerp = False
    # #Same Fabric Site? #RP in the same site?
    potential_rps  = []
    isinternal = None
    if samerp is True:
        fhrsitefabricsite = fhrdevice.profiled_device.fabric_site_hierarchy
        lhrsitefabricsite = lhrdevice.profiled_device.fabric_site_hierarchy
        profiledrps = profile_devices_with_ip(fhr_rpinfo.rp,catc,service)
        for rp in profiledrps:
            rp_site = rp.fabric_site_hierarchy
            if (rp_site == fhrsitefabricsite) and (rp_site == lhrsitefabricsite):
                isinternal = True
                potential_rps.append(rp)
            else:
                isinternal = False

    else:
        profiledrps = []
        isinternal = None

    # #Possible MSDP configuration?
    total_rps = len(potential_rps)
    msdpcriteria = False
    if total_rps > 1:
        print ("Found more than 1 RP in the same fabric site, MSDP peering will be considered\n")
        print ("Fabric Sites for profiled RPs: \n")
        msdpcriteria = True
        for rp in potential_rps:
            print ("RP Device: {} with an RP IP of : {} is part of Fabric Site: {}".format(rp.hostname,fhr_rpinfo.rp,rp.fabric_site_id))
    # #RP is internal?
    consistency_check = {
        'samerp' : samerp,
        'profiledrps' : profiledrps,
        'internalrp' : isinternal,
        'msdpcheck' : msdpcriteria
    }
    return consistency_check

def fhr_validations(fhrdevice,service):

    print("Validating FHR L2 Flooding Information...\n")
    # Is this device really an FHR? What constitutes an FHR?
        #PIM Tunnel, Loopback 0 PIM enablement, Broadcast Underlay and more are covered by main validations (single device underlay profiling)
        #An FHR is defined by a device that is able to create an S,G based on traffic; this criteria can use a source VLAN to determine if there are any active ports sending BUM traffic.
        #Steps to determine if Flooding S,G must be created: 1, there are fwding interfaces on the vlan, there is at least 1 interface with incoming bcast traffic from these, the S,G is created based on this traffic.
    #Step 1 Retrieve STP available ports from Object: umcastdevice. and confirm if there are interfaces with incoming broadcast packets
    hostname = fhrdevice.profiled_device.hostname
    stpinterfaces = fhrdevice.l2lispinterfacestatus.stpstatus.fwdinterfaces
    if len(stpinterfaces) != 0:
        for interface in stpinterfaces:
            interfacecounters = Interfaces(interface,hostname)
            interfacecounters.show_controllers_ethernet_controllers(service)
            bcastcounters = interfacecounters.ethcontrollers_info['receive']['broadcast_frames']
            if bcastcounters > 1:
                print ("Incoming broadcast packets found in Interface {}, total incoming broadcasts: {} on device {}\n".format(interface,bcastcounters,hostname))
                break
    #Step 2 Verify if the S,G is created on the device:
    #RPF to Null0?
    # (Is it stuck in registration? FT Flags? if F not there, registration is stuck.
    # , what is the OIL state?,
    loopback0 = fhrdevice.profiled_device.loopback
    group = fhrdevice.l2floodingproperties.broadcastunderlay
    iid = fhrdevice.l2floodingproperties.iid
    localmroute = MulticastRoutes(None,hostname)
    localmroute.mroute_get(group,loopback0,service)
        #It exists?
    if localmroute.mrouteinfo is None:
        print ("WARNING!: No Local S,G found!, expecting an S,G of {},{} on device: {}\n".format(loopback0,group,hostname))
        print("WARNING!: Verify conditions for defect: CSCwf12353 \n")
        print("Try removing \"broadcast-underlay {}\" from the L2LISP instance {} and re-configure it again on device: {}".format(group,iid,hostname))
        sys.exit("\n")
    elif localmroute.mrouteinfo[0]['source'] == "*":
        print ("WARNING!: No Local S,G found!, expecting an S,G of {},{} on device: {}\n".format(loopback0,group,hostname))
        print("WARNING!: Verify conditions for defect: CSCwf12353 \n")
        print("Try removing \"broadcast-underlay {}\" from the L2LISP instance {} and re-configure it again on device: {}".format(group,iid,hostname))
        sys.exit("\n")
    else:
        print("Found Local S,G of {},{} on device: {}\n".format(loopback0, group,hostname))
        #RPF is Null0?
    rpfinterface = localmroute.mrouteinfo[0]['incominginterface']
    if rpfinterface == 'Null0':
        print("Local S,G of {},{} RPF interface is Null0, which is expected, on device: {}\n".format(loopback0, group, hostname))
    else:
        print("WARNING!: Local S,G of {},{} RPF interface is {}, expecting Null0, on device: {}\n ".format(loopback0, group, rpfinterface, hostname))
        sys.exit("Verify RPF to the Loopack0 IP, is there an static mroute pointing to somewhere else?")
        #Is stuck in register?
    mrouteflags = localmroute.mrouteinfo[0]['flags']
    registerflag = ['F']
    if any(x in mrouteflags for x in registerflag):
        print ("Local S,G for {},{} is not stuck in Registering, F flag set on device {}\n".format(loopback0,group, hostname))
    else:
        print ("WARNING: Local S,G for {},{} is stuck in Registering, F flag NOT set on device {}\n".format(loopback0,group, hostname))
        #What are the OILs, are there any?
    mrouteoils = localmroute.mrouteinfo[0]['outgoinginterfacelist']
    if len(mrouteoils) == 0:
        print("WARNING: Local S,G for {},{} has no OILs on device {}\n".format(loopback0,group,hostname))
        fwdingoils = False
    else:
        fwdingoils = True
        print("Local S,G for {},{} has OILs on device {}\n".format(loopback0, group, hostname))
        print("OILs for the Local S,G:\n")
        for oil in mrouteoils:
            print (oil)

        #MFIB validation
    #MFIB  Verbosity, cannot be used for the *,G as the output is too big, MFIB cannot specify the *,G
    mfibinfo = MulticastRoutes(None,hostname)
    mfibinfo.mfib_verbose(group,loopback0,service)
    localmfib = mfibinfo
    return localmroute,localmfib,fwdingoils

def lhr_sg_validations(fhrdevice,lhrdevice,service):

    print("Validating LHR L2 Flooding Information...\n")
    # All L2 Flooding Enabled devices are considered LHRs. Skipping PIM Encapsulation information, but S,G states.
        #An LHR is defined by a device that expects traffic from the FHR in the form of an S,G;
    hostname = lhrdevice.profiled_device.hostname
    #Step 1 Verify if the S,G is created on the device:
    #RPF must be a PIM neighbor
    #If the S,G exists, it must have the L2LISP interface as OIL
    # Flags: J and T (SPT Bit and Traffic Triggered)
    # How many packets average? Bigger than 0?
    #Hardware Forwarded bigger than SW forwarding?
    loopback0 = fhrdevice.profiled_device.loopback
    group = fhrdevice.l2floodingproperties.broadcastunderlay
    remotemroute = MulticastRoutes(None,hostname)
    remotemroute.mroute_get(group,loopback0,service)
        #It exists?
    if remotemroute.mrouteinfo is None:
        print ("WARNING!: No Remote S,G found!, expecting an S,G of {},{} on device: {}".format(loopback0,group,hostname))
        print("Starting Shared Tree validations for Underlay Multicast")
        return None, None, None
    elif remotemroute.mrouteinfo[0]['source'] == "*":
        print ("WARNING!: No Remote S,G found!, expecting an S,G of {},{} on device: {}".format(loopback0,group,hostname))
        print("Starting Shared Tree validations for Underlay Multicast")
        return None,None,None
    else:
        print("Found Local S,G of {},{} on device: {}\n".format(loopback0, group,hostname))
        #RPF is PIM neighbor?
        rpfinterface = remotemroute.mrouteinfo[0]['incominginterface']
        pimneighbors = lhrdevice.pimneighbors.pimneighbors
        is_rpf_pimintf = False
        for pimneighbor in pimneighbors:
            currentinterface = pimneighbor['interface']
            if rpfinterface == currentinterface:
                is_rpf_pimintf = True
        if is_rpf_pimintf is False:
            sys.exit("RPF Interface for S,G Entry {},{} on device is {} which is not a PIM neighbor on device: {}, verify RPF resolution for source {}".format(loopback0,group,rpfinterface,hostname,loopback0))

        #Correct Flags?
        mrouteflags = remotemroute.mrouteinfo[0]['flags']
        sptflags = ['J','T']
        if all(x in mrouteflags for x in sptflags):
            print ("Remote S,G for {},{} has correct flags for this mroute: {}  on device {}".format(loopback0,group, mrouteflags, hostname))
        else:
            print ("Remote S,G for {},{} is missing the expected JT flags , flags for this mroute are: {}  on device {}".format(loopback0,group, mrouteflags, hostname))
        #L2LISP or Tunnel interface in OIL?
        expectedoil = lhrdevice.l2lispinterfacestatus.l2lispfinalinterface
        mrouteoils = remotemroute.mrouteinfo[0]['outgoinginterfacelist']
        if len(mrouteoils) == 0:
            print("WARNING: Remote S,G for {},{} has no OILs on device {}".format(loopback0,group,hostname))
            fwdingoils = False
        else:
            fwdingoils = True
            print("Remote S,G for {},{} has OILs on device {}".format(loopback0, group, hostname))
            l2lispinoil = False
            for oil in mrouteoils:
                currentoilinterface = oil['interface']
                if currentoilinterface == expectedoil:
                    l2lispinoil = True
            if l2lispinoil is False:
                sys.exit("Remote S,G for {},{} has interfaces in the OIL, but not the expected interface {}, on device: {} this is an unexpected error, outside of the scope of this script".format(loopback0,group,expectedoil,hostname))
         #S,G Counters
        mfibinfo = MulticastRoutes(None,hostname)
        mfibinfo.mfib_verbose(group,loopback0,service)
        remotemfib = mfibinfo
        mfibswcounters = remotemfib.sw_packet_count
        mfibhwcounters = remotemfib.hw_packet_count
        #Hw counters must be greater than sw counters:
        if int(mfibhwcounters) >= int(mfibswcounters):
            print ("Remote S,G for {},{} has registered {} packets in hardware and {} in software on device: {}, which is expected".format(loopback0,group,mfibhwcounters,mfibswcounters,hostname))
        else:
            print("Remote S,G for {},{} has registered {} packets in software, more than total {} in hardware, can be unexpected, confirm that HW counters are increasing and not SW, otherwise this is unexpected and outside the scope of this script".format(loopback0, group, mfibhwcounters, mfibswcounters))

        return remotemroute,remotemfib,fwdingoils

def rp_validations(fhrdevice,service):
    #Step 1: Is the S,G in the FHR registered?
    return None
