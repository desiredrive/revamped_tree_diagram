import re
import ipverifications
import sys
import controlplane
import device_profiler
import hostonboarding
from pprint import pformat
import ctsprocessing

#Switching Flow  : From one LISP XTR to Another
'''
Verifications:

Are source and destination in the same subnet? If Yes:
    Are these in an L2 only network? - 1st Exception, Check L2 only flag
    Is Flood ARPnd Enabled? - 
        Yes - Verification of L2 AR LISP is marked as strict 
        No - Verification of L2 AR LISP is only to find remote RLOCs
            If remote RLOCs cannot be found (missing AR), an exception must be performed - Request Destination MAC of the endpoint
            If remote RLOCs cannot be found (missing MAC), an exception must be performed - Request Destination device (mgmtip) to perform Host Onboarding Validations
    if L2 only: SGT and DHCP operations must be performed differently
    CP queries:
        if Flood ARPnd disabled : L2MAC and L2AR are mandatory
        if Flood ARPnd enabled: L2MAC is mandatory, L2AR is relaxed
'''
def flowelection(epinfo, dstip):
    issamesubnet=ipverifications.subnet_validator(epinfo.sourceip,dstip,epinfo.mask)
    if issamesubnet==False:
        print ("Devices in different Subnet, Routing Flow\n")
    if issamesubnet==True:
        print ("Devices in the same Subnet, starting Switching Flow \n")
        return ("L2")

def ar_relay_resolution(dstip, iid, l2cps, service):
    print ("Querying site Control Planes for LISP AR for {} \n".format(dstip))
    ar_res = []
    for i in l2cps:
        queriedcp = i
        ar_q = controlplane.cp_eid(dstip,iid,queriedcp)
        ar_q.address_q(service)
        ar_res.append(ar_q)

    macs = []
    etrs = []

    if ar_res == None:
        sys.exit("No MAC address were found in any of the local Control Planes")
    print ("Address-Resolution Binding results: \n")

    for i in ar_res:
        mac = i.arbinding
        etr = i.etrs
        print (pformat(vars(i), indent=4, width =1, sort_dicts=False))
        macs.append(mac)
        etrs.append(etr)
    print ("\n")
    macs = list(set(macs))
    macs = [x for x in macs if x is not None]
    if len (macs) > 1:
        sys.exit("The destination IP {} has more than 1 MAC address: {} from {} \n".format(dstip, macs, etrs))
    
    if len (macs) == 0:
        sys.exit("No MAC address were found in any of the local Control Planes")
    return (macs[0])

def mac_rloc_resolution(dstmac, iid, l2cps, service):
    print ("Querying site Control Planes for L2LISP MAC for {} \n".format(dstmac))
    l2_res = []
    for i in l2cps:
        queriedcp = i
        mac_q = controlplane.cp_eid(dstmac, iid, queriedcp)
        mac_q.ethernet_q(service)
        l2_res.append(mac_q)

    wlcs = []    
    etrs = []
    if l2_res == None:
        sys.exit ("There were no RLOCs binded to this MAC address in any of the local Control Planes")
    print ("L2 LISP MAC Control Plane results: \n")
    for i in l2_res:
        print (pformat(vars(i), indent=4, width =1, sort_dicts=False))
        try:
            for j in i.etrs:
                if j != None:
                    etrs.append(j)
        except:
            pass
        try:
            for k in i.wlcip:
                if k != None:
                    wlcs.append(k)
        except:
            pass
    print ("\n")
    wlcs = list(set(wlcs))
    etrs = list(set(etrs))
    etrs = [x for x in etrs if x  not in wlcs]

    if len (etrs) > 1:
        sys.exit("The destination MAC {} has more than 1 RLOCs: {} \n".format(dstmac, etrs))
                 
    return (etrs[0])

def l2_east_west(srcdevice, sourceep, dstmac, rloc, dstip, rmtdevice, service):

    #execution of L2 LISP Map Cache
    l2mapcache = controlplane.l2_map_cache(dstmac,sourceep.l2lispiid,srcdevice)
    l2mapcache.l2map(service)

    print (pformat(vars(l2mapcache), indent=4, width =1, sort_dicts=False)) 

    l2rloc = l2mapcache.rloc
    state= l2mapcache.rlocstate

    bad_states = ['route-reject', 'own', 'admin']
    if any(x  in state for x in bad_states):
        print ("RLOC is marked as {}, validating RLOC state \n")
        #sequence to validate RLOC
    if state == "UP":
        print ("RLOC is marked as UP, validating end-to-end connectivity \n")
    
    #validaiton of map-cache state
    if l2rloc == rloc:
        print ("L2 Map-Cache matches CP regsitered RLOC: {} \n".format(rloc))
    else:
        print ("SMR verifications comming soon \n")
        sys.exit("L2 Map-cache {} does not match CP registered RLOC {} \n").format(l2rloc, rloc)

    #troubleshooting actions

    #underlay recursion to the RLOC
        
    print ("RLOC reachability information: \n")
    rloc_reachability = controlplane.route_recursion(rloc,srcdevice)
    rloc_reachability.rloc_data(service)
    print (pformat(vars(rloc_reachability), indent=4, width =1, sort_dicts=False))

    print ("Egress Interface details: \n")
    egressstate = []
    for i in rloc_reachability.phy:
        states = controlplane.underlay_validations(i, srcdevice)
        states.intf_parse(service)
        egressstate.append(states)
    for i in egressstate:
        print (pformat(vars(i), indent=4, width =1, sort_dicts=False))
    
    if int(rloc_reachability.ping_to_rloc) <= 70:
        print ("WARNING! : Packet Loss to {} is below threshold of 70%, actual value is {} % \n".format(rloc, rloc_reachability.ping_to_rloc))
    else:
        print ("ICMP Connectivity to  {} is good at {} % success rate with low MTU \n".format(rloc,rloc_reachability.ping_to_rloc))
    
    if int(rloc_reachability.mtu_validation) <= 70:
        print ("WARNING! : Packet Loss  to {} is below threshold of 70% with MTU of {}, ping rate is value is {} %\n".format(rloc,rloc_reachability.mtu,rloc_reachability.mtu_validation))
    else:
        print ("ICMP Connectivity to  {} is good at {} % success rate with an MTU of {}\n".format(rloc,rloc_reachability.mtu_validation,rloc_reachability.mtu))

    #Host Onboarding for the destination:
    print ("Profiling device where the Destination is located...\n")
    dxtr = device_profiler.device(rmtdevice)
    dxtr.profile_device(service)
    print (pformat(vars(dxtr), indent=4, width =1, sort_dicts=False))

    #Gathering information about the source...
    print ("Gathering information about the source endpoint...\n")
    destep = hostonboarding.endpoint_info(dstip)
    destep.host_onboarding_validation(dxtr,service)
    print (pformat(vars(destep), indent=4, width =1, sort_dicts=False))


    #Performing CTS evaluations...
    print ("Gathering CTS information between SGTs...\n")
    ctsstate = ctsprocessing.cts_info(sourceep,destep,dxtr.hostname)
    ctsstate.enforcement_flow(service)
    print (pformat(vars(ctsstate), indent=4, width=100, sort_dicts=False))

    ctscounters = ctsstate.counters
    hwdenies = ctscounters['HW Denied']
    swdenies = ctscounters['SW Denied']
    
    if ctsstate.globalenforcement==True and ctsstate.vlanenforcement==True:
        if int(hwdenies) != 0:
            print ("Warning!!, A total of {} HW deny counters found for traffic between {} and {} in device: {} , RBACL is : {}, evaluate if this impacts your traffic".format(hwdenies, sourceep.sourceip, dstip, dxtr.hostname, ctsstate.aclname))
        if int(swdenies) != 0:
            print ("Warning!!, A total of {} SW deny counters found for traffic between {} and {} in device: {} , RBACL is : {}, evaluate if this impacts your traffic".format(swdenies, sourceep.sourceip, dstip, dxtr.hostname, ctsstate.aclname))
    else:
        print ("CTS Global Enforcement is : ")
        print ("CTS VLAN {} Enforcement is : ".format(destep.sourcevlan))


def switchingflow(epinfo, dstip, service, l2cps):
    l2onlystate = epinfo.isl2only
    floodarp = epinfo.arpflood
    iid = epinfo.l2lispiid

    #Step 1 : LISP AR Request, find destination MAC:
    
    mac = ar_relay_resolution(dstip, iid, l2cps, service)

    #Step 2: LISP L2 MAC Request, find the MAC RLOC:

    mac_rloc = mac_rloc_resolution(mac, iid, l2cps, service)
    

    return (mac, mac_rloc)



        
