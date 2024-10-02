import ipverifications
import sys
import traffic_flows.l2_lisp_interxtr
from routingmodules import lisp
from routingmodules import iprouting
from routingmodules import cef
from catalystcenterapi import catcapi
from device_profiler import device
from pprint import pformat

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
        return ("L3")
    if issamesubnet==True:
        print ("Devices in the same Subnet, starting Switching Flow \n")
        return ("L2")

def device_flow(flow_type, sourcextr, sourceep, destip, service):
    if flow_type == "L2":
        print("Determining if flow is Inter-XTR or Intra-XTR")
        
        #Step 1: Profile L2 LISP parameters for the Source Endpoint
        l2lispsrc = lisp.l2lisp_info()
        l2lispsrc.l2_lisp_parameters(sourcextr, sourceep, service)
        print (pformat(vars(l2lispsrc), indent=4, width =1, sort_dicts=False))

        #Step 2: Identify AR-Request, find the endpoint in Control Plane 
        l2lisp_ar = traffic_flows.l2_lisp_interxtr.ar_relay_resolution(destip, l2lispsrc.l2lispiid,l2lispsrc.l2cps,service,sourcextr.dnac, sourcextr.fabric_site_hierarchy)

        #Step 3: Identify L2 EID / MAC-Address, extract destination RLOC
        l2lisp_mac = traffic_flows.l2_lisp_interxtr.mac_rloc_resolution(l2lisp_ar[0],l2lispsrc.l2lispiid,l2lisp_ar[1],service)

        sourcerloc = sourcextr.loopback
        dstrloc = l2lisp_mac[0]
        mac = l2lisp_mac[1]

        if sourcerloc==dstrloc:
            print ("Host {} and {} are in the same XTR {}, performing local checks \n".format(sourceep.sourceip,destip,dstrloc))
            print ("Starting Intra-XTR Switching Flow (L2), Flow is Same-Device")
        else:
            print ("Host {} is in RLOC {} and Host {} is in RLOC {} \n".format(sourceep.sourceip, sourcerloc, destip ,dstrloc))
            print ("Starting Inter-XTR Switching Flow (L2), Flow is East-West\n")
            inter_xtr_ew(sourcextr, sourceep, l2lispsrc, dstrloc, destip, mac, service)
    return None

def inter_xtr_ew(srcxtr, srcep, l2lispsrc, dstrloc, dstip, mac, service):
    #Execution of L2LISP Map Cache
    #Get the hostname of the destination RLOC and then Management IP:

    dstxtruuid= catcapi.get_device_from_lo0(dstrloc, srcxtr.dnac, service)[0]['deviceUUID']
    dstxtrmgmtip = catcapi.get_network_device_byuuid(dstxtruuid,srcxtr.dnac,service)

    #Profiling Destination XTR:
    #[Object: Destination XTR]
    dstxtr = device(dstxtrmgmtip,srcxtr.dnac)
    dstxtr.profile_device(service)
    print (pformat(vars(dstxtr), indent=4, width =1, sort_dicts=False))

    #Determining Inter or Intra Site:
    dstsite = dstxtr.fabric_site_hierarchy
    srcsite = srcxtr.fabric_site_hierarchy
    if (srcsite == dstsite):
        print ("Source XTR {} in Fabric: {}, is in the same Fabric Site as Destination XTR {}".format(srcxtr.hostname, srcsite, dstxtr.hostname))
    else:
        print ("Source XTR {} in Fabric: {}, not int the same  Fabric Site: {} as Destination XTR {}".format(srcxtr.hostname, srcsite, dstsite, dstxtr.hostname))
    #Remote Map-Cache Calculation
    #[Object: L2LISP Map Cache]
    l2mapcache = traffic_flows.l2_lisp_interxtr.l2lisp_map_cache_validation(l2lispsrc, dstrloc, srcxtr.hostname, mac, service)
    print (pformat(vars(l2mapcache), indent=4, width =1, sort_dicts=False))

    #Underlay Routing Modules:
    #[Object: Recursed Route]
    rlocroute = iprouting.ip_route_get(l2mapcache.rloc,None,srcxtr.hostname)
    rlocroute.iproute_prefix(service)
    print (pformat(vars(rlocroute), indent=4, width =1, sort_dicts=False))

    #RLOC reachability for L2 requires /32 másk
    if int(rlocroute.mask) != 32:
        sys.exit("WARNING!: LISP Layer 2 Extension requires a /32 for each RLOC, RLOC {} is known via route {} with mask {} which is not exact!".format(l2mapcache.rloc, rlocroute.prefix, rlocroute.mask)) 
    #[CEF: Route to Underlay]:
    rloccef = cef.ip_cef_internal(l2mapcache.rloc,None,srcxtr.hostname)
    rloccef.get_cef_internal(service)
    print (pformat(vars(rloccef), indent=4, width =1, sort_dicts=False))

    #Resolving Virtual Interfaces and Layer 2 Interfaces


    return None
def site_flow():
    return None

def transit_flow():
    return None

def inter_vrf():
    return None
