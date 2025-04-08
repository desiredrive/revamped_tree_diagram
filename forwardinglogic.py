import ipverifications
import sys
import traffic_flows.l2_lisp_interxtr
from traffic_flows.operational_tests import Ping
from routingmodules import lisp
from routingmodules import iprouting
from routingmodules import cef
from switchingmodules.interfaces import Interfaces
from catalystcenterapi import catcapi
from device_profiler import Device, collection_success
from hostonboarding import endpoint_info,host_onboarding_success
from securitymodules.ciscotrustsec import cts_endpoint_info
from securitymodules.ciscotrustsec import cts_rules,cts_ep_collection,cts_rule_collection
from radkit_cli import logging_info,logging_error,logging_warning
from pprint import pformat
from traffic_flows.l2_lisp_interxtr import cp_l2_results,l2_mapcache_results
from routingmodules.iprouting import ip_route_collection
from routingmodules.cef import ip_cef_collection,phy_cef_collection

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
def flowelection(epinfo, dstip,step):
    process = "Forwarding-Logic"
    subprocess = "[Flow-Election]"
    issamesubnet=ipverifications.subnet_validator(epinfo.sourceip,dstip,epinfo.mask)
    if issamesubnet==False:
        logging_info(step, process, subprocess,"Main",
                      "Devices in different Subnet, Routing Flow")
        #print ("Devices in different Subnet, Routing Flow\n")
        return ("L3")
    if issamesubnet==True:
        logging_info(step, process, subprocess,"Main",
                      "Devices in the same Subnet, starting Switching Flow")
        #print ("Devices in the same Subnet, starting Switching Flow \n")
        return ("L2")

def device_flow(flow_type, sourcextr, sourceep, destip, service,step):
    process = "Forwarding-Logic"
    if flow_type == "L2":
        subprocess = "[L2]"
        logging_info(step, process, subprocess,"Main",
                      "Determining if flow is Inter-XTR or Intra-XTR")
        #print("Determining if flow is Inter-XTR or Intra-XTR")
        
        #Step 1: Profile L2 LISP parameters for the Source Endpoint
        step = step+1
        l2lispsrc = lisp.l2lisp_info()
        l2lispsrc.l2_lisp_parameters(sourcextr, sourceep, service)
        hostname = sourcextr.hostname
        collection_summary = "VLAN: {}, L2VNI: {}, MAC: {}, In L2DynEID?: {}, In L2DB: {}, , L2CPs: {}, Signal-Supress: {}".format(l2lispsrc.sourcevlan,l2lispsrc.l2lispiid, l2lispsrc.sourcemac,l2lispsrc.l2dynstate,l2lispsrc.l2lispdbstate,l2lispsrc.l2cps,l2lispsrc.l2signalsupressstate)
        string = "Result: Success"
        logging_info(step, process, subprocess, hostname, collection_summary)
        logging_info(step, process, subprocess, hostname, string)
        #print (pformat(vars(l2lispsrc), indent=4, width =1, sort_dicts=False))

        #Step 2: Identify AR for Local MAC and Local AR:
        step = step+1
        l2lisp_ar_src = traffic_flows.l2_lisp_interxtr.ar_relay_resolution(sourceep.sourceip, l2lispsrc.l2lispiid,l2lispsrc.l2cps,service,sourcextr.dnac, sourcextr.fabric_site_hierarchy,step)
        collection_summary = "EID: {}, L2VNI: {}, ETRs: {}, AR-Binding: {}, Protocol: {}, CP: {}, AuthenticationFailures: {}".format(l2lispsrc.sourcevlan,l2lispsrc.l2lispiid, l2lispsrc.sourcemac,l2lispsrc.l2dynstate,l2lispsrc.l2lispdbstate,l2lispsrc.l2cps,l2lispsrc.l2signalsupressstate)
        string = "Result: Success"
        logging_info(step, process, subprocess, hostname, collection_summary)
        logging_info(step, process, subprocess, hostname, string)
        step = step+1
        l2lisp_mac = traffic_flows.l2_lisp_interxtr.mac_rloc_resolution(l2lisp_ar_src[0],l2lispsrc.l2lispiid,l2lisp_ar_src[1],service,step)



        #Step 2: Identify AR-Request, find the endpoint in Control Plane
        step = step+1
        l2lisp_ar = traffic_flows.l2_lisp_interxtr.ar_relay_resolution(destip, l2lispsrc.l2lispiid,l2lispsrc.l2cps,service,sourcextr.dnac, sourcextr.fabric_site_hierarchy,step)
        collection_summary = "EID: {}, L2VNI: {}, ETRs: {}, AR-Binding: {}, Protocol: {}, CP: {}, AuthenticationFailures: {}".format(l2lispsrc.sourcevlan,l2lispsrc.l2lispiid, l2lispsrc.sourcemac,l2lispsrc.l2dynstate,l2lispsrc.l2lispdbstate,l2lispsrc.l2cps,l2lispsrc.l2signalsupressstate)
        string = "Result: Success"
        logging_info(step, process, subprocess, hostname, collection_summary)
        logging_info(step, process, subprocess, hostname, string)

        #Step 3: Identify L2 EID / MAC-Address, extract destination RLOC
        step = step+1
        l2lisp_mac = traffic_flows.l2_lisp_interxtr.mac_rloc_resolution(l2lisp_ar[0],l2lispsrc.l2lispiid,l2lisp_ar[1],service,step)
        sourcerloc = sourcextr.loopback
        dstrloc = l2lisp_mac[0]
        mac = l2lisp_mac[1]
        step = step + 1
        if sourcerloc==dstrloc:
            logging_info(step,process,subprocess,"Main","Host {} and {} are in the same XTR {}, performing local checks".format(sourceep.sourceip,destip,dstrloc))
            #print ("Host {} and {} are in the same XTR {}, performing local checks \n".format(sourceep.sourceip,destip,dstrloc))
            logging_info(step,process,subprocess,"Main","Starting Intra-XTR Switching Flow (L2), Flow is Same-Device")
            #print ("Starting Intra-XTR Switching Flow (L2), Flow is Same-Device")
        else:
            logging_info(step,process,subprocess,"Main","Host {} is in RLOC {} and Host {} is in RLOC {}".format(sourceep.sourceip, sourcerloc, destip ,dstrloc))
            #print ("Host {} is in RLOC {} and Host {} is in RLOC {} \n".format(sourceep.sourceip, sourcerloc, destip ,dstrloc))
            logging_info(step, process, subprocess, "Main",
                         "Starting Inter-XTR Switching Flow (L2), Flow is East-West")
            #print ("Starting Inter-XTR Switching Flow (L2), Flow is East-West\n")
            l2_inter_xtr_ew(sourcextr, sourceep, l2lispsrc, dstrloc, destip, mac, service,step)
    return None

def l2_inter_xtr_ew(srcxtr, srcep, l2lispsrc, dstrloc, dstip, mac, service,step):
    process = "Forwarding-Logic"
    subprocess = "[East-West]"

    #Execution of L2LISP Map Cache
    #Get the hostname of the destination RLOC and then Management IP:

    dstxtruuid= catcapi.get_device_from_lo0(dstrloc, srcxtr.dnac, service)[0]['deviceUUID']
    dstxtrmgmtip = catcapi.get_network_device_byuuid(dstxtruuid,srcxtr.dnac,service)


    #Profiling Destination XTR:
    #[Object: Destination XTR:
    logging_info(step, process, subprocess, "Main",
                 "Profiling device where the Destination is located")
    #print ("Profiling device where the Destination is located...\n")
    dstxtr = Device(dstxtrmgmtip,srcxtr.dnac,step)
    dstxtr.profile_device(service)
    collection_success(dstxtr)
    #print (pformat(vars(dstxtr), indent=4, width =1, sort_dicts=False))

    step = step+1
    #Determining Inter or Intra Site:
    dstsite = dstxtr.fabric_site_hierarchy
    srcsite = srcxtr.fabric_site_hierarchy
    if srcsite == dstsite:
        logging_info(step, process, subprocess, "Main",
                     "Source XTR {} in Fabric: {}, is in the same Fabric Site as Destination XTR {}".format(srcxtr.hostname, srcsite, dstxtr.hostname))
        #print ("Source XTR {} in Fabric: {}, is in the same Fabric Site as Destination XTR {}".format(srcxtr.hostname, srcsite, dstxtr.hostname))
    else:
        logging_info(step, process, subprocess, "Main","Source XTR {} in Fabric: {}, not int the same  Fabric Site: {} as Destination XTR {}".format(srcxtr.hostname, srcsite, dstsite, dstxtr.hostname))
        #print ("Source XTR {} in Fabric: {}, not int the same  Fabric Site: {} as Destination XTR {}".format(srcxtr.hostname, srcsite, dstsite, dstxtr.hostname))
    #Remote Map-Cache Calculation
    #[Object: L2LISP Map Cache]
    l2mapcache = traffic_flows.l2_lisp_interxtr.l2lisp_map_cache_validation(l2lispsrc, dstrloc, srcxtr.hostname, mac, service,step)
    l2_mapcache_results(l2mapcache,step)
    #print (pformat(vars(l2mapcache), indent=4, width =1, sort_dicts=False))

    #Underlay Routing Modules:
    step = step+1
    subprocess = "[Underlay]"
    #[Object: Recursed Route]
    logging_info(step,process,subprocess,srcxtr.hostname,"Collecting RIB Information for prefix: {}".format(l2mapcache.rloc))
    rlocroute = iprouting.IPRoute(l2mapcache.rloc,None,srcxtr.hostname)
    rlocroute.iproute_prefix(service,step)
    ip_route_collection(rlocroute,step)
    #print (pformat(vars(rlocroute), indent=4, width =1, sort_dicts=False))

    #RLOC reachability for L2 requires /32 másk
    if int(rlocroute.mask) != 32:
        logging_error(step,process,subprocess,srcxtr.hostname,"WARNING!: LISP Layer 2 Extension requires a /32 for each RLOC, RLOC {} is known via route {} with mask {} which is not exact!".format(l2mapcache.rloc, rlocroute.prefix, rlocroute.mask))
        sys.exit("WARNING!: LISP Layer 2 Extension requires a /32 for each RLOC, RLOC {} is known via route {} with mask {} which is not exact!".format(l2mapcache.rloc, rlocroute.prefix, rlocroute.mask))
    
    #[CEF: Route to Underlay]:
    #[Object: CEF Internal Information]
    step = step+1
    logging_info(step,process,subprocess,srcxtr.hostname,"Processing CEF Internal Information for prefix: {}".format(l2mapcache.rloc))
    rloccef = cef.IPCef(l2mapcache.rloc,None,srcxtr.hostname)
    rloccef.get_cef_internal(service)
    ip_cef_collection(rloccef,step)
    #print (pformat(vars(rloccef), indent=4, width =1, sort_dicts=False))

    #Resolving Virtual Interfaces and Layer 2 Interfaces
    step = step+1
    #[Object: RLOC Physical Interfaces]
    logging_info(step, process, subprocess, srcxtr.hostname,
                 "Calculating Physical Interfaces")
    rlocintfs = cef.physical_recursion(rloccef, srcxtr.hostname)
    rlocintfs.get_physical_interfaces(service,step)

    #print (pformat(vars(rlocintfs), indent=4, width =1, sort_dicts=False))

    #Underlay Interface Parsing
    #[Object: Interface Information and Counters - interfaceobjects]
    nexthops = rlocintfs.nexthops
    interfaceobjects = []
    mtus = []
    for i in nexthops:
        nhinterface = i['oif']
        nhinterfaceinfo = Interfaces(nhinterface, srcxtr.hostname)
        nhinterfaceinfo.show_interface(service)
        interfaceobjects.append(nhinterfaceinfo)
    for i in interfaceobjects:
            phy_cef_collection(i,step)
            #print (pformat(vars(i), indent=4, width =1, sort_dicts=False))
            mtus.append(i.mtu)
            #print ("\n")
    
    #Minimum MTU calculation
    subprocess = "[MTU]"
    step = step + 1
    mtus.sort()
    minimum = mtus[0]
    logging_info(step,process,subprocess,srcxtr.hostname,"The lowest MTU between underlay interfaces for device: {} is {}".format(srcxtr.hostname, minimum))
    #print ("The lowest MTU between underlay interfaces for device: {} is {}".format(srcxtr.hostname, minimum))

    #RLOC to RLOC Ping Validation
    #1) Without MTU
    #print ("RLOC to RLOC results with low MTU")
    normal_ping = Ping(rloccef.ip, srcxtr.hostname)
    normal_ping.ping_with_source(None,"Lo0",None,False,service)
    logging_info(step,process,subprocess,srcxtr.hostname,"RLOC to RLOC results with low MTU: {} % Success".format(normal_ping.result))
    #print (pformat(vars(normal_ping), indent=4, width =1, sort_dicts=False))
    #2) With MTU
    #print ("RLOC to RLOC results with {} MTU".format(minimum))
    mtu_ping = Ping(rloccef.ip, srcxtr.hostname)
    mtu_ping.ping_with_source(None,"Lo0",minimum,True,service)
    #print (pformat(vars(mtu_ping), indent=4, width =1, sort_dicts=False))
    logging_info(step,process,subprocess,srcxtr.hostname,"RLOC to RLOC results with {} MTU: {} % Success".format(minimum,normal_ping.result))


    if int(normal_ping.result) <= 70:
        logging_warning(step,process,subprocess,srcxtr.hostname,"WARNING! : Packet Loss from {} to {} is below threshold of 70%, current value is {} % with low MTU".format(srcxtr.hostname, rloccef.ip, normal_ping.result))
        #print ("WARNING! : Packet Loss from {} to {} is below threshold of 70%, current value is {} % with low MTU \n".format(srcxtr.hostname, rloccef.ip, normal_ping.result))
    else:
        logging_info(step,process,subprocess,srcxtr.hostname,"ICMP Connectivity from {} to {} is good at {} % success rate with low MTU".format(srcxtr.hostname, rloccef.ip, normal_ping.result))
        #print ("ICMP Connectivity from {} to {} is good at {} % success rate with low MTU \n".format(srcxtr.hostname, rloccef.ip, normal_ping.result))
    
    if int(mtu_ping.result) <= 70:
        logging_warning(step,process,subprocess,srcxtr.hostname,"WARNING! : Packet Loss from {} to {} is below threshold of 70%, current value is {} % with {} MTU".format(srcxtr.hostname, rloccef.ip, normal_ping.result, minimum))
        #print ("WARNING! : Packet Loss from {} to {} is below threshold of 70%, current value is {} % with {} MTU \n".format(srcxtr.hostname, rloccef.ip, normal_ping.result, minimum))
    else:
        logging_info(step,process,subprocess,srcxtr.hostname,"ICMP Connectivity from {} to {} is good at {} % success rate with {} MTU".format(srcxtr.hostname, rloccef.ip, normal_ping.result, minimum))
        #print ("ICMP Connectivity from {} to {} is good at {} % success rate with {} MTU \n".format(srcxtr.hostname, rloccef.ip, normal_ping.result, minimum))

    #Profiling Endpoint in Remote XTR
    process ="Host-Onboarding"
    subprocess = None,
    step = step+1
    logging_info(step, process, subprocess,dstxtr.hostname, "Gathering information about the destination endpoint")
    #print ("Gathering information about the source endpoint...\n")
    dstep = endpoint_info(dstip)
    dstep.host_onboarding_validation(dstxtr,service,step)
    host_onboarding_success(dstep,dstxtr.hostname)
    #print (pformat(vars(dstep), indent=4, width =1, sort_dicts=False))

    #Performing CTS evaluations for the Source
    step = step+1
    subprocess = "[CTS]"
    logging_info(step, process, subprocess,srcxtr.hostname, "Gathering CTS information between SGTs")
    #print ("Gathering CTS information between SGTs...\n")
    srcctsinfo = cts_endpoint_info(srcep.sourceip,srcep.sourcevrf, srcxtr.hostname)
    srcctsinfo.cts_sgt_mapping(service)
    ctsbinding = {'ip':srcctsinfo.endpoint_ip, 'sgt': srcctsinfo.sgt, 'source': srcctsinfo.source}
    srcctsinfo.cts_class_method(srcep.sourceport, ctsbinding, service)
    srcctsinfo.cts_enforcement(srcep.sourcevlan, srcep.sourceport,service)
    cts_ep_collection(srcctsinfo,step)
    #print (pformat(vars(srcctsinfo), indent=4, width =1, sort_dicts=False))
    #Performing CTS evaluations for the Destination
    dstctsinfo = cts_endpoint_info(dstep.sourceip,dstep.sourcevrf, dstxtr.hostname)
    dstctsinfo.cts_sgt_mapping(service)
    ctsbinding = {'ip':dstctsinfo.endpoint_ip, 'sgt': dstctsinfo.sgt, 'source': dstctsinfo.source}
    dstctsinfo.cts_class_method(dstep.sourceport, ctsbinding, service)
    dstctsinfo.cts_enforcement(dstep.sourcevlan, dstep.sourceport,service)
    cts_ep_collection(dstctsinfo, step)
    #print (pformat(vars(dstctsinfo), indent=4, width =1, sort_dicts=False))

    sgt = srcctsinfo.cefsgt
    dgt = dstctsinfo.cefsgt

    #CTS Rules on Destination XTR
    step=step+1
    logging_info(step, process, subprocess,"Main", "Identifying CTS Rule used for traffic between {} and {}".format(srcep.sourceip, dstep.sourceip))
    #print ("Identifying CTS Rule used for traffic between {} and {}\n".format(srcep.sourceip, dstep.sourceip))
    logging_info(step, process, subprocess,"Main", "Source SGT is {} and Destination SGT is {}".format(sgt,dgt))
    #print ("Source SGT is {} and Destination SGT is {}\n".format(sgt,dgt))
    ctsrules = cts_rules(dstxtr.hostname)
    ctsrules.cts_rbac_permissions(sgt, dgt, service)
    rbacl = ctsrules.rbacl
    ctsrules.cts_rbac_rbacls(rbacl,service)
    ctsrules.cts_rbac_counters(sgt,dgt,service)
    cts_rule_collection(ctsrules,step)
    #print (pformat(vars(ctsrules), indent=4, width =1, sort_dicts=False))

    if ctsrules.isdefaultrule is True:
        logging_info(step, process, subprocess, dstxtr.hostname, "No specific rule found for SGT {} and Destination SGT {} on device {}, using default rule".format(sgt,dgt,dstxtr.hostname))
        logging_info(step, process, subprocess, dstxtr.hostname, "Default rule information is: {}".format(ctsrules.rbacl))
        logging_info(step, process, subprocess, dstxtr.hostname, "ACEs for the default rule: {}".format(ctsrules.aces))
        #print ("Default rule information is: {}\n".format(ctsrules.rbacl))
        #print ("ACEs for the default rule: {}\n".format(ctsrules.aces))
    else:
        logging_info(step, process, subprocess, dstxtr.hostname, "Specific rule found for SGT {} and Destination SGT {} on device {}, using RBACL:".format(sgt,dgt,dstxtr.hostname, ctsrules.rbacl))
        logging_info(step, process, subprocess, dstxtr.hostname, "ACEs for the specific rule: {}".format(ctsrules.aces))

        #print ("Specific rule found for SGT {} and Destination SGT {} on device {}, using RBACL: \n".format(sgt,dgt,dstxtr.hostname, ctsrules.rbacl))
        #print ("ACEs for the specific rule: {}\n".format(ctsrules.aces))
    if (ctsrules.hw_denied_count > 0) or (ctsrules.sw_denied_count > 0):
        logging_warning(step, process, subprocess, dstxtr.hostname,"WARNING! : CTS Counters found for rule from SGT {} to SGT {} on device: {}".format(sgt, dgt, dstxtr.hostname))
        #print ("WARNING! : CTS Counters found for rule from SGT {} to SGT {} on device: {}".format(sgt, dgt, dstxtr.hostname))
    else:
        logging_info(step, process, subprocess, dstxtr.hostname, "CTS Counters NOT dropping for rule from SGT {} to SGT {} on device: {}".format(sgt, dgt, dstxtr.hostname))
        #print ("CTS Counters NOT dropping for rule from SGT {} to SGT {} on device: {}".format(sgt, dgt, dstxtr.hostname))

    return None

def site_flow():
    return None

def transit_flow():
    return None

def inter_vrf():
    return None
