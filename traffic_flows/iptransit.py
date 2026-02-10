import sys
from pprint import pformat
from re import search, IGNORECASE, match
import re
from concurrent.futures import ThreadPoolExecutor
from functools import partial

from catalystcenterapi.catcapi import getFabricBorders, getL3Handoffs, getanycastgateway, getFabricCPs
from device_profiler import Device
from radkit_cli import logging_info, logging_warning, logging_error
from routingmodules.bgp import BGP, BGPNeighbor
from routingmodules.cef import VRF, IPCef, physical_recursion
from typing import Any, Optional, Tuple
import ipaddress
from routingmodules.iprouting import IPRoute
from routingmodules.lisp import LISPForwarding, LISPRemoteDefault, lisp_route_import, LISPLocalDB, LISPInstanceStatus, \
    LISPMapCache, LISPControlPlane, LISPSession
from securitymodules.accesslists import AccessList
from securitymodules.ciscotrustsec import cts_endpoint_info
from switchingmodules.interfaces import Interfaces
from traffic_flows.lispsessiontroubleshooting import singleETRProfiling
from traffic_flows.operational_tests import Ping

def exit_program(step, process, subprocess, hostname, error, message):
    logging_error(step, process, subprocess, hostname, error)
    logging_info(step, process, subprocess, hostname, message)
    sys.exit("Error: {} | {}".format(error, message))

def find_best_advertised_route(data: Any, target_ip: str) -> Tuple[Optional[str], Optional[dict]]:
    """
    Walks an arbitrarily-nested dict/list structure, finds any 'advertised' dicts,
    and returns the longest-prefix match for target_ip.

    Returns:
      (best_prefix, best_route_dict)
    If no match is found:
      (None, None)
    """
    try:
        ip_obj = ipaddress.ip_address((target_ip or "").strip())
    except ValueError:
        return None, None

    best_prefix = None
    best_route = None
    best_plen = -1

    stack = [data]
    while stack:
        node = stack.pop()

        if isinstance(node, dict):
            adv = node.get("advertised")
            if isinstance(adv, dict):
                for prefix, route in adv.items():
                    try:
                        net = ipaddress.ip_network(prefix, strict=False)
                    except ValueError:
                        continue
                    if ip_obj in net and net.prefixlen > best_plen:
                        best_plen = net.prefixlen
                        best_prefix = prefix
                        best_route = route

            stack.extend(node.values())

        elif isinstance(node, list):
            stack.extend(node)

    return best_prefix, best_route

class BorderDevice:
    def __init__(self, mgmtip):
        self.mgmtip = mgmtip

    def api_parameters(self, api_parameters):
        self.api_parameters = api_parameters

    def device_profiler(self, isdhcp, catc,service,step):
        devprof = Device(self.mgmtip,catc,step)
        devprof.profile_device(service)
        self.profiled_device = devprof
        self.isdhcp = isdhcp
        hostname = devprof.hostname
        self.hostname = hostname

    def append_cp_objects(self,controlplanes):
        self.control_planes = controlplanes

    def ip_transit_handoffs(self,service,step):
        fabric_id = self.profiled_device.fabric_id
        borderuuid = self.profiled_device.deviceuuid
        catc_name = self.profiled_device.dnac
        l3handoffinfo = l3_handoff_borders(step, fabric_id, catc_name,borderuuid, service)
        self.l3handoffinfo = l3handoffinfo

    def anycastgateways(self,vlan,service,step):
        fabric_id = self.profiled_device.fabric_id
        site_id = self.profiled_device.fabric_site_id
        catc_name = self.profiled_device.dnac
        self.anycastgwinfo = find_anycastgw(fabric_id,site_id,vlan,catc_name,service,step)

    def vrf_information(self,vrf, anycastgw, service,step):
        hostname = self.profiled_device.hostname
        self.vrf = vrf
        vrfdetail_info, anycastgw, anycastgwphy = vrf_configuration(step, vrf, hostname, anycastgw,service)
        li_interface = next((i for i in (vrfdetail_info.get("interfaces") or []) if str(i).startswith("LI")), None)
        m = search(r"LI\d+\.(\d+)", li_interface or "")
        lisp_instance_id = int(m.group(1)) if m else None
        self.lispiid = lisp_instance_id
        self.vrfdetail_info = vrfdetail_info
        self.anycastgw = anycastgw
        self.anycastgwphy = anycastgwphy

    def bgp_information(self, dstip, service):
        hostname = self.profiled_device.hostname
        vrf = self.vrf
        neighbors = self.l3handoffinfo
        bgpinfo , bgpneighborsinfo = bgp_parameters(vrf,neighbors,hostname,dstip,service)
        self.bgpinfo = bgpinfo
        self.bgpneighborsinfo = bgpneighborsinfo

    def bgp_local_route(self,prefix,service):
        hostname = self.profiled_device.hostname
        vrf = self.vrf
        self.local_route = bgp_local_route(vrf,hostname,prefix,service)

    def bgp_vpnv4(self,service):
        hostname = self.profiled_device.hostname
        bgpvpnv4info, bgpvpvn4neighbor = bgp_vpnv4_session(hostname,service)
        self.bgpvpnv4info = bgpvpnv4info
        self.bgpvpvn4neighbor = bgpvpvn4neighbor

    def defaultetrlocator(self,btype,service,step):
        hostname = getattr(self.profiled_device, "hostname", "Unknown")
        vrf = getattr(self, "vrf", None)
        iid = getattr(self, "lispiid", None)
        ispubsub = getattr(self.profiled_device, "ispubsub", False)
        extracted_data = petr_availability(hostname,vrf,iid,ispubsub,btype,service,step)
        self.defaultetrinfo = extracted_data

    def forwarding_to_destination(self,dstip,service,step):
        hostname = self.profiled_device.hostname
        vrf = self.vrf
        self.dstip = dstip
        iid  = self.lispiid
        cef_information, lispmapcache, lispfwding, outgoingports = forwarding_state(iid,dstip,hostname,vrf,service,step)
        self.destcefinformation = cef_information
        self.destoutgoingports = outgoingports
        self.destlispmapcache = lispmapcache
        self.destlispfwding = lispfwding

    def forwarding_to_source(self,sourceip,isdhcp,service,step):
        hostname = self.profiled_device.hostname
        vrf = None if isdhcp else self.vrf
        iid  = self.lispiid
        cef_information, lispmapcache, lispfwding, outgoingports = forwarding_state(iid,sourceip,hostname,vrf,service,step)
        self.sourcecefinformation = cef_information
        self.sourceoutgoingports = outgoingports
        self.sourcelispmapcache = lispmapcache
        self.sourcelispfwding = lispfwding

    def ping(self,service,step):
        hostname = self.profiled_device.hostname
        vrf = self.vrf
        dstip = self.dstip
        anycastgwphy = self.anycastgwphy
        self.ping_results = destinationreachability(hostname,vrf,dstip,anycastgwphy,service,step)

    def lisp_parameters(self,destroute,service,step):
        iid = self.lispiid
        hostname = self.profiled_device.hostname
        lispfwdinglocaleid, remote_iid_locators, destrouteimport, lispdbroute, lispstatus = lispforwarding(iid,destroute,hostname,service,step)
        self.lispfwdinglocaleid = lispfwdinglocaleid
        self.remote_iid_locators = remote_iid_locators
        self.destrouteimport = destrouteimport
        self.lispdbroute = lispdbroute
        self.lispstatus = lispstatus

    def interface_counters(self,service):
        hostname = self.profiled_device.hostname
        dstports = self.destoutgoingports
        srcports = self.sourceoutgoingports
        self.interfacestats = interfacecounters(srcports,dstports,hostname,service)

    def acl_information(self,service):
        hostname = self.profiled_device.hostname
        vrf = self.vrf
        l3handoffinfo = self.l3handoffinfo
        self.egress_acls = aclinformation(l3handoffinfo,vrf,hostname,service)

    def cts_information(self,service,step):
        hostname = self.profiled_device.hostname
        dstip = self.dstip
        vrf = self.vrf
        destcefinformation = self.destcefinformation
        egressintf = self.destoutgoingports
        self.ctsinfo = ctsinformation(dstip,vrf,hostname,destcefinformation, egressintf, service,step)

class ControlPlaneDevice:
    def __init__(self, mgmtip):
        self.mgmtip = mgmtip

    def device_profiler(self, catc,service,step):
        devprof = Device(self.mgmtip,catc,step)
        devprof.profile_device(service)
        self.profiled_device = devprof
        hostname = devprof.hostname
        self.hostname = hostname
        self.ispubsub = devprof.ispubsub

    def cp_configuration(self,service):
        hostname = self.hostname
        lispcp_configuration = LISPControlPlane(hostname)
        lispcp_configuration.lisp_service_ipv4(service)
        lispcp_configuration.site_uci(service)
        lispcp_configuration.domains(service)
        lispcp_configuration.rloc_members(service)
        self.lispcpconfig = lispcp_configuration

    def lisp_operations(self,iid,service):
        hostname = self.hostname
        ispubsub = self.ispubsub
        lispsession = LISPSession(hostname)
        # Get VPNv4 Sessions if exist
        # Get LISP Sessions
        lispsession.globallispsession(service)
        if ispubsub is True:
            # Get IID Prefix List (PubSub)
            lispsession.lisp_prefix_list(service)
            # Get Subscriber State
            lispsession.lisp_subscribers(iid,service)
        self.lispsession = lispsession

#Collection Functions
def get_obj_data(obj):
    if hasattr(obj, 'to_dict'): # Common in Cisco/Genie objects
        return obj.to_dict()
    if hasattr(obj, '__dict__'):
        return vars(obj)
    if hasattr(obj, '__slots__'):
        return {s: getattr(obj, s) for s in obj.__slots__ if hasattr(obj, s)}
    return str(obj)

def in_site_fabric_borders(step,fabric_id, catc_name, service):
    l3_borders = getFabricBorders(fabric_id,catc_name,service,step)
    return l3_borders

def in_site_control_Planes(fabric_id,iid, catc,service,step):
    #Identify Fabric ControlPlanes
    cps = getFabricCPs(fabric_id,catc,service,step)
    subprocess = ['controlPlaneProfiling']
    #For each Reachable fabric CP, profile it.
    control_plane_objects = []
    for cp in cps:
        mgmt_ip = cp.get('mgmtip', 'Unknown')
        if cp.get('status', '').lower() != 'reachable':
            logging_warning(step, PROCESS, subprocess, catc, f"Skipping CP {mgmt_ip} - Status is Unreachable")
            continue
        else:
            control_plane = ControlPlaneDevice(mgmt_ip)
            control_plane.device_profiler(catc,service,step)
            #Get Control Plane Configuration (Site_UCI)
            control_plane.cp_configuration(service)
            control_plane.lisp_operations(iid,service)
            control_plane_objects.append(control_plane)

    return control_plane_objects

def l3_handoff_borders(step, fabric_id, catc_name, borderuuid,service):
    l3handoffinfo = getL3Handoffs(fabric_id,borderuuid,catc_name,service,step)
    return l3handoffinfo

def vrf_configuration(step, vrf, borderhostname, anycastgw, service):
    vrfdetail = VRF(borderhostname,vrf)
    vrfdetail.vrfdetail(service)
    vrfdetail_info = vrfdetail.vrfdetailed

    anycastgw = IPCef(anycastgw,vrf,borderhostname)
    anycastgw.get_cef_internal(service)

    anycastgwphy = physical_recursion(anycastgw,borderhostname)
    anycastgwphy.get_physical_interfaces(service,step)

    return vrfdetail_info, anycastgwphy, anycastgwphy

def bgp_parameters(vrf, l3handoffneighbors, hostname, dstip, service):
    target_vn = (vrf or "").strip().lower()  # e.g. "campus"

    vn_entries = [
        e for e in (l3handoffneighbors or [])
        if (e.get("virtualNetworkName") or "").strip().lower() == target_vn
    ]

    remote_ips = [
        e["remoteIpAddress"].split("/", 1)[0]
        for e in vn_entries
        if e.get("remoteIpAddress")
    ]

    bgpinfo = BGP(hostname, vrf)
    bgpinfo.bgp_sum_vrf(service)
    bgpinfo.bgp_ipprotocols(service)
    bgpinfo.bgp_defaultroute_vrf(service)
    bgpinfo.bgp_rib_vrf(dstip, service)
    bgpinfo.bgp_updategroups_vrf(service)

    #Get multiple neighbors from bgpsummary:
    bgsum_dict = getattr(bgpinfo, "bgsum", {}) or {}
    vrf_name = getattr(bgpinfo, "vrf", "default")

    # Navigate the dictionary structure to find the neighbors
    neighbors_dict = (
        bgsum_dict.get("vrf", {})
        .get(vrf_name, {})
        .get("neighbor", {})
    )

    # Extract keys (neighbor IPs) as a list
    neighbor_list = list(neighbors_dict.keys())

    # Merge with remote_ips and remove duplicates while preserving order
    remote_ips = list(dict.fromkeys(remote_ips + neighbor_list))
    bgpneighborsinfo = []
    for neighbor_ip in remote_ips:
        bgpneighbor = BGPNeighbor(hostname,neighbor_ip,vrf)
        bgpneighbor.bgp_neighbor_vrf(service)
        bgpneighbor.bgp_advroutes_vrf(service)
        advertisedroutes = bgpneighbor.advertisdedroutes
        best_prefix, best_route = find_best_advertised_route(advertisedroutes,dstip)
        bgpneighbor.advprefix = best_prefix
        bgpneighbor.advroute = best_route
        bgpneighborsinfo.append(bgpneighbor)
    return bgpinfo, bgpneighborsinfo

def bgp_vpnv4_session(hostname,service):
    #See if there are one or more BGP sessions the global routing table like:
    bgpsumobject = BGP(hostname,None)
    bgpsumobject.bgp_sum(service)

    #Extract the iBGP neighbors from the bgpsumobject:
    bgsum_data = getattr(bgpsumobject, "bgsum", {}) or {}

    # 2. Identify the Local AS (bgp_id)
    local_as = bgsum_data.get("bgp_id")

    # 3. Access the neighbors dictionary
    # Note: Genie usually puts 'show ip bgp summary' data under the 'default' vrf key
    neighbors_dict = bgsum_data.get("vrf", {}).get("default", {}).get("neighbor", {})

    internal_neighbors = []

    # 4. Iterate through the neighbors to find iBGP peers
    for nbr_ip, nbr_data in neighbors_dict.items():
        # Dig into address_family to find the remote AS
        # In your output, the address family key is an empty string ''
        address_families = nbr_data.get("address_family", {})

        for af_name, af_data in address_families.items():
            remote_as = af_data.get("as")

            # If Remote AS matches Local AS, it is an internal neighbor (iBGP)
            if remote_as == local_as and local_as is not None:
                internal_neighbors.append(nbr_ip)
                # Break the inner loop to avoid adding the same neighbor twice
                # if multiple address families exist
                break
    bgpneighborsinfo = []
    for neighbor_ip in internal_neighbors:
        bgpneighbor = BGPNeighbor(hostname, neighbor_ip, None)
        bgpneighbor.bgp_neighbor(service)
        bgpneighborsinfo.append(bgpneighbor)
    return bgpsumobject, bgpneighborsinfo

def find_anycastgw(fabricid,siteid,vlan,catc,service,step):
    anycastgw = getanycastgateway(fabricid,siteid,vlan,catc,service,step)
    return anycastgw

def bgp_local_route(vrf, hostname, prefix, service):
    bgplocalroute = BGP(hostname,vrf)
    bgplocalroute.bgp_rib_vrf(prefix,service)
    local_route = bgplocalroute.route
    return local_route

def petr_availability(hostname, vrf, iid, ispubsub, border_type, service, step):
    """
    Extracts default route information from the RIB and LISP Database.
    Returns a dictionary with the extracted values.
    """
    # Initialize the data structure with None values
    extracted_data = {
        "rib_default": {
            "prefix": None,
            "mask": None,
            "nexthop": None
        },
        "lisp_db_default": {
            "eid": None,
            "iid": None,
            "locators": None
        }
    }

    # Only attempt extraction if Pub/Sub is enabled and border is an exit point
    if ispubsub and border_type in ["isexternal", "isanywhere"]:
        # 1) Extract IP Route info for 0.0.0.0
        # Assuming the IPRoute class/method exists as per previous context
        route_query = IPRoute("0.0.0.0", vrf, hostname)
        route_query.iproute_prefix_soft(service,step)

        extracted_data["rib_default"]["prefix"] = getattr(route_query, "prefix", None)
        extracted_data["rib_default"]["mask"] = getattr(route_query, "mask", None)
        extracted_data["rib_default"]["nexthop"] = getattr(route_query, "nexthop", None)

        # 2) Extract LISP Database info for 0.0.0.0/0
        # Assuming the LISPDatabase class/method exists as per previous context
        lisp_db_query = LISPLocalDB("0.0.0.0/0", iid, hostname)
        lisp_db_query.LISPDBEntry("ipv4",service)

        extracted_data["lisp_db_default"]["eid"] = getattr(lisp_db_query, "eid", None)
        extracted_data["lisp_db_default"]["iid"] = getattr(lisp_db_query, "iid", None)
        extracted_data["lisp_db_default"]["locators"] = getattr(lisp_db_query, "locators", None)

    return extracted_data

def forwarding_state(iid, dstip, hostname, vrf, service, step):
    forwarding_state = IPCef(dstip, vrf, hostname)
    forwarding_state.get_cef_internal(service)

    process = "externalConnectivity"
    subprocess = "[forwardingValidation]"

    lispmapcache = None
    lispforwarding = None
    rlocs = []
    total_phys = []
    map_cache_triggered = False

    # --- 1. Check for Unusable MPLS/VPNv4 Path at the Object Level ---
    # We check the 'ismpls' attribute directly from the forwarding_state object
    if getattr(forwarding_state, "ismpls", False):
        msg1 = "Fabric Edge - Unusable MPLS Path"
        message = (
            f"Finding: The CEF entry for {dstip} is identified as an unusable MPLS/VPNv4 path. "
            f"Reason: In SD-Access, a BGP VPNv4 route is a last-resort path that should not be used "
            f"for data plane forwarding. This occurs when the expected LISP or iBGP VRF route is missing. "
            f"Action: Treating this path as 'drop' to prevent suboptimal or broken routing."
        )
        logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1
        total_phys.append("drop")
        # Since the path is unusable, we return early with the 'drop' status
        return forwarding_state, lispmapcache, lispforwarding, total_phys

    # --- 2. Process Nexthops (Only if not MPLS) ---
    for nh in (getattr(forwarding_state, "nexthops", None) or []):
        nexthop = (nh.get("nexthop") or "").strip()
        oif_val = nh.get("oif")

        # Normalize OIF to a list of strings
        if isinstance(oif_val, dict):
            oifs = list(oif_val.keys())
        elif isinstance(oif_val, str):
            oifs = [oif_val]
        else:
            oifs = []

        for oif in oifs:
            oif_str = str(oif)

            # OIF is LISP
            if oif_str.startswith("LISP"):
                if not map_cache_triggered:
                    map_cache = LISPMapCache(iid, hostname)
                    map_cache.mapcache("ipv4", dstip, service)
                    lispmapcache = map_cache

                    lispfwd = LISPForwarding(hostname, iid)
                    lispfwd.fwdingeidremote(dstip, service)
                    lispforwarding = lispfwd

                    fwdeidremote = getattr(lispfwd, "fwdeidremote", None) or {}
                    ifnums = fwdeidremote.get("ifnums", []) or []
                    rlocs = [x.get("rloc") for x in ifnums if isinstance(x, dict) and x.get("rloc")]
                    map_cache_triggered = True

                if nexthop.lower() == "attached":
                    continue

                for rloc in rlocs:
                    underlaycef = IPCef(rloc, None, hostname)
                    underlaycef.get_cef_internal(service)
                    phys_list_obj = physical_recursion(underlaycef, hostname)
                    phys_list_obj.get_physical_interfaces(service, step)
                    phys_list = phys_list_obj.total_phys
                    normalized = [item for sublist in phys_list for item in sublist]
                    total_phys.extend(normalized)
                continue

            # OIF is Null/Drop/Tunnel
            if oif_str.lower() in {"null0", "drop"} or oif_str.startswith("Tunnel"):
                total_phys.append(oif_str)
                continue

            # OIF is VLAN
            if oif_str.startswith("Vlan"):
                ipcefvlan = IPCef(dstip, vrf, hostname)
                ipcefvlan.get_cef_internal(service)
                phys_list_obj = physical_recursion(ipcefvlan, hostname)
                phys_list_obj.get_physical_interfaces(service, step)
                phys = phys_list_obj.total_phys
                if any(isinstance(i, list) for i in phys):
                    phys = [item for sublist in phys for item in sublist]
                total_phys.extend(phys)

            # Otherwise treat as physical
            else:
                total_phys.append(oif_str)

    # De-duplicate and preserve order
    seen = set()
    total_phys = [i for i in total_phys if not (i in seen or seen.add(i))]
    return forwarding_state, lispmapcache, lispforwarding, total_phys

def destinationreachability(hostname, vrf,dstip, sourceintf, service, step):
    subprocess = "[borderReachability]"
    process = "externalConnectivity"
    # Underlay Interface Parsing
    # [Object: Interface Information and Counters - interfaceobjects]
    phys_interfaces = []
    for group in (getattr(sourceintf, "total_phys", None) or []):
        for item in (group or []):
            if isinstance(item, dict):
                phys_interfaces.extend(item.keys())
    phys_interfaces = sorted(set(phys_interfaces))[0]

    normal_ping = Ping(dstip, hostname)
    normal_ping.ping_with_source(vrf, phys_interfaces, None, False, service)
    logging_info(step, process, subprocess, hostname,
                     "Ping from {} to {} with source interface {} : {} % Success".format(hostname,dstip, phys_interfaces, normal_ping.result))
    # print (pformat(vars(normal_ping), indent=4, width =1, sort_dicts=False))
    if int(normal_ping.result) <= 70:
        logging_warning(step, process, subprocess, hostname,
                            "WARNING! : Packet Loss from {} to {} is below threshold of 70%, current value is {} % , it is normal for all Borders except one to fail due to anycast gateway".format(
                                 hostname, dstip, normal_ping.result))
            # print ("WARNING! : Packet Loss from {} to {} is below threshold of 70%, current value is {} % with low MTU \n".format(srcxtr.hostname, rloccef.ip, normal_ping.result))
    else:
        logging_info(step, process, subprocess, hostname,
                     "ICMP Connectivity from {} to {} is good at {} % success rate, it is normal for all Borders except one to fail due to anycast gateway".format(hostname,
                                                                                                        dstip,
                                                                                                        normal_ping.result))
    return normal_ping

def lispforwarding(iid, destroute, hostname, service, step):
    #Get LISP Forwarding for Local EID:
    lispfwding = LISPForwarding(hostname,iid)
    lispfwding.fwdingeidlocal(service)
    lispfwdinglocaleid = lispfwding.fwdeidlocal

    #Search RIB default route
    ribroute = IPRoute("0.0.0.0 0.0.0.0",None,hostname)
    ribroute.iproute_prefix_soft(service,step)

    #Get LISP Remote Default Information (if any)
    lispremotedefaultetr = LISPRemoteDefault(hostname)
    lispremotedefaultetr.lispremotedefault(service)
    remotedefaultlocator = lispremotedefaultetr.remotelocatoripv4

    iid_key = str(iid)
    results = []
    for rloc_ip, rloc_data in (remotedefaultlocator.get("rloc", {}) or {}).items():
        inst = (rloc_data.get("instance_id", {}) or {}).get(iid_key, {})
        if not inst:
            continue
        results.append(
            {
                "rloc_ip": rloc_ip,
                "instance_id": iid,
                "priority": inst.get("priority"),
                "weight": (inst.get("weight") or "").strip() or inst.get("weight"),
                "metric": inst.get("metric"),
                "domainid": inst.get("domain_id"),
                "mhid": inst.get("multihome_id"),
            }
        )
    remote_iid_locators = results

    #Get Route_Import and Local DB parameters for Imported Routes:
    route_import = lisp_route_import(iid,hostname)
    route_import.route_import_database_specific(destroute,service)
    destrouteimport = route_import.routeimportprefix

    #Get LISP DB details for routed import:
    lispdbstatus = LISPLocalDB(destroute,iid,hostname)
    lispdbstatus.LISPDBEntry("ipv4",service)
    lispdbroute = lispdbstatus

    #Get PETRs if configured:
    lispstatus = LISPInstanceStatus(hostname,iid)
    lispstatus.eidstatus("ipv4",service)
    lispstatus = lispstatus

    return lispfwdinglocaleid,remote_iid_locators,destrouteimport,lispdbroute,lispstatus

def interfacecounters(sourceports, dstports, hostname, service):
    interface_objects = []
    total_interfaces = list(dict.fromkeys(sourceports + dstports))
    for interface in total_interfaces:
        interfaceobject  = Interfaces(interface,hostname)
        interfaceobject.show_interface(service)
        interface_objects.append(interfaceobject)
    return interface_objects

def ctsinformation(dstip, vrf, hostname, destcefinformation, egressintf, service, step):
    process = "externalConnectivity"
    subprocess = "ctsEnforcement"
    ctsenforcementinfo = []

    # 1. Safely retrieve nexthops to prevent 'NoneType' iteration error
    l3interfaces = getattr(destcefinformation, "nexthops", []) or []

    if not l3interfaces:
        msg1 = "CTS Enforcement - No Path Found"
        message = f"Finding: No L3 nexthops found in CEF for destination {dstip}. Action: Skipping CTS validation."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        return ctsenforcementinfo, step + 1

    # 2. Extract unique Outgoing Interfaces (OIFs)
    oifs = []
    for item in l3interfaces:
        oif = item.get("oif")
        if isinstance(oif, dict):
            # Extract the first key if it's a dictionary
            oifs.append(next(iter(oif.keys()), None))
        else:
            oifs.append(oif)

    # Remove duplicates while preserving order
    oifs_unique = [x for x in dict.fromkeys(oifs) if x]

    # 3. Evaluate each unique interface
    for oif in oifs_unique:
        oif_str = str(oif)

        if "LISP" in oif_str.upper():
            msg1 = "CTS Enforcement - LISP Interface"
            message = (
                f"Finding: Path uses LISP interface {oif_str}. "
                f"Action: CTS enforcement is not evaluated on LISP interfaces; skipping validation for this hop."
            )
            logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
            step += 1
            continue

        elif oif_str.startswith("Vlan"):
            msg1 = "CTS Enforcement - VLAN Interface"
            message = (
                f"Finding: Path uses {oif_str}. "
                f"Action: CTS will be evaluated at the VLAN and downstream port level."
            )
            logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
            step += 1

            # Initialize CTS info object
            ctsinfo = cts_endpoint_info(dstip, vrf, hostname)
            ctsinfo.cts_sgt_mapping(service)

            # Extract VLAN ID from string (e.g., 'Vlan3002' -> 3002)
            vlan_match = re.search(r"vlan\s*(\d+)", oif_str, re.IGNORECASE)
            vlan_id = int(vlan_match.group(1)) if vlan_match else None

            interface = egressintf[0]
            ctsinfo.cts_enforcement(vlan_id, interface, service)
            ctsenforcementinfo.append(ctsinfo)

    return ctsenforcementinfo, step

def aclinformation(handoff_list, target_vrf, hostname,service):
    """
    Filters handoff info by VRF and returns a list of interface strings
    in three formats: vlan<id>, shortened physical, and physical.vlan.
    """
    interface_list = []

    # Mapping for shortening common Cisco interface names
    short_names = {
        "TwentyFiveGigE": "twe",
        "TenGigabitEthernet": "te",
        "GigabitEthernet": "gi",
        "FastEthernet": "fa",
        "Ethernet": "et"
    }

    for entry in handoff_list:
        # Check if the entry belongs to the target VRF
        if entry.get("virtualNetworkName") == target_vrf:
            vlan_id = entry.get("vlanId")
            full_name = entry.get("interfaceName", "")

            # Create the shortened name (e.g., TwentyFiveGigE1/0/3 -> twe1/0/3)
            short_name = full_name
            for long, short in short_names.items():
                if full_name.startswith(long):
                    short_name = full_name.replace(long, short)
                    break

            # 1. Format: vlan<id>
            interface_list.append(f"vlan{vlan_id}")

            # 2. Format: shortened physical (e.g., twe1/0/3)
            interface_list.append(short_name.lower())

            # 3. Format: physical + vlan id (e.g., twe1/0/3.3003)
            interface_list.append(f"{short_name.lower()}.{vlan_id}")

    all_acl_names = []
    for interface in interface_list:
        acl_obj = AccessList(hostname)
        acl_obj.aclbyinterface(interface, service)
        # Safely retrieve the list of ACL names from the object
        found_acls = getattr(acl_obj, "aclnames", []) or []
        # Add them to our master list
        all_acl_names.extend(found_acls)
    # Remove duplicates while preserving the order in which they were found
    final_acl_list = list(dict.fromkeys(all_acl_names))

    return final_acl_list

def border_print_attributes(border):
    print(pformat(vars(border), indent=4, width=1, sort_dicts=False))

    if getattr(border, "profiled_device", None) is not None:
        print(pformat(vars(border.profiled_device), indent=4, width=1, sort_dicts=False))

    if getattr(border, "anycastgw", None) is not None:
        print(pformat(vars(border.anycastgw), indent=4, width=1, sort_dicts=False))

    if getattr(border, "anycastgwphy", None) is not None:
        print(pformat(vars(border.anycastgwphy), indent=4, width=1, sort_dicts=False))

    if getattr(border, "bgpinfo", None) is not None:
        print(pformat(vars(border.bgpinfo), indent=4, width=1, sort_dicts=False))

    # bgpneighborsinfo is a list of objects
    for nbr in (getattr(border, "bgpneighborsinfo", None) or []):
        if nbr is not None:
            print(pformat(vars(nbr), indent=4, width=1, sort_dicts=False))

    if getattr(border, "destcefinformation", None) is not None:
        print(pformat(vars(border.destcefinformation), indent=4, width=1, sort_dicts=False))

    if getattr(border, "destlispmapcache", None) is not None:
        print(pformat(vars(border.destlispmapcache), indent=4, width=1, sort_dicts=False))

    if getattr(border, "destlispfwding", None) is not None:
        print(pformat(vars(border.destlispfwding), indent=4, width=1, sort_dicts=False))

    if getattr(border, "sourcecefinformation", None) is not None:
        print(pformat(vars(border.sourcecefinformation), indent=4, width=1, sort_dicts=False))

    if getattr(border, "lispdbroute", None) is not None:
        print(pformat(vars(border.lispdbroute), indent=4, width=1, sort_dicts=False))

    if getattr(border, "lispstatus", None) is not None:
        print(pformat(vars(border.lispstatus), indent=4, width=1, sort_dicts=False))

    # interfacestats is a list of objects
    for intf in (getattr(border, "interfacestats", None) or []):
        if intf is not None:
            print(pformat(vars(intf), indent=4, width=1, sort_dicts=False))

#Validation Functions

PROCESS = "externalConnectivity"

def route_recursion_function(rloc_ips, step, hostname,service):
    """
    For each rloc_ip:
      - triggers route lookup (placeholder)
      - validates mask is not 0
      - validates nexthop is not Null0/Drop/LISP*

    Returns step.
    """
    process = "externalConnectivity"
    subprocess = "rlocRecursion"

    for rloc_ip in (rloc_ips or []):
        # Placeholder: replace with your real route collector (returns an object or dict)
        # route_obj = get_route_object(hostname, rloc_ip)
        route_obj = IPRoute(rloc_ip,None,hostname)
        route_obj.iproute_prefix_soft(service,step)

        if not route_obj:
            error = "RLOC Recursion - Route Not Found"
            message = (
                f"No route information was found for RLOC {rloc_ip} on {hostname}. "
                f"Remediation: verify underlay routing reachability to the RLOC."
            )
            exit_program(step, process, subprocess, hostname, error, message)

        # support dict or object
        mask = (route_obj.get("mask") if isinstance(route_obj, dict) else getattr(route_obj, "mask", None))
        nexthop = (route_obj.get("nexthop") if isinstance(route_obj, dict) else getattr(route_obj, "nexthop", None))

        # mask must not be 0
        try:
            mask_int = int(str(mask).strip())
        except Exception:
            mask_int = None

        if mask_int == 0:
            error = "RLOC Recursion - Invalid Mask"
            message = (
                f"Route recursion for RLOC {rloc_ip} on {hostname} returned mask 0, which is invalid for reachability. "
                f"Remediation: verify routing table and underlay reachability."
            )
            exit_program(step, process, subprocess, hostname, error, message)

        # normalize nexthops into a list of strings
        if isinstance(nexthop, list):
            nh_list = [str(x).strip() for x in nexthop if str(x).strip()]
        elif isinstance(nexthop, str):
            nh_list = [nexthop.strip()] if nexthop.strip() else []
        else:
            nh_list = []

        bad = [nh for nh in nh_list if nh in {"Null0", "Drop"} or nh.startswith("LISP")]

        if bad:
            error = "RLOC Recursion - Invalid Next-Hop"
            message = (
                f"Route recursion for RLOC {rloc_ip} on {hostname} returned an invalid next-hop {bad}. "
                f"Remediation: verify underlay routing so the RLOC resolves via physical next-hops."
            )
            exit_program(step, process, subprocess, hostname, error, message)

        msg1 = "RLOC Recursion - Valid"
        message = f"Underlay recursion to RLOC {rloc_ip} on {hostname} resolves via next-hop(s) {nh_list}."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

    return step

def rloc_state_validation(map_cache,service,step):
    """
    Returns True if at least one RLOC is in 'up' state.
    Returns False if no RLOCs exist or if all RLOCs are down.

    If RLOCs exist and all are down, collects the RLOC IPs and triggers
    the route_recursion_function placeholder.
    """
    rlocs = (getattr(map_cache, "rlocs", None) or (map_cache.get("rlocs") if isinstance(map_cache, dict) else []) or [])

    if not rlocs:
        return False

    rloc_ips = []
    any_up = False

    for entry in rlocs:
        if not isinstance(entry, dict):
            continue
        rloc_ip = entry.get("rloc")
        state = (entry.get("state") or "").strip().lower()

        if rloc_ip:
            rloc_ips.append(rloc_ip)

        if state == "up":
            any_up = True

    if any_up:
        return True

    # All RLOCs are present but none are up
    rloc_ips = sorted(set(rloc_ips))
    if rloc_ips:
        route_recursion_function(rloc_ips,step,map_cache.device,service)  # placeholder trigger
    return False

def validate_source_recursion(border, step, hostname,service):
    process = "externalConnectivity"
    subprocess = "sourceRecursionValidation"

    dhcpflag = bool(getattr(border, "isdhcp", False))

    # Determine if this border has any Established external BGP neighbor
    has_established_external_bgp = False
    for n in (getattr(border, "bgpneighborsinfo", None) or []):
        nbr_ip = getattr(n, "neighborip", None)
        vrf = getattr(n, "vrf", None)

        bgpneighbor = getattr(n, "bgpneighbor", None) or {}
        nbr_data = (
            ((((bgpneighbor.get("vrf", {}) or {}).get(vrf, {}) or {}).get("neighbor", {}) or {}).get(nbr_ip, {}) or {})
        )
        if (nbr_data.get("link") or "").strip().lower() == "external" and (nbr_data.get("session_state") or "").strip().lower() == "established":
            has_established_external_bgp = True
            break

    if dhcpflag:
        ports = getattr(border, "sourceoutgoingports", None) or []

        def _is_bad_port(p: str) -> bool:
            s = (p or "").strip()
            if not s:
                return False
            return (
                s.startswith("LISP")
                or s.startswith("Tunnel")
                or s in {"Null0", "Drop"}
                or s.startswith("Vlan")
                or s.startswith("Port-channel")
            )

        bad_ports = [p for p in ports if _is_bad_port(p)]

        if bad_ports:
            error = "External Connectivity - Invalid RLOC Next-Hop"
            message = (
                f"Fabric RLOC recursion on {hostname} includes unsupported next-hop interfaces {bad_ports}. "
                f"Remediation: the next-hop for the fabric RLOC must resolve only through physical interfaces "
                f"(excluding VLAN and Port-Channel)."
            )
            exit_program(step, process, subprocess, hostname, error, message)

        if not ports and has_established_external_bgp:
            error = "External Connectivity - RLOC Recursion Missing"
            message = (
                f"No physical outgoing ports were identified for fabric RLOC recursion on {hostname}. "
                f"An Established external BGP neighbor is present, so this condition can blackhole traffic. "
                f"Remediation: verify underlay reachability and recursion for the fabric RLOC toward the external domain."
            )
            exit_program(step, process, subprocess, hostname, error, message)

        msg1 = "External Connectivity - Fabric RLOC Recursion"
        message = (
            f"Fabric RLOC recursion on {hostname} resolves through the following physical interfaces: {ports}."
            if ports else
            f"No physical outgoing ports were identified for fabric RLOC recursion on {hostname}; no Established external BGP neighbor was detected."
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1
        return step

    # Non-DHCP case: evaluate source CEF (must be LISP-only)
    src_cef = getattr(border, "sourcecefinformation", None) or {}
    vrf = src_cef.get("vrf")
    nexthops = src_cef.get("nexthops") or []

    oifs = []
    nh_ips = []

    for nh in nexthops:
        oif = nh.get("oif")
        if oif:
            oifs.append(str(oif))
        nh_ip = (nh.get("nexthop") or "").strip()
        if nh_ip:
            nh_ips.append(nh_ip)

    non_lisp_oifs = [o for o in oifs if not str(o).startswith("LISP")]

    if non_lisp_oifs:
        error = "External Connectivity - Invalid Source Recursion"
        message = (
            f"Source recursion on {hostname} for VRF {vrf} includes non-LISP interfaces {non_lisp_oifs}. "
            f"Remediation: fabric sources (APs/extended nodes/internal endpoints) must be learned via LISP. "
            f"Non-LISP recursion may indicate an unexpected route advertisement."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    # If OIFs are LISP but there is no IP in nexthop, consult sourcelispmapcache
    if oifs and not nh_ips:
        mc = getattr(border, "sourcelispmapcache", None) or {}
        mc_source = (mc.get("sources") or "").strip().lower()

        if mc_source == "static-send-map-request":
            msg1 = "External Connectivity - LISP Map-Cache Pending"
            message = (
                f"LISP recursion on {hostname} is via LISP but no RLOC was resolved yet (map-cache source is static-send-map-request). "
                f"If this is LISP/BGP, traffic to the destination may not be hitting this border. "
                f"If this is LISP pub-sub, verify the endpoint is registered in the control plane."
            )
            logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)
            step += 1
            return step

        if mc_source in {"pub-sub", "map-reply"}:
            # placeholders expected to exist in caller scope
            rloc_state_ok = rloc_state_validation(mc, service,step)  # placeholder variable/return

            if rloc_state_ok:
                msg1 = "External Connectivity - LISP Resolution Valid"
                message = (
                    f"LISP resolution on {hostname} indicates the internal endpoint is reachable; LISP next-hops are valid."
                )
                logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
                step += 1
                return step

            msg1 = "External Connectivity - RLOC Not Reachable"
            message = (
                f"LISP map-cache on {hostname} has a resolved source ({mc_source}), but the RLOC reachability is not up. "
                f"Remediation: validate RLOC state and run route recursion to identify underlay forwarding issues."
            )
            rloc_state_ok = rloc_state_validation(mc, service,step)  # placeholder
            logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)

        msg1 = "External Connectivity - LISP Map-Cache Unknown Source"
        message = (
            f"LISP recursion on {hostname} is via LISP but map-cache source '{mc.get('sources')}' is not recognized; "
            f"review LISP map-cache details and control-plane state."
        )
        logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1
        return step

    msg1 = "External Connectivity - Source Recursion via LISP"
    message = f"Source recursion on {hostname} for VRF {vrf} is exclusively via LISP interfaces ({oifs})."
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    step += 1
    return step

def validate_anycast_gateway_recursion(border, step):
    subprocess = "[anycastGateway]"
    hostname = border.profiled_device.hostname

    gw_fwd = getattr(border, "anycastgw", None)
    vrf = (getattr(gw_fwd, "vrf", None) or (gw_fwd.get("vrf") if isinstance(gw_fwd, dict) else None))
    nexthops = (
        getattr(gw_fwd, "nexthops", None)
        or (gw_fwd.get("nexthops") if isinstance(gw_fwd, dict) else [])
        or []
    )

    valid = False
    matched_oif = None

    for nh in nexthops:
        nh_val = (nh.get("nexthop") or "").strip().lower() if isinstance(nh, dict) else (
            getattr(nh, "nexthop", "") or ""
        ).strip().lower()

        oif_val = nh.get("oif") if isinstance(nh, dict) else getattr(nh, "oif", None)
        oifs = list(oif_val.keys()) if isinstance(oif_val, dict) else ([oif_val] if isinstance(oif_val, str) else [])

        if nh_val == "receive" and any(str(o).startswith(("Loopback", "Vlan")) for o in oifs):
            valid = True
            matched_oif = next((str(o) for o in oifs if str(o).startswith(("Loopback", "Vlan"))), None)
            break

    if not valid:
        error = "External Connectivity - Anycast Gateway Recursion Invalid"
        message = (
            f"Anycast gateway recursion on border {hostname} (VRF {vrf}) is not using a 'receive' next-hop on a Loopback/SVI. "
            f"Remediation: verify the anycast gateway is configured on the border and that its recursion resolves to a "
            f"local receive adjacency (Loopback or Vlan interface) in the VRF."
        )
        exit_program(step, PROCESS, subprocess, hostname, error, message)

    msg1 = "External Connectivity - Anycast Gateway Recursion"
    message = f"Anycast gateway recursion on border {hostname} (VRF {vrf}) resolves to a local receive adjacency on {matched_oif}."
    logging_info(step, PROCESS, subprocess, hostname, msg1 + " | " + message)
    return step + 1

def validate_vrf_configuration(border, step):
    subprocess = "[vrfConfiguration]"
    hostname = border.hostname

    vrfdetail = getattr(border, "vrfdetail_info", None) or {}
    route_distinguisher = (vrfdetail.get("route_distinguisher") or "").strip()
    interfaces = vrfdetail.get("interfaces") or []
    ipv4_af = (vrfdetail.get("address_family", {}) or {}).get("ipv4 unicast", {}) or {}
    route_targets = ipv4_af.get("route_targets", {}) or {}

    if not route_distinguisher:
        error = "VRF Validation - Missing Route Distinguisher"
        message = (
            f"VRF configuration on {border.mgmtip} is missing a route distinguisher. "
            f"Remediation: configure a route distinguisher for the VRF and re-provision the fabric border."
        )
        exit_program(step, PROCESS, subprocess, hostname, error, message)

    m = match(r"^\d+:(\d+)$", route_distinguisher)
    iid_from_rd = m.group(1) if m else None
    expected_li = f"LI0.{iid_from_rd}" if iid_from_rd else None

    li_intf = next((i for i in interfaces if str(i).startswith("LI")), None)
    if not li_intf:
        error = "VRF Validation - Missing LISP Interface"
        message = (
            f"VRF configuration on {border.mgmtip} does not include a LISP interface (expected LI0.<iid>). "
            f"Remediation: verify LISP interface creation/provisioning for this VRF on the border."
        )
        exit_program(step, PROCESS, subprocess, hostname, error, message)

    if expected_li and li_intf != expected_li:
        error = "VRF Validation - RD and LISP IID Mismatch"
        message = (
            f"VRF route distinguisher {route_distinguisher} does not match the LISP interface {li_intf}. "
            f"Expected LISP interface {expected_li} for this RD. Remediation: re-provision the VRF and LISP instance "
            f"so the LI interface IID matches the VRF RD."
        )
        exit_program(step, PROCESS, subprocess, hostname, error, message)

    if route_distinguisher not in route_targets:
        error = "VRF Validation - Missing IPv4 Route Target"
        message = (
            f"VRF {border.vrf} on {border.mgmtip} is missing the expected IPv4 route-target {route_distinguisher}. "
            f"Remediation: ensure the VRF has the correct route-targets and re-provision the border."
        )
        exit_program(step, PROCESS, subprocess, hostname, error, message)

    msg1 = "VRF Validation - RD and LISP IID"
    message = (
        f"VRF {border.vrf} on {border.mgmtip} has route distinguisher {route_distinguisher}, "
        f"LISP interface {li_intf}, and IPv4 route-target {route_distinguisher}."
    )
    logging_info(step, PROCESS, subprocess, hostname, msg1 + " | " + message)
    return step + 1

def validate_control_plane_status(fabric_id,iid,catc,service,step):
    control_planes = in_site_control_Planes(fabric_id,iid,catc,service,step)
    return control_planes

def validate_bgp_summary(border, step):
    subprocess = "[bgpSummary]"
    hostname = border.hostname
    ispubsub = border.profiled_device.ispubsub
    b = getattr(border, "bgpinfo", None) or {}
    bgsum = getattr(b, "bgsum", None) or {}
    ipprotocols_obj = getattr(b, "ipprotocols", None) or {}
    vrfs = (bgsum.get("vrf", {}) or {})
    vrf_name = getattr(border, "vrf", None)

    vrf_bgp = (vrfs.get(vrf_name, {}) or {})
    neighbors = (vrf_bgp.get("neighbor", {}) or {})

    if not bgsum or not vrfs:
        error = "BGP Validation - BGP Not Configured"
        message = (
            f"BGP routing information was not found on {hostname} for VRF {vrf_name}. "
            f"Remediation: verify BGP is configured and operational for external connectivity."
        )
        exit_program(step, PROCESS, subprocess, hostname, error, message)

    #LISP Redistribution and Incoming Route-MAPs
    subprocess = "bgpRedistribution"

    ipv4 = (
            ((((ipprotocols_obj.get("protocols", {}) or {}).get("bgp", {}) or {}).get("instance", {}) or {})
             .get("default", {}) or {}).get("vrf", {}) or {}
    )
    vrf_name = next(iter(ipv4.keys()), None)
    af = (((ipv4.get(vrf_name, {}) or {}).get("address_family", {}) or {}).get("ipv4", {}) or {})

    # 1) LISP must be redistributed
    redistributing = [x.lower() for x in (af.get("redistributing") or [])]
    if "lisp" not in redistributing:
        error = "BGP Validation - LISP Redistribution Missing"
        message = (
            f"BGP in VRF {vrf_name} on {hostname} is not redistributing LISP. "
            f"Remediation: configure LISP redistribution into BGP for this VRF so fabric prefixes are advertised correctly."
        )
        exit_program(step, PROCESS, subprocess, hostname, error, message)

    # 2) Neighbor route-map must be DROP_FABRIC_ROUTES (skip enforcement if pub-sub enabled)
    expected_routemap = "DROP_FABRIC_ROUTES"
    neighbors = af.get("neighbors", {}) or {}

    if not ispubsub:
        missing_rm = []
        for nbr, nbr_data in neighbors.items():
            rm = (nbr_data.get("route_map") or "").strip()
            if rm != expected_routemap:
                missing_rm.append({"neighbor": nbr, "route_map": rm or "Not Configured"})

        if missing_rm:
            error = "BGP Validation - Neighbor Route-Map Missing"
            message = (
                f"BGP neighbor route-map configuration is incomplete on {hostname} for VRF {vrf_name}. "
                f"Expected route-map '{expected_routemap}' on each neighbor; issues found: {missing_rm}. "
                f"Remediation: apply '{expected_routemap}' to the BGP neighbor(s) to prevent fabric routes from being leaked/looped."
            )
            exit_program(step, PROCESS, subprocess, hostname, error, message)

    msg1 = "BGP Validation - Redistribution and Route-Maps"
    message = (
        f"LISP redistribution into BGP is configured on {hostname} for VRF {vrf_name}, and BGP neighbor route-maps are properly configured."
        if not ispubsub
        else
        f"LISP redistribution into BGP is configured on {hostname} for VRF {vrf_name}. Neighbor route-map enforcement was skipped because pub-sub is enabled."
    )
    logging_info(step, PROCESS, subprocess, hostname, msg1 + " | " + message)

    if not neighbors:
        msg1 = "BGP Validation - No Neighbors"
        message = f"BGP is present on {hostname} for VRF {vrf_name}, but no neighbors were found in the BGP summary output."
        logging_warning(step, PROCESS, subprocess, hostname, msg1 + " | " + message)
        return step + 1

    zero_prefix_neighbors = []
    for nbr_ip, nbr_data in neighbors.items():
        afs = (nbr_data.get("address_family", {}) or {})
        for _, af_data in afs.items():
            remote_as = af_data.get("as")
            total_entries = (af_data.get("prefixes", {}) or {}).get("total_entries")
            if total_entries is None or int(total_entries) == 0:
                zero_prefix_neighbors.append({"neighbor": nbr_ip, "as": remote_as})

    if zero_prefix_neighbors:
        msg1 = "BGP Validation - No Prefixes Received"
        message = (
            f"BGP neighbors are present on {hostname} for VRF {vrf_name}, but one or more neighbors show no received prefixes: "
            f"{zero_prefix_neighbors}."
        )
        logging_warning(step, PROCESS, subprocess, hostname, msg1 + " | " + message)
        return step + 1

    msg1 = "BGP Validation - Neighbors OK"
    message = f"BGP is configured and operational on {hostname} for VRF {vrf_name}; neighbors are present and prefixes are being received."
    logging_info(step, PROCESS, subprocess, hostname, msg1 + " | " + message)
    step +=1

    return step + 1

def validate_bgp_neighbors(border, step):
    subprocess = "bgpNeighborValidation"
    hostname = border.hostname

    bgp_neighbors = getattr(border, "bgpneighborsinfo", None) or []
    if not bgp_neighbors:
        msg1 = "BGP Neighbor Validation - No Neighbors Found"
        message = (
            f"No BGP neighbor objects were found on {hostname}. "
            f"Verify BGP neighbor configuration for VRF {getattr(border, 'vrf', None)} if external connectivity is expected."
        )
        logging_warning(step, PROCESS, subprocess, hostname, msg1 + " | " + message)
        return step + 1

    any_established = False

    for n in bgp_neighbors:
        vrf = getattr(n, "vrf", None)
        nbr_ip = getattr(n, "neighborip", None)

        bgpneighbor = getattr(n, "bgpneighbor", None) or {}
        nbr_data = (
            ((((bgpneighbor.get("vrf", {}) or {}).get(vrf, {}) or {}).get("neighbor", {}) or {}).get(nbr_ip, {}) or {})
        )

        remote_as = nbr_data.get("remote_as")
        state = (nbr_data.get("session_state") or "Unknown")
        link_type = (nbr_data.get("link") or "").strip().lower()

        if state.strip().lower() == "established":
            any_established = True

        msg1 = "BGP Neighbor - Status"
        message = f"BGP neighbor {nbr_ip} in VRF {vrf} is in state {state} with remote AS {remote_as}."
        logging_info(step, PROCESS, subprocess, hostname, msg1 + " | " + message)
        step += 1

        datagram_sent = (
            (((nbr_data.get("bgp_session_transport", {}) or {}).get("datagram", {}) or {}).get("datagram_sent", {}) or {})
        )
        retransmit = datagram_sent.get("retransmit", 0) or 0
        fastretransmit = datagram_sent.get("fastretransmit", 0) or 0

        if retransmit or fastretransmit:
            msg1 = "BGP Neighbor - TCP Retransmissions"
            message = (
                f"BGP TCP session to neighbor {nbr_ip} shows retransmissions (retransmit={retransmit}, fastretransmit={fastretransmit}). "
                f"This may be benign if the session is stable, but investigate if the session is flapping or packet loss is suspected."
            )
            logging_warning(step, PROCESS, subprocess, hostname, msg1 + " | " + message)
            step += 1

        if link_type == "external":
            af = (nbr_data.get("address_family", {}) or {}).get("vpnv4 unicast", {}) or {}
            comm = bool(af.get("community_attribute_sent"))
            extcomm = bool(af.get("extended_community_attribute_sent"))
            if not (comm and extcomm):
                msg1 = "BGP Neighbor - Send-Community Not Enabled"
                message = (
                    f"BGP neighbor {nbr_ip} is an external peer, but community/extended-community signaling is not fully enabled. "
                    f"Remediation: configure 'send-community both' toward this neighbor; otherwise loop-prevention mechanisms between "
                    f"LISP and BGP may not work as expected."
                )
                logging_warning(step, PROCESS, subprocess, hostname, msg1 + " | " + message)
                step += 1

    if not any_established:
        msg1 = "BGP Neighbor Validation - No Established Neighbors"
        message = f"BGP neighbors were found on {hostname}, but none are in Established state. Verify adjacency formation and VRF reachability."
        logging_warning(step, PROCESS, subprocess, hostname, msg1 + " | " + message)
        step += 1
    return step

def validate_bgp_neighbor_policies(border, step, hostname):
    """
    Iterates through all BGP neighbors in border.bgpneighborsinfo and validates
    weight and route-map configurations based on link type and border role.
    """
    process = "externalConnectivity"
    subprocess = "bgpNeighborPolicy"

    bgp_neighbors = getattr(border, "bgpneighborsinfo", None) or []
    if not bgp_neighbors:
        return step

    border_type = (getattr(border, "type", "") or "").strip().lower()
    ispubsub = border.profiled_device.ispubsub
    # Correctly access ipprotocols from border.bgpinfo
    bgp_info_obj = getattr(border, "bgpinfo", {}) or {}
    ipprotocols = getattr(bgp_info_obj, "ipprotocols", {}) or {}
    for n_info in bgp_neighbors:
        # Extract context from the neighbor info object
        nbr_ip = getattr(n_info, "neighborip", None)
        vrf = getattr(n_info, "vrf", None)
        weight = (getattr(n_info, "bgpneighbor", {}) or {}).get("default_weight", 0)
        # Navigate the nested bgpneighbor dictionary
        bgp_obj = getattr(n_info, "bgpneighbor", {}) or {}
        nbr_data = (
            bgp_obj.get("vrf", {})
            .get(vrf, {})
            .get("neighbor", {})
            .get(nbr_ip, {})
        )

        if not nbr_data:
            continue

        link_type = (nbr_data.get("link") or "").strip().lower()
        # Retrieve the weight (added to the dict during parsing)


        # Extract inbound route-map from the corrected ipprotocols path
        af_ipv4 = (
            ipprotocols.get("protocols", {})
            .get("bgp", {})
            .get("instance", {})
            .get("default", {})
            .get("vrf", {})
            .get(vrf, {})
            .get("address_family", {})
            .get("ipv4", {})
        )
        inroute_map = (af_ipv4.get("neighbors", {}).get(nbr_ip, {}).get("route_map"))

        # --- 1) External BGP Weight Validation ---
        if link_type == "external":
            if weight != 65535:
                error = "BGP Validation - Invalid External Weight"
                message = (
                    f"BGP neighbor {nbr_ip} is an external peer but is configured with weight {weight} instead of 65535. "
                    f"Remediation: any external BGP neighbor must be configured with a weight of 65535 (Catalyst Center standard) "
                    f"to prevent advertisement loops in SD-Access."
                )
                exit_program(step, process, subprocess, hostname, error, message)
            else:
                msg1 = "BGP Validation - External Weight OK"
                message = f"BGP neighbor {nbr_ip} (eBGP) has the correct weight of 65535."
                logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
                step += 1

        # --- 2) Internal BGP Weight Validation ---
        elif link_type == "internal":
            if weight != 0:
                msg1 = "BGP Validation - Non-Zero Internal Weight"
                message = (
                    f"BGP neighbor {nbr_ip} is an internal peer and has a weight of {weight}. "
                    f"Internal peers do not require weight 65535; typically this should be 0."
                )
                logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)
                step += 1

            # --- 3) iBGP Route-Map Validation (LISP/BGP specific) ---
            if not ispubsub and border_type in {"isanywhere", "isinternal"}:
                if inroute_map is None:
                    msg1 = "BGP Validation - iBGP Inbound Route-Map Missing"
                    message = (
                        f"BGP neighbor {nbr_ip} (iBGP) on an {border_type} border has no inbound route-map configured. "
                        f"A route-map with a community-set must be configured on the iBGP neighbor in LISP/BGP designs "
                        f"without Pub/Sub to prevent advertisement loops."
                    )
                    logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)
                    step += 1
                else:
                    msg1 = "BGP Validation - iBGP Inbound Route-Map OK"
                    message = f"BGP neighbor {nbr_ip} (iBGP) has inbound route-map '{inroute_map}' configured."
                    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
                    step += 1

    return step

def validate_advertised_local_prefix(border, step):
    subprocess = "bgpAdvertisedRoute"
    hostname = border.hostname
    vrf_name = getattr(border, "vrf", None)

    local_route = getattr(border, "local_route", None) or {}
    local_prefixes = (
        ((((local_route.get("instance", {}) or {}).get("default", {}) or {}).get("vrf", {}) or {}).get(vrf_name, {}) or {})
        .get("address_family", {}) or {}
    ).get("vpnv4 unicast", {}).get("prefixes", {}) or {}
    local_prefix = next(iter(local_prefixes.keys()), None)
    if not local_prefix:
        error = "BGP Advertised Route - Local Prefix Not Found"
        message = f"No local route prefix was found to validate BGP advertisement in VRF {vrf_name} on {hostname}."
        exit_program(step, PROCESS, subprocess, hostname, error, message)

    found_advertisement = False

    for n in (getattr(border, "bgpneighborsinfo", None) or []):
        nbr_ip = getattr(n, "neighborip", None)
        vrf = getattr(n, "vrf", None) or vrf_name

        bgpneighbor = getattr(n, "bgpneighbor", None) or {}
        nbr_data = (
            ((((bgpneighbor.get("vrf", {}) or {}).get(vrf, {}) or {}).get("neighbor", {}) or {}).get(nbr_ip, {}) or {})
        )
        state = (nbr_data.get("session_state") or "").strip().lower()
        if state != "established":
            continue

        adv = getattr(n, "advertisdedroutes", None) or getattr(n, "advertisedroutes", None) or {}
        af = (
            ((((adv.get("vrf", {}) or {}).get(vrf, {}) or {}).get("neighbor", {}) or {}).get(nbr_ip, {}) or {})
            .get("address_family", {}) or {}
        )

        for af_name, af_data in af.items():
            ad = (af_data.get("advertised", {}) or {})
            if not isinstance(ad, dict) or not ad:
                continue

            if local_prefix in ad:
                idx = (ad[local_prefix].get("index", {}) or {}).get(1, {}) or {}
                next_hop = idx.get("next_hop")
                origin_code = idx.get("origin_codes")

                msg1 = "BGP Advertised Route - Local Prefix"
                message = (
                    f"Local prefix {local_prefix} is advertised to BGP neighbor {nbr_ip} in VRF {vrf_name}. "
                    f"Next hop is {next_hop} and origin code is {origin_code}."
                )
                logging_info(step, PROCESS, subprocess, hostname, msg1 + " | " + message)
                step += 1
                found_advertisement = True
                break

        if found_advertisement:
            break

    if not found_advertisement:
        msg1 = "BGP Advertised Route - Prefix Not Advertised"
        message = f"Local prefix {local_prefix} was not found in advertised routes toward any Established BGP neighbor in VRF {vrf_name}."
        logging_warning(step, PROCESS, subprocess, hostname, msg1 + " | " + message)
        step += 1

    return step

def validate_destination_not_lisp(border, step, hostname):
    """
    Validates that a destination outside the fabric is not being forwarded via LISP on this border.

    Uses:
      - border.dstip
      - border.destcefinformation (dict-like)
      - border.destoutgoingports (list)

    Returns updated step.
    """
    process = "externalConnectivity"
    subprocess = "destinationNotLisp"

    dstip = getattr(border, "dstip", None)

    cef = getattr(border, "destcefinformation", None) or {}
    nexthops = getattr(cef, "nexthops", None) or {}
    #nexthops = cef.get("nexthops") or []
    destoutgoingports = getattr(border, "destoutgoingports", None) or []

    # Gather (oif, nexthop) pairs
    pairs = []
    for nh in nexthops:
        nexthop = (nh.get("nexthop") or "").strip()
        oif_val = nh.get("oif")

        if isinstance(oif_val, dict):
            oifs = list(oif_val.keys())
        elif isinstance(oif_val, str):
            oifs = [oif_val]
        else:
            oifs = []

        for oif in oifs:
            pairs.append((str(oif), nexthop))

    # If any OIF is LISP, apply the LISP-specific rules
    lisp_pairs = [(oif, nh) for oif, nh in pairs if oif.startswith("LISP")]

    for oif, nh in lisp_pairs:
        nh_l = nh.lower()

        # LISP + attached/drop: ignore this border for destination forwarding validations
        if nh_l in {"attached", "drop"}:
            msg1 = "External Connectivity - Destination Forwarding (LISP Ignored)"
            message = (
                f"Destination {dstip} on {hostname} resolves via {oif} with next-hop '{nh}'. "
                f"Forwarding validations for this destination on this border will be ignored; this becomes relevant "
                f"only if all borders fail to provide a valid non-LISP path."
            )
            logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
            step += 1
            return step

        # LISP + IP nexthop: warning (destination should not be LISP)
        if nh and nh_l not in {"attached", "drop"}:
            msg1 = "External Connectivity - Destination Recursion via LISP"
            message = (
                f"Destination {dstip} on {hostname} resolves via {oif} with next-hop {nh}. "
                f"The destination next-hop should not be LISP for an external destination. Possible causes include: "
                f"(1) a fabric device with RLOC {nh} importing a more specific prefix for the destination, "
                f"(2) a fabric device with RLOC {nh} importing the next-hop IP (often due to L3 handoff subnets imported into LISP, "
                f"causing invalid recursion), or (3) an SD-Access transit scenario not yet supported by this module."
            )
            logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)
            step += 1
            return step

    # 1. Check if the list is empty (Recursion failure)
    if not destoutgoingports:
        error = "External Connectivity - Destination Recursion Failed"
        message = (
            f"Finding: Destination {dstip} on {hostname} is not using LISP forwarding, but no physical outgoing ports were derived. "
            f"Remediation: This indicates recursion to an egress interface was not possible. Verify the routing table (RIB) "
            f"and CEF adjacency for the destination IP."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    # 2. Check for "drop" or "null" in the outgoing ports (Case-insensitive)
    bad_ports = [p for p in destoutgoingports if any(x in str(p).lower() for x in ["drop", "null"])]

    if bad_ports:
        error = "External Connectivity - Destination Dropped"
        message = (
            f"Finding: Destination {dstip} on {hostname} resolves to an invalid outgoing port: {bad_ports}. "
            f"Remediation: A 'drop' or 'null' adjacency in CEF indicates a routing blackhole. "
            f"Verify the routing protocol state (BGP/LISP) and ensure a valid next-hop is present in the RIB."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    # 3. Success Log
    msg1 = "External Connectivity - Destination Forwarding"
    message = (
        f"Finding: Destination {dstip} on {hostname} resolves to the following outgoing interface(s): {destoutgoingports}."
    )
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    step += 1
    return step

def validate_ping_results(border,step,hostname):
    process = "externalConnectivity"
    subprocess = "pingReachability"

    normal_ping = border.ping_results
    dstip = border.dstip
    step +=1
    logging_info(step, process, subprocess, hostname,
                     "Ping from {} to {}  : {} % Success".format(hostname,dstip, normal_ping.result))
    # print (pformat(vars(normal_ping), indent=4, width =1, sort_dicts=False))
    if int(normal_ping.result) <= 70:
        logging_warning(step, process, subprocess, hostname,
                            "WARNING! : Packet Loss from {} to {} is below threshold of 70%, current value is {} % , it is normal for all Borders except one to fail due to anycast gateway".format(
                                 hostname, dstip, normal_ping.result))
            # print ("WARNING! : Packet Loss from {} to {} is below threshold of 70%, current value is {} % with low MTU \n".format(srcxtr.hostname, rloccef.ip, normal_ping.result))
    else:
        logging_info(step, process, subprocess, hostname,
                     "ICMP Connectivity from {} to {} is good at {} % success rate, it is normal for all Borders except one to fail due to anycast gateway".format(hostname,
                                                                                                        dstip,
                                                                                                            normal_ping.result))
    return step

def validate_route_import(border, step, hostname):
    process = "externalConnectivity"
    subprocess = "routeImportValidation"

    border_type = (getattr(border, "type", "") or "").strip().lower()
    if border_type == "isexternal":
        return step  # skip (per requirement)

    vrf_name = getattr(border, "vrf", None)

    # --- 1) Get best BGP route prefix toward destination (border.bgpinfo["route"]) ---
    b = getattr(border, "bgpinfo", None) or {}
    route_obj = getattr(b, "route", None) or {}
    #route_obj = bgpinfo.get("route", {}) or {}

    prefixes = (
        ((((route_obj.get("instance", {}) or {}).get("default", {}) or {}).get("vrf", {}) or {})
         .get(vrf_name, {}) or {})
        .get("address_family", {}) or {}
    ).get("vpnv4 unicast", {}).get("prefixes", {}) or {}

    bgp_prefix = next(iter(prefixes.keys()), None)

    if not bgp_prefix:
        msg1 = "Route Import - BGP Route Not Found"
        message = (
            f"No BGP route was found for VRF {vrf_name} on {hostname}. "
            f"This is only a problem if no borders have a valid route for the destination."
        )
        logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1
        return step
    # Default route => ignore route-import validation
    if bgp_prefix == "0.0.0.0/0":
        msg1 = "Route Import - Default Route"
        message = (
            f"BGP best route in VRF {vrf_name} on {hostname} is the default route; "
            f"route-import validation will be ignored because default routes are not imported into the LISP database."
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        return step + 1

    # Reject “default-like” overlaps (0.0.0.0 with non-/0 mask)
    try:
        net = ipaddress.ip_network(bgp_prefix, strict=False)
        if str(net.network_address) == "0.0.0.0" and net.prefixlen != 0:
            error = "Route Import - Unsupported Default Summary"
            message = (
                f"BGP route {bgp_prefix} in VRF {vrf_name} on {hostname} is a default-summary overlap. "
                f"This is not supported in SD-Access. Remediation: remove/adjust the summarization so a valid prefix is learned."
            )
            exit_program(step, process, subprocess, hostname, error, message)
    except ValueError:
        pass

    # --- 2) Check LISP route-import database utilization (border.lispstatus) ---
    lispstatus = getattr(border, "lispstatus", None) or {}
    ri = (((lispstatus.get("database", {}) or {}).get("route_import", {}) or {}))
    ri_size = ri.get("size")
    ri_limit = ri.get("limit")

    try:
        util = (int(ri_size) / int(ri_limit)) if ri_size is not None and ri_limit is not None and int(ri_limit) > 0 else None
    except Exception:
        util = None

    if util is not None and util >= 0.95:
        error = "Route Import - Database Near Limit"
        message = (
            f"LISP route-import database utilization is high on {hostname} for VRF {vrf_name} "
            f"({ri_size}/{ri_limit}). The route-import process may not be able to add new prefixes. "
            f"Remediation: reduce the number of routes received via BGP on this border or increase the limit using "
            f"`route-import database maximum-prefix` under `lisp service ipv4`."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    # --- 3) Validate LISP DB entry exists/healthy for the imported route (border.lispdbroute) ---
    lispdb = getattr(border, "lispdbroute", None) or {}
    eid = (lispdb.get("eid") or "").strip()

    if not eid or eid == "0.0.0.0/0":
        error = "Route Import - LISP DB Entry Not Found"
        message = (
            f"No LISP route-import database entry was found for BGP prefix {bgp_prefix} in VRF {vrf_name} on {hostname}. "
            f"Remediation: review LISP redistribution/route-import configuration or advertise the route using a BGP network statement."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    locators = lispdb.get("locators") or []
    if not locators:
        error = "Route Import - Missing Locator-Set"
        message = (
            f"LISP DB entry for {eid} on {hostname} has no locators. "
            f"This typically indicates the RLOC/locator-set definition was removed. "
            f"Remediation: reconfigure the RLOC under the LISP locator-set configuration."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    mapservers = lispdb.get("mapservers") or []
    any_ack = any((str(ms.get("ack") or "").strip().lower() == "yes") for ms in mapservers if isinstance(ms, dict))

    if not any_ack:
        msg1 = "Route Import - No Map-Server ACK"
        message = (
            f"LISP DB entry for {eid} on {hostname} did not receive an ACK from any control-plane map-server. "
            f"Remediation: troubleshoot LISP sessions between the border and the local control planes."
        )
        logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)
        return step + 1

    msg1 = "Route Import - Validated"
    message = (
        f"Route-import validation succeeded for VRF {vrf_name} on {hostname}. "
        f"BGP prefix {bgp_prefix} is present in the LISP database as {eid} and has at least one map-server ACK."
    )
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    return step + 1

def validate_petr_settings(border, step, hostname):
    process = "externalConnectivity"
    subprocess = "petrValidation"

    border_type = (getattr(border, "type", "") or "").strip().lower()
    if border_type not in {"isexternal", "isanywhere"}:
        return step

    lispstatus = getattr(border, "lispstatus", None) or {}
    petr = getattr(lispstatus, "petr", None) or {}
    usepetrs = getattr(lispstatus, "usepetrs", None) or {}
    if not petr:
        error = "External Connectivity - PETR Not Enabled"
        message = (
            f"Border {hostname} is configured as {border_type}, but it is not acting as a Proxy-ETR (petr is not enabled). "
            f"Remediation: enable PETR under `router lisp` -> `service ipv4` using the `petr` command and re-provision the border."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    if usepetrs:
        error = "External Connectivity - use-petr Configured on Border"
        message = (
            f"Border {hostname} has use-petr configured. Borders should not use a PETR because they are the PETR themselves; "
            f"this can cause loops and traffic blackholing. Another possible cause is an SD-Access transit design, which is not "
            f"covered by this module. Remediation: remove use-petr configuration from the border and re-test."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    msg1 = "External Connectivity - PETR Validation"
    message = f"Border {hostname} is correctly configured as a Proxy-ETR for external connectivity."
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    return step + 1

def validate_default_route_and_default_etr(border, step, hostname):
    process = "externalConnectivity"
    subprocess = "defaultRouteValidation"

    border_type = (getattr(border, "type", "") or "").strip().lower()
    if border_type not in {"isexternal", "isanywhere"}:
        return step

    vrf_name = getattr(border, "vrf", None)

    b = getattr(border, "bgpinfo", None) or {}
    defroute = getattr(b, "defroute", None) or {}
    #bgpinfo = getattr(border, "bgpinfo", None) or {}
    #defroute = bgpinfo.get("defroute", {}) or {}

    prefixes = (
        ((((defroute.get("instance", {}) or {}).get("default", {}) or {}).get("vrf", {}) or {})
         .get(vrf_name, {}) or {})
        .get("address_family", {}) or {}
    ).get("vpnv4 unicast", {}).get("prefixes", {}) or {}

    has_default = "0.0.0.0/0" in prefixes

    if not has_default:
        msg1 = "External Connectivity - Default Route Missing"
        message = (
            f"Border {hostname} is configured as {border_type}, but no BGP default route (0.0.0.0/0) is learned in VRF {vrf_name}."
        )
        logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)
        return step + 1

    # Default route exists: verify LISP DB has 0.0.0.0/0
    lispdb = getattr(border, "lispdbroute", None) or {}
    eid = getattr(lispdb, "eid", None) or {}

    if eid != "0.0.0.0/0":
        error = "External Connectivity - Default ETR Missing"
        message = (
            f"Border {hostname} has a BGP default route in VRF {vrf_name}, but 0.0.0.0/0 is not present in the LISP database. "
            f"Remediation: configure `database-mapping 0.0.0.0/0 locator-set DEFAULT_ETR_LOCATOR default-etr` "
            f"under the appropriate LISP instance-id."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    msg1 = "External Connectivity - Default Route and Default ETR"
    message = (
        f"Border {hostname} has a BGP default route in VRF {vrf_name}, and 0.0.0.0/0 is present in the LISP database."
    )
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    step += 1

    # Validate remote_iid_locators for this border loopback (lispstatus.rloc) and priority != 255
    lispstatus = getattr(border, "lispstatus", None) or {}
    border_rloc = getattr(lispstatus, "rloc", None) or {}

    remote_iid_locators = getattr(border, "remote_iid_locators", None) or []
    match_entry = next((e for e in remote_iid_locators if (e.get("rloc_ip") or "").strip() == border_rloc), None)

    if not match_entry:
        error = "External Connectivity - Missing Default ETR Locator"
        message = (
            f"Border {hostname} loopback RLOC {border_rloc} was not found in remote IID locator entries. "
            f"Remediation: verify the default-etr locator-set configuration and control-plane locator programming."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    priority = str(match_entry.get("priority") or "").strip()
    if priority == "255":
        error = "External Connectivity - Default ETR Priority Invalid"
        message = (
            f"Border {hostname} loopback RLOC {border_rloc} is present in remote IID locators, but has priority 255. "
            f"Remediation: correct the locator-set priority so the default ETR is usable for default-route forwarding."
        )
        exit_program(step, process, subprocess, hostname, error, message)

    msg1 = "External Connectivity - Default ETR Locator Validated"
    message = (
        f"Border {hostname} loopback RLOC {border_rloc} is present in remote IID locators with priority {priority}."
    )
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    step += 1

    return step

def validate_overlapping_summaries(border, step, hostname):
    process = "externalConnectivity"
    subprocess = "overlappingSummaries"

    border_type = (getattr(border, "type", "") or "").strip().lower()
    if border_type not in {"isanywhere", "isinternal"}:
        return step

    lisp_local = getattr(border, "lispfwdinglocaleid", None) or {}
    prefixes = lisp_local.get("prefixes") or []

    nets = []
    for p in prefixes:
        try:
            net = ipaddress.ip_network(str(p).strip(), strict=False)
        except ValueError:
            continue
        # default route is the only supported "summary"
        if str(net) == "0.0.0.0/0":
            continue
        nets.append(net)

    overlapping_wide = set()
    for i in range(len(nets)):
        for j in range(len(nets)):
            if i == j:
                continue
            a, b = nets[i], nets[j]
            # mark the wider prefix if it contains a more specific
            if a.supernet_of(b):
                overlapping_wide.add(a)

    if overlapping_wide:
        msg1 = "External Connectivity - Overlapping Summary Detected"
        message = (
            f"Overlapping summary prefixes were detected in the local LISP EID list on {hostname}: "
            f"{sorted(str(n) for n in overlapping_wide)}. "
            f"Overlapping summaries are not supported in SD-Access (default route is the only supported summary) and can "
            f"cause map-cache resolution issues, especially for multicast. Remediation: remove the overlapping summary prefix(es)."
        )
        logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1
        return step

    msg1 = "External Connectivity - Overlapping Summary Check"
    message = (
        f"No overlapping summary prefixes were detected in the local LISP EID list on {hostname}."
    )
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    step += 1
    return step

def validate_interface_counters(border, step, hostname):
    process = "externalConnectivity"
    subprocess = "interfaceCounters"

    issues_found = False

    for intf_obj in (getattr(border, "interfacestats", None) or []):
        d = vars(intf_obj) if hasattr(intf_obj, "__dict__") else (intf_obj or {})

        intf = d.get("interface")
        iqdrops = d.get("iqdrops") or 0
        outputdrops = d.get("outputdrops") or 0
        giants = d.get("giants") or 0
        runts = d.get("runts") or 0
        crcerrors = d.get("crcerrors") or 0

        if any(v > 0 for v in [iqdrops, outputdrops, giants, runts, crcerrors]):
            issues_found = True
            msg1 = "Interface Counters - Errors/Drops Detected"
            message = (
                f"Interface {intf} on {hostname} has non-zero error/drop counters. "
                f"Input queue drops {iqdrops}, output drops {outputdrops}, CRC errors {crcerrors}, "
                f"giants {giants}, runts {runts}. Remediation: investigate link quality, congestion, and physical layer health."
            )
            logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)
            step += 1

    if not issues_found:
        msg1 = "Interface Counters - Clean"
        message = f"No interface drops or error counters were detected on {hostname} for the evaluated interfaces."
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

    return step

def log_cts_enforcement_status(border, step, hostname):
    process = "externalConnectivity"
    subprocess = "ctsEnforcement"
    dstip = border.dstip
    for cts_obj in (getattr(border, "ctsinfo", None) or []):
        d = vars(cts_obj) if hasattr(cts_obj, "__dict__") else (cts_obj or {})
        global_state = getattr(cts_obj, "globalenforcement", None)
        vlan_state = getattr(cts_obj, "vlanenforcement", False)
        port_state = getattr(cts_obj, "ctsportenabled", False)

        vrf = getattr(cts_obj, "vrf", None)
        cefsgt = getattr(cts_obj, "cefsgt", 0)

        msg1 = "CTS Enforcement - Status"
        message = (
            f"CTS enforcement status on {hostname}: global enforcement is {global_state}, VLAN enforcement is {vlan_state}, "
            f"and port status is {port_state}. For destination {dstip} in VRF {vrf}, the destination SGT is {cefsgt}."
        )
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        step += 1

    return step

def validate_control_plane_logic(border, step,service):
    """
    Validates LISP Control Plane configurations, sessions, and Pub/Sub parameters.

    Inputs:
      - control_planes: List of CP objects
      - target_iid: The VNI/Instance-ID to check (e.g., 4099)
      - target_subnet: The fabric subnet to verify (e.g., '172.19.10.0/24')
      - target_ip: The peer IP for session/subscriber checks (e.g., '10.31.136.74')
    """
    process = "fabricControlPlane"
    control_planes = getattr(border, "control_planes", [])
    target_iid = getattr(border, "lispiid", None)
    anycastgw = border.anycastgwinfo
    ip4 = ((anycastgw.get("ipPoolDetails", {}) or {}).get("ipV4AddressSpace", {}) or {})
    subnet = ip4.get("subnet")
    prefix_length = ip4.get("prefixLength")
    prefixandslash = str(subnet) + "/" + str(prefix_length)
    target_subnet = prefixandslash
    lispstatus = getattr(border, "lispstatus", {})
    target_ip = (
        lispstatus.get("rloc")
        if isinstance(lispstatus, dict)
        else getattr(lispstatus, "rloc", None)
    )
    for cp in control_planes:
        hostname = getattr(cp, "hostname", "Unknown")
        is_pubsub = getattr(cp, "ispubsub", False)

        # Access nested objects safely
        cp_config = getattr(cp, "lispcpconfig", {})
        # Handle if cp_config is an object with a __dict__ or a dictionary
        cp_config_dict = vars(cp_config) if hasattr(cp_config, "__dict__") else cp_config

        lispservice = cp_config_dict.get("lispservice", {}).get("lisp_id", {}).get(0, {})
        site_uci = cp_config_dict.get("site_uci", {})

        session_obj = getattr(cp, "lispsession", {})
        session_dict = vars(session_obj) if hasattr(session_obj, "__dict__") else session_obj

        # --- 1) Map-Server / Map-Resolver Enablement ---
        ms_enabled = lispservice.get("map_server", {}).get("enabled")
        mr_enabled = lispservice.get("map_resolver", {}).get("enabled")

        if not (ms_enabled is True and mr_enabled is True):
            error = "LISP CP Validation - MS/MR Disabled"
            message = (
                f"Control Plane {hostname} is not fully enabled as a Map-Server and Map-Resolver. "
                f"Remediation: enable both 'map-server' and 'map-resolver' under the LISP process configuration."
            )
            exit_program(step, process, "[cpConfig]", hostname, error, message)

        # --- 2) EID Record Presence ---
        eid_records = site_uci.get("eid_records", {}).get(target_iid, [])
        if target_subnet not in eid_records:
            error = "LISP CP Validation - Missing EID Record"
            message = (
                f"Fabric subnet {target_subnet} is not present in the EID records for Instance-ID {target_iid} "
                f"on Control Plane {hostname}. Remediation: ensure the subnet is correctly defined in the LISP site configuration."
            )
            exit_program(step, process, "[siteUCI]", hostname, error, message)

        # --- 3) Pub/Sub: Default ETR Propagation (allow-locator) ---
        if is_pubsub:
            allow_locators = site_uci.get("allow_locator_default_etr", {}).get(target_iid, [])
            if "ipv4" not in [str(a).lower() for a in allow_locators]:
                error = "LISP CP Validation - Default ETR Not Allowed"
                message = (
                    f"Fabric {hostname} is not configured for default-route propagation in IID {target_iid}. "
                    f"The 'allow-locator-default-etr ipv4' configuration is missing. This will impact internet/external reachability."
                )
                exit_program(step, process, "[siteUCI]", hostname, error, message)

        # --- 4) Pub/Sub: RLOC Members Distribute ---
        '''
        rloc_dist = cp_config_dict.get("rloc_members_distribute")
        if is_pubsub and rloc_dist is False:
            error = "LISP CP Validation - RLOC Distribution Disabled"
            message = (
                f"The command 'map-server rloc members distribute' is missing on {hostname}. "
                f"This command is indispensable for Control Plane operations in a Pub/Sub environment."
            )
            exit_program(step, process, "[cpConfig]", hostname, error, message)
        '''
        # --- 5) LISP Session State ---
        peer_sessions = session_dict.get("peers", {}).get(target_ip, [])
        session_up = any(s.get("state") == "Up" for s in peer_sessions)

        if not session_up:
            # Placeholder for LISP Session troubleshooting function
            mgmtip = (getattr(border, "mgmtip", "") or "")
            type  = (getattr(border, "type", "") or "")
            vlan = None
            vrf = (getattr(border, "vrf", "") or "")
            pd = getattr(border, "profiled_device", None)
            catc_name = getattr(pd, "dnac", "Unknown") if pd else "Unknown"

            if type == "isexternal" or type =="isanywhere":
                eid = "0.0.0.0/0"
                singleETRProfiling(mgmtip,eid,vlan,vrf,catc_name,service,step,pd)
            if type == "isiniternal":
                #LISP Session Publication is not available for Internal Only Borders
                pass

            # --- 6) Pub/Sub: LISP Prefix-List (SITE_LOCAL_EIDS_V4) ---
        if is_pubsub:
            # 1. Safely get the top-level LISP data
            lisp_prefix_data = session_dict.get("lisp_prefixlist")

            # 2. If it's None or empty, SDA transit is not in use; skip this validation
            if lisp_prefix_data is not None:
                # Safely navigate the rest of the tree
                prefix_lists = lisp_prefix_data.get("lisp_id", {}).get(0, {}).get("prefix_list_name", {})
                local_eids = prefix_lists.get("SITE_LOCAL_EIDS_V4", {}).get("entries", {})

                # 3. Only validate if we actually found local_eids data
                if local_eids and target_subnet not in local_eids:
                    error = "LISP CP Validation - Missing Prefix-List Entry"
                    message = (
                        f"Subnet {target_subnet} is not configured in the LISP-internal prefix-list 'SITE_LOCAL_EIDS_V4' on {hostname}. "
                        f"Remediation: add the subnet to the LISP prefix-list under the 'router lisp' process."
                    )
                    exit_program(step, process, "[prefixList]", hostname, error, message)
            else:
                message = f"SDA Transit (LISP Prefix-List) is not in use on {hostname}. Skipping validation."
                logging_info(step, process, "[prefixList]", hostname, message)

        # --- 7) Pub/Sub: Subscriber Type ---
        if is_pubsub:
            subscribers = (
                session_dict.get("lispsubscribers", {})
                .get("lisp_id", {})
                .get(0, {})
                .get("instance_id", {})
                .get(target_iid, {})
                .get("subscribers", {})
            )
            sub_data = subscribers.get(target_ip, {})
            if sub_data and sub_data.get("type") != "IID":
                error = "LISP CP Validation - Invalid Subscriber Type"
                message = (
                    f"Subscriber {target_ip} on {hostname} has an invalid subscription type '{sub_data.get('type')}'. "
                    f"Expected type 'IID' for proper fabric operation."
                )
                exit_program(step, process, "[subscribers]", hostname, error, message)

        # If all checks pass for this CP
        msg1 = "LISP CP Validation - Status OK"
        message = f"Control Plane {hostname} passed all LISP configuration and session validations for IID {target_iid}."
        logging_info(step, process, "[validationSummary]", hostname, msg1 + " | " + message)
        step += 1

    return step

def individual_border_validations(border,step,service):
    # The IP Transit Validation Module validates the following things in a single fabric site.
    # Identification of Borders - API (names, mgmtips, radkitinventory, device profiler)*
    # Identification of Border roles (external, anywhere or internal) - API - (parser/device profiler)]*
    # Identitification of Borders with IP Transit - API (get AS, configured peers per vrf, physical interface mapped)*
    # sFor a given vrf and source pool, valdiate anycast gateway existence (SVI or Loopback)*
    # With a given VRF (including default), verify the status of the BGP peers (bgp state, number of routes, presence of default route, tableversion, uptime)
    # sWith a given VRF, identify the local fabric pool and identify it's origin (Network? Route Exported?)
    # sWith a given VRF (including default), verify the status of a given fabric route advertised to all active BGP peers (summary, attributes, locally originated)
    # dWith a given VRF and source (fabric only) verify reachability to a particular source (route & cef verification (LISP), physical recursion)
    # dWith a given destination outside the fabric, validate that the destination is not LISP (Internal endpoint or sda transit)
    # dWith a given VRF, verify outside reachability to a particular destination (route & cef verification, physical recursion and ping test)
    # dWith a given destination prefix:
    # extBorder : validate default route (if required), if pusbub = default import flow, if 1.0 = No check
    # intBorder : validate specific route (if exists), verify route-import command, operation and CP registration
    # anyBorder : do both validations depending on the type of prefix (default or specific)
    # overlappig prefix warning if found
    # Validate interface drops and counter statistics
    # Verify CTS enforcement to a given destination (requires SGT source calculation for non INFRA)
    # Verify ACL (L2 and L3) to a given destination
    # For a given ACL or RBACL and a given traffic flow, validate if traffic is denied or allowed

    # This function parses every border object to find inconsistencies

    # Confirm that the anycast gateway is configured on the Border in a way that the nexthop for the anycast gateway is "receive" in the form of a Loopback or SVI
    #for border in border_objects:
            hostname = border.profiled_device.hostname
        # sFor a given vrf and source pool, valdiate anycast gateway existence (SVI or Loopback)*
            step = validate_anycast_gateway_recursion(border, step)
            step = validate_petr_settings(border, step, hostname)
        #Validate CP information
            step = validate_control_plane_logic(border,step,service)
        # With a given VRF (including default), verify the status of the BGP peers (bgp state, number of routes, presence of default route, tableversion, uptime)
            step = validate_vrf_configuration(border, step)
            step = validate_bgp_summary(border, step)
            step = validate_bgp_neighbors(border, step)
            step = validate_bgp_neighbor_policies(border,step,hostname)
        # sWith a given VRF, identify the local fabric pool and identify it's origin (Network? Route Exported?)
        # sWith a given VRF (including default), verify the status of a given fabric route advertised to all active BGP peers (summary, attributes, locally originated)
            step = validate_advertised_local_prefix(border, step)
        # sWith a given VRF and source (fabric only) verify reachability to a particular source (route & cef verification (LISP), physical recursion)
            step = validate_source_recursion(border,step,hostname,service)
        # dWith a given destination outside the fabric, validate that the destination is not LISP (Internal endpoint or sda transit)
        # dWith a given VRF, verify outside reachability to a particular destination (route & cef verification, physical recursion and ping test)
            step = validate_destination_not_lisp(border,step,hostname)
            step = validate_ping_results(border,step,hostname)
        # dWith a given destination prefix:
        # extBorder : validate default route (if required), if pusbub = default import flow, if 1.0 = No check
        # intBorder : validate specific route (if exists), verify route-import command, operation and CP registration
        # anyBorder : do both validations depending on the type of prefix (default or specific)
            step = validate_route_import(border,step,hostname)
            step = validate_default_route_and_default_etr(border,step,hostname)
        # overlappig prefix warning if found
            step = validate_overlapping_summaries(border,step,hostname)
        # Validate interface drops and counter statistics
            step = validate_interface_counters(border,step,hostname)
        # Validate CTS status
            step = log_cts_enforcement_status(border,step,hostname)
            return step

def multi_border_validation(borders, step, service):
    process = "externalConnectivity"
    subprocess = "multiBorderValidation"

    if not borders:
        return step

    valid_egress_found = False
    any_valid_petr_found = False  # Track if at least one border has 0.0.0.0/0 in LISP DB
    handoff_map = {}  # { "hostname": [IPv4Network, ...] }

    # Since Pub/Sub state is consistent across the site, check the first border
    is_pubsub_site = getattr(borders[0].profiled_device, "ispubsub", False)

    # --- FIRST PASS: Collect global data across all borders ---
    for border in borders:
        hostname = border.hostname
        current_vrf = getattr(border, "vrf", "")

        # 1. Use CEF information to determine valid egress (non-LISP)
        cef_info = getattr(border, "destcefinformation", None)
        if cef_info:
            nexthops = getattr(cef_info, "nexthops", []) if not isinstance(cef_info, dict) else cef_info.get("nexthops",
                                                                                                             [])
            for nh in nexthops:
                oif_val = nh.get("oif", {})
                oif_names = list(oif_val.keys()) if isinstance(oif_val, dict) else [str(oif_val)]
                if any(not str(name).startswith("LISP") for name in oif_names):
                    valid_egress_found = True
                    break

        # 2. Check for valid PETR registration (Only if Pub/Sub is enabled)
        if is_pubsub_site:
            info = getattr(border, "defaultetrinfo", {})
            if info:
                lisp_db = info.get("lisp_db_default", {})
                if lisp_db.get("eid") == "0.0.0.0/0" and (lisp_db.get("locators") or []):
                    any_valid_petr_found = True

        # 3. Collect L3 handoff prefixes for this specific border and VRF
        handoffs = getattr(border, "l3handoffinfo", []) or []
        border_specific_nets = []
        for link in handoffs:
            vn_name = link.get("virtualNetworkName")
            if vn_name and str(vn_name).lower() == str(current_vrf).lower():
                local_ip = link.get("localIpAddress")
                if local_ip:
                    try:
                        net = ipaddress.ip_network(local_ip, strict=False)
                        border_specific_nets.append(net)
                    except ValueError:
                        continue
        handoff_map[hostname] = border_specific_nets

    # --- GLOBAL (SITE-WIDE) VALIDATIONS ---

    # Global 1: Egress Path Availability
    if not valid_egress_found:
        error = "Multi-Border - No Egress Path"
        message = "None of the profiled borders have a valid physical (non-LISP) outgoing path to the destination."
        exit_program(step, process, subprocess, "Fabric-Wide", error, message)
    else:
        logging_info(step, process, subprocess, "Fabric-Wide",
                     "Multi-Border - Egress Path | At least one border has a valid physical path.")
        step += 1

    # Global 2: Site-Wide PETR Availability (Pub/Sub Only)
    is_external_site = any(getattr(b, "type", "").lower() in ["isexternal", "isanywhere"] for b in borders)
    if is_pubsub_site and is_external_site:
        if not any_valid_petr_found:
            error = "Multi-Border - No Default Route in LISP"
            message = (
                "Pub/Sub is enabled, but none of the external borders have the default route (0.0.0.0/0) "
                "propagated into the LISP database with valid locators. At least one external border "
                "must provide this for the fabric to reach unknown destinations."
            )
            exit_program(step, process, subprocess, "Fabric-Wide", error, message)
        else:
            logging_info(step, process, subprocess, "Fabric-Wide",
                         "Multi-Border - LISP Default Route | At least one border is propagating 0.0.0.0/0 into LISP.")
            step += 1

    # --- SECOND PASS: Individual Border consistency checks ---
    for border in borders:
        hostname = border.hostname
        border_type = (getattr(border, "type", "") or "").strip().lower()
        is_collocated_cp = getattr(border.profiled_device, "cp", False)
        iid = getattr(border, "lispiid", "Unknown")

        # Validation 1: Individual PETR Details (Pub/Sub Only)
        if is_pubsub_site:
            info = getattr(border, "defaultetrinfo", {})
            if info:
                rib = info.get("rib_default", {})
                lisp_db = info.get("lisp_db_default", {})
                rt_prefix = rib.get("prefix")
                rt_nexthop = rib.get("nexthop")

                if rt_prefix == "0.0.0.0":
                    # Check for Null nexthop
                    is_null = any("null" in str(nh).lower() for nh in rt_nexthop) if isinstance(rt_nexthop,
                                                                                                list) else "null" in str(
                        rt_nexthop).lower()
                    if is_null:
                        error = "PETR Availability - Null Next-Hop"
                        message = f"Border {hostname} has a default route, but the next-hop is Null. Traffic will be dropped."
                        exit_program(step, process, subprocess, hostname, error, message)

                    msg1 = "PETR Availability - Default Route Valid"
                    message = f"Border {hostname} is using next-hop(s) {rt_nexthop} for default-route forwarding."
                    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
                    step += 1

                    if lisp_db.get("eid") != "0.0.0.0/0":
                        error = "PETR Availability - LISP DB Entry Missing"
                        message = (
                            f"Border {hostname} has a valid default route in RIB, but it is missing in LISP DB for IID {iid}. "
                            "Remediation: Configure 'database-mapping 0.0.0.0/0 locator-set DEFAULT_ETR_LOCATOR default-etr'."
                        )
                        exit_program(step, process, subprocess, hostname, error, message)

                    if not (lisp_db.get("locators") or []):
                        error = "PETR Availability - Missing Locators"
                        message = (
                            f"Border {hostname} has 0.0.0.0/0 in LISP DB, but 0 RLOCs. "
                            "Remediation: The locator-set 'DEFAULT_ETR_LOCATOR' is unavailable or has lost its Loopback0 definition."
                        )
                        exit_program(step, process, subprocess, hostname, error, message)

        # Validation 2: iBGP Redundancy (Classic LISP/BGP only)
        if not is_pubsub_site and border_type in ["isexternal", "isanywhere"]:
            bgp_neighbors = getattr(border, "bgpneighborsinfo", []) or []
            has_ibgp_up = False
            for nbr in bgp_neighbors:
                bgp_obj = getattr(nbr, "bgpneighbor", {}) or {}
                vrf_data = bgp_obj.get("vrf", {}).get(border.vrf, {}).get("neighbor", {}).get(nbr.neighborip, {})
                if (vrf_data.get("link") == "internal" and vrf_data.get("session_state") == "Established"):
                    has_ibgp_up = True
                    break

            if not has_ibgp_up:
                msg1 = "Multi-Border - Redundancy Warning"
                message = (
                    f"Border {hostname} is an external exit but has no established iBGP neighbors in VRF {border.vrf}. "
                    "This indicates a lack of overlay redundancy for external reachability."
                )
                logging_warning(step, process, subprocess, hostname, msg1 + " | " + message)
                step += 1

        # Validation 3: L3 Handoff Prefixes in LISP (Loop Prevention)
        if border_type in ["isinternal", "isanywhere"]:
            lisp_local = getattr(border, "lispfwdinglocaleid", {}) or {}
            fabric_prefixes = lisp_local.get("prefixes", [])

            # Identify handoff subnets belonging to OTHER borders
            other_borders_handoffs = []
            for h_name, h_nets in handoff_map.items():
                if h_name != hostname:
                    other_borders_handoffs.extend(h_nets)

            conflicts = []
            for f_pref in fabric_prefixes:
                try:
                    f_net = ipaddress.ip_network(f_pref, strict=False)
                    for h_net in other_borders_handoffs:
                        if f_net.overlaps(h_net):
                            conflicts.append(f"{f_net} overlaps with peer handoff {h_net}")
                except ValueError:
                    continue

            if conflicts:
                error = "Multi-Border - L3 Handoff Leak"
                message = (
                    f"Border {hostname} is importing L3 handoff subnets belonging to PEER borders into the LISP database: {conflicts}. "
                    "This can cause invalid LISP-to-LISP recursion and routing loops."
                )
                exit_program(step, process, subprocess, hostname, error, message)
            else:
                msg1 = "Multi-Border - LISP Leak Check"
                message = f"No foreign L3 handoff leaks detected in LISP database for {hostname}."
                logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
                step += 1

        # Validation 4: VPNv4 iBGP Session (Classic LISP/BGP + Non-Collocated only)
        if not is_pubsub_site and not is_collocated_cp:
            bgp_neighbors = getattr(border, "bgpneighborsinfo", []) or []
            has_vpnv4_up = False

            for nbr_info in bgp_neighbors:
                if not getattr(nbr_info, "is_vpnv4_enabled", False):
                    continue

                nbr_ip = getattr(nbr_info, "neighborip", None)
                bgp_dict = getattr(nbr_info, "bgpneighbor", {}) or {}
                nbr_data = bgp_dict.get("vrf", {}).get("default", {}).get("neighbor", {}).get(nbr_ip, {})

                if (nbr_data.get("link") == "internal" and nbr_data.get("session_state") == "Established"):
                    has_vpnv4_up = True
                    break

            if not has_vpnv4_up:
                error = "Multi-Border - No VPNv4 Session"
                message = (
                    f"Border {hostname} is a non-collocated node in a LISP/BGP design, but no established VPNv4 iBGP sessions were found. "
                    "This is required to receive endpoint reachability from the Control Plane."
                )
                exit_program(step, process, subprocess, hostname, error, message)
            else:
                msg1 = "Multi-Border - VPNv4 Session OK"
                message = f"Border {hostname} has at least one established VPNv4 iBGP session."
                logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
                step += 1
        else:
            reason = "Pub/Sub is enabled" if is_pubsub_site else "Border is a collocated Control Plane"
            msg1 = "Multi-Border - VPNv4 Session"
            message = f"VPNv4 session check skipped for {hostname} because {reason}."
            logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
            step += 1

    return step

#Concurrent Border Collection

def _fetch_single_border_data(border, fabric_id, vrf, vlanid, srcip, dstip, service, isdhcp, iid, catc_name,
                              control_planes, step):
    """
    Worker function: Performs all heavy CLI collection and parsing in parallel.
    This function does NOT perform logging to avoid interleaved/messy logs.
    """
    reachability_status = (border.get("status") or "").strip().lower()
    if reachability_status != "reachable":
        return None

    mgmtip = border['managementIpAddress']

    # 1. Initialize Object
    border_object = BorderDevice(mgmtip)
    border_object.api_parameters(border)

    # 2. Heavy Data Collection (The slow parts)
    border_object.device_profiler(isdhcp, catc_name, service, step)
    border_object.append_cp_objects(control_planes)

    # Determine type
    isinternal = bool(border_object.api_parameters.get("importExternalRoutes"))
    isexternal = bool(border_object.api_parameters.get("isDefaultExit"))
    if isinternal and isexternal:
        border_object.type = "isanywhere"
        border_type = "isanywhere"
    elif isexternal:
        border_object.type = "isexternal"
        border_type =  "isexternal"
    else:
        border_object.type = "isinternal"
        border_type = "isinternal"

    # 3. Continue Collection
    border_object.ip_transit_handoffs(service, step)
    border_object.anycastgateways(vlanid, service, step)

    # Calculate prefix for BGP/LISP methods
    anycastgw = border_object.anycastgwinfo
    ip4 = ((anycastgw.get("ipPoolDetails", {}) or {}).get("ipV4AddressSpace", {}) or {})
    gateway_ip = ip4.get("gatewayIpAddress")
    prefixandslash = f"{ip4.get('subnet')}/{ip4.get('prefixLength')}"

    border_object.vrf_information(vrf, gateway_ip, service, step)
    border_object.bgp_information(dstip, service)
    border_object.bgp_local_route(prefixandslash, service)
    border_object.bgp_vpnv4(service)
    if border_type in ["isexternal", "isanywhere"]:
        border_object.defaultetrlocator(border_type, service, step)
    # CEF Recursion (The most time-consuming part)
    border_object.forwarding_to_destination(dstip, service, step)
    border_object.forwarding_to_source(srcip, isdhcp, service, step)

    # LISP Parameters
    destroute = border_object.bgpinfo.route
    prefixes = (
                       (((destroute.get("instance", {}) or {}).get("default", {}) or {}).get("vrf", {}) or {})
                       .get(vrf, {}) or {}
               ).get("address_family", {}).get("vpnv4 unicast", {}).get("prefixes", {}) or {}
    prefix = next(iter(prefixes.keys()), None)

    border_object.lisp_parameters(prefix, service, step)

    # Final checks
    border_object.ping(service, step)
    border_object.interface_counters(service)
    border_object.acl_information(service)
    border_object.cts_information(service, step)

    return border_object


def border_ip_transit(step, catc_name, fabric_id, vrf, vlanid, srcip, dstip, service, isdhcp: bool, iid):
    process = "externalConnectivity"
    subprocess = "[main]"

    # Initial Setup
    logging_info(step, process, subprocess, catc_name,
                 "External Connectivity - Main | Profiling fabric site border nodes")
    step += 1

    l3_borders = in_site_fabric_borders(step, fabric_id, catc_name, service)
    control_planes = validate_control_plane_status(fabric_id, iid, catc_name, service, step)
    step += 1

    # --- PHASE 1: Parallel Collection ---
    # We use a thread pool to fetch data from all borders simultaneously
    reachable_borders = [b for b in l3_borders if (b.get("status") or "").strip().lower() == "reachable"]

    with ThreadPoolExecutor(max_workers=len(reachable_borders)) as executor:
        # Bind static arguments to the worker function
        worker_func = partial(_fetch_single_border_data,
                              fabric_id=fabric_id, vrf=vrf, vlanid=vlanid, srcip=srcip,
                              dstip=dstip, service=service, isdhcp=isdhcp, iid=iid,
                              catc_name=catc_name, control_planes=control_planes, step=step)

        # Execute in parallel
        results = list(executor.map(worker_func, reachable_borders))

    # --- PHASE 2: Sequential Logging & Validation ---
    # Now we loop through the results to print the logs in the correct order
    border_objects = []
    for border_object in results:
        #border_print_attributes(border_object)
        if border_object is None:
            continue

        mgmtip = border_object.mgmtip

        # Re-generate the "Discovery" logs so the user sees progress in the log file
        logging_info(step, process, "[deviceProfiler]", catc_name,
                     f"External Connectivity - Main | Profiling Border device {mgmtip}.")
        step += 1
        logging_info(step, process, "[deviceProfiler]", catc_name,
                     f"External Connectivity - Border Role | Identifying {mgmtip} Border type.")
        step += 1
        logging_info(step, process, "[l3Handoffs]", catc_name,
                     f"External Connectivity - Border L3 Handoffs | Identifying {mgmtip} L3 HandOffs.")
        step += 1
        logging_info(step, process, "[l3Handoffs]", catc_name,
                     f"External Connectivity - Border Anycast Gateways | Identifying {mgmtip} VRF details and Anycast Gateways.")
        step += 1
        logging_info(step, process, "[l3Handoffs]", catc_name,
                     f"External Connectivity - Border BGP Information | Verifying {mgmtip} BGP Configuration and Neighbor Information.")
        step += 1

        # Run the validation logic (if/else checks)
        individual_border_validations(border_object, step, service)

        border_objects.append(border_object)
    #Multi_Border_validation:
    multi_border_validation(border_objects,step,service)

    return border_objects, step

