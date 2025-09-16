import sys

from genie.libs.sdk.apis.iosxe.platform.configure import configure_platform_mgmt_interface

from catalystcenterapi.catcapi import find_control_plane
from device_profiler import Device
from ipverifications import (
   mac_address_validator,
   ipaddress_validator_no_return,
   ipsubnet_validator_no_return
)
from routingmodules.cef import IPCef, physical_recursion, phy_cef_collection
from routingmodules.iprouting import IPRoute, IGPInfo
from securitymodules.accesslists import AccessList, hexdecimal_representation_acl, acl_evaluation
from securitymodules.ciscotrustsec import cts_endpoint_info, cts_rules, cts_rule_collection
from switchingmodules.interfaces import Interfaces
from switchingmodules.maclearning import mac_learning
from routingmodules.lisp import l2lisp_info, LISPLocalDB, LISPEIDWatch, lisp_map_servers, LISPInstanceStatus, \
    LISPSession
from radkit_cli import logging_info,logging_error,logging_warning,get_catc_api,get_any_single_output,get_single_output_genie
from pprint import pformat

from traffic_flows.operational_tests import Ping


#LISP Session Troubleshooting Steps:
#1 Identify the EID to register (MAC (UDP/TCP), IP (UDP/TCP), AR(TCP)
#2 Identify if the method for LISP DB insertion (DynamicEID/SISF, Route-Import, Static, WLC notification).
#3 Identify the limits of method registration
#4 Identify the limits for DB insertion
#5 Identify if the EID is in the LISP Database (Can be IP, EID, Prefix, Host, etc)
#7 Identify the source RLOC for registration (valid RLOC)
#8 Identify the Map-Resolvers for the Registration, verify proxy flag, node must be ETR
#9 Identify the status of the LISP session (global)
#10 Identify the status of the LISP session (per ID, Optional)
#11 Identify LISP registration metrics and statistics
#12 UDP Listen State in MS/MR
#13 TCP test in ETR
#13 Recurse route to the Mpa Servers
#14 Identify global MTU and egress interface (lowest) MTU towards the Map-Servers
#15 Identify global MTU and egress interface (lowest) MTU towards the ETR
#16 Verify if PMTUD is enabled or not between ETR and MS
#17 ICMP MTU Validations (Informational)
#18 CTS Rules and Enforcement
#19 Identify the status of the TCP socket
#20 Identify the status of the TCB (mss, retransmissions, pmtud)
#21 MS/MR Site_UCI configuration (definition as map-server, map-resolver, site_uci, rloc_members distribute, domain/MID consistency (pubsub)
#22 MS/MR has EID space configured (L2,L3)
#23 MS/MR limits and statistics
#24 Authentication Counters for EID in both ETR and MS/MR (looking for logs as well?)
#25 Session State between CPs
#26 Registration is in both CPs?
#27 L2LISP Statistics
#28 WLC RLOC definition and passiveopen

class EIDIdentification():
    def __init__(self, device,eid):
        self.device = device
        self.eid = eid

    def eid_identification(self,vlan,vrf,service,step):
        #If the EID is a MAC address, it must come from L2SISF.
        #If the EID is an IPv4 address but the AR flag is set, treat it as AR binding
        #If the EID is an IPv4 address, it must be a /32 to NOT be Dynamic EID
        #If it is /32, search for Dynamic EID, there must be an L3 interface binded with a DynamicEID group
        #If it is /32 and there is no Dynamic EID, fallback to a possible database-mapping (search through the VRF LISP configuration)
        #If it is /32 and there is no static database-mapping, the only possible method is route-import from BGP, search over BGP table) and the role must be border
        #If it is not /32, fallback to database-mapping and route-import in the same order.
        #Relevant Parameters: EID, Type, Source (Route-Import, AutoL2, DynamicEid, Static, Map-Notify, Publication)
        eid = self.eid
        device = self.device
        db_status = False
        db_method = None
        reg_status = None
        origin = None
        origin_state = None
        iid = None

        step = step
        process = "lispSession"
        subprocess ="eidIdentification"
        #Identify if the EID is a MAC or an IP:
        if mac_address_validator(eid)[0] is True:
            eid_type = "MAC"
        elif ipaddress_validator_no_return(eid) is True:
            eid_type = "IPv4Host"
        elif ipsubnet_validator_no_return(eid) is True:
            eid_type = "IPv4Subnet"
        else:
            eid_type = "Unsupported"

        #L2SISF Identification
        if eid_type == "MAC":
            #MATM State:
            qtype = 'ethernet'
            origin = "MATM"
            macstate = mac_learning(device)
            macstate.mac_learning_mac(eid,vlan,service)
            try:
                mac = macstate.mac
                origin_state = True
            except AttributeError:
                mac = None
                origin_state = None
            if mac is None:
                error = "EID Identification - MAC Learning"
                message = "The following MAC {} is NOT found in the MAC Address Table for VLAN {}. Review the GPS_SDA Collection logfile for more information.".format(eid,vlan)
                exit_program(step, process, subprocess, device, error, message)
            if macstate.port == "L2LI0":
                error = "EID Identification - MAC Learning"
                message = "The following MAC {} is NOT a local MAC address, it points to a LISP Interface. Review the GPS_SDA Collection logfile for more information.".format(mac)
                exit_program(step, process, subprocess, device, error, message)

            #L2SISF - Nathan
                #1 Search for MAC entry, reachable state
                #2 If not in MAC entry, review SISF Limits

            #L2IID
            iid = l2lisp_info()
            iid.l2_lisp_instance(device,vlan,service)
            iid = iid.l2lispiid
            if iid is None:
                error = "EID Identification - L2LISP Instance"
                message = "The  L2LISP Instance is NOT found in the LISP EID Table for VLAN {}. Review the GPS_SDA Collection logfile for more information.".format(vlan)
                exit_program(step, process, subprocess, device, error, message)

            self.iid = iid
            #L2DB Method.
                #1. Search for database mac under L2LISP, error if not configured.
            lispdb = LISPLocalDB(mac,iid,device)
            lispdb.L2LISPDyn(service)

                #2. Search for DynEID entry
            dynmacs = lispdb.dynmacs
            is_mac_dyn = False
            for mac in dynmacs:
                if mac==eid:
                    is_mac_dyn = True
            is_mac_static = False
            if is_mac_dyn is False:
                print ("MAC Address {} not found in Dynamic EID for IID {} searching for Static Binding".format(eid,iid))
                #3. Search for static DB if any
                lispdb.L2LISPStaticDB(service)
                for mac in lispdb.static_mappings:
                    if eid == mac:
                        print("MAC Address {} not found in Dynamic EID for IID {} but it is configured as Static Binding, this is not standard SD-Access Configuration".format(eid,iid))
                        is_mac_static = True

            # 4. If not in any of these methods:
            if is_mac_dyn is False and is_mac_static is False:
                print ("WARNING!: MAC Address {} not found in Dynamic EID for IID {} neither as Static Binding, verifying LISP limits".format(eid,iid))
                lispdb.LISPDBLimits(qtype, service)
                if lispdb.total_database is None:
                    sys.exit("Unable to retrieve LISPDB statistics from IID {}, parser exception".format(iid))
                else:
                    if is_mac_static is True and lispdb.static_database_pr > 97:
                        sys.exit("WARNING!: MAC Address {} is Static Binding for IID {}, total utilization of Static Bindings exceed 97%".format(
                                eid, iid))
                    elif is_mac_static is False and lispdb.dynamic_database_pr  > 97:
                        sys.exit("WARNING!: MAC Address {} is DynEID for IID {}, total utilization of Database Bindings exceed 97%".format(
                                eid, iid))
                    else:
                        print("MAC Address {} not found in Dynamic EID for IID {} neither as Static Binding, verifying Global LISP Limits".format(eid,iid))
                        if lispdb.global_database_usage_pr > 97:
                            sys.exit("WARNING!: MAC Address {} is DynEID for IID {}, total utilization of Total Database Bindings exceed 97%".format( eid, iid))
                        else:
                            print ("MAC Address {} is DynEID for IID {}, total utilization of Total Database Bindings below 97%, verifying EID Watch state".format( eid, iid))
                            eidwatch = LISPEIDWatch(device,iid)
                            eidwatch.eidwatch_status(qtype,'SISF client',service)
                            if eidwatch.processid is None:
                                sys.exit( "EID Watch process for LISP IID {} not found, unable to retrieve any more details".format(iid))
                            else:
                                if eidwatch.connection_status != 'ENABLED':
                                    sys.exit("EID Watch process for LISP IID {} found with process {}, connection to LISP process is {} SISF-LISP process is impacted".format(iid,eidwatch.processid,eidwatch.connection_status))
                                else:
                                    sys.exit("EID Watch process for LISP IID {} found with process {}, connection to LISP process is {} unable to determine root cause".format(iid,eidwatch.processid,eidwatch.connection_status))
            #L2DB State
            lispdb.LISPDBEntry(qtype, service)

            if lispdb.address_family is None:
                print("MAC Address {} not found in LISP Database for IID {} ".format(eid,iid))
                if  lispdb.static_database_pr > 97:
                    sys.exit("WARNING!: MAC Address {} not found LISP Database {}, total utilization of Static Bindings exceed 97%".format(
                            eid, iid))
                elif lispdb.dynamic_database_pr > 97:
                    sys.exit("WARNING!: MAC Address {} not found LISP Database {}, total utilization of Database Bindings exceed 97%".format(
                            eid, iid))
                else:
                    print("MAC Address {} not found LISP Database for IID {} neither as Static Binding, verifying Global LISP Limits".format(
                            eid, iid))
                    if lispdb.global_database_usage_pr > 97:
                        sys.exit("WARNING!: MAC Address {} not found LISP Database for IID {}, total utilization of Total Database Bindings exceed 97%".format(
                                eid, iid))
            else:
                db_method = lispdb.eid_origin
                if len(lispdb.locators) == 0:
                    sys.exit("MAC Address {} is LISP Database for IID {} but no RLOC is configured, verify if the Loopback0 interface is defined as RLOC".format(eid, iid))
                else:
                    db_status = True
                if len(lispdb.mapservers) == 0:
                    sys.exit("MAC Address {} is LISP Database for IID {} but no Map_Server is configured, verify if Map_Servers are defined in the L2LISP IID".format(eid, iid))
                else:
                    reg_status = lispdb.mapservers

        self.eid_type = eid_type
        self.origin = origin
        self.origin_state = origin_state
        self.db_method = db_method
        self.db_status = db_status
        self.mapservers = reg_status
        #return eid, eid_type, origin, origin_state, iid, db_method, db_status, reg_status

class ETRConfiguration():
    def __init__(self,device):
        self.device = device

    def etr_map_servers(self,eidident,service):
        # 8 Identify the Map-Resolvers for the Registration, verify proxy flag, node must be ETR
        # 9 Identify the status of the LISP session (global)
        # 10 Identify the status of the LISP session (per ID, Optional)
        device = self.device
        map_servers = eidident.mapservers

        step = "X"
        process = "lispSession"
        subprocess = "[mapServerConfiguration]"
        #Map Server Configuration Validations:
            #P-Flag Enablement #Unreliable check...
            #ETR Status
        # P-Flag Enablement #Unreliable check...
        mapservers_shwrun = lisp_map_servers(device,service)
        map_servers_noflag = find_mismatch_key_and_proxy_reply(mapservers_shwrun)
        if len(map_servers_noflag) > 0:
            error = "LISP Configuration - Map Servers"
            message = "The following Map-Servers {} are NOT configured for Proxy-Reply flag. Review the GPS_SDA Collection logfile for more information.".format(map_servers_noflag)
            exit_program(step,process,subprocess,device,error,message)

def exit_program(step, process, subprocess, hostname, error, message):
    logging_error(step, process, subprocess, hostname, error)
    logging_info(step, process, subprocess, hostname, message)
    sys.exit("Error: {} | {}".format(error, message))

def find_mismatch_key_and_proxy_reply(output):
    # Split the output into lines
    lines = output.strip().split("\n")

    # Dictionaries to count "key" and "proxy-reply" occurrences for each IP
    key_counts = {}
    proxy_reply_counts = {}

    for line in lines:
        # Check if the line contains "etr map-server"
        if "etr map-server" in line:
            parts = line.split()
            ip = parts[2]  # Extract the IP address

            # Count occurrences of "key"
            if "key" in line:
                if ip not in key_counts:
                    key_counts[ip] = 0
                key_counts[ip] += 1

            # Count occurrences of "proxy-reply"
            if "proxy-reply" in line:
                if ip not in proxy_reply_counts:
                    proxy_reply_counts[ip] = 0
                proxy_reply_counts[ip] += 1

    # Find IPs where the "key" count doesn't match the "proxy-reply" count
    mismatched_ips = []
    for ip in key_counts:
        key_count = key_counts.get(ip, 0)
        proxy_reply_count = proxy_reply_counts.get(ip, 0)
        if key_count != proxy_reply_count:
            mismatched_ips.append(ip)

    return mismatched_ips

def cp_routing(step,specific_lisp_session, mapserverip,hostname,service):
    # Route Check:
    process = "lispSession"
    subprocess = "[routing]"

    state = specific_lisp_session.session_state
    step = step + 1
    route = IPRoute(mapserverip, None, hostname)
    route.iproute_prefix(service, step)
    if route.mask == '0':
        error = "LISP Specific Session - IP Routing"
        message = "LISP Session to {} is in state {} on device {}. The routing table entry to the Map-Server/ETR is not specific, it uses a default route".format(
            mapserverip, state, hostname)
        exit_program(step, process, subprocess, hostname, error, message)
    else:
        error = "LISP Specific Session - IP Routing"
        message = "A route exists to the Map-Server/ETR {}, nexthop(s) are: {}".format(mapserverip,
                                                                                                  route.nexthop,
                                                                                                  hostname)
        logging_info(step, process, subprocess, hostname, error + " | " + message)
    # IGP Neighbors

    step = step + 1
    cef = IPCef(mapserverip, None, hostname)
    cef.get_cef_internal(service)
    error = "LISP Specific Session - CEF"
    message = "A  CEF entry exists to the Map-Server {}, nexthop(s) are: {}".format(mapserverip,
                                                                                                  cef.nexthops,
                                                                                                  hostname)
    logging_info(step, process, subprocess, hostname, error + " | " + message)

    for entry in cef.nexthops:
        oif = entry['oif']
        if oif == "Null0":
            error = "LISP Specific Session - IP Routing"
            message = "LISP Session to {} is in state {} on device {}. The CEF table entry to the Map-Server/ETR is Null0, this results in traffic drop".format(
                mapserverip, state, hostname)
            exit_program(step, process, subprocess, hostname, error, message)

    # Physical Recursion:
    step = step + 1
    if 'onnected' not in route.protocol:
        igp = route.protocol
        phys = IGPInfo(hostname)
        phys.igp_neighbors(igp, service)
        if phys.igp_neighbors is None:
            error = "LISP Specific Sessions - Unable to recurse route"
            message = "LISP Session to {} is in state {} on device {}. but the flow was unable to find the neighbor interfaces for the IGP: {}".format(
                mapserverip, state, hostname, igp)
            logging_warning(step, process, subprocess, hostname, error + " | " + message)
        else:
            phyinterfaces = phys.neighbor_interfaces
            error = "LISP Specific Session - Physical Interfaces"
            message = "A valid/specific CEF entry exists to the Map-Server {}, physical interfaces towards CP are: {}".format(
                mapserverip, phyinterfaces, hostname)
            logging_info(step, process, subprocess, hostname, error + " | " + message)
    else:
        phy = route.nexthop
        phys = [phy]

    #Returned objects: routing object, cef object, igp object and physical interfaces
    return route, cef, phys

def session_access_lists(acls,hostname,service,mapserverip,step,etrdefinition):
    process = "lispSession"
    subprocess = "[accessLists]"
    total_acls = acls
    if len(total_acls) != 0:
        error = "LISP Specific Session - ACLs"
        message = "ACLs found on physical interfaces in the direction to the Map-Server {} on device: {}, evaluating ACLs".format(
            mapserverip, hostname)
        logging_info(step, process, subprocess, hostname, error + " | " + message)
        # Verifying if LISP attributes are blocked by any of the ACLs: tcp/udp, any-to-4342 and 4342-to-any
        evaluation = {'sourceip': etrdefinition.profiled_device.loopback,
                      'destinationip': mapserverip,
                      'protocol': 'tcp',
                      'srcport': 4342,
                      'dstport': 4342}
        revaluation = {'sourceip': mapserverip,
                       'destinationip': etrdefinition.profiled_device.loopback,
                       'protocol': 'tcp',
                       'srcport': 4342,
                       'dstport': 4342}
        for acl in total_acls:
            hit = acl_evaluation(service, hostname, acl,False,evaluation)
            if hit[1] == 'deny':
                error = "LISP Session - Denied by ACL"
                message = "The ACL {} on {} denying traffic from the device RLOC and the Map-Server {} in sequence: {}".format(
                    acl, hostname, mapserverip, hit[2])
                logging_error(step, process, subprocess, hostname, error)
                logging_info(step, process, subprocess, hostname, message)
                # raise BDBTaskError("Error: {} | {}".format(error,message))
                sys.exit("Error: {} | {}".format(error, message))
            if hit[1] == 'permit':
                in_acl_summary = "The ACL {} on {} is allowing traffic from the device RLOC and the Map-Server {} in sequence: {}".format(
                    acl, hostname, mapserverip, hit[2])
                logging_info(step, process, subprocess, hostname, in_acl_summary)
            hit = acl_evaluation(service, hostname, acl, False,revaluation)
            if hit[1] == 'deny':
                error = "LISP Session - Denied by ACL"
                message = "The ACL {} on {} denying traffic from the Map-Server {} to the device RLOC in sequence: {}".format(
                    acl, hostname, mapserverip, hit[2])
                logging_error(step, process, subprocess, hostname, error)
                logging_info(step, process, subprocess, hostname, message)
                # raise BDBTaskError("Error: {} | {}".format(error,message))
                sys.exit("Error: {} | {}".format(error, message))
            if hit[1] == 'permit':
                in_acl_summary = "The ACL {} on {} is allowing traffic from the Map-Server {} to the device RLOC in sequence: {}".format(
                    acl, hostname, mapserverip, hit[2])
                logging_info(step, process, subprocess, hostname, in_acl_summary)
    return step

def cp_ping_tests(interfaces,hostname,service,step,loopback,mapserverip):
    process = "lispSession"
    subprocess = "[pingTests]"

    interfaceobjects = []
    mtus = []
    for interface in interfaces:
        interfaceinfo = Interfaces(interface, hostname)
        interfaceinfo.show_interface(service)
        interfaceobjects.append(interfaceinfo)
    for interfaceobject in interfaceobjects:
        phy_cef_collection(interfaceobject, step)
        mtus.append(interfaceobject.mtu)
    mtus.sort()
    minimum = mtus[0]
    error = "LISP Specific Session - Physical Interfaces"
    message = "The lowest MTU between underlay interfaces for device: {} is {}".format(hostname, minimum)
    logging_info(step, process, subprocess, hostname, error + " | " + message)

    # RLOC to RLOC Ping Validation
    # 1) Without MTU
    # print ("RLOC to RLOC results with low MTU")
    rloc = loopback
    normal_ping = Ping(mapserverip, hostname)
    normal_ping.ping_with_source(None, rloc, None, False, service)
    # 2) With MTU
    mtu_ping = Ping(mapserverip, hostname)
    mtu_ping.ping_with_source(None, rloc, minimum, True, service)

    if int(normal_ping.result) <= 70:
        logging_warning(step, process, subprocess, hostname,
                        "WARNING! : Packet Loss from {} to {} is below threshold of 70%, current value is {} % with low MTU".format(
                            hostname, mapserverip, normal_ping.result))
    else:
        logging_info(step, process, subprocess, hostname,
                     "ICMP Connectivity from {} to {} is good at {} % success rate with low MTU".format(hostname,
                                                                                                        mapserverip,
                                                                                                        normal_ping.result))
    if int(mtu_ping.result) <= 70:
        logging_warning(step, process, subprocess, hostname,
                        "WARNING! : Packet Loss from {} to {} is below threshold of 70%, current value is {} % with {} MTU".format(
                            hostname, mapserverip, normal_ping.result, minimum))
    else:
        logging_info(step, process, subprocess, hostname,
                     "ICMP Connectivity from {} to {} is good at {} % success rate with {} MTU".format(
                         hostname, mapserverip, normal_ping.result, minimum))
    return None

def cp_trustsec_rules(step,loopback,mapserverip,hostname,service):
    process = "lispSession"
    subprocess = "[ciscoTrustSec]"
    srcctsinfo = cts_endpoint_info(loopback, None, hostname)
    srcctsinfo.cts_sgt_mapping(service)
    srcctsbinding = {'ip': srcctsinfo.endpoint_ip, 'sgt': srcctsinfo.sgt, 'source': srcctsinfo.source}
    dstctsinfo = cts_endpoint_info(mapserverip, None, hostname)
    dstctsinfo.cts_sgt_mapping(service)
    dstctsbinding = {'ip': dstctsinfo.endpoint_ip, 'sgt': dstctsinfo.sgt, 'source': dstctsinfo.source}
    sgt = srcctsbinding['sgt']
    dgt = dstctsbinding['sgt']
    logging_info(step, process, subprocess,"Main", "Identifying CTS Rule used for traffic between {} and {}".format(loopback,mapserverip))
    logging_info(step, process, subprocess,"Main", "Source SGT is {} and Destination SGT is {}".format(sgt,dgt))
    ctsrules = cts_rules(hostname)
    ctsrules.cts_rbac_permissions(sgt, dgt, service)
    rbacl = ctsrules.rbacl
    if ctsrules.isdefaultrule:
        ctsrules.cts_rbac_counters(0, 0, service)
        ctsrules.cts_rbac_rbacls(rbacl, service)
        cts_rule_collection(ctsrules, 0)
        try:
            if ctsrules.defaultpermit is True:
                ctsrules.aces = None
        except AttributeError:
            pass
        cts_rule_collection(ctsrules, 0)
    else:
        ctsrules.cts_rbac_rbacls(rbacl, service)
        ctsrules.cts_rbac_counters(sgt, dgt, service)
        cts_rule_collection(ctsrules, 0)

    if ctsrules.isdefaultrule is True:
        logging_info(step, process, subprocess, hostname, "No specific rule found for SGT {} and Destination SGT {} on device {}, using default rule".format(sgt,dgt,hostname))
        logging_info(step, process, subprocess, hostname, "Default rule information is: {}".format(ctsrules.rbacl))
        logging_info(step, process, subprocess, hostname, "ACEs for the default rule: {}".format(ctsrules.aces))
    else:
        logging_info(step, process, subprocess, hostname, "Specific rule found for SGT {} and Destination SGT {} on device {}, using RBACL: {}".format(sgt,dgt,hostname, ctsrules.rbacl))
        logging_info(step, process, subprocess, hostname, "ACEs for the specific rule: {}".format(ctsrules.aces))
    if (ctsrules.hw_denied_count > 0) or (ctsrules.sw_denied_count > 0):
        logging_warning(step, process, subprocess, hostname,"WARNING! : CTS Counters found for rule from SGT {} to SGT {} on device: {}".format(sgt, dgt, hostname))
    else:
        logging_info(step, process, subprocess, hostname, "CTS Counters NOT dropping for rule from SGT {} to SGT {} on device: {}".format(sgt, dgt, hostname))

    return ctsrules

def session_rbacls(step,acl,loopback,mapserverip,hostname,service):
    process = "lispSession"
    subprocess = "[ciscoTrustSec]"
    error = "LISP Specific Session - RBACLs"
    message = "SGACL/RBACL found on in the direction to the Map-Server {} on device: {}, evaluating RBACL".format(
            mapserverip, hostname)
    logging_info(step, process, subprocess, hostname, error + " | " + message)
    # Verifying if LISP attributes are blocked by any of the ACLs: tcp/udp, any-to-4342 and 4342-to-any
    evaluation = {'sourceip': loopback,
                      'destinationip': mapserverip,
                      'protocol': 'tcp',
                      'srcport': 65535,
                      'dstport': 4342}
    revaluation = {'sourceip': mapserverip,
                       'destinationip': loopback,
                       'protocol': 'tcp',
                       'srcport': 4342,
                       'dstport': 65535}
    hit = acl_evaluation(service, hostname, acl,True,evaluation)
    if hit[1] == 'deny':
                error = "LISP Session - Denied by RBACL"
                message = "The RBACL {} on {} denying traffic from the device RLOC and the Map-Server {} in sequence: {}".format(
                    acl, hostname, mapserverip, hit[2])
                logging_error(step, process, subprocess, hostname, error)
                logging_info(step, process, subprocess, hostname, message)
                # raise BDBTaskError("Error: {} | {}".format(error,message))
                sys.exit("Error: {} | {}".format(error, message))
    if hit[1] == 'permit':
                in_acl_summary = "The RBACL {} on {} is allowing traffic from the device RLOC and the Map-Server {} in sequence: {}".format(
                    acl, hostname, mapserverip, hit[2])
                logging_info(step, process, subprocess, hostname, in_acl_summary)
    hit = acl_evaluation(service, hostname, acl, True,revaluation)
    if hit[1] == 'deny':
                error = "LISP Session - Denied by RBACL"
                message = "The ACL {} on {} denying traffic from the Map-Server {} to the device RLOC in sequence: {}".format(
                    acl, hostname, mapserverip, hit[2])
                logging_error(step, process, subprocess, hostname, error)
                logging_info(step, process, subprocess, hostname, message)
                # raise BDBTaskError("Error: {} | {}".format(error,message))
                sys.exit("Error: {} | {}".format(error, message))
    if hit[1] == 'permit':
                in_acl_summary = "The RBACL {} on {} is allowing traffic from the Map-Server {} to the device RLOC in sequence: {}".format(
                    acl, hostname, mapserverip, hit[2])
                logging_info(step, process, subprocess, hostname, in_acl_summary)
    return None

def down_init_procedure(mapserverip,catc_name,service,step,hostname,etrdefinition,specific_lisp_session):
    process = "lispSession"
    subprocess = "[downInitControlPlane]"
    # Verify if the Control Plane is reachable by Catalyst Center, if so, perform the checks, if unreachable, consider it unavailable and expected to be in this state.
    control_plane = find_control_plane(mapserverip, catc_name, service, step, process, subprocess)
    cp_hostname = control_plane['radkithostname']
    cp_status = control_plane['reachability']
    step = step + 1
    error = "LISP Specific Sessions - Catalyst Center Reachability"
    message = "Control Plane {} reachability status on Catalyst Center is \"{}\", unreachable CP's will not be considered as failure".format(
        cp_hostname, cp_status)
    logging_warning(step, process, subprocess, hostname, error + " | " + message)
    loopback = etrdefinition.profiled_device.loopback
    if cp_status == 'Reachable':
        # Routing, CEF and Phy Validation
        routing_state = cp_routing(step, specific_lisp_session, mapserverip, hostname, service)
        interfaces = routing_state[2].neighbor_interfaces
        # ACL Validation
        step = step + 1
        total_acls = []
        for interface in interfaces:
            acls = AccessList(hostname)
            acls.aclbyinterface(interface, service)
            if len(acls.aclnames) != 0:
                for acl in acls.aclnames:
                    total_acls.append(acl)
        total_acls = set(total_acls)
        step = session_access_lists(total_acls, hostname, service, mapserverip, step, etrdefinition)
        # CTS Validation
        step = step + 1
        # Identify if the IGP interfaces are CTS enabled or not, possibly VLAN = check enforcement or Physical = check cts enabled.
        # Supported interfaces: Physical - CTS disabled on the IF, VLAN - CTS disabled on the VLAN, PortChannel (L3) - CTS disabled on the members (not portchanneling for now)
        interfacectsflag = False
        for interface in interfaces:
            if "Vlan" in interface:
                vlan_id = int(interface[4:])  # Remove 'Vlan' prefix and convert to integer
                ctsinterface = cts_endpoint_info(None, None, hostname)
                ctsinterface.cts_enforcement(vlan_id, None, service)
                if (ctsinterface.vlanenforcement is True) and (ctsinterface.globalenforcement is True) and (
                        ctsinterface.enforcingvlan is True):
                    error = "LISP Specific Sessions - Interface CTS Enforcement"
                    message = "CTS Enforcement is enabled on interface {} on device {}. Verifying RBACL Rules".format(
                        interface, hostname)
                    logging_info(step, process, subprocess, hostname, error + " | " + message)
                    interfacectsflag = True
                    rules = cp_trustsec_rules(step, loopback, mapserverip, hostname, service)
                    rbacl = rules.rbacl
                    if rbacl[0] is not None:
                        session_rbacls(step, rbacl, loopback, mapserverip, hostname, service)
            elif "hannel" in interface:
                break
                # You must first enable SGACL policy enforcement globally for Cisco TrustSec-enabled routed interfaces. This feature is not supported on Port Channel interfaces
                # Get physical members
                # then same logic as physical interface
                # Not yet supported flow.
            else:
                # Physical L3 Interface
                ctsinterface = cts_endpoint_info(None, None, hostname)
                ctsinterface.cts_enforcement(None, interface, service)
                if (ctsinterface.ctsportenabled is True) and (ctsinterface.globalenforcement is True):
                    error = "LISP Specific Sessions - Interface CTS Enforcement"
                    message = "CTS Enforcement is enabled on interface {} on device {}. Verifying RBACL Rules".format(
                        interface, hostname)
                    logging_info(step, process, subprocess, hostname, error + " | " + message)
                    interfacectsflag = True
                    rules = cp_trustsec_rules(step, loopback, mapserverip, hostname, service)
                    rbacl = rules.rbacl
                    if rbacl is not None:
                        session_rbacls(step, rbacl, loopback, mapserverip, hostname, service)
        if interfacectsflag is False:
            error = "LISP Specific Sessions - Interface CTS Enforcement"
            message = "No underlay interfaces enabled for CTS Enforcement on device {}. Skipping RBACL Rules".format(
                hostname)
            logging_info(step, process, subprocess, hostname, error + " | " + message)

        # Ping Test (low MTU and MaxMTU)
        step = step + 1
        cp_ping_tests(routing_state[2].neighbor_interfaces, hostname, service, step, loopback, mapserverip)

    return step,control_plane

def map_server_local_session(step,mapserverip,state, control_plane,catc_name,service):
    # Map-Server Check: Self LISP Session.
    cp_mgmtip = control_plane['mgmtip']
    cp_hostname = control_plane['radkithostname']

    process = "lispSession"
    subprocess = "[downInitCPLocalSession]"
    step = step + 1
    error = "LISP Specific Sessions - Down or Init"
    message = "LISP Session to {} is in state {} on device {}. Performing checks on Map-Server".format(mapserverip,
                                                                                                       state, cp_hostname)
    logging_warning(step, process, subprocess, cp_hostname, error + " | " + message)

    # Device Profiling:
    cp = ETRDevice(cp_mgmtip, step)
    cp.device_profiler(catc_name, service)

    # LISP Session to the CP itself:
    cplisp = LISPSession(cp_hostname)
    cplisp.specificlispsession(mapserverip, service)
    cp_routing_state = None
    # If the Self Local LISP Session is down:
    if cplisp.session_state == 'Up':
        error = "LISP Specific Sessions - Down or Init"
        message = "LISP Session to {} is in state {} on device {}. Performing checks".format(mapserverip,
                                                                                             cplisp.session_state,
                                                                                             cp_hostname)
        logging_warning(step, process, subprocess, cp_hostname, error + " | " + message)

        # Routing, CEF and Phy Validation
        cp_routing_state = cp_routing(step, cplisp, mapserverip, cp_hostname, service)

    return step, cp_routing_state, cp

def down_init_procedure_to_etr(step,cp_hostname,etrloopback,service,cpdefinition):
    process = "lispSession"
    subprocess = "[downInitControlPlane]"
    step = step + 1
    error = "LISP Specific Sessions - Connectivity from Map-Server to ETR"
    message = "Verifying connectivity from the Map-Server (CP) {} to the affected ETR".format(
        cp_hostname)
    logging_warning(step, process, subprocess, cp_hostname, error + " | " + message)
    loopback = cpdefinition.profiled_device.loopback

    class specificsession():
        def __init__(self):
            self.session_state = 'Listening'
    specific_lisp_session = specificsession()
    specific_lisp_session.session_state = 'Listening'

    # Routing, CEF and Phy Validation
    routing_state = cp_routing(step, specific_lisp_session, etrloopback, cp_hostname, service)
    interfaces = routing_state[2].neighbor_interfaces
    # ACL Validation
    step = step + 1
    total_acls = []
    for interface in interfaces:
        acls = AccessList(cp_hostname)
        acls.aclbyinterface(interface, service)
        if len(acls.aclnames) != 0:
           for acl in acls.aclnames:
                total_acls.append(acl)
    total_acls = set(total_acls)
    step = session_access_lists(total_acls, cp_hostname, service, etrloopback, step, cpdefinition)
    # CTS Validation
    step = step + 1
    # Identify if the IGP interfaces are CTS enabled or not, possibly VLAN = check enforcement or Physical = check cts enabled.
    # Supported interfaces: Physical - CTS disabled on the IF, VLAN - CTS disabled on the VLAN, PortChannel (L3) - CTS disabled on the members (not portchanneling for now)
    interfacectsflag = False
    for interface in interfaces:
        if "Vlan" in interface:
            vlan_id = int(interface[4:])  # Remove 'Vlan' prefix and convert to integer
            ctsinterface = cts_endpoint_info(None, None, cp_hostname)
            ctsinterface.cts_enforcement(vlan_id, None, service)
            if (ctsinterface.vlanenforcement is True) and (ctsinterface.globalenforcement is True) and (
                        ctsinterface.enforcingvlan is True):
                error = "LISP Specific Sessions - Interface CTS Enforcement"
                message = "CTS Enforcement is enabled on interface {} on device {}. Verifying RBACL Rules".format(
                        interface, cp_hostname)
                logging_info(step, process, subprocess, cp_hostname, error + " | " + message)
                interfacectsflag = True
                rules = cp_trustsec_rules(step, loopback, etrloopback, cp_hostname, service)
                rbacl = rules.rbacl
                if rbacl[0] is not None:
                    session_rbacls(step, rbacl, loopback, etrloopback, cp_hostname, service)
        elif "hannel" in interface:
                break
                # You must first enable SGACL policy enforcement globally for Cisco TrustSec-enabled routed interfaces. This feature is not supported on Port Channel interfaces
                # Get physical members
                # then same logic as physical interface
                # Not yet supported flow.
        else:
                # Physical L3 Interface
                ctsinterface = cts_endpoint_info(None, None, cp_hostname)
                ctsinterface.cts_enforcement(None, interface, service)
                if (ctsinterface.ctsportenabled is True) and (ctsinterface.globalenforcement is True):
                    error = "LISP Specific Sessions - Interface CTS Enforcement"
                    message = "CTS Enforcement is enabled on interface {} on device {}. Verifying RBACL Rules".format(
                        interface, cp_hostname)
                    logging_info(step, process, subprocess, cp_hostname, error + " | " + message)
                    interfacectsflag = True
                    rules = cp_trustsec_rules(step, loopback, etrloopback, cp_hostname, service)
                    rbacl = rules.rbacl
                    if rbacl is not None:
                        session_rbacls(step, rbacl, loopback, etrloopback, cp_hostname, service)
    if interfacectsflag is False:
            error = "LISP Specific Sessions - Interface CTS Enforcement"
            message = "No underlay interfaces enabled for CTS Enforcement on device {}. Skipping RBACL Rules".format(
                cp_hostname)
            logging_info(step, process, subprocess, cp_hostname, error + " | " + message)

    # Ping Test (low MTU and MaxMTU)
    step = step + 1
    cp_ping_tests(routing_state[2].neighbor_interfaces, cp_hostname, service, step, loopback, etrloopback)

    return step

class ETRDevice:
    def __init__(self, mgmtip,step):
        self.mgmtip = mgmtip
        self.step = step

    def device_profiler(self, catc,service):
        devprof = Device(self.mgmtip,catc,self.step)
        devprof.profile_device(service)
        self.profiled_device = devprof

    def existing_profiled(self, profiled_device):
        self.profiled_device = profiled_device

    def eid_identification(self,eid,vlan,vrf,step,service):
        hostname = self.profiled_device.hostname
        eid_properties = EIDIdentification(hostname, eid)
        eid_properties.eid_identification(vlan,vrf,service,step)
        self.eid_properties = eid_properties

    def cp_configuration(self,vni,vrf,step,service):
        hostname = self.profiled_device.hostname


    def eid_configuration(self,eid_properties,service):
        hostname = self.profiled_device.hostname
        etr_configuration = ETRConfiguration(hostname)
        etr_configuration.etr_map_servers(eid_properties,service)
        self.eid_configuration = etr_configuration

    def global_lisp_session(self,service):
        hostname = self.profiled_device.hostname
        etr_lispsessions = LISPSession(hostname)
        etr_lispsessions.globallispsession(service)
        self.global_lisp_sessions = etr_lispsessions

    def specific_lisp_session(self,mapserver,service):
        hostname = self.profiled_device.hostname
        etr_specificsession = LISPSession(hostname)
        etr_specificsession.specificlispsession(mapserver,service)
        self.specific_lisp_session = etr_specificsession

        
def singleETRProfiling(mgmtip,eid,vlan,vrf,catc_name,service,step):

    #ETR
    etrdefinition = ETRDevice(mgmtip,step)
    etrdefinition.device_profiler(catc_name, service)
    hostname = etrdefinition.profiled_device.hostname

    process = "lispSession"
    subprocess = "[main]"
    msg1 = "LISP Sessions - Main"
    message = "Starting LISP Session validations on device {}.".format(hostname)
    logging_info(step, process, subprocess, hostname, msg1 + "|" + message)
    step = step+1
    # ETR Identification and Configuration (Steps 1-8)

    subprocess = "[eidIdentification]"
    msg1 = "LISP Sessions - EID Identification"
    message = "Identifying EID properties for device: {}.".format(hostname)
    logging_info(step, process, subprocess, hostname, msg1 + "|" + message)
    etrdefinition.eid_identification(eid,vlan,vrf,step,service)
    step = step + 1
    #print(pformat(vars(etrdefinition.eid_properties), indent=4, width=1, sort_dicts=False))

    subprocess = "[eidConfiguration]"
    msg1 = "LISP Sessions - EID Configuration"
    message = "Verifying LISP Map-Server configuration on device: {}.".format(hostname)
    logging_info(step, process, subprocess, hostname, msg1 + "|" + message)
    etrdefinition.eid_configuration(etrdefinition.eid_properties,service)
    step = step + 1

    # LISP Session Local Status (Global)
    subprocess = "[globalLISPSession]"
    msg1 = "LISP Sessions - Global LISP Sessions"
    message = "Verifying Local LISP session status for device:  {}.".format(hostname)
    logging_info(step, process, subprocess, hostname, msg1 + "|" + message)
    etrdefinition.global_lisp_session(service)
    #print(pformat(vars(etrdefinition.global_lisp_sessions), indent=4, width=1, sort_dicts=False))

    #Bad LISP Session states: Down, Init, NoRoute, at least 1 LISP session must be up to the map-servers and not itself.
    etr_rloc = etrdefinition.profiled_device.loopback
    lisp_sessions = etrdefinition.global_lisp_sessions.peers
    single_up = False
    for peer in lisp_sessions:
        if peer != etr_rloc:
            state = lisp_sessions[peer][0]['state']
            if state == 'Up':
                single_up = True
    if single_up is False:
        error = "LISP Sessions - All Down"
        message = "All LISP sessions are down  on device {}.".format(hostname)
        logging_warning(step, process, subprocess, hostname, error+"|"+message)
    step = step + 1

    #Verifying unique LISP sessions.
    subprocess = "[specificLISPSession]"
    msg1 = "LISP Sessions - Specific LISP Sessions"
    message = "Verifying Specific LISP session status for Map-Servers on device:  {}.".format(hostname)
    logging_info(step, process, subprocess, hostname, msg1 + "|" + message)
    # LISP Session Specific Status (Only to map-servers)
    eid_map_servers = etrdefinition.eid_properties.mapservers
    map_server_ips = []
    for map_server in eid_map_servers:
        map_server_ip = map_server['map_server']
        if map_server_ip != etr_rloc:
            map_server_ips.append(map_server_ip)
    specific_lisp_sessions = []
    for ip in map_server_ips:
        a = LISPSession(hostname)
        a.specificlispsession(ip,service)
        specific_lisp_sessions.append(a)
    # If all of specific sessions are in the wrong state, RCA will be attempted on all, depending on the code status:
        #No Route: call underlay recursion
        #Down/Init : Route check, cef check, ACL check, ping check, ping MTU check, telnet test.

    for specific_lisp_session in specific_lisp_sessions:
        mapserverip = specific_lisp_session.peer_addr
        state = specific_lisp_session.session_state
        if (state=="Down") or (state=="Init"):
            error = "LISP Specific Sessions - Down or Init"
            message = "LISP Session to {} is in state {} on device {}. Performing checks".format(mapserverip,state,hostname)
            logging_warning(step, process, subprocess, hostname, error + " | " + message)
            #Verifications for down/init session to a CP
            down_init_cp = down_init_procedure(mapserverip,catc_name, service, step, hostname, etrdefinition, specific_lisp_session)
            step = down_init_cp[0]
            control_plane = down_init_cp[1]
            cp_state = control_plane['reachability']
            cp_hostname = control_plane['radkithostname']
            if cp_state == 'Reachable':
                #Routing/CEF/Physical Interfaces
                cpstatus = map_server_local_session(step,mapserverip,state,control_plane,catc_name,service)
                step = cpstatus[0]
                cpstatus_routing = cpstatus[1]
                interfaces = cpstatus_routing[2]
                #ACL
                step = step + 1
                total_acls = []
                for interface in interfaces:
                    acls = AccessList(hostname)
                    acls.aclbyinterface(interface, service)
                    if len(acls.aclnames) != 0:
                        for acl in acls.aclnames:
                            total_acls.append(acl)
                total_acls = set(total_acls)
                step = session_access_lists(total_acls, hostname, service, mapserverip, step, etrdefinition)

                #End of Self-LISP Session
                #Start of LISP Session validation to the ETR
                cpdefinition = cpstatus[2]
                down_init_etr = down_init_procedure_to_etr(step,cp_hostname,etr_rloc,service,cpdefinition)
        if state=="NoRoute":
            error = "LISP Specific Sessions - No Route"
            message = "LISP Session to {} is in state {} on device {}. Performing checks".format(mapserverip,state,hostname)
            logging_warning(step, process, subprocess, hostname, error + " | " + message)
            #Verifications for down/init session to a CP
            down_init_cp = down_init_procedure(mapserverip,catc_name, service, step, hostname, etrdefinition, specific_lisp_session)
            step = down_init_cp[0]

    #### Starting this, the status of LISP session establishment between XTR and Map-Servers have been validated.
    #Steps covered are now:
    vni = etrdefinition.eid_properties.iid
    subprocess = "[mapServerConfiguration]"
    msg1 = "LISP Sessions - Map-Server Configuration"
    message = "All LISP Sessions in correct state, verifying CP configuration and statistics for VNI {}".format(vni)
    logging_info(step, process, subprocess, hostname, msg1 + "|" + message)
    step = step + 1

    for cp in map_server_ips:
        control_plane = find_control_plane(cp, catc_name, service, step, process, subprocess)
        cp_status = control_plane['reachability']
        cp_mgmtip = control_plane['mgmtip']

        #Is the CP available?
        if cp_status == 'Reachable':
            control_plane = ETRDevice(cp_mgmtip,step)
            control_plane.device_profiler(catc_name,service)
            cp_hostname = control_plane.profiled_device.hostname
            




    # 21 MS/MR Site_UCI configuration (definition as map-server, map-resolver, site_uci, rloc_members distribute, domain/MID consistency (pubsub)
    # 22 MS/MR has EID space configured (L2,L3)
    # 23 MS/MR limits and statistics
    # 24 Authentication Counters for EID in both ETR and MS/MR (looking for logs as well?)
    # 27 L2LISP Statistics

    ### Map_Server configuration and statistics are correct for each "valid" Map-Server (reachable from CatC). Next steps are:
    # 19 Identify the status of the TCP socket
    # 20 Identify the status of the TCB (mss, retransmissions, pmtud)

    ### Inter-Map-Server verifications (up to 4)
    # 25 Session State between CPs
    # 26 Registration is in both CPs?

    ## Extra: WLC
    # 28 WLC RLOC definition and passiveopen


