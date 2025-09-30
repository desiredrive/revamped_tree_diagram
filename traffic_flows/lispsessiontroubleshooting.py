import sys
import re
from collections import defaultdict
from catalystcenterapi.catcapi import find_control_plane
from device_profiler import Device
from ipverifications import (
   mac_address_validator,
   ipaddress_validator_no_return,
   ipsubnet_validator_no_return
)
from routingmodules.cef import IPCef, phy_cef_collection
from routingmodules.iprouting import IPRoute, IGPInfo
from routingmodules.tcp import TCPSocket
from securitymodules.accesslists import AccessList,acl_evaluation
from securitymodules.ciscotrustsec import cts_endpoint_info, cts_rules, cts_rule_collection
from securitymodules.type7decryptor import decrypt_password
from switchingmodules.interfaces import Interfaces
from switchingmodules.maclearning import mac_learning
from routingmodules.lisp import l2lisp_info, LISPLocalDB, LISPEIDWatch, lisp_map_servers, LISPInstanceStatus, \
    LISPSession, L2LISPControlPlane
from radkit_cli import logging_info,logging_error,logging_warning
from pprint import pformat

from traffic_flows.core import CoreDevice, cpu_utilization_warning, cpu_platform_utilization_warning
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
            if lispdb.dynmacconfig is False:
                error = "EID Identification - L2LISP Instance"
                message = "The database-mapping configuration is NOT found in the LISP EID Table for VLAN {}. Review the GPS_SDA Collection logfile for more information.".format(vlan)
                exit_program(step, process, subprocess, device, error, message)

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

    def etr_map_servers(self,eidident, servicetype, service):
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
            #Authentication Key

        mapservers_shwrun = lisp_map_servers(device,servicetype,service)
        mapservers_shwrunparsed = ''
        for line in mapservers_shwrun.splitlines():
            if "map-server" in line:
                mapservers_shwrunparsed = mapservers_shwrunparsed + '\n' + line
        mapservers_shwrun = mapservers_shwrunparsed
        map_servers_noflag = find_mismatch_key_and_proxy_reply(mapservers_shwrun)

        # P-Flag Enablement #Unreliable check...
        if len(map_servers_noflag) > 0:
            error = "LISP Configuration - Map Servers"
            message = "The following Map-Servers {} are NOT configured for Proxy-Reply flag. Review the GPS_SDA Collection logfile for more information.".format(map_servers_noflag)
            exit_program(step,process,subprocess,device,error,message)

        #Map-Server-Key Evaluation:
        map_server_config = mismatch_keys_servers(mapservers_shwrun)
        keys_per_ip = defaultdict(set)

        for entry in map_server_config:
            if entry['decrypted']:
                keys_per_ip[entry['map_server_ip']].add(entry['authentication_key'])
        # Check for inconsistencies
        for ip, keys in keys_per_ip.items():
            if len(keys) > 1:
                error = "LISP Configuration - Map Servers"
                message = "Error: Multiple different keys (decrypted) found for map_server_ip {}: {}".format(ip, keys)
                exit_program(step, process, subprocess, device, error, message)
        self.mapserverconfiguration = map_server_config

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

    def cp_configuration(self,iid,service):
        hostname = self.profiled_device.hostname
        cp_configuration = L2LISPControlPlane(hostname)
        cp_configuration.lisp_service_ethernet(service)
        cp_configuration.site_uci(iid,service)
        cp_configuration.rloc_members(service)
        cp_configuration.domains(service)
        self.cp_configuration = cp_configuration

    def eid_configuration(self,eid_properties,servicetype,service):
        hostname = self.profiled_device.hostname
        etr_configuration = ETRConfiguration(hostname)
        etr_configuration.etr_map_servers(eid_properties,servicetype,service)
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

    def lisp_statistics(self,iid,servicetype,service):
        hostname = self.profiled_device.hostname
        lispstatistics = LISPInstanceStatus(hostname,iid)
        lispstatistics.eidStatistics(servicetype,service)
        self.lispstatistics = lispstatistics

    def tcp_tcb_statistics(self,srcetr,dstetr,srcport,service):
        hostname = self.profiled_device.hostname
        tcp_information = TCPSocket(hostname)
        tcp_information.tcpbrief(service)
        matching_sockets = []
        for entry in tcp_information.tcbs:
            if (entry.get('source_ip') == srcetr and
                    entry.get('destination_ip') == dstetr and
                    entry.get('source_port') == srcport):
                matching_sockets.append(entry)
        tcb_statistics = []
        for socket in matching_sockets:
            tcb = socket['tcb']
            socket = TCPSocket(hostname)
            socket.tcptcb(tcb,service)
            tcb_statistics.append(socket)
        self.tcb_statistics = tcb_statistics

    def cpu_utilization(self,service):
        hostname = self.profiled_device.hostname
        cpu = CoreDevice(hostname)
        cpu.cpu_utilization(service)
        cpu.cpu_utilization_platform(service)
        self.cpu_statistics = cpu

def exit_program(step, process, subprocess, hostname, error, message):
    logging_error(step, process, subprocess, hostname, error)
    logging_info(step, process, subprocess, hostname, message)
    sys.exit("Error: {} | {}".format(error, message))

def parse_uptime_to_minutes(uptime_str):
    """
    Parses an uptime string (e.g., '04:02:00' or '1d06h') into total minutes.
    """
    total_minutes = 0
    if 'd' in uptime_str:
        # Format like '1d06h'
        match = re.match(r'(\d+)d(?:(\d+)h)?', uptime_str)
        if match:
            days = int(match.group(1))
            hours = int(match.group(2)) if match.group(2) else 0
            total_minutes = (days * 24 * 60) + (hours * 60)
    elif ':' in uptime_str:
        # Format like 'HH:MM:SS'
        parts = uptime_str.split(':')
        if len(parts) >= 2: # At least HH:MM
            hours = int(parts[0])
            minutes = int(parts[1])
            total_minutes = (hours * 60) + minutes
    return total_minutes

def mismatch_keys_servers(lines):
    unique_entries = {}
    for line in lines.splitlines():
        line = line.strip()
        if not line.startswith("etr map-server"):
            continue
        parts = line.split()
        # Expected format: etr map-server <ip> key <type> <key>
        if len(parts) < 6:
            continue
        if parts[3] != "key":
            continue
        map_server_ip = parts[2]
        key_type_str = parts[4]
        auth_key = parts[5]

        # Use tuple key to ensure uniqueness by IP, key_type, and auth_key
        unique_key = (map_server_ip, key_type_str, auth_key)
        if unique_key in unique_entries:
            continue

        try:
            key_type = int(key_type_str)
        except ValueError:
            key_type = -1  # Unknown type

        if key_type == 7:
            decrypted_value = decrypt_password(auth_key)
            decrypted = decrypted_value is not None
            auth_key_final = decrypted_value if decrypted else auth_key
        elif key_type == 0:
            decrypted = True
            auth_key_final = auth_key
        else:
            decrypted = False
            auth_key_final = auth_key

        unique_entries[unique_key] = {
            "map_server_ip": map_server_ip,
            "key_type": key_type,
            "decrypted": decrypted,
            "authentication_key": auth_key_final
        }
    return list(unique_entries.values())

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

def unique_lisp_session(hostname,step,eid_map_servers,etr_rloc,service,catc_name,etrdefinition,vni):
    process = "lispSession"
    subprocess = "[specificLISPSession]"
    msg1 = "LISP Sessions - Specific LISP Sessions"
    message = "Verifying Specific LISP session status for Map-Servers on device:  {}.".format(hostname)
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    map_server_ips = []
    for map_server in eid_map_servers:
        map_server_ip = map_server['map_server']
        if map_server_ip != etr_rloc:
            map_server_ips.append(map_server_ip)
    specific_lisp_sessions = []

    #Remove the local ETR_RLOC form the map-server list, useful when validating CP-to-CP LISP Sessions.
    while etr_rloc in map_server_ips:
        map_server_ips.remove(etr_rloc)

    for ip in map_server_ips:
        a = LISPSession(hostname)
        a.specificlispsession(ip, service)
        specific_lisp_sessions.append(a)
    # If all of specific sessions are in the wrong state, RCA will be attempted on all, depending on the code status:
    # No Route: call underlay recursion
    # Down/Init : Route check, cef check, ACL check, ping check, ping MTU check, telnet test.
    for specific_lisp_session in specific_lisp_sessions:
        mapserverip = specific_lisp_session.peer_addr
        state = specific_lisp_session.session_state
        if (state == "Down") or (state == "Init") or (state is None):
            error = "LISP Specific Sessions - Down, Init or Not Found"
            message = "LISP Session to {} is in state {} on device {}. Performing checks".format(mapserverip, state,
                                                                                                 hostname)
            logging_warning(step, process, subprocess, hostname, error + " | " + message)
            # Verifications for down/init session to a CP
            down_init_cp = down_init_procedure(mapserverip, catc_name, service, step, hostname, etrdefinition,
                                               specific_lisp_session)
            step = down_init_cp[0]
            control_plane = down_init_cp[1]
            cp_state = control_plane['reachability']
            cp_hostname = control_plane['radkithostname']
            if cp_state == 'Reachable':
                # Routing/CEF/Physical Interfaces
                cpstatus = map_server_local_session(step, mapserverip, state, control_plane, catc_name, service, vni)
                step = cpstatus[0]
                cpstatus_routing = cpstatus[1]
                interfaces = cpstatus_routing[2]
                # ACL
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

                # End of Self-LISP Session
                # Start of LISP Session validation to the ETR
                cpdefinition = cpstatus[2]
                down_init_etr = down_init_procedure_to_etr(step, cp_hostname, etr_rloc, service, cpdefinition)
        if state == "NoRoute":
            error = "LISP Specific Sessions - No Route"
            message = "LISP Session to {} is in state {} on device {}. Performing checks".format(mapserverip, state,
                                                                                                 hostname)
            logging_warning(step, process, subprocess, hostname, error + " | " + message)
            # Verifications for down/init session to a CP
            down_init_cp = down_init_procedure(mapserverip, catc_name, service, step, hostname, etrdefinition,
                                               specific_lisp_session)
            step = down_init_cp[0]

        return step, map_server_ips,

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
        message = "ACLs found on physical interfaces in the direction to the node {} on device: {}, evaluating ACLs".format(
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

def map_server_local_session(step,mapserverip,state,control_plane,catc_name,service,vni):
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

    # 21 MS/MR Site_UCI configuration (definition as map-server, map-resolver, site_uci, rloc_members distribute, domain/MID consistency (pubsub)
    cp.cp_configuration(vni, service)
    # Validations
    cp_configuration = cp.cp_configuration
    cp_configuration_validation(step, cp_configuration, vni)

    #Authentication Match

    # LISP Session to the CP itself:
    cplisp = LISPSession(cp_hostname)
    cplisp.specificlispsession(mapserverip, service)
    cp_routing_state = None
    # If the Self Local LISP Session is down:
    if cplisp.session_state == 'Up':
        error = "LISP Specific Sessions - Session UP"
        message = "LISP Session to {} is in state {} on device {}. Performing checks".format(mapserverip,
                                                                                             cplisp.session_state,
                                                                                             cp_hostname)
        logging_info(step, process, subprocess, cp_hostname, error + " | " + message)

        # Routing, CEF and Phy Validation
        cp_routing_state = cp_routing(step, cplisp, mapserverip, cp_hostname, service)
    if cplisp.session_state != 'Up':
        error = "LISP Specific Sessions - Down, Init or Not Found"
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

def cp_configuration_validation(step,cp_configuration,vni):
    cp_hostname = cp_configuration.device
    process = "lispConfiguration"
    subprocess = "[cpConfigurationValidation]"
    error = "LISP Control Plane - Control Plane Configuration"
    message = "Verifying configuration of CP {}".format(cp_hostname)
    logging_info(step, process, subprocess, cp_hostname, error + " | " + message)
    # 21 MS/MR Site_UCI configuration (definition as map-server, map-resolver, site_uci, rloc_members distribute, domain/MID consistency (pubsub)

    #Map-Server & Map-Resolver Role
    if cp_configuration.map_server is not True:
        error = "LISP Control Plane - Control Plane Configuration"
        message = "LISP Control Plane {} is not configured as Map Server, correct this configuration under router-lisp".format(cp_hostname)
        exit_program(step, process, subprocess, cp_hostname, error, message)
    if cp_configuration.map_resolver is not True:
        error = "LISP Control Plane - Control Plane Configuration"
        message = "LISP Control Plane {} is not configured as Map Resolver, correct this configuration under router-lisp".format(
            cp_hostname)
        exit_program(step, process, subprocess, cp_hostname, error, message)
    #Site_UCI is configured and the required VNI is configured as well:
    if cp_configuration.site_uci is not True:
        error = "LISP Control Plane - Control Plane Configuration"
        message = "LISP Control Plane {} does not have site_uci defined, correct this configuration under router-lisp".format(
            cp_hostname)
        exit_program(step, process, subprocess, cp_hostname, error, message)
    if cp_configuration.authenkey is not True:
        error = "LISP Control Plane - Control Plane Configuration"
        message = "LISP Control Plane {} does not have an authentication key configured under site_uci, correct this configuration under router-lisp".format(
            cp_hostname)
        exit_program(step, process, subprocess, cp_hostname, error, message)
    if cp_configuration.iid_site is not True:
        error = "LISP Control Plane - Control Plane Configuration"
        message = "LISP Control Plane {} does not have LISP IID {} configured under site_uci, correct this configuration under router-lisp".format(
            cp_hostname,vni)
        exit_program(step, process, subprocess, cp_hostname, error, message)

def authentication_key_validation(step,cp_configuration,cp_hostname,etr_mapservers,cp_loopback,hostname):
    process = "lispConfiguration"

    map_server_configuration = etr_mapservers
    cp_authenkey = cp_configuration.authentication_key[1]
    cp_decrypted = cp_configuration.decrypted
    # If the cp_decrypted value is False, keys cannot be evaluated
    if cp_decrypted is False:
        subprocess = "[controlPlaneAuthentication]"
        msg1 = "LISP Control Plane - Authentication Key"
        message = "Authentication key on device:  {} cannot be decrypted due it's encryption type, skipping validation".format(
            cp_hostname)
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    else:
        subprocess = "[controlPlaneAuthentication]"
        msg1 = "LISP Control Plane - Authentication Key"
        message = "Validating authentication keys for device:  {}".format(cp_hostname)
        logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
        for map_server in map_server_configuration:
            if map_server['map_server_ip'] == cp_loopback:
                etr_key = map_server['authentication_key'][1]
                if etr_key == cp_authenkey:
                    message = "Authentication keys are matching between Control Plane {} and {} ".format(cp_hostname,hostname)
                    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
                else:
                    error = "LISP Control Plane - Authentication Key"
                    message = "Authentication keys are not matching between  Control Plane {} : Key: {} and {} : Key {}, correct the authentication keys".format(
                        cp_hostname, cp_authenkey, hostname, etr_key)
                    exit_program(step, process, subprocess, cp_hostname, error, message)

def lispstatisticsparser(step,lispstatistics,cp_hostname):
    vni = lispstatistics.iid
    process = "lispStatistics"
    subprocess = "[lispStatisticsControlPlane]"
    step = step + 1
    error = "LISP Statistics - IID Statistics"
    message = "Verifying LISP Statistics for Instance-ID {} for CP {}".format(vni,cp_hostname)
    logging_info(step, process, subprocess, cp_hostname, error + " | " + message)

    #Map Request Counters
    map_request_counters = lispstatistics.map_requests
    if map_request_counters['in'] == 0:
        error = "LISP Statistics - Map-Request"
        message = "No Map-Requests messages have been received by the Control Plane {}.".format(cp_hostname)
        logging_warning(step, process, subprocess, cp_hostname, error+" | "+message)
    if lispstatistics.map_request_invalid_source_rloc_drops !=0:
        error = "LISP Statistics - Map-Request"
        message = "Invalid RLOC source drops have been detected in Control Plane {}.".format(cp_hostname)
        logging_warning(step, process, subprocess, cp_hostname, error+" | "+message)
    if lispstatistics.map_request_format_errors != 0:
        error = "LISP Statistics - Map-Request"
        message = "Map Request format errors have been detected in Control Plane {}, common causes are invalid VNID or special attributes (SGT Distribution)".format(cp_hostname)
        logging_warning(step, process, subprocess, cp_hostname, error+" | "+message)
    #Map Reply Counters
    map_reply_counters = lispstatistics.map_reply
    if map_reply_counters['out'] == 0:
        error = "LISP Statistics - Map-Reply"
        message = "No Map-Reply messages have been forwarded by the Control Plane {}.".format(cp_hostname)
        logging_warning(step, process, subprocess, cp_hostname, error+" | "+message)
    #Map Register Counters
    map_register_counters = lispstatistics.map_register
    if map_register_counters['in'] == 0:
        error = "LISP Statistics - Map-Register"
        message = "No Map-Register messages have been received by the Control Plane {}.".format(cp_hostname)
        logging_warning(step, process, subprocess, cp_hostname, error+" | "+message)
    if map_register_counters['authentication_failures'] != 0:
        error = "LISP Statistics - Map-Register"
        message = "Authentication Failures have been detected in Control Plane {}.".format(cp_hostname)
        logging_warning(step, process, subprocess, cp_hostname, error+" | "+message)
    if map_register_counters['disallowed_locators'] != 0:
        error = "LISP Statistics - Map-Register"
        message = "Disallowed Locator failures have been detected in Control Plane {}.".format(cp_hostname)
        logging_warning(step, process, subprocess, cp_hostname, error+" | "+message)
    if lispstatistics.map_register_invalid_source_rloc_drops !=0:
        error = "LISP Statistics - Map-Register"
        message = "Invalid Source RLOC drops have been detected in Control Plane {}.".format(cp_hostname)
        logging_warning(step, process, subprocess, cp_hostname, error+" | "+message)
    #WLC Registration Errors:
    wlc_map_register_counters = lispstatistics.wlc_map_registers
    if wlc_map_register_counters['in'] == 0:
        error = "LISP Statistics - WLC Map-Register"
        message = "No WLC Map-Register messages have been received by the Control Plane {}.".format(cp_hostname)
        logging_warning(step, process, subprocess, cp_hostname, error+" | "+message)
    if wlc_map_register_counters['failures']['in'] != 0:
        error = "LISP Statistics - WLC Map-Register"
        message = "WLC Registration failures have been detected in Control Plane {} , these are often caused by invalid VNID attributes".format(cp_hostname)
        logging_warning(step, process, subprocess, cp_hostname, error+" | "+message)
    #Misc Errors
    if lispstatistics.rejected_eid_prefix_due_to_limit != 0:
        error = "LISP Statistics - Rejected EID"
        message = "Some EIDs might have been rejected due to limit or scale Control Plane {}, total rejected : {}".format(cp_hostname,lispstatistics.rejected_eid_prefix_due_to_limit)
        logging_warning(step, process, subprocess, cp_hostname, error+" | "+message)
    if lispstatistics.ip_version_drops !=0:
        error = "LISP Statistics - Map-Register"
        message = "IP version drops have been detected in Control Plane {}.".format(cp_hostname)
        logging_warning(step, process, subprocess, cp_hostname, error+" | "+message)
    if lispstatistics.ip_header_drops !=0:
        error = "LISP Statistics - Map-Register"
        message = "IP header drops have been detected in Control Plane {}.".format(cp_hostname)
        logging_warning(step, process, subprocess, cp_hostname, error+" | "+message)
    if lispstatistics.ip_proto_field_drops !=0:
        error = "LISP Statistics - Map-Register"
        message = "IP protocol drops have been detected in Control Plane {}.".format(cp_hostname)
        logging_warning(step, process, subprocess, cp_hostname, error+" | "+message)
    if lispstatistics.packet_size_drops !=0:
        error = "LISP Statistics - Map-Register"
        message = "IP packet size drops have been detected in Control Plane {}.".format(cp_hostname)
        logging_warning(step, process, subprocess, cp_hostname, error+" | "+message)
    if lispstatistics.lisp_control_port_drops !=0:
        error = "LISP Statistics - Map-Register"
        message = "Invalid LISP control port drops have been detected in Control Plane {}.".format(cp_hostname)
        logging_warning(step, process, subprocess, cp_hostname, error+" | "+message)
    if lispstatistics.unsupported_lisp_packet_drops !=0:
        error = "LISP Statistics - Map-Register"
        message = "Unsupported LISP packet type drops have been detected in Control Plane {}.".format(cp_hostname)
        logging_warning(step, process, subprocess, cp_hostname, error+" | "+message)
    if lispstatistics.lisp_checksum_drops !=0:
        error = "LISP Statistics - Map-Register"
        message = "Invalid LISP checksum drops have been detected in Control Plane {}.".format(cp_hostname)
        logging_warning(step, process, subprocess, cp_hostname, error+" | "+message)

def tcbstatistcisparser(step,tcbstatistics,cp_hostname):
    process = "tcpStatistics"
    subprocess = "[tcpTCBStatistics]"
    step = step + 1
    error = "TCP Statistics - TCB Statistics"

    for element in tcbstatistics:
        sourceip = element.local_host
        destip = element.foreign_host
        sourceport = element.local_port
        destport = element.foreign_port
        mss = element.mss
        message = "Verifying TCP Socket Statistics for {}:{} to {}:{} with MSS of {} on device: {}".format(sourceip,sourceport,destip,destport,mss,cp_hostname)
        logging_info(step, process, subprocess, cp_hostname, error + " | " + message)

        #Retransmit Queue status:
        retransmitqueuecounter = element.retransmitqueue
        if retransmitqueuecounter != 0:
            error = "TCP Statistics - Retransmit Queue"
            message = "Retransmission Queue counters have been detected for {}:{} to {}:{} on device: {}, possible packet loss scenario".format(sourceip,sourceport,destip,destport,cp_hostname)
            logging_warning(step, process, subprocess, cp_hostname, error + " | " + message)
        #Retransmit Counters
        retransmitcounter = element.retransmitcounter
        if retransmitcounter != 0:
            error = "TCP Statistics - Retransmit Counters"
            message = "Retransmission counters have been detected for {}:{} to {}:{} on device: {}, possible packet loss scenario".format(sourceip,sourceport,destip,destport,cp_hostname)
            logging_warning(step, process, subprocess, cp_hostname, error + " | " + message)
        #Fast Retransmit Counters
        fastretransmitcounter = element.fastretransmitcounter
        if fastretransmitcounter != 0:
            error = "TCP Statistics - Fast Retransmit Counters"
            message = "Fast retransmission counters have been detected for {}:{} to {}:{} on device: {}, possible packet loss scenario".format(sourceip,sourceport,destip,destport,cp_hostname)
            logging_warning(step, process, subprocess, cp_hostname, error + " | " + message)


##### Main Troubleshooting Flow #####

def singleETRProfiling(mgmtip,eid,vlan,vrf,catc_name,service,step,sourcextr):

    if sourcextr is None:
        #ETR
        etrdefinition = ETRDevice(mgmtip,step)
        etrdefinition.device_profiler(catc_name, service)
        hostname = etrdefinition.profiled_device.hostname
    else:
        etrdefinition = ETRDevice(sourcextr.mgmtip,step)
        etrdefinition.existing_profiled(sourcextr)
        hostname = etrdefinition.profiled_device.hostname

    process = "lispSession"
    subprocess = "[main]"
    msg1 = "LISP Sessions - Main"
    message = "Starting LISP Session validations on device {}.".format(hostname)
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    step = step+1
    # ETR Identification and Configuration (Steps 1-8)

    subprocess = "[eidIdentification]"
    msg1 = "LISP Sessions - EID Identification"
    message = "Identifying EID properties for device: {}.".format(hostname)
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    etrdefinition.eid_identification(eid,vlan,vrf,step,service)
    etrloopback = etrdefinition.profiled_device.loopback
    step = step + 1

    subprocess = "[eidConfiguration]"
    msg1 = "LISP Sessions - EID Configuration"
    message = "Verifying LISP Map-Server configuration on device: {}.".format(hostname)
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    eid_type = etrdefinition.eid_properties.eid_type
    if eid_type == "MAC":
        servicetype = "ethernet"
    etrdefinition.eid_configuration(etrdefinition.eid_properties,servicetype,service)
    step = step + 1

    # LISP Session Local Status (Global)
    subprocess = "[globalLISPSession]"
    msg1 = "LISP Sessions - Global LISP Sessions"
    message = "Verifying Local LISP session status for device:  {}.".format(hostname)
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    etrdefinition.global_lisp_session(service)

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
        logging_warning(step, process, subprocess, hostname, error+" | "+message)
    step = step + 1

    #Verifying unique LISP sessions.
    # LISP Session Specific Status (Only to map-servers)
    vni = etrdefinition.eid_properties.iid
    eid_map_servers = etrdefinition.eid_properties.mapservers

    step,map_server_ips = unique_lisp_session(hostname,step,eid_map_servers,etr_rloc,service,catc_name, etrdefinition, vni)

    ## Highlight on UPtime Status (flapping) criteria - Less than 5 minutes.
    step = step + 1
    for ip_address, sessions_list in lisp_sessions.items():
        for session in sessions_list:
            if session.get('state') == 'Up':
                uptime_str = session.get('time')
                if uptime_str:
                    uptime_minutes = parse_uptime_to_minutes(uptime_str)
                    if uptime_minutes < 5:
                        error = "LISP Specific Sessions - Uptime"
                        message = "LISP Session to {} uptime is less than 5 minutes on device {}, consider verifying the underlay network stability".format(
                            ip_address, hostname)
                        logging_warning(step, process, subprocess, hostname, error + " | " + message)
                    else:
                        error = "LISP Specific Sessions - Uptime"
                        message = "LISP Session to {} has been stable for more than 5 minutes on device {}".format(
                            ip_address, hostname)
                        logging_info(step, process, subprocess, hostname, error + " | " + message)

    #### Starting this, the status of LISP session establishment between XTR and Map-Servers have been validated.
    #Steps covered are now:
    subprocess = "[mapServerConfiguration]"
    msg1 = "LISP Sessions - Map-Server Configuration"
    message = "All LISP Sessions in correct state, verifying CP configuration and statistics for VNI {}".format(vni)
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)

    map_server_configuration = etrdefinition.eid_configuration.mapserverconfiguration
    control_plane_information = []
    for cp in map_server_ips:
        control_plane = find_control_plane(cp, catc_name, service, step, process, subprocess)
        cp_status = control_plane['reachability']
        cp_mgmtip = control_plane['mgmtip']
        cp_hostname = control_plane['hostname']

        #Is the CP available?
        if cp_status == 'Reachable':
            control_plane = ETRDevice(cp_mgmtip,step)
            control_plane.device_profiler(catc_name,service)
            cp_loopback = control_plane.profiled_device.loopback

            # 21 MS/MR Site_UCI configuration (definition as map-server, map-resolver, site_uci, rloc_members distribute, domain/MID consistency (pubsub)
            # 22 MS/MR has EID space configured (L2,L3)
            step = step + 1
            control_plane.cp_configuration(vni,service)
            #Validations
            cp_configuration = control_plane.cp_configuration
            cp_configuration_validation(step,cp_configuration, vni)

            # 24 Authentication Counters for EID in both ETR and MS/MR (looking for logs as well?)
            step = step + 1
            authentication_key_validation(step,cp_configuration,cp_hostname,map_server_configuration,cp_loopback, hostname)

            # 23 MS/MR limits and statistics
            step = step + 1
            control_plane.lisp_statistics(vni,servicetype,service)
            lisp_statistics = control_plane.lispstatistics
            lispstatisticsparser(step,lisp_statistics,cp_hostname)

            # 19 Identify the status of the TCP socket
            step = step + 1
            control_plane.tcp_tcb_statistics(cp_loopback,etrloopback,4342,service)
            # 20 Identify the status of the TCB (mss, retransmissions, pmtud)
            tcb_stats = control_plane.tcb_statistics
            tcbstatistcisparser(step,tcb_stats,cp_hostname)

            # 26 CPU Utilization
            step = step + 1
            control_plane.cpu_utilization(service)
            highcpuprocesses = control_plane.cpu_statistics.high_cpu_processes
            highplatcpuprocesses =control_plane.cpu_statistics.plat_high_cpu_processes
            cpu_utilization_warning(step, highcpuprocesses, cp_hostname)
            cpu_platform_utilization_warning(step, highplatcpuprocesses, cp_hostname)

            #Append CP information
            control_plane_information.append(control_plane)

    ### Inter-Map-Server verifications (up to 4)
    # Get all "reachable" CPs from Catalyst Center
    subprocess = "[interCPSession]"
    msg1 = "LISP Sessions - Session between CPs"
    message = "Verifying LISP sessions between CPs reachable by Catalyst Center (Site-wide)."
    logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
    step = step + 1

    reachable_cp_information = []
    for cp in control_plane_information:
        reachable_status = cp.profiled_device.reachabilitystatus
        if reachable_status == 'Reachable':
            reachable_cp_information.append(cp)

    # 25 Session State between CPs
    for cp in reachable_cp_information:
        etr_rloc = cp.profiled_device.loopback
        hostname = cp.profiled_device.hostname
        map_server_ips = []
        for map_server in eid_map_servers:
            map_server_ip = map_server['map_server']
            if map_server_ip != etr_rloc:
                map_server_ips.append(map_server_ip)
        # Remove the local ETR_RLOC form the map-server list, useful when validating CP-to-CP LISP Sessions.
        while etr_rloc in map_server_ips:
            map_server_ips.remove(etr_rloc)
        map_server_strings = ", ".join(map_server_ips)

        if len(map_server_ips) != 0:
            subprocess = "[interCPSession]"
            msg1 = "LISP Sessions - Session between CPs"
            message = "Verifying LISP sessions from CP {} to CPs : {}".format(etr_rloc,map_server_strings)
            logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
            step = step + 1

            step, map_server_ips = unique_lisp_session(hostname, step, eid_map_servers, etr_rloc, service, catc_name,cp, vni)

        else:
            subprocess = "[interCPSession]"
            msg1 = "LISP Sessions - Session between CPs"
            message = "Control Plane {} is the sole reachable CP in the fabric site; skipping inter-CP session validation.".format(hostname)
            logging_info(step, process, subprocess, hostname, msg1 + " | " + message)
            step = step + 1
    return step
    ## Extra: WLC
    # 28 WLC RLOC definition and passiveopen


