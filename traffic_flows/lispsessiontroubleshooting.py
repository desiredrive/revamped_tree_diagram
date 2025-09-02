import sys
from ipverifications import (
   mac_address_validator,
   ipaddress_validator_no_return,
   ipsubnet_validator_no_return
)
from switchingmodules.maclearning import mac_learning
from routingmodules.lisp import l2lisp_info,LISPLocalDB,LISPEIDWatch,lisp_map_servers,LISPInstanceStatus
from radkit_cli import logging_info,logging_error,logging_warning,get_catc_api,get_any_single_output,get_single_output_genie
from pprint import pformat

#LISP Session Troubleshooting Steps:
#1 Identify the EID to register (MAC (UDP/TCP), IP (UDP/TCP), AR(TCP)
#2 Identify if the method for LISP DB insertion (DynamicEID/SISF, Route-Import, Static, WLC notification).
#3 Identify the limits of method registration
#4 Identify the limits for DB insertion
#5 Identify if the EID is in the LISP Database (Can be IP, EID, Prefix, Host, etc)
#7 Identify the source RLOC for registration (valid RLOC)
#8 Identify the Map-Resolvers for the Registration, verify proxy flag, node must be ETR
#9 Identify LISP registration metrics and statistics
#10 UDP Listen State in MS/MR
#11 TCP test in ETR
#10 Identify the status of the LISP session (global)
#12 Identify the status of the LISP session (per ID, Optional)
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

#1 Identify the EID to register (MAC (UDP/TCP), IP (UDP/TCP), AR(TCP)
#2 Identify if the method for LISP DB insertion (DynamicEID/SISF, Route-Import, Static, WLC notification).

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

class EIDIdentification():
    def __init__(self, device,eid):
        self.device = device
        self.eid = eid

    def eid_identification(self,vlan,vrf,service):
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

        step = "X"
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

    def map_servers(self,eidident,service):
        # 8 Identify the Map-Resolvers for the Registration, verify proxy flag, node must be ETR
        # 9 Identify LISP registration metrics and statistics
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

        lisp_iid_status = LISPInstanceStatus(device,eidident.iid)
        if eidident.eid_type == "MAC":
            qtype = "ethernet"
        lisp_iid_status.eidstatus(qtype,service)
        if lisp_iid_status.etr is not True:
            error = "LISP Configuration - ETR"
            message = "ETR Functionality is  NOT configured for the following device {}. Review the GPS_SDA Collection logfile for more information.".format(device)
            exit_program(step,process,subprocess,device,error,message)

        # 9 Identify LISP registration metrics and statistics
        lisp_iid_status.eidStatistics(qtype,service)


#Classes

#LISP Session (Global, Per IID, TCP Status, TCB Status)

