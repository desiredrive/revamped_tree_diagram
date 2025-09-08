import re
import sys

from asn1crypto.pkcs12 import AttributeType

from switchingmodules.interfaces import Interfaces
from switchingmodules.spanning_tree import SpanningTree
from switchingmodules.vlan import VlanInformation
from radkit_cli import logging_info, logging_error, logging_warning, get_any_single_output,get_single_output_genie

def parse_lisp_session(output):
    result = {}
    # Peer address and port
    peer_match = re.search(r"Peer address:\s+([\d\.]+):(\d+)", output)
    if peer_match:
        result['peer_addr'] = peer_match.group(1)
        result['peer_port'] = int(peer_match.group(2))
    else:
        # If port is missing, try without port
        peer_match = re.search(r"Peer address:\s+([\d\.]+)", output)
        if peer_match:
            result['peer_addr'] = peer_match.group(1)
            result['peer_port'] = None
    # Local address and port (port may be missing)
    local_match = re.search(r"Local address:\s+([\d\.]+)(?::(\d+))?", output)
    if local_match:
        result['local_address'] = local_match.group(1)
        result['local_port'] = int(local_match.group(2)) if local_match.group(2) else None
    # Session Type
    session_type_match = re.search(r"Session Type:\s+(\S+)", output)
    if session_type_match:
        result['session_type'] = session_type_match.group(1)
    # Session State and uptime
    session_state_match = re.search(r"Session State:\s+(\S+)(?: \(([^)]+)\))?", output)
    if session_state_match:
        result['session_state'] = session_state_match.group(1)
        result['session_state_time'] = session_state_match.group(2) if session_state_match.group(2) else None
    # Messages in/out
    messages_match = re.search(r"Messages in/out:\s+(\d+)/(\d+)", output)
    if messages_match:
        result['messages_in'] = int(messages_match.group(1))
        result['messages_out'] = int(messages_match.group(2))
    # Fatal errors
    fatal_errors_match = re.search(r"Fatal errors:\s+(\d+)", output)
    if fatal_errors_match:
        result['fatal_errors'] = int(fatal_errors_match.group(1))
    # Rcvd unsupported
    rcvd_unsupported_match = re.search(r"Rcvd unsupported:\s+(\d+)", output)
    if rcvd_unsupported_match:
        result['rcvd_unsupported'] = int(rcvd_unsupported_match.group(1))
    # Rcvd invalid VRF
    rcvd_invalid_vrf_match = re.search(r"Rcvd invalid VRF:\s+(\d+)", output)
    if rcvd_invalid_vrf_match:
        result['rcvd_invalid_vrf'] = int(rcvd_invalid_vrf_match.group(1))
    # Rcvd override
    rcvd_override_match = re.search(r"Rcvd override:\s+(\d+)", output)
    if rcvd_override_match:
         result['rcvd_override'] = int(rcvd_override_match.group(1))
    #Rcvd malformed
    rcvd_malformed_match = re.search(r"Rcvd malformed:\s+(\d+)", output)
    if rcvd_malformed_match:
        result['rcvd_malformed'] = int(rcvd_malformed_match.group(1))
    # Sent deferred
    sent_deferred_match = re.search(r"Sent deferred:\s+(\d+)", output)
    if sent_deferred_match:
        result['sent_defferred'] = int(sent_deferred_match.group(1))
    return result

def lisp_map_servers(device,service):
    lisp_cmd = "show run | i map-server"
    lisp_op = get_any_single_output(device,lisp_cmd,service)
    return (lisp_op)

class lisp_route_import:

    def __init__(self, iid, device):
        self.iid = iid
        self.hostname  = device
    
    def ridb_state(self, service):
        ridb_cmd = "show lisp instance-id {} ipv4 route-import database".format(self.iid)
        ridb_op = get_any_single_output(self.hostname,ridb_cmd,service)
        iids = []
        configflag = []
        limits = []
        for line in ridb_op.splitlines():
            if "Output for" in line:
                iid = re.compile("(?<=ce-id )[0-9]+").search(line).group().strip()
                iids.append(iid)
            if "There are no" in line:
                configflag.append(None)
                limits.append(None)
            if "Config" in line:
                configflag.append(True)
                limit = re.compile("(?<=limit )[0-9]+").search(line).group().strip()
                limits.append(limit)
            if "EID table not" in line:
                configflag.append(False)
                limits.append(False)

class controlplane_eid:

    def __init__(self,eid, iid, queriedcp):
        #self.qtype = qtype  #Types: L3v4, L3v6, L2, L2AR
        self.eid = eid      #Can be : IPv4, MAC address (IPv6 not needed for now)
        self.iid = iid      #LISP Instance ID for the request
        self.protocol = "UDP" #Was this registered using UDP or TCP?
        self.queriedcp = queriedcp #What is the IP address of this queried CP?

    def address_q(self, service):
            hostname = self.queriedcp
            process = "LISP"
            subprocess = "[Control-Plane]"
            cmd = "sh lisp instance-id {} ethernet server address-resolution {}".format(self.iid, self.eid)
            cp_server_output = get_single_output_genie(self.queriedcp,cmd,service)
            #Address resolution is always registered using TCP
            self.protocol = "TCP"            
            #Parsing:
            if cp_server_output == None:
                logging_info("X",process,subprocess,hostname,
                             "ARP Registration not found in CP {}".format(self.queriedcp))
                #print("ARP Registration not found in CP {}".format(self.queriedcp))
            else:
                response_path = cp_server_output['lisp_id'][0]['instance_id'][self.iid]
                host = self.eid+"/32"
                host_path = response_path['host_address'][host]
                self.authenfailures = host_path['registration_errors']['authentication_failures']
                etrssession = []
                etrs = []
                for i in host_path['etr']:
                    j = i.split(":")
                    etrs.append(j[0])
                    etrssession.append(i)
                self.etrsessions = etrssession
                self.etrs = etrs
                self.arbinding = host_path['hardware_address'] 

    def ethernet_q(self, service):
        hostname = self.queriedcp
        process = "LISP"
        subprocess = "[Control-Plane]"
        wlc_cmd = "show run | se set WLC"
        wlc_op = get_any_single_output(self.queriedcp,wlc_cmd,service)
        wlcs = []
        wlc_match = ['locator-set', 'WLC', '#']
        for line in wlc_op.splitlines():
            if not any(x  in line for x in wlc_match):
                wlcs.append(line.strip())
        self.wlcip = wlcs

        etr_list = []
        cmd = "sh lisp instance-id {} ethernet server {}".format(self.iid, self.eid)
        cp_server_output = get_any_single_output(self.queriedcp,cmd,service)
        self.arbinding = "NA"

        if cp_server_output == None:
            logging_info("X", process, subprocess, hostname,
                         "MAC Registration not found in CP {}".format(self.queriedcp))
            #print("MAC Registration not found in CP {}".format(self.queriedcp))
        try:
            for line in cp_server_output.splitlines():
                if "ETR" in line:
                    etrs = re.compile( "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" ).search(line).group().strip()
                    etr_list.append(etrs) 

                if "sourced by reliable transport" in line:
                    self.protocol = "TCP"

                if "WLC AP bit:" in line:
                    self.regbywlc = "True" 
                    if "Set" in line:
                        self.isfewap = "True"
                    if "Clear" in line:
                        self.isfewap = "False"
        except:
            pass
        etrs_list = [i for i in etr_list if i not in wlcs]
        etrs_list = set(etrs_list)
        if len(etrs_list) > 1:
            logging_error("X", process, subprocess, hostname,
                          "Multiple RLOCs detected for this L2 Registration, triggering troubleshooting flow\n {}".format(etrs_list))
            sys.exit("Multiple RLOCs detected for this L2 Registration, triggering troubleshooting flow\n {}".format(etrs_list))
        self.etrs = etrs_list

class l2lisp_info:

    def l2_lisp_instance(self,device,vlan,service):
        self.sourcevlan = vlan
        self.hostname = device

        process = "LISP"
        subprocess = "[L2LISP]"
        # print ("Obtaining LISP-related information for L2 IID\n")
        lispdyneidcmd = "show lisp eid-table vlan {} dynamic-eid summary".format(self.sourcevlan)
        lispdyneidop = get_single_output_genie(device, lispdyneidcmd, service)
        try:
            instance = lispdyneidop['lisp_id'][0]['instance_id']
        except AttributeError:
            instance = 0
        for i in instance:
            self.l2lispiid = i
        if self.l2lispiid == 0 :
            self.l2lispiid = None


    def l2_lisp_parameters(self, xtr, ep, service):
        self.mgmtip = xtr.mgmtip
        hostname = xtr.hostname
        self.sourcemac = ep.sourcemac
        self.sourcevlan = ep.sourcevlan


        #L2 LISP Operations (Local DB, Local EID and DynEID)
        #Find the L2 instance-id

        if ep.isl3only==False:

            #Original Command = "show lisp eid-table vlan {vlan} dynamic-eid summary"
            process = "LISP"
            subprocess = "[L2LISP]"
            #print ("Obtaining LISP-related information for L2 IID\n")
            lispdyneidcmd = "show lisp eid-table vlan {} dynamic-eid summary".format(self.sourcevlan)
            lispdyneidop = get_single_output_genie(hostname,lispdyneidcmd,service)
            instance = lispdyneidop['lisp_id'][0]['instance_id']
            for i in instance:
                self.l2lispiid = i
            if self.l2lispiid==0:
                logging_error("X", process, subprocess, hostname,
                              "L2 LISP IID Not Found, Is this an L3 Only Subnet?")
                sys.exit("L2 LISP IID Not Found, Is this an L3 Only Subnet?")

            #L2LISPACL
            l2lispaclcmd = "show ip interface l2lisp0"
            l2lispaclop = get_single_output_genie(hostname, l2lispaclcmd, service)
            l2lispaclout = None
            l2lispaclin = None
            if l2lispaclop is not None:
                try:
                    l2lispaclout = l2lispaclop["L2LISP0"]["outbound_access_list"]
                except KeyError:
                    l2lispaclout = None
                try:
                    l2lispaclin = l2lispaclop["L2LISP0"]["inbound_access_list"]
                except KeyError:
                    l2lispaclin = None
            self.l2lispaclout = l2lispaclout
            self.l2lispaclin = l2lispaclin

            #Basic L2 LISP Information
            l2lispservice_cmd = "show lisp all instance-id {} ethernet".format(self.l2lispiid)
            l2lispservice_op = get_single_output_genie(hostname,l2lispservice_cmd,service)
            lispservicepath = l2lispservice_op['lisp_id'][0]['instance_id'][self.l2lispiid]

            if lispservicepath['itr']['enabled'] == True:
                self.l2itr = True
            else:
                logging_error("X", process, subprocess, hostname,
                              "LISP Ethernet Instance {} is not enabled as ITR!, configure \"itr\" under the global service ethernet instance".format(self.l2lispiid))
                sys.exit("LISP Ethernet Instance {} is not enabled as ITR!, configure \"itr\" under the global service ethernet instance".format(self.l2lispiid))
            if lispservicepath['etr']['enabled'] == True:
                self.l2etr = True
            else:
                logging_error("X", process, subprocess, hostname,
                              "LISP Ethernet Instance {} is not enabled as ETR!, configure \"etr\" under the global service ethernet instance".format(self.l2lispiid))
                sys.exit("LISP Ethernet Instance {} is not enabled as ETR!, configure \"etr\" under the global service ethernet instance".format(self.l2lispiid))

            self.l2lispsmrmode = lispservicepath['itr']['solicit_map_request']
            self.l2lispmcastfloodaccesstunnel = lispservicepath['mcast_flood_access_tunnel']

            map_resolvers = []
            for i in (lispservicepath['itr_map_resolvers']):
                if i != "found":
                    map_resolvers.append(i)
            self.l2cps = map_resolvers
            
            self.ipv4minmask = lispservicepath['locator_status_algorithms']['ipv4_rloc_min_mask_len']
            self.ipv6minmask = lispservicepath['locator_status_algorithms']['ipv6_rloc_min_mask_len']

            proxyeteronly_cmd = "show run | i ipv4 locator reachability"
            proxyeteronly_op = get_any_single_output(hostname,proxyeteronly_cmd,service)

            self.ipv4reachpetronly = False
            if proxyeteronly_op is not None:
                for line in proxyeteronly_op.splitlines():
                    if 'proxy-etr-only' in line:
                        self.ipv4reachpetronly = True

            self.l2mapcache_current = lispservicepath['map_cache']['size']
            self.l2mapcache_limit = lispservicepath['map_cache']['limit']

            current = (lispservicepath['map_cache']['size'])
            limit = (lispservicepath['map_cache']['limit'])
            threshold = 90
            percentage = round((current/limit)*100,2)

            if (percentage > threshold):
                logging_warning("X", process, subprocess, hostname,
                              "Current number of L2 Map-Caches is {} , limit is {}, capacity at {}%".format(current,limit,percentage))
                #print ("WARNING! Current number of L2 Map-Caches is {} , limit is {}, capacity at {}%".format(current,limit,percentage))
            #else:
            #    logging_info("X", process, subprocess, hostname,
            #                  "Current number of L2 Map-Caches is {} , limit is {}, capacity at {}%".format(current,limit,percentage))
            #    #print ("INFO: Current number of L2 Map-Caches is {} , limit is {}, capacity at {}%".format(current,limit,percentage))
            
            self.l2dbcache_current = lispservicepath['database']['total_database_mapping']
            self.l2dbcache_limit = lispservicepath['database']['dynamic_database']['limit']

            current = (lispservicepath['database']['total_database_mapping'])
            limit = (lispservicepath['database']['dynamic_database']['limit'])
            threshold = 90
            percentage = round((current/limit)*100,2)

            if (percentage > threshold):
                logging_warning("X", process, subprocess, hostname,
                              "Current number of L2 Database Entries is {} , limit is {}, capacity at {}%".format(current,limit,percentage))
                #print ("WARNING! Current number of L2 Database Entries is {} , limit is {}, capacity at {}%".format(current,limit,percentage))
            #else:
            #    logging_info("X", process, subprocess, hostname,
            #                  "Current number of L2 Database Entries is {} , limit is {}, capacity at {}%".format(current,limit,percentage))
            #    #print ("INFO: Current number of L2 Database Entries is {} , limit is {}, capacity at {}%".format(current,limit,percentage))

            self.l2signalsupressstate = lispservicepath['map_cache']['signal_supress']
            if self.l2signalsupressstate is True:
                logging_error("X", process, subprocess, hostname,
                              "WARNING! Signal Supression is enabled, no more map-requests will be created for this instance!")
                sys.exit("Signal Supression is enabled, no more map-requests will be created for this instance!")

            #Searching the source MAC in LISP L2 Dynamic EID
            eids = lispdyneidop['lisp_id'][0]['instance_id'][self.l2lispiid]['dynamic_eids']['Auto-L2-group-{}'.format(self.l2lispiid)]['eids']
            if any(x  in self.sourcemac for x in eids):
                self.l2dynstate = True
            else:
                logging_error("X", process, subprocess, hostname,
                              "Source MAC {} in IPDT but not in LISP {} Dynamic-EID, is LISP database-mapping configured for VLAN {}?".format(self.sourcemac,self.l2lispiid,self.sourcevlan))
                sys.exit("Source MAC {} in IPDT but not in LISP {} Dynamic-EID, is LISP database-mapping configured for VLAN {}?".format(self.sourcemac,self.l2lispiid,self.sourcevlan))

            #Searching the source MAC in LISP Database
            dbl2_cmd = "show lisp instance-id {} ethernet database".format(self.l2lispiid)
            dbl2_op = get_single_output_genie(hostname,dbl2_cmd,service)
            eids = dbl2_op['lisp_id'][0]['instance_id'][self.l2lispiid]['entries']['eids']
            mac = self.sourcemac+"/48"
            if any(x  in mac for x in eids):
                self.l2lispdbstate = True
            else:
                logging_error("X", process, subprocess, hostname,
                              "Source MAC {} in IPDT/ DynEID but not in LISP {} Database? Debug LISP".format(self.sourcemac, self.l2lispiid))
                sys.exit("Source MAC {} in IPDT/ DynEID but not in LISP {} Database? Debug LISP".format(self.sourcemac,self.l2lispiid))

class L2LISPInterface:
    def __init__(self,vlan,device):
        self.hostname = device
        self.vlan = vlan


    def l2lispinterfacestatus(self,service):
        process = "LISP"
        subprocess = "[L2LISPInterface]"
        hostname = self.hostname

        #STP Status for the VLAN
        stpstatus = SpanningTree(self.hostname)
        stpstatus.spt_vlan_active(self.vlan,service)
        if stpstatus is None:
            logging_error("X", process, subprocess, hostname,
                          "WARNING!: No Spanning Tree Information for VLAN {} in device: {} , is the VLAN created? There are no active in this VLAN".format(self.vlan, self.hostname))
            sys.exit("WARNING!: No Spanning Tree Information for VLAN {} in device: {} , is the VLAN created? There are no active in this VLAN".format(self.vlan, self.hostname))
        if stpstatus.number_of_fwd_interfaces == 0:
            sys.exit("WARNING!: No FWD enabled ports in VLAN {} in device: {} , are the ports assigned to the correct VLAN and connected?".format(self.vlan, self.hostname))
        self.stpstatus = stpstatus

        #VLAN Status and L2LISP type
        vlanstatus = VlanInformation(self.vlan,self.hostname)
        vlanstatus.vlanbrief_manual(service)
        l2lispparentintf = None
        l2lispparenttype = None
        l2lispiid = None
        for port in vlanstatus.ports:
            if "Tu" in port:
                l2lispparentintf = port
                l2lispparenttype = 'Tunnel'
            elif "L2LI0" in port:
                l2lispparentintf = port
                l2lispparenttype = 'L2LISP0'
                l2lispsubinterfacesplit = port.split(":")
                l2lispiid = l2lispsubinterfacesplit[1]
        if l2lispparentintf is None:
            logging_error("X", process, subprocess, hostname,
                          "WARNING!: No L2LISP (or Tunnel) interface found attached to VLAN {} in device: {}! - This might be the result of an unexpected switchover or ISSU upgrade; remove the affected L2LISP instance and create it again".format(self.vlan, self.hostname))
            sys.exit("WARNING!: No L2LISP (or Tunnel) interface found attached to VLAN {} in device: {}! - This might be the result of an unexpected switchover or ISSU upgrade; remove the affected L2LISP instance and create it again".format(self.vlan, self.hostname))
        self.vlanstatus = vlanstatus
        self.l2lispparenttype = l2lispparenttype

        #L2LISP0 Main Interface and L2LISP Subinterface (if applicable)
        if l2lispparenttype == 'L2LISP0':
            l2lisp0interface = Interfaces('L2LISP0', self.hostname)
            l2lisp0interface.show_interface(service)
            if l2lisp0interface.linestate != 'up':
                logging_error("X", process, subprocess, hostname,
                              "WARNING!: L2LISP Interface is DOWN in device: {}".format(self.hostname))
                sys.exit("WARNING!: L2LISP Interface is DOWN in device: {}".format(self.hostname))
            l2lispsubintf = "L2LISP0."+l2lispiid
            l2lispsubinterface = Interfaces(l2lispsubintf,self.hostname)
            l2lispsubinterface.show_interface(service)
            if l2lispsubinterface.linestate != 'up':
                logging_error("X", process, subprocess, hostname,
                              "WARNING!: {} Interface is DOWN in device: {}".format(l2lispsubintf,self.hostname))
                sys.exit("WARNING!: {} Interface is DOWN in device: {}".format(l2lispsubintf,self.hostname))
            self.l2lispparenstatus = l2lisp0interface
            self.l2lispsubinterfacestatus = l2lispsubinterface
            self.l2lispfinalinterface = l2lispsubinterface.interface
        if l2lispparenttype == 'Tunnel':
            tunnelinterface = Interfaces(l2lispparentintf, self.hostname)
            tunnelinterface.show_interface(service)
            if tunnelinterface.linestate != 'up':
                logging_error("X", process, subprocess, hostname,
                              "WARNING!: l2lispparentintf Interface is DOWN in device: {}".format(self.hostname))
                sys.exit("WARNING!: l2lispparentintf Interface is DOWN in device: {}".format(self.hostname))
            self.l2lispparenstatus = tunnelinterface
            self.l2lispfinalinterface = tunnelinterface.interface

        #L2LISP statistics

class L2LISPConfiguration:
    def __init__(self,iid,device):
        self.hostname = device
        self.iid = iid

    def l2flooding_configuration(self,service):
        hostname = self.hostname
        hostname = self.hostname
        iid = self.iid
        matches = ['#', 'show']
        self.floodunknownunicast = False
        self.broadcastunderlay = None
        self.floodarpnd = False
        self.floodaccesstunnel = False

        #Structure is {Type: Unicast|Multicast, Multicast Group : Group, Vlan: Vlan
        l2floodingconfig_cmd = "show run | se instance-id {}".format(iid)
        l2floodingconfig_op = get_any_single_output(hostname,l2floodingconfig_cmd,service)
        if l2floodingconfig_op is not None:
            for line in l2floodingconfig_op.splitlines():
                if not any(x in line for x in matches):
                    if "broadcast-underlay" in line:
                        self.broadcastunderlay = re.compile("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").search(line).group().strip()
                    if "flood unknown-unicast" in line:
                        self.floodunknownunicast = True
                    if "flood arp-nd" in line:
                        self.floodarpnd = True
                    if "flood access-tunnel" in line:
                        self.floodaccesstunnel = True
                        try:
                            mcasttunnelip = re.compile("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").search(line).group().strip()
                            self.floodaccesstunneltype = 'Multicast'
                            self.floodaccesstunnelgroup = mcasttunnelip
                            floodatmcaststringvlan = re.compile("vlan [0-9]{4}").search(line).group()
                            self.floodaccesstunnelvlan = int(floodatmcaststringvlan.split("vlan")[1].strip())
                        except:
                            pass

class l2_map_cache:

    def __init__(self,eid, iid, queriedev):
        self.eid = eid              #Can be : IPv4, MAC address (IPv6 not needed for now)
        self.iid = iid              #LISP Instance ID for the request
        self.queriedev = queriedev

    def l2map(self, service):
            process = "LISP"
            subprocess = "[Map-Cache]"
            eid = None
            map_cache_cmd = "sh lisp instance-id {} ethernet map-cache {}".format(self.iid, self.eid)
            map_cache_output = get_single_output_genie(self.queriedev,map_cache_cmd,service)
            if map_cache_output is None:
                logging_error("X", process,subprocess,self.queriedev,
                              "WARNING!: No map-cache found for EID {} in IID {} in device {}, maybe ARP is not working?".format(self.eid, self.iid, self.queriedev))
                sys.exit("WARNING!: No map-cache found for EID {} in IID {} in device {}, maybe ARP is not working?".format(self.eid, self.iid, self.queriedev) )
            else:
                try:
                    mapcache_path = map_cache_output['lisp_id'][0]['instance_id'][self.iid]['eid_prefix']
                except KeyError:
                    logging_error("X", process, subprocess, self.queriedev,
                                  "WARNING!: No map-cache found for EID {} in IID {} in device {}, maybe ARP is not working?".format(
                                      self.eid, self.iid, self.queriedev))
                    sys.exit(
                        "WARNING!: No map-cache found for EID {} in IID {} in device {}, maybe ARP is not working?".format(
                            self.eid, self.iid, self.queriedev))
                self.mask = 48
                for i in mapcache_path:
                    eid = i
                self.uptime = mapcache_path[eid]['uptime']
                self.expiration = mapcache_path[eid]['expiry_time']
                self.source = mapcache_path[eid]['source_type']
                i = None
                for i in mapcache_path[eid]['rloc_set']:
                    self.rloc = i
                self.rlocstate = mapcache_path[eid]['rloc_set'][i]['rloc_state']
                self.priority = mapcache_path[eid]['rloc_set'][i]['priority']
                self.weight = mapcache_path[eid]['rloc_set'][i]['weight']
            
class LISPLocalDB:

    def __init__(self,eid, iid, device):
        self.eid = eid              #Can be : IPv4, MAC address (IPv6 not needed for now)
        self.iid = iid              #LISP Instance ID for the request
        self.device = device

    def L2LISPDyn(self,service):
        l2lispdyncmd = "show lisp instance-id {} dynamic-eid detail".format(self.iid)
        l2lispdynop = get_single_output_genie(self.device,l2lispdyncmd,service)
        try:
            path = l2lispdynop['lisp_id'][0]['instance_id'][self.iid]['dynamic_eids']
        except KeyError:
            path = []
        dynmacconfig = False
        for group in path:
            if 'Auto-L2' in group:
                dynmacconfig = True
        self.dynmacconfig = dynmacconfig

        dynmacs = []
        if dynmacconfig is True:
            striid = str(self.iid)
            autol2group ='Auto-L2-group-{}'.format(striid)
            path = path[autol2group]['eid_entries']
            for key in path:
                dynmacs.append(key)
        self.dynmacs = dynmacs

    def L2LISPStaticDB(self,service):
        static_mappings = []
        l2lispconfig = "show run | sec instance-id {}".format(self.iid)
        l2lispconfig_op = get_any_single_output(self.device,l2lispconfig,service)
        if l2lispconfig_op is not None:
            for line in l2lispconfig_op.splitlines():
                if 'database-mapping' in line:
                    if 'mac' not in line:
                        macregex = "([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})"
                        try:
                            mac = re.compile(macregex).search(line).group().strip()
                            static_mappings.append(mac)
                        except AttributeError:
                            mac = None
        self.static_mappings = static_mappings

    def LISPDBLimits(self,type,service):
        lispinstanceparameters = "show lisp instance-id {} {}".format(self.iid,type)
        lispinstanceparameters_op = get_single_output_genie(self.device,lispinstanceparameters,service)
        lispglobalparameters = "show lisp service {} summary".format(type)
        lispglobalparameters_op = get_single_output_genie(self.device,lispglobalparameters,service)

        try:
            path = lispinstanceparameters_op['lisp_id'][0]['instance_id'][self.iid]['database']
            gpath = lispglobalparameters_op['lisp_router_instances'][0]['service'][type]['etr']['summary']
            total_global_database = gpath['total_db_entries']
            total_global_maxdb = gpath['maximum_db_entries']
            total_database = path['total_database_mapping']
            inactive_database = path['inactive']
            static_database = path['static_database']
            dynamic_database = path['dynamic_database']
            rimport_database = path['route_import']
            sitereg_database = path['import_site_reg']
            publication_database = path['import_publication']
            static_database_pr = round((static_database['size'] / static_database['limit']) * 100, 2)
            dynamic_database_pr = round((dynamic_database['size'] / dynamic_database['limit']) * 100, 2)
            global_db_pr = round((total_global_database / total_global_maxdb) * 100, 2)
        except AttributeError:
            total_global_database = None
            total_global_maxdb = None
            total_database = None
            inactive_database = None
            static_database = None
            dynamic_database = None
            rimport_database = None
            sitereg_database = None
            publication_database = None
            static_database_pr =  None
            dynamic_database_pr = None
            global_db_pr = None

        self.global_total_db_entries = total_global_database
        self.global_maximum_db_entries = total_global_maxdb
        self.global_database_usage_pr = global_db_pr
        self.total_database = total_database
        self.inactive_database = inactive_database
        self.static_database = static_database
        self.static_database_pr = static_database_pr
        self.dynamic_database = dynamic_database
        self.dynamic_database_pr = dynamic_database_pr
        self.rimport_database = rimport_database
        self.sitereg_database = sitereg_database
        self.publication_database = publication_database

    def LISPDBEntry(self,type,service):
        lispdbeid = "show lisp instance-id {} {} database {}".format(self.iid,type,self.eid)
        lispdbeid_op = get_single_output_genie(self.device,lispdbeid,service)
        try:
            path = lispdbeid_op['lisp_id'][0]['instance_id'][self.iid]
            self.address_family = path['address_family']
            self.eid_table = path['eid_table']
            self.eid = path['eid_prefix']
            eid_info = path['eid_info']
            if "dynamic-eid" in eid_info:
                self.eid_origin = 'dynamic-eid'
            elif "route-import" in eid_info:
                self.eid_origin = 'route-import'
            elif 'publica' in eid_info:
                self.eid_origin = 'publication'
            else:
                self.eid_origin = 'static'
            rlocs = path['locators']
            locators = []
            for locator in rlocs:
                priority = rlocs[locator]['priority']
                weight = rlocs[locator]['weight']
                locators.append({'rloc': locator, 'priority': priority, 'weight': weight})
            mapservers = []
            dbmap_servers = path['map_servers']
            for map_server in dbmap_servers:
                ackstate = dbmap_servers[map_server]['ack']
                mapservers.append({'map_server': map_server, 'ack': ackstate})
            self.locators = locators
            self.mapservers = mapservers

        except AttributeError:
            self.address_family = None
            self.eid_table = None
            self.eid = None
            self.eid_origin = None
            self.locators = None
            self.mapservers = None

class LISPEIDWatch:
    def __init__(self,device,iid):
        self.iid = iid
        self.device = device
    def eidwatch_status(self,qtype, process, service):
        #Possible Processes: 'SISF Client', 'Multicast' and 'PDM-Steering'
        device = self.device
        iid = self.iid
        lispeidwatch = "show lisp instance-id {} {} eid-watch".format(iid, qtype)
        lispeidwatch_op = get_any_single_output(device,lispeidwatch,service)
        if lispeidwatch_op is not None:
                # Regex pattern
                pattern = r"Client\s*:\s*(.*?)\nProcess\s*ID\s*:\s*(\d+)\nConnection\s*to\s*LISP\s*control\s*process\s*:\s*(.*?)\nIPC\s*end\s*point\s*:\s*(\d+)\nClient\s*notifications\s*:\s*(.*?)\n"

                # Find all matches
                matches = re.findall(pattern, lispeidwatch_op)
                self.client = None
                self.processid = None
                self.connection_status = None
                self.ipc_endpoint = None
                self.client_notifications = None

                # Print extracted information
                for match in matches:
                    client, process_id, connection_status, ipc_endpoint, notifications = match
                    if client == process:
                        self.client = process
                        self.processid = int(process_id)
                        self.connection_status = connection_status
                        self.ipc_endpoint = int(ipc_endpoint)
                        self.client_notifications = notifications

class LISPInstanceStatus:

    def __init__(self,device,iid):
        self.iid = iid
        self.device = device
    def eidstatus(self,qtype,service):
        device = self.device
        iid = self.iid

        lispiidstatus_cmd = "show lisp instance-id {} {}".format(iid,qtype)
        lispiidstatus_op = get_single_output_genie(device,lispiidstatus_cmd,service)

        if lispiidstatus_op is not None:
            path = lispiidstatus_op['lisp_id'][0]['instance_id'][iid]
            # Parameter List
            self.locator_table = path['locator_table']
            self.eid = path['eid_table']
            self.itr = path['itr']['enabled']
            self.pitr = path['itr']['proxy_itr_router']
            self.rloc = path['itr']['local_rloc_last_resort']
            self.smr = path['itr']['solicit_map_request']
            self.etr = path['etr']['enabled']
            self.petr = path['etr']['proxy_etr_router']
            self.ms = path['map_server']
            self.mr = path['map_resolver']
            self.mapresolvers = []
            mresolvers = path['itr_map_resolvers']
            for i in mresolvers:
                if "found" not in i:
                    mapresolver = i
                    state = mresolvers[i]['reachable']
                    mapresolver = {'mapresolver': mapresolver, 'state': state}
                    self.mapresolvers.append(mapresolver)
            self.mapservers = []
            mservers = path['etr_map_servers']
            for i in mservers:
                if "found" not in i:
                    mapserver = i
                    try:
                        transportstate = mservers[i]['last_map_register']['transport_state']
                    except KeyError:
                        transportstate = None
                    mapserver = {'mapserver': mapserver, 'transportstate': transportstate}
                    self.mapservers.append(mapserver)
            self.xtrid = path['xtr_id']
            self.encapsulation = path['encapsulation_type']

        else:
            self.locator_table = None
            self.eid = None
            self.itr = None
            self.pitr = None
            self.rloc = None
            self.smr = None
            self.etr = None
            self.petr = None
            self.ms = None
            self.mr = None
            self.mapresolvers = None
            self.mapservers = None
            self.xtrid = None
            self.encapsulation = None


    def eidStatistics(self,qtype,service):
        device = self.device
        iid = self.iid

        lispiidstats_cmd = "show lisp instance-id {} {} statistics".format(iid,qtype)
        lispiidstats_op = get_single_output_genie(device,lispiidstats_cmd,service)

        print (lispiidstats_op)

class LISPSession:

    def __init__(self,device):
        self.device = device

    def globallispsession(self,service):
        device = self.device
        lispsessionall = "show lisp session all"
        lispsessionallop = get_single_output_genie(device, lispsessionall, service)
        if lispsessionallop is not None:
            path = lispsessionallop['vrf']['default']
            self.totalsessions = int(path['total'])
            self.establishedsessions = int(path['established'])
            self.peers = path['peers']

    def specificlispsession(self,mapserver,service):
        device = self.device
        lispsessionspecific = "show lisp session {}".format(mapserver)
        lispsessionspecificop = get_single_output_genie(device, lispsessionspecific, service)
        if lispsessionspecificop is not None:
            path = lispsessionspecificop['lisp_id'][0]
            self.peer_addr = path["peer_addr"]
            self.peer_port = path["peer_port"]
            self.local_address = path["local_address"]
            self.local_port = path["local_port"]
            self.session_type = path["session_type"]
            self.session_state = path["session_state"]
            self.session_state_time = path["session_state_time"]
            self.messages_in = path["messages_in"]
            self.messages_out = path["messages_out"]
            self.fatal_errors = path["fatal_errors"]
            self.rcvd_unsupported = path["rcvd_unsupported"]
            self.rcvd_invalid_vrf = path["rcvd_invalid_vrf"]
            self.rcvd_override = path["rcvd_override"]
            self.rcvd_malformed = path["rcvd_malformed"]
            self.sent_defferred = path["sent_defferred"]
        if lispsessionspecificop is None:
            lispsessionspecific = "show lisp session {}".format(mapserver)
            lispsessionspecificop = get_any_single_output(device, lispsessionspecific, service)
            if lispsessionspecificop is not None:
                parsed_data = parse_lisp_session(lispsessionspecificop)
                self.peer_addr = parsed_data["peer_addr"]
                self.peer_port = parsed_data["peer_port"]
                self.local_address = parsed_data["local_address"]
                self.local_port = parsed_data["local_port"]
                self.session_type = parsed_data["session_type"]
                self.session_state = parsed_data["session_state"]
                self.session_state_time = parsed_data["session_state_time"]
                self.messages_in = parsed_data["messages_in"]
                self.messages_out = parsed_data["messages_out"]
                self.fatal_errors = parsed_data["fatal_errors"]
                self.rcvd_unsupported = parsed_data["rcvd_unsupported"]
                self.rcvd_invalid_vrf = parsed_data["rcvd_invalid_vrf"]
                self.rcvd_override = parsed_data["rcvd_override"]
                self.rcvd_malformed = parsed_data["rcvd_malformed"]
                self.sent_defferred = parsed_data["sent_defferred"]




