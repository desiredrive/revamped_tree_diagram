import re
import sys

import radkit_cli
from switchingmodules.interfaces import Interfaces
from switchingmodules.spanning_tree import SpanningTree
from switchingmodules.vlan import VlanInformation


class lisp_route_import:

    def __init__(self, iid, device):
        self.iid = iid
        self.hostname  = device
    
    def ridb_state(self, service):
        ridb_cmd = "show lisp instance-id {} ipv4 route-import database".format(self.iid)
        ridb_op = radkit_cli.get_any_single_output(self.hostname,ridb_cmd,service)
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
            cmd = "sh lisp instance-id {} ethernet server address-resolution {}".format(self.iid, self.eid)
            cp_server_output = radkit_cli.get_single_output_genie(self.queriedcp,cmd,service)
            #Address resolution is always registered using TCP
            self.protocol = "TCP"            
            #Parsing:
            if cp_server_output == None:
                print("ARP Registration not found in CP {}".format(self.queriedcp))
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

        wlc_cmd = "show run | se set WLC"
        wlc_op = radkit_cli.get_any_single_output(self.queriedcp,wlc_cmd,service)
        wlcs = []
        wlc_match = ['locator-set', 'WLC', '#']
        for line in wlc_op.splitlines():
            if not any(x  in line for x in wlc_match):
                wlcs.append(line.strip())
        self.wlcip = wlcs

        etr_list = []
        cmd = "sh lisp instance-id {} ethernet server {}".format(self.iid, self.eid)
        cp_server_output = radkit_cli.get_any_single_output(self.queriedcp,cmd,service)
        self.arbinding = "NA"

        if cp_server_output == None:
            print("MAC Registration not found in CP {}".format(self.queriedcp))
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
        if len(etrs_list) > 1:
            sys.exit("Multiple RLOCs detected for this L2 Registration, triggering troubleshooting flow\n {}".format(etrs_list))
        self.etrs = etrs_list

class l2lisp_info:

    def l2_lisp_parameters(self, xtr, ep, service):
        self.mgmtip = xtr.mgmtip
        hostname = xtr.hostname
        self.sourcemac = ep.sourcemac
        self.sourcevlan = ep.sourcevlan


        #L2 LISP Operations (Local DB, Local EID and DynEID)
        #Find the L2 instance-id   

        if ep.isl3only==False:

            #Original Command = "show lisp eid-table vlan {vlan} dynamic-eid summary"
            print ("Obtaining LISP-related information for L2 IID\n")
            lispdyneidcmd = "show lisp eid-table vlan {} dynamic-eid summary".format(self.sourcevlan)
            lispdyneidop = radkit_cli.get_single_output_genie(hostname,lispdyneidcmd,service)
            instance = lispdyneidop['lisp_id'][0]['instance_id']
            for i in instance:
                self.l2lispiid = i
            if self.l2lispiid==0:
                sys.exit("L2 LISP IID Not Found, Is this an L3 Only Subnet?")
            
            #Basic L2 LISP Information

            l2lispservice_cmd = "show lisp all instance-id {} ethernet".format(self.l2lispiid)
            l2lispservice_op = radkit_cli.get_single_output_genie(hostname,l2lispservice_cmd,service)
            lispservicepath = l2lispservice_op['lisp_id'][0]['instance_id'][self.l2lispiid]

            if lispservicepath['itr']['enabled'] == True:
                self.l2itr = True
            else:
                sys.exit("LISP Ethernet Instance {} is not enabled as ITR!, configure \"itr\" under the global service ethernet instance".format(self.l2lispiid))
            if lispservicepath['etr']['enabled'] == True:
                self.l2etr = True
            else:
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
            proxyeteronly_op = radkit_cli.get_any_single_output(hostname,proxyeteronly_cmd,service)

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
            percentage = (current/limit)*100

            if (percentage > threshold):
                print ("WARNING! Current number of L2 Map-Caches is {} , limit is {}, capacity at {}%".format(current,limit,percentage))
            else:
                print ("INFO: Current number of L2 Map-Caches is {} , limit is {}, capacity at {}%".format(current,limit,percentage))
            
            self.l2dbcache_current = lispservicepath['database']['total_database_mapping']
            self.l2dbcache_limit = lispservicepath['database']['dynamic_database']['limit']

            current = (lispservicepath['database']['total_database_mapping'])
            limit = (lispservicepath['database']['dynamic_database']['limit'])
            threshold = 90
            percentage = (current/limit)*100

            if (percentage > threshold):
                print ("WARNING! Current number of L2 Database Entries is {} , limit is {}, capacity at {}%".format(current,limit,percentage))
            else:
                print ("INFO: Current number of L2 Database Entries is {} , limit is {}, capacity at {}%".format(current,limit,percentage))

            self.l2signalsupressstate = lispservicepath['map_cache']['signal_supress']
            if self.l2signalsupressstate is True:
                sys.exit("WARNING! Signal Supression is enabled, no more map-requests will be created for this instance!")

            #Searching the source MAC in LISP L2 Dynamic EID
            eids = lispdyneidop['lisp_id'][0]['instance_id'][self.l2lispiid]['dynamic_eids']['Auto-L2-group-8192']['eids']
            if any(x  in self.sourcemac for x in eids):
                self.l2dynstate = True
            else:
                sys.exit("Source MAC {} in IPDT but not in LISP {} Dynamic-EID, is LISP database-mapping configured for VLAN {}?".format(self.sourcemac,self.l2lispiid,self.sourcevlan))

            #Searching the source MAC in LISP Database
            dbl2_cmd = "show lisp instance-id {} ethernet database".format(self.l2lispiid)
            dbl2_op = radkit_cli.get_single_output_genie(hostname,dbl2_cmd,service)
            eids = dbl2_op['lisp_id'][0]['instance_id'][self.l2lispiid]['entries']['eids']
            mac = self.sourcemac+"/48"
            if any(x  in mac for x in eids):
                self.l2lispdbstate = True
            else:
                sys.exit("Source MAC {} in IPDT/ DynEID but not in LISP {} Database? Debug LISP".format(self.sourcemac,self.l2lispiid))

class L2LISPInterface:
    def __init__(self,vlan,device):
        self.hostname = device
        self.vlan = vlan

    def l2lispinterfacestatus(self,service):
        #STP Status for the VLAN
        stpstatus = SpanningTree(self.hostname)
        stpstatus.spt_vlan_active(self.vlan,service)
        if stpstatus is None:
            sys.exit("WARNING!: No Spanning Tree Information for VLAN {} in device: {} , is the VLAN created? There are no active in this VLAN".format(self.vlan, self.hostname))
        if stpstatus.number_of_fwd_interfaces == 0:
            sys.exit("WARNING!: No FWD enabled ports in VLAN {} in device: {} , are the ports assigned to the correct VLAN and connected?".format(self.vlan, self.hostname))
        self.stpstatus = stpstatus

        #VLAN Status and L2LISP type
        vlanstatus = VlanInformation(self.vlan,self.hostname)
        vlanstatus.vlanbrief(service)
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
            sys.exit("WARNING!: No L2LISP (or Tunnel) interface found attached to VLAN {} in device: {}! - This might be the result of an unexpected switchover or ISSU upgrade; remove the affected L2LISP instance and create it again".format(self.vlan, self.hostname))
        self.vlanstatus = vlanstatus
        self.l2lispparenttype = l2lispparenttype

        #L2LISP0 Main Interface and L2LISP Subinterface (if applicable)
        if l2lispparenttype == 'L2LISP0':
            l2lisp0interface = Interfaces('L2LISP0', self.hostname)
            l2lisp0interface.show_interface(service)
            if l2lisp0interface.linestate != 'up':
                sys.exit("WARNING!: L2LISP Interface is DOWN in device: {}".format(self.hostname))
            l2lispsubintf = "L2LISP0."+l2lispiid
            l2lispsubinterface = Interfaces(l2lispsubintf,self.hostname)
            l2lispsubinterface.show_interface(service)
            if l2lispsubinterface.linestate != 'up':
                sys.exit("WARNING!: {} Interface is DOWN in device: {}".format(l2lispsubintf,self.hostname))
            self.l2lispparenstatus = l2lisp0interface
            self.l2lispsubinterfacestatus = l2lispsubinterface
        if l2lispparenttype == 'Tunnel':
            tunnelinterface = Interfaces(l2lispparentintf, self.hostname)
            tunnelinterface.show_interface(service)
            if tunnelinterface.linestate != 'up':
                sys.exit("WARNING!: l2lispparentintf Interface is DOWN in device: {}".format(self.hostname))
            self.l2lispparenstatus = tunnelinterface

        #L2LISP statistics

class L2LISPConfiguration:
    def __init__(self,iid,device):
        self.hostname = device
        self.iid = iid

    def l2flooding_configuration(self,service):
        hostname = self.hostname
        iid = self.iid
        matches = ['#', 'show']
        self.floodunknownunicast = False
        self.broadcastunderlay = None
        self.floodarpnd = False
        self.floodaccesstunnel = False

        #Structure is {Type: Unicast|Multicast, Multicast Group : Group, Vlan: Vlan
        l2floodingconfig_cmd = "show run | se instance-id {}".format(iid)
        l2floodingconfig_op = radkit_cli.get_any_single_output(hostname,l2floodingconfig_cmd,service)
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
            eid = None
            map_cache_cmd = "sh lisp instance-id {} ethernet map-cache {}".format(self.iid, self.eid)
            map_cache_output = radkit_cli.get_single_output_genie(self.queriedev,map_cache_cmd,service)
            if map_cache_output == None:
                sys.exit("WARNING!: No map-cache found for EID {} in IID {} in device {}, maybe ARP is not working?".format(self.eid, self.iid, self.queriedev) )
            else:
                mapcache_path = map_cache_output['lisp_id'][0]['instance_id'][self.iid]['eid_prefix']
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
            
