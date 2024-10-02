from dataclasses import dataclass
import re
import sys
import radkit_cli

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
            

class l2_map_cache:

    def __init__(self,eid, iid, queriedev):
        self.eid = eid              #Can be : IPv4, MAC address (IPv6 not needed for now)
        self.iid = iid              #LISP Instance ID for the request
        self.queriedev = queriedev

    def l2map(self, service):

            map_cache_cmd = "sh lisp instance-id {} ethernet map-cache {}".format(self.iid, self.eid)
            map_cache_output = radkit_cli.get_single_output_genie(self.queriedev,map_cache_cmd,service)
            if map_cache_output == None:
                sys.exit("WARNING!: No map-cache found for EID {} in IID {} in device {}, maybe ARP is not working?".format(self.eid, self.iid, self.queriedev) )
                return None
            else:
                mapcache_path = map_cache_output['lisp_id'][0]['instance_id'][self.iid]['eid_prefix']
                self.mask = 48
                for i in mapcache_path:
                    eid = i
                self.uptime = mapcache_path[eid]['uptime']
                self.expiration = mapcache_path[eid]['expiry_time']
                self.source = mapcache_path[eid]['source_type']
                for i in mapcache_path[eid]['rloc_set']:
                    self.rloc = i
                self.rlocstate = mapcache_path[eid]['rloc_set'][i]['rloc_state']
                self.priority = mapcache_path[eid]['rloc_set'][i]['priority']
                self.weight = mapcache_path[eid]['rloc_set'][i]['weight']
            
