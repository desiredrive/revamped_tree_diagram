from dataclasses import dataclass
import re
import sys
import radkit_cli

class lisp_route_import:

    def __init__(self, iid, device):
        self.iid = iid
        self.configured_iids = None 
        self.sourceprotocol = None
        self.limit = None
        self.rlocs = None
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
        self.etrs = None    #List of ETRs registering this EID
        self.etrsessions = None #LISP Session Port (if any)
        self.protocol = "UDP" #Was this registered using UDP or TCP?
        self.isfewap = None #Is this EID an AP Radio MAC? True or False
        self.wlcip = None    #IP of the WLC if any
        self.regbywlc = None #Is this EID registered by a WLC? True or False? If so, whats the WLC IP?
        self.domainid = None #Domain ID for this registration
        self.multidomain =  None #Multihoming ID for this registration
        self.arbinding = None #What is the MAC address of this IP binding if any?
        self.authenfailures = None #Are there any authentication failures?
        self.queriedcp = queriedcp #What is the IP address of this queried CP?

    def address_q(self, service):
            cmd = "sh lisp instance-id {} ethernet server address-resolution {}".format(self.iid, self.eid)
            cp_server_output = radkit_cli.get_single_output_genie(self.queriedcp,cmd,service)
            #Address resolution is always registered using TCP
            self.protocol = "TCP"
            self.domainid = "NA"
            self.multidomain = "NA" 
            self.isfewap = "NA"
            self.regbywlc = "NA"
            
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

class l2lisp_info:

    def __init__(self):
        self.sourcemac = None
        self.l2lispiid = None
        self.l2dynstate = False
        self.l2lispdbstate = False
        self.l2cps = [] 

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

            #Retrieving L2LISP CPs

            matches = ["#", "show"]
            l2mr_cmd = "show lisp instance-id {} ethernet | se Map-Resol".format(self.l2lispiid)
            l2mr_op = radkit_cli.get_any_single_output(hostname,l2mr_cmd,service)
            for line in l2mr_op.splitlines():
                if not any(x  in line for x in matches):
                    if '.' in line:
                        msmr = re.compile( "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" ).search(line).group().strip()
                        try:
                            self.l2cps.append(msmr)
                        except AttributeError:
                            sys.exit("Source device {} has no Control Planes defined for L2".format(hostname))