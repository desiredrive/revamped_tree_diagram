import re
import sys
import radkit_cli
from ipverifications import stringvalidator
from catalystcenterapi.catcapi import get_device_from_lo0

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


class ar_relay_resolution:

    def __init__ (self):
        self.test = None

    def ar_resolution_cp(dstip, iid, l2cps, service, dnac):

        #Step 1, identify Control Planes
        device_uuids = []
        for i in l2cps:
            devices = get_device_from_lo0(i, dnac, service)
            if devices == None:
                sys.exit("No Control Planes found with Loopback 0 with IP {} in Catalyst Center Inventory, make sure these are in Managed state".format(i))
            for j in devices:
                device_uuids.append(j['deviceUUID'])
        print(device_uuids)

'''
    print ("Querying site Control Planes for LISP AR for {} \n".format(dstip))
    ar_res = []
    for i in l2cps:
        queriedcp = i
        ar_q = controlplane.cp_eid(dstip,iid,queriedcp)
        ar_q.address_q(service)
        ar_res.append(ar_q)

    macs = []
    etrs = []

    if ar_res == None:
        sys.exit("No MAC address were found in any of the local Control Planes")
    print ("Address-Resolution Binding results: \n")

    for i in ar_res:
        mac = i.arbinding
        etr = i.etrs
        print (pformat(vars(i), indent=4, width =1, sort_dicts=False))
        macs.append(mac)
        etrs.append(etr)
    print ("\n")
    macs = list(set(macs))
    macs = [x for x in macs if x is not None]
    if len (macs) > 1:
        sys.exit("The destination IP {} has more than 1 MAC address: {} from {} \n".format(dstip, macs, etrs))
    
    if len (macs) == 0:
        sys.exit("No MAC address were found in any of the local Control Planes")
    return (macs[0])

'''
            