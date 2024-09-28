import re
import sys
import radkit_cli
from ipverifications import stringvalidator

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




            