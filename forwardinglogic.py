import re
import ipverifications
import sys
import traffic_flows.l2_lisp_interxtr
from pprint import pformat

#Switching Flow  : From one LISP XTR to Another
'''
Verifications:

Are source and destination in the same subnet? If Yes:
    Are these in an L2 only network? - 1st Exception, Check L2 only flag
    Is Flood ARPnd Enabled? - 
        Yes - Verification of L2 AR LISP is marked as strict 
        No - Verification of L2 AR LISP is only to find remote RLOCs
            If remote RLOCs cannot be found (missing AR), an exception must be performed - Request Destination MAC of the endpoint
            If remote RLOCs cannot be found (missing MAC), an exception must be performed - Request Destination device (mgmtip) to perform Host Onboarding Validations
    if L2 only: SGT and DHCP operations must be performed differently
    CP queries:
        if Flood ARPnd disabled : L2MAC and L2AR are mandatory
        if Flood ARPnd enabled: L2MAC is mandatory, L2AR is relaxed
'''
def flowelection(epinfo, dstip):
    issamesubnet=ipverifications.subnet_validator(epinfo.sourceip,dstip,epinfo.mask)
    if issamesubnet==False:
        print ("Devices in different Subnet, Routing Flow\n")
        return ("L3")
    if issamesubnet==True:
        print ("Devices in the same Subnet, starting Switching Flow \n")
        return ("L2")

def device_flow(flow_type, sourcextr, sourceep, destip, service):
    if flow_type == "L2":
        print("Determining if flow is Inter-XTR or Intra-XTR")
        
        #Step 1: Profile L2 LISP parameters for the Source Endpoint
        l2lispsrc = traffic_flows.l2_lisp_interxtr.l2lisp_info()
        l2lispsrc.l2_lisp_parameters(sourcextr, sourceep, service)
        print (pformat(vars(l2lispsrc), indent=4, width =1, sort_dicts=False))

        #Step 2: Identify AR-Request, find the endpoint in Control Plane 
        l2lisp_ar = traffic_flows.l2_lisp_interxtr.ar_relay_resolution()
        l2lisp_ar.ar_resolution_cp(l2lispsrc.l2lispiid,l2lispsrc.l2cps,service,sourcextr.dnac)

    return None

def site_flow():
    return None

def transit_flow():
    return None

def inter_vrf():
    return None
