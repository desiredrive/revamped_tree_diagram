import re
import sys
from routingmodules.lisp import controlplane_eid
from routingmodules.lisp import l2_map_cache
from pprint import pformat
from catalystcenterapi.catcapi import get_device_from_lo0, get_network_device_byuuid, validate_cp_infabric
from radkit_cli import get_hostname_from_mgmtip,logging_info,logging_error

def ar_relay_resolution(dstip, iid, l2cps, service, dnac, fabricsite):

        #Step 1, identify Control Planes
        device_uuids = []
        for i in l2cps:
            devices = get_device_from_lo0(i, dnac, service)
            if devices is None:
                step = "X"
                process = 'controlPlane'
                subprocess = '[addresResolutionQuery]'
                error = "Catalyst Center API - No Device Found"
                message = "No Control Planes found with Loopback 0 with IP {} in Catalyst Center Inventory, make sure these are in Managed state".format(
                    i)
                logging_error(step, process, subprocess, dnac, error)
                logging_info(step, process, subprocess, dnac, message)
                #raise BDBTaskError("Error: {} | {}".format(error, message))
                sys.exit("Error: {} | {}".format(error, message))
            for j in devices:
                device_uuids.append(j['deviceUUID'])
        #Step 2, identify Management IP for CPs
        local_cps_mgmtips = []
        for i in device_uuids:
            cpmgmtip = get_network_device_byuuid(i,dnac,service)
            if cpmgmtip is None:
                continue
            is_local = validate_cp_infabric(cpmgmtip,fabricsite,dnac,service)
            if is_local is True:
                local_cps_mgmtips.append(cpmgmtip)

        #Step 3, Query AR to Obtain L2EID/MAC of Destination
        address_resolution = []
        queriedcpname = None
        for i in local_cps_mgmtips:
            queriedcp = i
            queriedcpname = get_hostname_from_mgmtip(queriedcp,service)
            #eid, iid, queriedcp):
            ar_query = controlplane_eid(dstip, iid, queriedcpname)
            ar_query.address_q(service)
            address_resolution.append(ar_query)
        
        macs = []
        etrs = []
        if len(address_resolution) is None:
            step = "X"
            process = 'controlPlane'
            subprocess = '[addresResolutionQuery]'
            error = "Control Plane - No Address Resolution Records"
            message = "No AR-Binding records were found in any of the local Control Planes on the fabric site, to debug this condition, validate the status of the LISP session between Fabric Edges and Control Planes, for more reference, consult the GPA_SDA Collection Log file"
            logging_error(step, process, subprocess, queriedcpname, error)
            logging_info(step, process, subprocess, queriedcpname, message)
            #raise BDBTaskError("Error: {} | {}".format(error, message))
            sys.exit("Error: {} | {}".format(error, message))

        #print ("Address-Resolution Binding results: \n")

        for i in address_resolution:
            mac = i.arbinding
            etr = i.etrs
            print (pformat(vars(i), indent=4, width =1, sort_dicts=False))
            macs.append(mac)
            etrs.append(etr)
        print ("\n")
        macs = list(set(macs))
        macs = [x for x in macs if x is not None]
        if len (macs) > 1:
            step = "X"
            process = 'controlPlane'
            subprocess = '[addresResolutionQuery]'
            error = "Control Plane - Multiple AR Bindings"
            message = "The destination IP {} has more than 1 MAC address: {} from {}, for more information, consult the GPA_SDA Collection Log file".format(
                dstip, macs, etrs)
            logging_error(step, process, subprocess, queriedcpname, error)
            logging_info(step, process, subprocess, queriedcpname, message)
            #raise BDBTaskError("Error: {} | {}".format(error, message))
            sys.exit("Error: {} | {}".format(error, message))

        if len (macs) == 0:
            step = "X"
            process = 'controlPlane'
            subprocess = '[addresResolutionQuery]'
            error = "Control Plane - No MAC Address Found"
            message = "No AR-Binding records were found in any of the local Control Planes on the fabric site, to debug this condition, validate the status of the LISP session between Fabric Edges and Control Planes, for more reference, consult the GPA_SDA Collection Log file"
            logging_error(step, process, subprocess, queriedcpname, error)
            logging_info(step, process, subprocess, queriedcpname, message)
            # raise BDBTaskError("Error: {} | {}".format(error, message))
            sys.exit("Error: {} | {}".format(error, message))
        return (macs[0], local_cps_mgmtips)   

def mac_rloc_resolution(dstmac, iid, l2cps, service):
    #print ("Querying site Control Planes for L2LISP MAC for {} \n".format(dstmac))
    l2_res = []
    queriedcpname = None
    for i in l2cps:
        queriedcp = i
        queriedcpname = get_hostname_from_mgmtip(queriedcp,service)
        #eid, iid, queriedcp):
        mac_query = controlplane_eid(dstmac,iid,queriedcpname)
        mac_query.ethernet_q(service)
        l2_res.append(mac_query)
        wlcs = []    
        etrs = []
    if l2_res is None:
        step = "X"
        process = 'controlPlane'
        subprocess = '[macAddressQuery]'
        error = "Control Plane - No RLOC Found for L2 EID"
        message = "There were no RLOCs binded to this MAC address in any of the site Control Planes, for more information, consult the GPA_SDA Collection Log file"
        logging_error(step, process, subprocess, queriedcpname, error)
        logging_info(step, process, subprocess, queriedcpname, message)
        #raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))

    print ("L2 LISP MAC Control Plane results: \n")
    for i in l2_res:
        print (pformat(vars(i), indent=4, width =1, sort_dicts=False))
        try:
            for j in i.etrs:
                if j != None:
                    etrs.append(j)
        except:
            pass
        try:
            for k in i.wlcip:
                if k != None:
                    wlcs.append(k)
        except:
            pass
    print ("\n")
    wlcs = list(set(wlcs))
    etrs = list(set(etrs))
    etrs = [x for x in etrs if x  not in wlcs]
    if len (etrs) > 1:
        step = "X"
        process = 'controlPlane'
        subprocess = '[macAddressQuery]'
        error = "Control Plane - Muliple RLOCs"
        message = "The destination MAC {} has more than 1 unique RLOCs: {}, this indicates multiple ETRs registering the same endpoint, for more information, consult the GPA_SDA Collection Log file".format(
            dstmac, etrs)
        logging_error(step, process, subprocess, queriedcpname, error)
        logging_info(step, process, subprocess, queriedcpname, message)
        #raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))
    return (etrs[0])
            
def l2lisp_map_cache_validation(eid, l2lispinfo, calculated_rloc, querieddev):
    l2mapcache = l2_map_cache(eid, l2lispinfo.l2lispiid, querieddev)
    l2mapcache.l2map

    l2rloc = l2mapcache.rloc
    state= l2mapcache.rlocstate

    print (pformat(vars(l2mapcache), indent=4, width =1, sort_dicts=False)) 

    bad_states = ['route-reject', 'own', 'admin']
    if any(x  in state for x in bad_states):
        print ("RLOC is marked as {}, validating RLOC state \n")
        #sequence to validate RLOC
    if state == "UP":
        print ("RLOC is marked as UP, validating end-to-end connectivity \n")
    
    #validaiton of map-cache state
    if l2rloc == calculated_rloc:
        print ("L2 Map-Cache matches CP regsitered RLOC: {} \n".format(calculated_rloc))
    else:
        print ("SMR verifications comming soon \n")
        step = "X"
        process = 'controlPlane'
        subprocess = '[mapCacheValidation]'
        error = "Control Plane - Inconsistent RLOCs"
        message = "L2 Map-cache {} does not match CP registered RLOC {}, this is a possible event of LISP Mobility where the SMR mechanism did not trigger properly, for more information, consult the GPA_SDA Collection Log file".format(
            l2rloc, calculated_rloc)
        logging_error(step, process, subprocess, querieddev, error)
        logging_info(step, process, subprocess, querieddev, message)
        #raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))

 