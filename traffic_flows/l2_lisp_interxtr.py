import sys
from routingmodules.lisp import controlplane_eid
from routingmodules.lisp import l2_map_cache
from pprint import pformat
from catalystcenterapi.catcapi import get_device_from_lo0, get_network_device_byuuid, validate_cp_infabric
from radkit_cli import logging_info,logging_error,logging_warning,get_hostname_from_mgmtip

def cp_l2_results(l2object,step):
    collection_summary = ("EID: {}, L2VNI: {}, ETRs: {}, Protocol: {}, CP: {}").format(l2object.eid, l2object.iid, l2object.etrs, l2object.protocol, l2object.queriedcp,l2object.wlcip)
    string = "Result: Success"
    logging_info(step, "L2LISP", "[L2Registration]",l2object.queriedcp, collection_summary)
    logging_info(step, "L2LISP", "[L2Registration]",l2object.queriedcp, string)

def l2_mapcache_results(l2mapcache,step):
    collection_summary = ("EID: {}, L2VNI: {}, RLOC: {}, CP: {}, State: {}, Priority: {}, Weight: {}").format(l2mapcache.eid, l2mapcache.iid, l2mapcache.rloc, l2mapcache.queriedev, l2mapcache.rlocstate,l2mapcache.priority, l2mapcache.weight)
    string = "Result: Success"
    logging_info(step, "L2LISP", "[L2-Map-Cache]",l2mapcache.queriedev, collection_summary)
    logging_info(step, "L2LISP", "[L2-Map-Cache]",l2mapcache.queriedev, string)



def ar_relay_resolution(dstip, iid, l2cps, service, dnac, fabricsite,step):
        process = "controlPlaneL2lisp"
        subprocess = '[addresResolutionQuery]'
        #Step 1, identify Control Planes
        device_uuids = []
        for i in l2cps:
            devices = get_device_from_lo0(i, dnac, service)
            if devices is None:
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
            is_local = validate_cp_infabric(cpmgmtip,fabricsite,dnac,service,step)
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

        #print ("Address-Resolution Binding results: \n")
        for i in address_resolution:
            try:
                mac = i.arbinding
                etr = i.etrs
                #print (pformat(vars(i), indent=4, width =1, sort_dicts=False))
                macs.append(mac)
                etrs.append(etr)
            except AttributeError:
                pass
        #print ("\n")
        macs = list(set(macs))
        macs = [x for x in macs if x is not None]
        if len (macs) > 1:
            error = "Control Plane - Multiple AR Bindings"
            message = "The destination IP {} has more than 1 MAC address: {} from {}, for more information, consult the GPA_SDA Collection Log file".format(
                dstip, macs, etrs)
            logging_error(step, process, subprocess, queriedcpname, error)
            logging_info(step, process, subprocess, queriedcpname, message)
            #raise BDBTaskError("Error: {} | {}".format(error, message))
            sys.exit("Error: {} | {}".format(error, message))
        
        if len (macs) == 0:
            error = "Control Plane - No MAC Address Found"
            message = "No AR-Binding records were found in any of the local Control Planes on the fabric site, try running this script swapping the source and destination parameters. To debug this condition, validate the status of the LISP session between Fabric Edges and Control Planes, for more reference, consult the GPA_SDA Collection Log file"
            logging_error(step, process, subprocess, queriedcpname, error)
            logging_info(step, process, subprocess, queriedcpname, message)
            # raise BDBTaskError("Error: {} | {}".format(error, message))
            sys.exit("Error: {} | {}".format(error, message))
        return macs[0], local_cps_mgmtips

def mac_rloc_resolution(dstmac, iid, l2cps, service,step):
    process = "controlPlaneL2lisp"
    subprocess = "[macAddressQuery]"
    logging_info(step, process,subprocess,"Main","Querying site Control Planes for L2LISP MAC for {}".format(dstmac))
    #print ("Querying site Control Planes for L2LISP MAC for {} \n".format(dstmac))
    l2_res = []
    etrs = []
    wlcs = []
    queriedcpname = None
    for i in l2cps:
        queriedcp = i
        queriedcpname = get_hostname_from_mgmtip(queriedcp,service)
        #eid, iid, queriedcp):
        mac_query = controlplane_eid(dstmac,iid,queriedcpname)
        mac_query.ethernet_q(service)
        l2_res.append(mac_query)
    if l2_res is None:
        error = "Control Plane - No RLOC Found for L2 EID"
        message = "There were no RLOCs binded to this MAC address in any of the site Control Planes, for more information, consult the GPA_SDA Collection Log file"
        logging_error(step, process, subprocess, queriedcpname, error)
        logging_info(step, process, subprocess, queriedcpname, message)
        #raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))

    logging_info(step, process,subprocess,"Main","L2 LISP MAC Control Plane results:")
    #print ("L2 LISP MAC Control Plane results: \n")
    for i in l2_res:
        cp_l2_results(i,step)
        #print (pformat(vars(i), indent=4, width =1, sort_dicts=False))
        try:
            for j in i.etrs:
                if j is not None:
                    etrs.append(j)
        except (KeyError,AttributeError,TypeError):
            pass
        try:
            for k in i.wlcip:
                if k is not None:
                    wlcs.append(k)
        except (KeyError,AttributeError,TypeError):
            pass
    wlcs = list(set(wlcs))
    etrs = list(set(etrs))
    etrs = [x for x in etrs if x  not in wlcs]
    if len (etrs) > 1:
        error = "Control Plane - Muliple RLOCs"
        message = "The destination MAC {} has more than 1 unique RLOCs: {}, this indicates multiple ETRs registering the same endpoint, for more information, consult the GPA_SDA Collection Log file".format(
            dstmac, etrs)
        logging_error(step, process, subprocess, queriedcpname, error)
        logging_info(step, process, subprocess, queriedcpname, message)
        #raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))
    return etrs[0], dstmac
            
def l2lisp_map_cache_validation(l2lispinfo, calculated_rloc, querieddev, mac, service,step):
    process = "L2LISP"
    subprocess = "[L2-Map-Cache]"
    l2mapcache = l2_map_cache(mac, l2lispinfo.l2lispiid, querieddev)
    l2mapcache.l2map(service)

    l2rloc = l2mapcache.rloc
    state= l2mapcache.rlocstate

    bad_states = ['route-reject', 'own', 'admin']
    if any(x  in state for x in bad_states):
        logging_info(step, process, subprocess, querieddev,
                     "RLOC is marked as {}, validating RLOC state")
        #print ("RLOC is marked as {}, validating RLOC state \n")
        #sequence to validate RLOC

    
    #validaiton of map-cache state
    if l2rloc == calculated_rloc:
        logging_info(step, process, subprocess, querieddev,
                     "L2 Map-Cache matches CP regsitered RLOC: {}".format(calculated_rloc))
        #print ("L2 Map-Cache matches CP regsitered RLOC: {} \n".format(calculated_rloc))
    else:
        logging_info(step,process,subprocess,querieddev,"SMR verifications comming soon")
        #print ("SMR verifications comming soon \n")
        error = "Control Plane - Inconsistent RLOCs"
        message = "L2 Map-cache {} does not match CP registered RLOC {}, this is a possible event of LISP Mobility where the SMR mechanism did not trigger properly, for more information, consult the GPA_SDA Collection Log file".format(
            l2rloc, calculated_rloc)
        logging_error(step, process, subprocess, querieddev, error)
        logging_info(step, process, subprocess, querieddev, message)
        #raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))


    if state == "UP":
        logging_info(step,process,subprocess,querieddev,"RLOC is marked as UP, validating end-to-end connectivity")
        #print ("RLOC is marked as UP, validating end-to-end connectivity \n")
    return l2mapcache