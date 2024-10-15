import sys
import radkit_cli
from routingmodules.lisp import controlplane_eid
from routingmodules.lisp import l2_map_cache
from pprint import pformat
from catalystcenterapi.catcapi import get_device_from_lo0, get_network_device_byuuid, validate_cp_infabric

def ar_relay_resolution(dstip, iid, l2cps, service, dnac, fabricsite):

        #Step 1, identify Control Planes
        device_uuids = []
        for i in l2cps:
            devices = get_device_from_lo0(i, dnac, service)
            if devices is None:
                sys.exit("No Control Planes found with Loopback 0 with IP {} in Catalyst Center Inventory, make sure these are in Managed state".format(i))
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
        for i in local_cps_mgmtips:
            queriedcp = i
            queriedcpname = radkit_cli.get_hostname_from_mgmtip(queriedcp,service)
            #eid, iid, queriedcp):
            ar_query = controlplane_eid(dstip, iid, queriedcpname)
            ar_query.address_q(service)
            address_resolution.append(ar_query)
        
        macs = []
        etrs = []

        print ("Address-Resolution Binding results: \n")
        for i in address_resolution:
            try:
                mac = i.arbinding
                etr = i.etrs
                print (pformat(vars(i), indent=4, width =1, sort_dicts=False))
                macs.append(mac)
                etrs.append(etr)
            except AttributeError:
                pass
        print ("\n")
        macs = list(set(macs))
        macs = [x for x in macs if x is not None]
        if len (macs) > 1:
            sys.exit("The destination IP {} has more than 1 MAC address: {} from {} \n".format(dstip, macs, etrs))
        
        if len (macs) == 0:
            sys.exit("No Address-Resolution bindings were found in any of the local Control Planes for IP {}".format(dstip))
        return macs[0], local_cps_mgmtips

def mac_rloc_resolution(dstmac, iid, l2cps, service):
    print ("Querying site Control Planes for L2LISP MAC for {} \n".format(dstmac))
    l2_res = []
    etrs = []
    wlcs = []
    for i in l2cps:
        queriedcp = i
        queriedcpname = radkit_cli.get_hostname_from_mgmtip(queriedcp,service)
        #eid, iid, queriedcp):
        mac_query = controlplane_eid(dstmac,iid,queriedcpname)
        mac_query.ethernet_q(service)
        l2_res.append(mac_query)
    if l2_res is None:
        sys.exit ("There were no RLOCs binded to this MAC address in any of the local Control Planes")
    print ("L2 LISP MAC Control Plane results: \n")
    for i in l2_res:
        print (pformat(vars(i), indent=4, width =1, sort_dicts=False))
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
    print ("\n")
    wlcs = list(set(wlcs))
    etrs = list(set(etrs))
    etrs = [x for x in etrs if x  not in wlcs]
    if len (etrs) > 1:
        sys.exit("The destination MAC {} has more than 1 RLOCs: {} \n".format(dstmac, etrs))          
    return etrs[0], dstmac
            
def l2lisp_map_cache_validation(l2lispinfo, calculated_rloc, querieddev, mac, service):
    l2mapcache = l2_map_cache(mac, l2lispinfo.l2lispiid, querieddev)
    l2mapcache.l2map(service)

    l2rloc = l2mapcache.rloc
    state= l2mapcache.rlocstate

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
        sys.exit("L2 Map-cache {} does not match CP registered RLOC {} \n").format(l2rloc, calculated_rloc)
    
    return l2mapcache