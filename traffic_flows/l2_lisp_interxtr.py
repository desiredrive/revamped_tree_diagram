import re
import sys
import radkit_cli
from ipverifications import stringvalidator
from routingmodules.lisp import controlplane_eid
from catalystcenterapi.catcapi import get_device_from_lo0, get_network_device_byuuid, validate_cp_infabric


def ar_relay_resolution(dstip, iid, l2cps, service, dnac, fabricsite):

        #Step 1, identify Control Planes
        device_uuids = []
        for i in l2cps:
            devices = get_device_from_lo0(i, dnac, service)
            if devices == None:
                sys.exit("No Control Planes found with Loopback 0 with IP {} in Catalyst Center Inventory, make sure these are in Managed state".format(i))
            for j in devices:
                device_uuids.append(j['deviceUUID'])
        #Step 2, identify Management IP for CPs
        local_cps_mgmtips = []
        for i in device_uuids:
            cpmgmtip = get_network_device_byuuid(i,dnac,service)
            if cpmgmtip == None:
                continue
            is_local = validate_cp_infabric(cpmgmtip,fabricsite,dnac,service)
            if is_local == True:
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
        print (address_resolution)



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
            