import sys
import ipaddress
import radkit_cli
from pprint import pformat
from catalystcenterapi.catcapi import get_device_from_lo0, get_network_device_byuuid, validate_cp_infabric
from ipverifications import ipaddress_validator_no_return, mac_address_validator

#Order of operations for verifying multicast
def text():
    '''
    Main Local Verifications
    -) Which traffic are you troubleshooting?
    -) Is it L2 Only VN?
    -) Is IGMP snooping enabled? - This controls IGMP verifications
    -) Is L3 multicast enabled?
    -) Is 17.6 or higher?
    -) Multicast Routing global enablement
    -) PIM enabled in Loopback0 Interfaces
    -) Multicast enabled in upstream interfaces (what are upstream interfaces?) (the ones used by the upstream protocol)
        - This requires per-protocol enablement and neighbor validation; for now: OSPF and ISIS
    -) PIM neighbor validations
    -) PIM enablement on L2 interfaces
    -) PIM DR election (Lo0 must be DR)
    -) L2LISP validations (already made)
    -) Determining Multicast Group for the required L2 Instance
    -) Determining RP to the required group
    -) Determining RP source interface = warning if lo0 is not the source
    -) Determining RP reachability and Tunnel encap (and decap if eligible)
    -) Determining if SSM is enabled using the default group 232.0.0.0/8
    -) *,G Creation based on L2LISP interface availability
    -) S,G Creation based on traffic:
        what constitutes traffic? - BUM traffic traversing L2 interfaces in the L2LISP domain/VLAN
            - STP verification
            - AcX exclusion
    -) L2LISP ACL (Parse if the required traffic is blocked or allowed by the L2LISP ACL 17.3 and 17.6)
    -) Multicast Limits and Counts
    -) PIM drops

LHR Validations:

-) Main validations
-) FHR Routes exist already? - Jump to SPT/SG Validations
-) PIM Rules (Rule 1,Rule 2,
-) *,G Creation and RPF
-) *,G Counters
-) *,G Flags (Rule 8)
-) MFIB equivalents
-) Identification of RPF interface
-) Identification of potential CDP neighbor (optional); mapping nexthop interface with L3 information
-) Identification of RPF neighbor (Lo0 to Device name to Radkit Inventory)
-) Identification of RPF upstream interface (CDP and L3)
-) Carrying RP information, how many RPs do exist? Are there more than 1? How can we tell.?
-) DO intermediate nodes exist?


RP Validations:
-) PIM Rules (3, 4, 5=Prunning, 6=Maintenance, 7=FHR Prunning)
-) Main Validations
-) Identification of the RP
-) Is the RP inside the fabric?
-) Is the RP consistent across fabric nodes?
-) MSDP Peer if any (RP more than 1)
-) MSDP SA Cache States
-) MSDP RPF Counters
-) MSDP Next Hop Resolution
-) Telnet for MSDP Validation
-) *,G Definition
-) *,G OILs (and matching with downstream device)
-) *,G Counters
-) S,G Flags (Rule 8)
-) S,G Validation (is registered-module)
-) S,G IIF validation
-) S,G OIL download to *,G Validaiton
-) Is RP joining the downstream Int or FHR?

FHR Validations
-) Main Validations
-) Is it the FHR?
-) Registration Validation (Stuck in Register?, PIM Tunnel, Recahability, Reg Counters)
-) S,G Validation
-) S,G Counters
-) S,G OIL State
-) S,G Counters
-) MFIB Equivalents
-) Is it SPT already?
'''
    return None

def multicast_ranges(mcast_group):
    mcastflag: bool = ipaddress.ip_address(mcast_group) in ipaddress.ip_network("224.0.0.0/4")
    if mcastflag is True:
        llmcastflag = ipaddress.ip_address(mcast_group) in ipaddress.ip_network("224.0.0.0/24")
        return mcastflag, llmcastflag

def is_l2_flooding(mcast_group, ttl, isl2only: bool):
    #Step 1, is this L3 or L2 Flooding?
    isip = ipaddress_validator_no_return(mcast_group)
    if isip is True:
        #mcasttype = multicast_ranges(mcast_group)
        #ismcast = multicast_ranges(mcast_group)
        #isllmcast = multicast_rangesmac_validator
        return None
    if isip is False:
        mactype = mac_address_validator(mcast_group)
        print (mactype)

