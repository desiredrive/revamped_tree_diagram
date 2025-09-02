import ipaddress
import sys
import re
import binascii
import logging
from ipaddress import ip_address


#Function to Validate if the IP is a valid UNICAST IP address, returns True or False.
def subnet_validator(sourceip,destip,mask):

    if destip=="255.255.255.255":
        error = "IP Error - Unsupported"
        message = "Destination IP is a Full Broadcast 255.255.255.255, unsupported flow"
        #raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))

    network = ipaddress.IPv4Network(sourceip+"/"+mask, strict=False)
    mcastflag = ipaddress.ip_address(destip) in ipaddress.ip_network("224.0.0.0/4")
    morereserved = ipaddress.ip_address(destip) in ipaddress.ip_network("240.0.0.0/4")
    reserved0 = ipaddress.ip_address(destip) in ipaddress.ip_network("0.0.0.0/8")
    localhost = ipaddress.ip_address(destip) in ipaddress.ip_network("127.0.0.0/8")
    if mcastflag is True:
        llmcastflag = ipaddress.ip_address(destip) in ipaddress.ip_network("224.0.0.0/24")
        if llmcastflag is True:
            error = "IP Error - Unsupported"
            message = "Destination IP is Link Local Multicast IP, unsupported flow"
            #raise BDBTaskError("Error: {} | {}".format(error, message))
            sys.exit("Error: {} | {}".format(error, message))
        if llmcastflag is False:
            error = "IP Error - Unsupported"
            message = "Destination IP is Private Group Multicast IP, unsupported flow"
            #raise BDBTaskError("Error: {} | {}".format(error, message))
            sys.exit("Error: {} | {}".format(error, message))
    if reserved0 is True:
        error = "IP Error - Unsupported"
        message = "Destination IP is reserved range 0.0.0.0/8, unsupported flow"
        #raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))
    if localhost is True:
        error = "IP Error - Unsupported"
        message = "Destination IP is reserved Loopback 127.0.0.0/8, unsupported flow"
        #raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))
    if morereserved is True:
        error = "IP Error - Unsupported"
        message = "Destination IP is reserved 240.0.0.0/8, unsupported flow"
        #raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))

    validation = ipaddress.ip_address(destip) in ipaddress.ip_network(network)
    if validation is True:
        if destip is str(network[-1]) or destip==str(network[0]):
            error = "IP Error - Unsupported"
            message = "Destination IP is a directed broadcast or subnet name, unsupported flow"
            #raise BDBTaskError("Error: {} | {}".format(error, message))
            sys.exit("Error: {} | {}".format(error, message))
    return validation

def subnetvalidation(subnet,mask):
    if subnet=="255.255.255.255":
        error = "IP Error - Unsupported"
        message = "Destination IP is a Full Broadcast 255.255.255.255, unsupported flow"
        #raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))
    network = ipaddress.IPv4Network(subnet+"/"+mask, strict=False)
    mcastflag = ipaddress.ip_address(subnet) in ipaddress.ip_network("224.0.0.0/4")
    morereserved = ipaddress.ip_address(subnet) in ipaddress.ip_network("240.0.0.0/4")
    reserved0 = ipaddress.ip_address(subnet) in ipaddress.ip_network("0.0.0.0/8")
    localhost = ipaddress.ip_address(subnet) in ipaddress.ip_network("127.0.0.0/8")
    if mcastflag is True:
        llmcastflag = ipaddress.ip_address(subnet) in ipaddress.ip_network("224.0.0.0/24")
        if llmcastflag is True:
            error = "IP Error - Unsupported"
            message = "Destination IP is Link Local Multicast IP, unsupported flow"
            #raise BDBTaskError("Error: {} | {}".format(error, message))
            sys.exit("Error: {} | {}".format(error, message))
        if llmcastflag is False:
            error = "IP Error - Unsupported"
            message = "Destination IP is Private Group Multicast IP, unsupported flow"
            #raise BDBTaskError("Error: {} | {}".format(error, message))
            sys.exit("Error: {} | {}".format(error, message))
    if reserved0 is True:
        error = "IP Error - Unsupported"
        message = "Destination IP is reserved range 0.0.0.0/8, unsupported flow"
        #raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))
    if localhost is True:
        error = "IP Error - Unsupported"
        message = "Destination IP is reserved Loopback 127.0.0.0/8, unsupported flow"
        #raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))
    if morereserved is True:
        error = "IP Error - Unsupported"
        message = "Destination IP is reserved 240.0.0.0/8, unsupported flow"
        #raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))
    return network

def inside_subnet(subnetstring, inputip):
    if subnetstring=="0.0.0.0/0":
        error = "IP Error - Unsupported"
        message = "Using a default route can result in profiling all devices in Cisco DNA Center, please do not use it"
        #raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))
    network = ipaddress.IPv4Network(subnetstring, strict=False)
    validation = ipaddress.ip_address(inputip) in ipaddress.ip_network(network)
    return validation

def stringvalidator(subnetstring):
    list_of_subnets = []
    ipr = re.compile(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?/\d{1,2})')
    ips = ipr.findall(subnetstring)
    for i,ips in enumerate(ips):
        pair = ips.split("/")
        subnet = pair[0]
        mask = pair[1]
        verifiedsubnet =  (subnetvalidation(subnet,mask))
        list_of_subnets.append(verifiedsubnet)
    return list_of_subnets

#Function to Validate if the IP is a valid IP address (any type) for input process
def ip_validator_input (ip_type: str):
    ip_address = None
    while True:
        try:
            ip_address = ipaddress.IPv4Address(input("{}".format(ip_type)))
        except ValueError:
            print ("Not a valid IPv4 address")
            continue
        else:
            #valid IP input
            break
    return str(ip_address)

#Function to Validate if the IP is a valid IP address (any type) as string
def ip_validator(ip_type: str):
    ip_address = None
    while True:
        try:
            ip_address = ipaddress.IPv4Address(ip_type)
        except ValueError:
            print ("Not a valid IPv4 address")
            continue
        else:
            #valid IP input
            break
    return ip_address

def ipsubnet_validator_no_return(ip_type: str):
    try:
        ipaddress.IPv4Network(ip_type)
        return True
    except ValueError:
            return False

def ipaddress_validator_no_return(ip_type: str):
    try:
        ipaddress.ip_address(ip_type)
        return True
    except ValueError:
            return False

def mac_address_validator(mac: str):
    mac_address_pattern = re.compile(
        r'([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})|'  # aaaa.bbbb.cccc
        r'([0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5})|'  # aa:aa:bb:bb:cc:cc
        r'([0-9A-Fa-f]{2}(-[0-9A-Fa-f]{2}){5})|'  # aa-aa-bb-bb-cc-cc
        r'([0-9A-Fa-f]{12})|'  # aaaabbbbcccc
        r'([0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})'  # aaaa-bbbb-cccc
    )
    try:
        match = mac_address_pattern.match(mac).group()
        #print(f"'{mac}' is a valid MAC address")
        i = mac
        if "." in i:
            macbytes = binascii.unhexlify(i.replace('.', ''))
        elif ":" in i:
            macbytes = binascii.unhexlify(i.replace(':', ''))
        elif "-" in i:
            macbytes = binascii.unhexlify(i.replace('-', ''))
        else:
            macbytes = binascii.unhexlify(i)
        first_octet_bits = "{0:b}".format(macbytes[0])
        last_bit = (first_octet_bits[-1])
        all_bits = ""
        for j in range (0,5):
            octecbits = "{0:b}".format(macbytes[j])
            all_bits = all_bits+octecbits
        if int(last_bit) == 1:
            if all_bits == '1111111111111111111111111111111111111111':
                #print("MAC Address {} is a Broadcast MAC address".format(i))
                mactype = 'Broadcast'
            else:
                #print("MAC Address {} is a Multicast MAC address".format(i))
                mactype = 'Multicast'
        else:
            mactype = 'Unicast'
        return True, mactype

    except AttributeError:
        #print(f"'{mac}' is NOT a valid MAC address")
        mactype = None
        return False, mactype

def issubnetbroadcast(subnetstring):
    subnet = ipaddress.IPv4Network(subnetstring, strict=False)
    networkbroadcast = subnet.broadcast_address
    prefix = subnetstring.split("/")[0]
    if prefix == str(networkbroadcast):
        return True
    else:
        return False

def wildcard_converter(address,mask):
    mask_int = int.from_bytes(ipaddress.IPv4Address(mask).packed, "big")
    address_int = int.from_bytes(ipaddress.IPv4Address(address).packed, "big")
    lower = ipaddress.IPv4Address((2 ** 32 - 1 - mask_int) & address_int)
    upper = ipaddress.IPv4Address(mask_int | address_int)
    subnet_range = list(ipaddress.summarize_address_range(lower, upper))
    return subnet_range