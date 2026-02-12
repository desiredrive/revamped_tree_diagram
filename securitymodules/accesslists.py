from pprint import pformat

import radkit_cli
import re
from ipverifications import (
    wildcard_converter,
    inside_subnet
)
import ipaddress

global ip_protocol_map
global protocol_port_map

ip_protocol_map = {
    "ahp": "    33",  # Authentication Header Protocol (51)
    "eigrp": "58",  # Cisco's EIGRP routing protocol (88)
    "esp": "32",  # Encapsulation Security Payload (50)
    "gre": "2F",  # Cisco's GRE tunneling (47)
    "icmp": "01",  # Internet Control Message Protocol (1)
    "igmp": "02",  # Internet Gateway Message Protocol (2)
    "ip": "ff",  # Not a specific protocol number. ff for this list purpose
    "ipv4": "ff",  # Not a specific protocol number. ff for this list purpose
    "ipinip": "04",  # IP in IP tunneling (4)
    "ospf": "59",  # OSPF routing protocol (89)p
    "pcp": "6C",  # Payload Compression Protocol (108)
    "pim": "67",  # Protocol Independent Multicast (103)
    "tcp": "06",  # Transmission Control Protocol (6)
    "udp": "11",  # User Datagram Protocol (17)
}
protocol_port_map = {
    # From the first list (UDP/General)
    "biff": 512,
    "bootpc": 68,
    "bootps": 67,
    "discard": 9,
    "dnsix": 195,
    "domain": 53,
    "echo": 7,
    "isakmp": 500,
    "mobile-ip": 434,
    "nameserver": 42,
    "netbios-dgm": 138,
    "netbios-ns": 137,
    "netbios-ss": 139,
    "non500-isakmp": 4500,
    "ntp": 123,
    "pim-auto-rp": 496,
    "rip": 520,
    "ripv6": 521,
    "snmp": 161,
    "snmptrap": 162,
    "sunrpc": 111,
    "syslog": 514,
    "tacacs": 49,
    "talk": 517,
    "tftp": 69,
    "time": 37,
    "who": 513,
    "xdmcp": 177,
    # From the second list (TCP) - duplicates will be overwritten with the same value
    "bgp": 179,
    "chargen": 19,
    "cmd": 514,  # Duplicate, but same port as syslog/talk
    "daytime": 13,
    # discard: already 9
    # domain: already 53
    # echo: already 7
    "exec": 512,  # Duplicate, but same port as biff
    "finger": 79,
    "ftp": 21,
    "ftp-data": 20,
    "gopher": 70,
    "hostname": 101,
    "ident": 113,
    "irc": 194,
    "klogin": 543,
    "kshell": 544,
    "login": 513,  # Duplicate, but same port as who
    "lpd": 515,
    "msrpc": 135,
    "nntp": 119,
    "onep-plain": 15001,
    "onep-tls": 15002,
    # pim-auto-rp: already 496
    "pop2": 109,
    "pop3": 110,
    "smtp": 25,
    # sunrpc: already 111
    # syslog: already 514
    # tacacs: already 49
    # talk: already 517
    "telnet": 23,
    # time: already 37
    "uucp": 540,
    "whois": 43,
    "www": 80
}

def acl_evaluation(service, hostname, aclname, rb_flag,evaluation):
    '''
    Sample evaluation payload:
    sourceip = evaluation['sourceip']
    destinationip = evaluation['destinationip']
    protocol = evaluation['protocol']
    srcport = evaluation['srcport']
    dstport = evaluation['dstport']
    '''
    #Get the ACL details by its name:
    if rb_flag is True:
        acl = AccessList(hostname)
        acl.rbaclacl(aclname,service)
    else:
        acl = AccessList(hostname)
        acl.aclbyidname(aclname,service)

    #Extract ACEs from ACL:
    acltype = acl.acltype
    aclaces = acl.aces
    acld = {
        'acltype': acltype,
        'aces': aclaces
    }
    #Create the Hexdecimal equivalent for each ACE
    hexacl = hexdecimal_representation_acl(acld)
    #Evaluate the hexdecimal ACE against the evaluation parameters
    for ace in hexacl:
        hit = hexdecimal_acl_hit(ace, evaluation)
        if type(hit) is tuple:
            if hit[0] is True:
                return hit

def hexdecimal_representation_acl(acl_object):
    HEX_DIGITS_FOR_32_BIT = 8
    #HEX_DIGITS_FOR_16_BIT = 4
    hex_aces = []
    for aces in acl_object['aces']:
        # 32bitsequence - 32 bit
        sequence = int(aces['index'])
        hex_representation = hex(sequence)[2:]
        hex_sequence = hex_representation.zfill(HEX_DIGITS_FOR_32_BIT).upper()

        # permit or deny - 1 bit, permit = 1, deny = 0
        action = aces['forwarding']
        hex_action = '0'
        if action == 'permit':
            hex_action = '1'

        # l3protocol - 8 bit
        l3protocol = aces['ace_protocol']
        for protocol in ip_protocol_map:
            if l3protocol == protocol:
                hex_protocol = (ip_protocol_map[protocol]).upper()

        # sourceprefix - 32 bit & #sourcewcard - 32 bit
        source_ace = aces['ace_source']
        # Any:
        if source_ace.lower() == 'any':
            hex_sourceprefix = '00000000'
            hex_sourcewcard = 'FFFFFFFF'
        elif 'host' in source_ace:
            hex_sourcewcard = '00000000'
            source = source_ace.split(" ")[1]
            ip_obj = ipaddress.IPv4Address(source)
            ip_int = int(ip_obj)
            hex_sourceprefix = f"{ip_int:08X}"
        else:
            source = source_ace.split(" ")
            sourceprefix = source[0].strip()
            sourcewildcard = source[1].strip()

            ip_obj = ipaddress.IPv4Address(sourceprefix)
            ip_int = int(ip_obj)
            hex_sourceprefix = f"{ip_int:08X}"

            ip_obj = ipaddress.IPv4Address(sourcewildcard)
            ip_int = int(ip_obj)
            hex_sourcewcard = f"{ip_int:08X}"

        # destinationprefix - 32 bit & destinationwcard - 32 bit
        dest_ace = aces['ace_destination']
        if dest_ace.lower() == 'any':
            hex_destprefix = '00000000'
            hex_destwcard = 'FFFFFFFF'
        elif 'host' in dest_ace:
            hex_destwcard = '00000000'
            destination = dest_ace.split(" ")[1]
            ip_obj = ipaddress.IPv4Address(destination)
            ip_int = int(ip_obj)
            hex_destprefix = f"{ip_int:08X}"
        else:
            destination = dest_ace.split(" ")
            destinationprefix = destination[0].strip()
            destinationwildcard = destination[1].strip()
            ip_obj = ipaddress.IPv4Address(destinationprefix)
            ip_int = int(ip_obj)
            hex_destprefix = f"{ip_int:08X}"
            ip_obj = ipaddress.IPv4Address(destinationwildcard)
            ip_int = int(ip_obj)
            hex_destwcard = f"{ip_int:08X}"

        # sourcestartrangeport - 16 bit & sourcesendrangeport - 16 bit
        srcports = aces['ace_srcports']
        if type(srcports) is not dict:
            if type(srcports) is str:
                if srcports.lower() == 'any':
                    hex_sourcestartrangeport = '0000'
                    hex_sourcesendrangeport = 'FFFF'
                else:
                    for protocol in protocol_port_map:
                        if srcports == protocol:
                            hex_sourcestartrangeport = f"{protocol_port_map[srcports]:04X}"
                            hex_sourcesendrangeport = f"{protocol_port_map[srcports]:04X}"
            elif type(srcports) is not str:
                hex_sourcestartrangeport = f"{int(srcports):04X}"
                hex_sourcesendrangeport = f"{int(srcports):04X}"

        else:
            lowerport = int(srcports['lower_port'])
            upperport = int(srcports['upper_port'])
            hex_sourcestartrangeport = f"{lowerport:04X}"
            hex_sourcesendrangeport = f"{upperport:04X}"

        # dststartrangeport - 16 bit & dstendrangeport - 16 bit
        dstports = aces['ace_dstports']
        if type(dstports) is not dict:
            if type(dstports) is str:
                if dstports.lower() == 'any':
                    hex_dststartrangeport = '0000'
                    hex_dstendrangeport = 'FFFF'
                else:
                    for protocol in protocol_port_map:
                        if dstports == protocol:
                            hex_dststartrangeport = f"{protocol_port_map[dstports]:04X}"
                            hex_dstendrangeport = f"{protocol_port_map[dstports]:04X}"
            elif type(dstports) is not str:
                hex_dststartrangeport = f"{int(dstports):04X}"
                hex_dstendrangeport = f"{int(dstports):04X}"

        else:
            lowerport = int(dstports['lower_port'])
            upperport = int(dstports['upper_port'])
            hex_dststartrangeport = f"{lowerport:04X}"
            hex_dstendrangeport = f"{upperport:04X}"
        # print (hex_sequence,hex_action,hex_protocol,hex_sourceprefix,hex_sourcewcard,hex_destprefix,hex_destwcard,hex_sourcestartrangeport,hex_sourcesendrangeport,hex_dststartrangeport,hex_dstendrangeport)
        aclhexsequence = hex_sequence + hex_action + hex_protocol + hex_sourceprefix + hex_sourcewcard + hex_destprefix + hex_destwcard + hex_sourcestartrangeport + hex_sourcesendrangeport + hex_dststartrangeport + hex_dstendrangeport
        hex_aces.append(aclhexsequence)
    aclimplicitdeny = 'FFFFFFFF0FF00000000FFFFFFFF00000000FFFFFFFF0000FFFF0000FFFF'
    hex_aces.append(aclimplicitdeny)
    return hex_aces

def ip_hex_to_int(ip_hex):
    return int(ip_hex, 16)

def hexdecimal_acl_hit(hexace, evaluation):
    # Step 1 - Define evaluation criteria: SourceIP/DstIP/Protocol/SrcPort/DstPort
    # Source and Destination IP are mandatory, Protocol defaults to "ip", ports are optional, set to None when needed.
    sourceip = evaluation['sourceip']
    destinationip = evaluation['destinationip']
    protocol = evaluation['protocol']
    sourceport = evaluation['srcport']
    destport = evaluation['dstport']

    ace_sequence = int(hexace[0:8],16)
    if ace_sequence == 4294967295:
        ace_sequence = "default deny"
    ace_action = hexace[8]
    ace_protocol = hexace[9:11]
    ace_source_net = hexace[11:19]
    ace_source_wcard = hexace[19:27]
    ace_dest_net = hexace[27:35]
    ace_dest_wcard = hexace[35:43]
    ace_srcport_start = hexace[43:47]
    ace_srcport_end = hexace[47:51]
    ace_dstport_start = hexace[51:55]
    ace_dstport_end = hexace[55:59]

    if int(ace_action) == 1:
        action = 'permit'
    else:
        action = 'deny'

    # Step 2 - Function to evaluate if an IP is within a network+wildcard for the source:
    ip_obj = ipaddress.IPv4Address(sourceip)
    ip_int = int(ip_obj)
    hexsource = f"{ip_int:08X}"
    ip = ip_hex_to_int(hexsource)
    sourcenet = ip_hex_to_int(ace_source_net)
    sourcewcard = ip_hex_to_int(ace_source_wcard)
    matchresult = (ip & ~sourcewcard) == (sourcenet & ~sourcewcard)
    if matchresult is False:
        return False

    # Step 3 - Function to evaluate if an IP is within a network+wildcard for the destination:
    ip_obj = ipaddress.IPv4Address(destinationip)
    ip_int = int(ip_obj)
    hexsource = f"{ip_int:08X}"
    ip = ip_hex_to_int(hexsource)
    destnet = ip_hex_to_int(ace_dest_net)
    destwcard = ip_hex_to_int(ace_dest_wcard)
    matchresult = (ip & ~destwcard) == (destnet & ~destwcard)
    if matchresult is False:
        return False

    protocolflag = False
    # Step 4 - Evaluate protocol, if the ace_protocol is "ip or FF" is automatic match, if not, compare only if protocol is not none.
    if protocol is not None:
        if ace_protocol != "FF":
            for l4protocol in ip_protocol_map:
                if protocol == l4protocol:
                    if ip_protocol_map[protocol].lower() == ace_protocol.lower():
                        protocolflag = True
            if protocolflag is not True:
                return False

    # Step 5 - Source Port validation: if None, do not evaluate, otherwise, evaluate if within the range
    if protocolflag is True:
        if sourceport is not None:
            start_port = int(ace_srcport_start, 16)
            end_port = int(ace_srcport_end, 16)
            matchresult = (start_port <= sourceport <= end_port)
            if matchresult is False:
                return False
        if destport is not None:
            start_port = int(ace_dstport_start, 16)
            end_port = int(ace_dstport_end, 16)
            matchresult = (start_port <= destport <= end_port)
            if matchresult is False:
                return False

    return True, action,ace_sequence

def is_acl_denying_dst(acldetails,destination):
    #Return True means Denied; Return False means Not Denied
    acltype = acldetails['acltype']
    aclaces = acldetails['aces']
    if acltype == 'extended':
        for ace in aclaces:
            destinationnet = ace['ace_destination']
            forwarding = ace['forwarding']
            if "host" in destinationnet:
                destinationip = destinationnet.split(" ")[1]
                if destination == destinationip:
                    if forwarding == 'deny':
                        return True
                    else:
                        return False
            elif "any" in destinationnet:
                if forwarding == 'deny':
                    return True
                else:
                    return False
            else:
                destinationnetwork = destinationnet.split(" ")
                destinationip = destinationnetwork[0]
                destinationwc = destinationnetwork[1]
                subnet_range = wildcard_converter(destinationip, destinationwc)
                for subnet in subnet_range:
                    result = inside_subnet(subnet, destination)
                    if result is True:
                        if forwarding == 'deny':
                            return True
                        else:
                            return False
    if acltype == 'standard':
        for ace in aclaces:
            sourcenet = ace['ace_source']
            forwarding = ace['forwarding']
            if "host" in sourcenet:
                sourceip = sourcenet.split(" ")[1]
                if sourceip == sourceip:
                    if forwarding == 'deny':
                        return True
                    else:
                        return False
            elif 'any' in sourcenet:
                if forwarding == 'deny':
                    return True
                else:
                    return False
            else:
                sourcenetwork = sourcenet.split(" ")
                sourceip = sourcenetwork[0]
                sourcewc = sourcenetwork[1]
                subnet_range = wildcard_converter(sourceip, sourcewc)
                for subnet in subnet_range:
                    result = inside_subnet(subnet, destination)
                    if result is True:
                        if forwarding == 'deny':
                            return True
                        else:
                            return False
    return False

def parse_rbacl_ace(line):
    """
    Parse a single ACE line from the raw CLI output and convert it into the specified dictionary format.
    Assumptions:
    - ace_source and ace_destination are always set to "any"
    - ace_protocol is the protocol keyword (tcp, udp, ip, icmp, etc.)
    - ace_srcoperator_type and ace_dstoperator_type are "eq", "range", or None
    - Ports follow src and dst keywords with operator and port(s)
    - Port ranges are represented as dictionaries with 'lower_port' and 'upper_port'
    """

    ace = {
        'index': None,
        'forwarding': None,
        'ace_source': "any",
        'ace_destination': "any",
        'ace_protocol': None,
        'ace_srcoperator_type': None,
        'ace_srcports': "any",
        'ace_dstoperator_type': None,
        'ace_dstports': "any"
    }

    tokens = line.strip().split()
    if not tokens:
        return None

    # Parse index
    if tokens[0].isdigit():
        ace['index'] = int(tokens[0])
        tokens = tokens[1:]
    else:
        return None

    # Parse forwarding action
    if tokens and tokens[0] in ('permit', 'deny'):
        ace['forwarding'] = tokens[0]
        tokens = tokens[1:]
    else:
        return None

    # Parse protocol
    if tokens:
        ace['ace_protocol'] = tokens[0]
        tokens = tokens[1:]
    else:
        return None

    def parse_port_segment(tokens):
        if not tokens:
            return None, None, tokens
        operator = None
        ports = None
        if tokens[0] in ('eq', 'range'):
            operator = tokens[0]
            tokens = tokens[1:]
            if operator == 'eq':
                if tokens:
                    ports = (tokens[0])
                    try:
                        ports = int(ports)
                    except ValueError:
                        pass
                    tokens = tokens[1:]
            elif operator == 'range':
                if len(tokens) >= 2:
                    ports = {
                        'lower_port': int(tokens[0]),
                        'upper_port': int(tokens[1])
                    }
                    tokens = tokens[2:]
        return operator, ports, tokens

    # Parse src ports
    if tokens and tokens[0] == 'src':
        tokens = tokens[1:]
        ace['ace_srcoperator_type'], ace['ace_srcports'], tokens = parse_port_segment(tokens)

    # Parse dst ports
    if tokens and tokens[0] == 'dst':
        tokens = tokens[1:]
        ace['ace_dstoperator_type'], ace['ace_dstports'], tokens = parse_port_segment(tokens)

    # Ignore remaining tokens like 'established'
    return ace

class AccessList:
    def __init__(self,device):
        self.hostname = device
        self.aclname = None
        self.acltype = None
        self.aclaftype = None
        self.aces = None
    def aclbyidname(self,aclname,service):
        aclid_cmd ="show access-lists {}".format(aclname)
        aclid_op = radkit_cli.get_single_output_genie(self.hostname,aclid_cmd,service)
        if aclid_op is not None:
            for acl in aclid_op:
                if '_exclude' not in acl:
                    aclname = acl
            self.aclname = aclname
            self.acltype = aclid_op[aclname]['acl_type']
            self.aclaftype = aclid_op[aclname]['type']
            aclpath = aclid_op[aclname]['aces']
            aces = []
            source_network = None
            destination_network = None
            operator_type = None
            for index in aclpath:
                protomatches = ['udp', 'tcp']
                ace_sourcenetwork = aclpath[index]['matches']['l3']['ipv4']['source_network']

                for network in ace_sourcenetwork:
                    source_network = network
                ace_source = aclpath[index]['matches']['l3']['ipv4']['source_network'][source_network]['source_network']
                ace_protocol = aclpath[index]['matches']['l3']['ipv4']['protocol']
                ace_type = aclpath[index]['actions']['forwarding']
                # Source ACEs
                try:
                    ace_srcoperator = aclpath[index]['matches']['l4'][ace_protocol]['source_port']
                    for operator in ace_srcoperator:
                        operator_type = operator
                    ace_srcports = aclpath[index]['matches']['l4'][ace_protocol]['source_port'][operator_type]
                    ace_srcoperator_type = operator_type
                    if operator_type == 'operator':
                        ace_srcoperator_type = ace_srcports['operator']
                        ace_srcports = int(ace_srcports['port'])
                except KeyError:
                    ace_srcoperator_type = None
                    ace_srcports = "Any"
                # Destination ACEs (Extended Only)
                try:
                    ace_destination = aclpath[index]['matches']['l3']['ipv4']['destination_network']
                    for network in ace_destination:
                        destination_network = network
                    ace_destination = \
                    aclpath[index]['matches']['l3']['ipv4']['destination_network'][destination_network][
                        'destination_network']
                    if any(x in ace_protocol for x in protomatches):
                        ace_dstoperator = aclpath[index]['matches']['l4'][ace_protocol]['destination_port']
                        for operator in ace_dstoperator:
                            operator_type = operator
                        ace_dstports = aclpath[index]['matches']['l4'][ace_protocol]['destination_port'][operator_type]
                        ace_dstoperator_type = operator_type
                        if operator_type == 'operator':
                            ace_dstoperator_type = ace_dstports['operator']
                            ace_dstports = int(ace_dstports['port'])
                    else:
                        ace_dstoperator_type = None
                        ace_dstports = "Any"
                except KeyError as e:
                    if e == 'destination_network':
                        ace_destination = None
                    else:
                        ace_dstoperator_type = None
                        ace_dstports = "Any"
                ace = {
                    'index': index,
                    'forwarding': ace_type,
                    'ace_source': ace_source,
                    'ace_destination': ace_destination,
                    'ace_protocol' : ace_protocol,
                    'ace_srcoperator_type': ace_srcoperator_type,
                    'ace_srcports': ace_srcports,
                    'ace_dstoperator_type': ace_dstoperator_type,
                    'ace_dstports': ace_dstports
                }
                aces.append(ace)
            aces = aces
            self.aces = aces

    def aclbyinterface(self,interface,service):
        hostname = self.hostname

        aclsbyintf_cmd= "show ip access-list interface {}".format(interface)
        aclsbyintf_op = radkit_cli.get_any_single_output(hostname,aclsbyintf_cmd,service)

        if aclsbyintf_op is not None:
            aclnames = []
            for line in aclsbyintf_op.splitlines():
                if "IP access" in line:
                    regex = "(?<=access list ).*"
                    aclname = re.compile(regex).search(line).group()
                    aclnames.append(aclname)
            aclnames = list(set(aclnames))
            self.aclnames = aclnames

    def rbaclacl(self,aclname,service):
        hostname = self.hostname
        rbaclcmd= "show ip access-list  \"{}\"".format(aclname)
        rbaclop = radkit_cli.get_any_single_output(hostname,rbaclcmd,service)
        if rbaclop is not None:
            parsed_aces = []
            for line in rbaclop.splitlines():
                line = line.strip()
                if not line:
                    continue
                # Skip header/footer lines that do not start with a digit
                if not line[0].isdigit():
                    continue
                ace = parse_rbacl_ace(line)
                if ace:
                    parsed_aces.append(ace)
            self.aclname = aclname
            self.acltype = 'role-based'
            self.aclaftype = 'ipv4-acl-type'
            self.aces = parsed_aces