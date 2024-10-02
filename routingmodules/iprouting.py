from dataclasses import dataclass
import re
import sys
import radkit_cli

class route_recursion:
    def __init__(self,route,device):
        self.device = device        #Device Name
        self.route = route            #IPv4 RLOC 
        self.criteria = None        #Exclude default, min /32 or min/32 proxy-etr-only
        self.prefix = None          #Prefix covering this RLOC in global RIB 
        self.mask = None            #Mask covering this prefix
        self.protocol = None        #Route IGP/EGP
        self.nexthop = None         #Next Hop(s) covering this prefix
        self.phy = None             #List of interfaces recursing this next hop 
        self.mtu = None             #MTU of physical interfaces
        self.ping_to_rloc = None    #Validation of RLOC-to-RLOC reachability
        self.mtu_validation = None  #MTU validation

    def rloc_data(self,service):
    
        #RLOC Reachability
        reach_op = True
        print("Determining Reachability Criteria")
        for line in reach_op.splitlines():
            
            if "ipv4" in line:
                if "minimum-mask" in line:
                    if "proxy-etr" in line:
                        self.criteria = "MM-PETR"
                    else: 
                        self.criteria = "MM"
                if "exclude" in line:
                    self.criteria = "ED"

'''
        #Route_Inspection:
        print("Processing RIB Information")
        if rib_op != None:
            nh = []
            for line in rib_op.splitlines():
                if "entry" in line:
                    prefix = re.compile("(?<=for ).*()").search(line).group().strip()
                    prefix = prefix.split("/")
                    self.prefix = prefix[0]
                    self.mask = prefix[1]
                if "Known" in line:
                    prc = re.compile("(?<=Known via).*(?=, d)").search(line).group().strip()
                    self.protocol = prc.strip("\"")
                if ", via" in line:
                    nhop = re.compile( "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" ).search(line).group(0).strip()
                    nh.append(nhop)
            self.nexthop = nh

        if rib_op == None:
            nh = []
            rib_cmd = "show ip route 0.0.0.0"
            rib_op = radkit_cli.get_any_single_output(self.queriedetr,rib_cmd,service)
            for line in rib_op.splitlines():
                if "Known" in line:
                    prc = re.compile("(?<=Known via).*(?=, d)").search(line).group().strip()
                    self.protocol = prc.strip("\"")
                    self.prefix = "0.0.0.0"
                    self.mask = "0"
                if ", via" in line:
                    nhop = re.compile( "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" ).search(line).group(0).strip()
                    nh.append(nhop)
            self.nexthop = nh
            if prc == None:
                sys.exit("No Route to RLOC! Traffic wil l be Dropped")
            
        #PHY Indentification
            
        #Current state supports the following Next Hop parsing form CEF: L3 Port-Channel, SVI and Physical.
        #Support for Tunnel, Apphosting, VTI, LISP and NVE interfaces is not yet considered...

        print("Calculating Physical Interfaces")
        phys = []
        matches = ["#", "show"]
        for line in cef_op.splitlines():
            if "nexthop " in line:
                #Layer 3 Port-Channel as next hop
                if "channel" in line:
                    phy = re.compile("(?:[A-Z][A-Za-z_-]*[a-z]|[A-Z])\s?\d+(?:\/\d+)*(?::\d+)?(?:\.\d+)?").search(line).group(0).strip()
                    po_phy = etherchannel_parse(service,phy,self.device)
                    for i in po_phy:
                        phys.append(i)
                #SVI as next as hop
                elif "Vlan" in line:
                    nh = re.compile("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").search(line).group().strip()
                    vid = re.compile("(?<=Vlan)[0-9]{4}(?=)").search(line).group().strip()
                    arp = "show ip arp {}".format(nh)
                    try:
                        arp_op = radkit_cli.get_any_single_output(self.device,arp,service)
                    except:
                        sys.exit("ARP Is Incomplete for next hop {}".format(nh))
                    for line in arp_op.splitlines():
                        if "ARPA" in line:
                            mac = re.compile( "[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}" ).search(line).group().strip()
                            maccmd = "show mac address address {} vlan {}".format(mac,vid)
                            try:
                                mac_op = radkit_cli.get_any_single_output(self.device,maccmd,service)
                            except:
                                sys.exit("MAC not learned for ARP {}".format(nh))
                    for line in mac_op.splitlines():
                        if not any(x  in line for x in matches):
                            phy = re.compile("(?:[A-Z][A-Za-z_-]*[a-z]|[A-Z])\s?\d+(?:\/\d+)*(?::\d+)?(?:\.\d+)?").search(line).group(0).strip()
                            if "Po" in phy:
                                po_phy = etherchannel_parse(service,phy,self.device)
                                for i in po_phy:
                                    phys.append(i)
                #Physical Interfaces 
                else:
                    phy = re.compile("(?:[A-Z][A-Za-z_-]*[a-z]|[A-Z])\s?\d+(?:\/\d+)*(?::\d+)?(?:\.\d+)?").search(line).group().strip()
                    if "." in phy:
                        subint = phy.split(("."))
                        phy = subint[0]
                    phys.append(phy)
        self.phy = phys
        if self.phy == "None":
            sys.exit("Unable to find the outgoing physical interfaces for prefix {}, confirm the outgoing interface on the device itself.".format(self.route))

        #MTU validation:

        mtus = []
        for i in phys:
            mtu_cmd = "show interface {} | i MTU".format(i)
            mtu_op = radkit_cli.get_any_single_output(self.device, mtu_cmd, service)
            for line in mtu_op.splitlines():
                if "bytes" in line:
                    mtu = re.compile("(?<=MTU).*(?=bytes)").search(line).group().strip()
                    mtu = int(mtu)
                    mtus.append(mtu)
        mtus.sort()
        mini = mtus[0]
        self.mtu = mini
        print ("Testing RLOC-to-RLOC reachability with MTU size of {}".format(mini))
        #Ping with and without MTU size
        pingm_cmd = "ping {} source lo0 time 1 size {} df-bit".format(self.route, mini)
        pingm_op = radkit_cli.get_any_single_output(self.device,pingm_cmd,service)

        #Ping Validation

        for line in ping_op.splitlines():
            if "Success" in line:
                percent = re.compile("(?<=is).*(?=percent)").search(line).group().strip()
                self.ping_to_rloc = percent
        for line in pingm_op.splitlines():
            if "Success" in line:
                percent = re.compile("(?<=is).*(?=percent)").search(line).group().strip()
                self.mtu_validation = percent
'''