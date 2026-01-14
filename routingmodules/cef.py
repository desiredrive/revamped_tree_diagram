
from switchingmodules import etherchannel
from switchingmodules.arp import arp_modules
from switchingmodules.maclearning import mac_learning
from re import compile, search, IGNORECASE
from radkit_cli import logging_info, logging_error, get_single_output_genie, get_any_single_output
import sys
from typing import Optional

def ip_cef_collection(ipcef,step):
    hostname = ipcef.hostname
    collection_summary = "Prefix: {}, VRF: {}, NextHop(s): {}, Sources: {}".format(ipcef.ip,ipcef.vrf,ipcef.nexthops,ipcef.sources)
    string = "Result: Success"
    logging_info(step, "Underlay", "[CEF]",hostname, collection_summary)
    logging_info(step, "Underlay", "[CEF]",hostname, string)

def phy_cef_collection(interface,step):
    hostname = interface.hostname
    collection_summary = "Interface: {}, OperState: {}, MTU: {}, OutputDrops: {}, IQDrops: {}".format(interface.interface,interface.operstate,interface.mtu,interface.outputdrops,interface.iqdrops)
    string = "Result: Success"
    logging_info(step, "Underlay", "[PHY]",hostname, collection_summary)
    logging_info(step, "Underlay", "[PHY]",hostname, string)

def parse_cef_sgt(output: str) -> Optional[int]:
    """
    Extracts SGT from lines like:
      ... [SGT 15 S D]
    Returns int SGT or None if not present.
    """
    for line in (output or "").splitlines():
        m = search(r"\[\s*SGT\s+(\d+)\b", line, IGNORECASE)
        if m:
            return int(m.group(1))
    return 0

class IPCef:

    def __init__(self, ip, vrf, device):
        self.ip = ip
        self.vrf = vrf
        self.hostname = device

    def get_cef_internal(self,service):
        #Route_Inspection:
        #print("Processing CEF Internal Information for prefix: {}\n".format(self.ip))

        if self.vrf == "default":
            vrf_mode = ""
        elif self.vrf is None:
            vrf_mode = ""
        elif self.vrf == "None":
            vrf_mode = ""
        else:
            vrf_mode = "vrf "+self.vrf+" "
        
        #show ip route command:
        ipcefint_cmd = "show ip cef {} {} internal".format(vrf_mode,self.ip)
        ipcefint_op = get_single_output_genie(self.hostname,ipcefint_cmd,service)
        #VRF utilization
        prefix = None
        if vrf_mode == "":
            vrf = 'default'
        else:
            vrf = self.vrf
        addipv4 = 'ipv4'
        cefpath = ipcefint_op['vrf'][vrf]['address_family'][addipv4]['prefix']
        for i in cefpath:
            prefix = i
        cefpath = cefpath[prefix]

        #CEF sources
        try:
            self.sources = cefpath['sources']
        except KeyError:
            self.sources = None
        
        try:
            subblocks = cefpath['subblocks']
        except KeyError:
            subblocks = []

        #LISP SMR detection

        try:
            if any(x in "LISP" for x in subblocks):
                self.lispsmr = (cefpath['subblocks']['LISP']['smr_enabled'])
        except TypeError:
            new_subblock = None
            for i in subblocks:
                new_subblock = i
            if any(x in "LISP" for x in subblocks[new_subblock]):
                self.lispsmr = (cefpath['subblocks'][new_subblock]['LISP']['smr_enabled'])

        #Ifnums readily available?
        try:
            ifnums = cefpath['ifnums']
            no_ifnums = False
        except KeyError:
            no_ifnums = True
            ifnums = []

        #CEF Special Type exclusion:
        special_types = ['Spc','DRH']
        special_flag = False

        #Next Hop Calculation
        if self.sources is not None:
            if any (x in self.sources for x in special_types):
                special_flag = True
            if (no_ifnums is True) and (special_flag is False):
                path_list = None
                paths = []
                nexthops = []
                nhlist = []
                cefpath_list = cefpath['path_list']
                for i in cefpath_list:
                    path_list = i
                cefpath_list = cefpath_list[path_list]
                for i in cefpath_list['path']:
                    paths.append(i)
                cefpath_list = cefpath_list['path']
                for i in paths:
                    nexthops.append(cefpath_list[i]['nexthop'])
                for i in nexthops:
                    for j in i:
                        oif = i[j]['outgoing_interface']
                        nexthop_format = {'nexthop' : j, 'oif': oif}
                        nhlist.append(nexthop_format)
                self.nexthops = nhlist
            elif (special_flag is False):
                nhlist = []
                for i in ifnums:
                    oif = i
                    try:
                        j = ifnums[oif]['address']
                        nexthop_format = {'nexthop' : j, 'oif': oif}
                        nhlist.append(nexthop_format)
                    except KeyError:
                        nexthop_format = {'nexthop' : None, 'oif': oif}
                        nhlist.append(nexthop_format)
                self.nexthops = nhlist
            elif any("LISP" in x for x in self.sources):
                # LISP Glean Scenario
                ipcef_cmd = "show ip cef {} {}".format(vrf_mode, self.ip)
                ipcef_op = get_single_output_genie(self.hostname, ipcef_cmd, service)
                if ipcef_op is not None:
                    vanillacefpath = ipcef_op['vrf'][vrf]['address_family'][addipv4]['prefix']
                    nexthops = []
                    nhlist = []
                    for prefix in vanillacefpath:
                        cefpath_list = vanillacefpath[prefix]
                        for i in cefpath_list:
                            nexthops.append(cefpath_list[i])
                        for i in nexthops:
                            for j in i:
                                oif = i[j]['outgoing_interface']
                                nexthop_format = {'nexthop': j, 'oif': oif}
                                nhlist.append(nexthop_format)
                    self.nexthops = nhlist
            elif len(ifnums) != 0:
                nhlist = []
                for oif in (ifnums or {}):
                    oif_raw = oif
                    if isinstance(oif_raw, dict):
                        oif_name = next(iter(oif_raw.keys()), None)  # e.g. "Vlan3002"
                    else:
                        oif_name = oif_raw
                    try:
                        j = ifnums[oif_raw].get("address")
                        nexthop_format = {"nexthop": j, "oif": oif_name}
                    except (KeyError, AttributeError, TypeError):
                        nexthop_format = {"nexthop": None, "oif": oif_name}
                    nhlist.append(nexthop_format)
                self.nexthops = nhlist
            else:
                # Empty next hop! (Special Adjacency???)
                self.nexthops = None
        else:
            rib_flag = cefpath['rib']
            # CEF Type: Connected
            if "C" in rib_flag:
                ipcef_cmd = "show ip cef {} {}".format(vrf_mode,self.ip)
                ipcef_op = get_single_output_genie(self.hostname, ipcef_cmd, service)
                if ipcef_op is not None:
                    vanillacefpath = ipcef_op['vrf'][vrf]['address_family'][addipv4]['prefix']
                    nexthops = []
                    nhlist = []
                    for prefix in vanillacefpath:
                        cefpath_list = vanillacefpath[prefix]
                        for i in cefpath_list:
                            nexthops.append(cefpath_list[i])
                        for i in nexthops:
                            for j in i:
                                oif = i[j]['outgoing_interface']
                                nexthop_format = {'nexthop': j, 'oif': oif}
                                nhlist.append(nexthop_format)
                    self.nexthops = nhlist

    def sgtfromcef(self,service):
        hostname = self.hostname
        if self.vrf == "default":
            vrf_mode = ""
        elif self.vrf is None:
            vrf_mode = ""
        elif self.vrf == "None":
            vrf_mode = ""
        else:
            vrf_mode = "vrf " + self.vrf + " "
        ip = self.ip
        # show ip route command:
        ipcefint_cmd = "show ip cef {} {} internal | i SGT".format(vrf_mode, ip)
        ipcefint_op = get_any_single_output(self.hostname, ipcefint_cmd, service)
        ipcefint_op = parse_cef_sgt(ipcefint_op)
        self.sgt = ipcefint_op

class physical_recursion():

    def __init__(self, cef_hops, device):
        self.hostname = device
        self.vrf = cef_hops.vrf
        self.nexthops = cef_hops.nexthops
    
    def get_physical_interfaces(self,service,step):
        process = 'CEF'
        hostname = self.hostname
        #VRF Is needed for ARP recursion
        #print("Calculating Physical Interfaces\n")
        #Current state supports the following Next Hop parsing form CEF: L3 Port-Channel, SVI and Physical (L2 or L3)
        #Support for Tunnel, Apphosting, VTI, LISP and NVE interfaces is not yet considered...
        total_phys = []
        for i in self.nexthops:
            nhphys = []
            interface = i['oif']
            if "LISP" in interface:
                #LISP Interface has no physical interface
                continue
            elif "channel" in interface:
                phys = etherchannel.etherchannel_parse(interface,self.hostname)
                nhphys.append(phys)
            #SVI as next as hop
            elif "Vlan" in interface:
                nhop = i['nexthop']
                intf = i['oif']
                vid = compile("(?<=Vlan)[0-9]{4}(?=.*)").search(intf).group().strip()
                arp = arp_modules(self.vrf, self.hostname)
                arp.arp_resolution_single_ip(nhop, intf, service)
                try:
                    mac = arp.mac
                except KeyError:
                    subprocess = "[ARP]"
                    error = "CEF - Incomplete Adjacency"
                    message = "ARP Is Incomplete for next hop {}, fix the ARP entry for this IP address in device: {}".format(nhop,hostname)
                    logging_error(step, process, subprocess, hostname, error)
                    logging_info(step, process, subprocess, hostname, message)
                    #raise BDBTaskError("Error: {} | {}".format(error, message))
                    sys.exit("Error: {} | {}".format(error, message))

                mac_ports = mac_learning(self.hostname)
                mac_ports.mac_learning_mac(mac, vid, service)

                if mac_ports is None:
                    subprocess = "[macLearning]"
                    error = "CEF - No Layer2 Recursion"
                    message = "MAC address {} is not learnt in any port, troubleshoot the MAC learning event in device: {}".format(
                        mac, hostname)
                    logging_error(step, process, subprocess, hostname, error)
                    logging_info(step, process, subprocess, hostname, message)
                    # raise BDBTaskError("Error: {} | {}".format(error, message))
                    sys.exit("Error: {} | {}".format(error, message))

                if type(mac_ports) is list:
                    for i in mac_ports.port:
                        if "Po" in i:
                            phys = etherchannel.etherchannel_parse(i, self.hostname)
                            nhphys.append(phys)
                        else:
                            nhphys.append(i)
                else:
                    if "Po" in mac_ports.port:
                        phys = etherchannel.etherchannel_parse(i, self.hostname)
                        nhphys = phys
                    else:
                        nhphys = mac_ports.port
            #Physical Interfaces 
            else:
                nhphys.append(interface)
            if len(nhphys)==0:
                subprocess = "[physicalPort]"
                error = "CEF - No Physical Port Recursion"
                message = "Unable to resolve the physical port for next-hop {}, validate the physical port recursion for ARP and MAC in device: {}".format(
                    i, hostname)
                logging_error(step, process, subprocess, hostname, error)
                logging_info(step, process, subprocess, hostname, message)
                # raise BDBTaskError("Error: {} | {}".format(error, message))
                sys.exit("Error: {} | {}".format(error, message))
            else:
                total_phys.append(nhphys)
            self.total_phys = total_phys



class VRF:
    def __init__(self,device,vrf):
        self.hostname = device
        self.vrf = vrf
    def vrfdetail(self,service):
        hostname = self.hostname
        vrfdetcmd = f"show vrf detail {self.vrf}"
        vrfdetop = get_single_output_genie(hostname,vrfdetcmd,service)
        vrf_data = next(iter((vrfdetop or {}).values()), {})
        self.vrfdetailed = vrf_data

