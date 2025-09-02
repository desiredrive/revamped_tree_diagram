
from switchingmodules import etherchannel
from switchingmodules.arp import arp_modules
from switchingmodules.maclearning import mac_learning
from re import compile
from radkit_cli import logging_info,logging_error,get_single_output_genie
import sys

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
        ipcefint_cmd = "show ip cef {} {} internal".format(self.ip,vrf_mode)
        ipcefint_op = get_single_output_genie(self.hostname,ipcefint_cmd,service)
        
        #VRF utilization
        prefix = None
        if vrf_mode == "":
            vrf = 'default'
        addipv4 = 'ipv4'
        cefpath = ipcefint_op['vrf'][vrf]['address_family'][addipv4]['prefix']
        for i in cefpath:
            prefix = i
        cefpath = cefpath[prefix]

        #CEF sources
        self.sources = cefpath['sources']
        
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

        #CEF Special Type exclusion:
        special_types = ['Spc']
        special_flag = False

        #Next Hop Calculation
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
        else:
            #Empty next hop! (Special Adjacency???)
            self.nexthops = None

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
            #Layer 3 Port-Channel as Next Hop
            if "channel" in interface:
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
                
                for i in mac_ports.port:
                    if "Po" in i:
                        phys = etherchannel.etherchannel_parse(i, self.hostname)
                        nhphys.append(phys)
                    else:
                        nhphys.append(i)
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
            
            


                


