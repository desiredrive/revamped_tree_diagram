import sys
import radkit_cli
from switchingmodules import etherchannel
from switchingmodules.arp import arp_modules
from switchingmodules.maclearning import mac_learning
from re import compile

class ip_cef_internal():

    def __init__(self, ip, vrf, device):
        self.ip = ip
        self.vrf = vrf
        self.hostname = device

    def get_cef_internal(self,service):
        #Route_Inspection:
        print("Processing CEF Internal Information")

        if self.vrf == "default":
            vrf_mode = ""
            vrf = ''
        elif self.vrf is None:
            vrf_mode = ""
            vrf = ''
        else:
            vrf_mode = "vrf "+self.vrf+" "
        
        #show ip route command:
        ipcefint_cmd = "show ip cef {} {} internal".format(self.ip, vrf_mode, self.vrf)
        ipcefint_op = radkit_cli.get_single_output_genie(self.hostname,ipcefint_cmd,service)
        
        #VRF utilization
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
            sys.exit("No next hop founds in CEF for prefix {} in vrf {} on Device: {}".format(self.ip,vrf,self.hostname))


class physical_recursion():

    def __init__(self, cef_hops, device):
        self.hostname = device
        self.vrf = cef_hops.vrf
        self.nexthops = cef_hops.nexthops
    
    def get_physical_interfaces(self,service):

        #VRF Is needed for ARP recursion

        
        print("Calculating Physical Interfaces\n")

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
                vid = compile("(?<=Vlan)[0-9]{4}(?=)").search(intf).group().strip()
                arp = arp_modules(self.vrf, self.hostname)
                arp.arp_resolution_single_ip(nhop, intf, service)
                try:
                    mac = arp.mac
                except:
                    sys.exit("ARP Is Incomplete for next hop {}".format(nhop))
                
                mac_ports = mac_learning(self.hostname)
                mac_ports.mac_learning_mac(mac, vid, service)

                if mac_ports == None:
                    sys.exit("MAC not learned for ARP {}".format(nhop))
                
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
                sys.exit("Unable to find the outgoing physical interfaces for next_hop {}, confirm the outgoing interface on the device itself.".format(self.route))
            else:
                total_phys.append(nhphys)
            
            


                


