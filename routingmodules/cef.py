from dataclasses import dataclass
import re
import sys
import radkit_cli

class ip_cef_internal():

    def __init__(self, ip, vrf, device):
        self.ip = ip
        self.vrf = vrf
        self.hostname = device

    def get_cef_internal(self,service):
        #Route_Inspection:
        print("Processing CEF Internal Information")

        if self.vrf == "default" or self.vrf is None:
            vrf_mode = ""
        else:
            vrf_mode = "vrf "+self.vrf+" "
        
        #show ip route command:
        ipcefint_cmd = "show ip route {} {}".format(self.ip, vrf_mode, self.vrf)
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
        if any (x in "LISP" for x in subblocks):
            self.lispsmr = (cefpath['subblocks']['LISP']['smr_enabled'])

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



