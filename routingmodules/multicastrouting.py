import radkit_cli
import re

def mroute_health_check(mrouteinfo):
    #Validations:
    #1 - Flags; F = Registered via RegStop, P = Prunned, No OIL;
    return None

class MulticastConfiguration:
    def __init__(self, vrf, device):
        self.hostname = device
        self.vrf = vrf

    def multicast_enabled(self, service):
        if self.vrf == "default":
            vrf_mode = ""
            vrf = ''
        elif self.vrf is None:
            vrf_mode = ""
            vrf = ''
        else:
            vrf = self.vrf
            vrf_mode = "vrf "+self.vrf+" "

        ipmcast_cmd = "show ip multicast {}".format(vrf_mode)
        ipmcast_op = radkit_cli.get_single_output_genie(self.hostname,ipmcast_cmd,service)
        mcast_path = ipmcast_op['vrf'][vrf]
        self.multicastenabled = mcast_path['enable']
        self.multipath = mcast_path['multipath']
        self.fallbackmode = mcast_path['fallback_group_mode']

    def multicast_ranges(self,service):
        if self.vrf == "default":
            vrf_mode = ""
            vrf = ''
        elif self.vrf is None:
            vrf_mode = ""
            vrf = ''
        else:
            vrf_mode = "vrf "+self.vrf+" "

        mcastrange_cmd = "show run | i group-range"
        mcastrange_op = radkit_cli.get_any_single_output(self.hostname, mcastrange_cmd,service)
        matches = ["#","show"]
        self.mcastrangeacl = None
        self.mcastrange = False
        if mcastrange_op is not None:
            if vrf_mode == '':
                #Default/Global RIB:
                for line in mcastrange_op.splitlines():
                    if not any (x in line for x in matches):
                        if "ip multicast group-range" in line:
                            self.mcastrangeacl = re.compile("(?<=range ).*").search(line).group().strip()
                            self.mcastrange = True

            else:
                #VRF aware:
                for line in mcastrange_op.splitlines():
                    if not any (x in line for x in matches):
                        mcastrangesearch = "ip multicast {}group-range".format(vrf_mode)
                        if mcastrangesearch in line:
                            self.mcastrangeacl = re.compile("(?<=range ).*").search(line).group().strip()
                            self.mcastrange = True

class MulticastRoutes:
    def __init__(self,vrf, device):
        self.hostname = device
        self.vrf = vrf

    def mroute_get(self,group,source,service):
        if self.vrf == "default":
            vrf_mode = ""
            vrf = ''
        elif self.vrf is None:
            vrf_mode = ""
            vrf = ''
        else:
            vrf = self.vrf
            vrf_mode = "vrf "+self.vrf+" "

        mroute_cmd = "show ip mroute {} {} {}".format(vrf_mode,group,source)
        mroute_op = radkit_cli.get_single_output_genie(self.hostname, mroute_cmd,service)
        if mroute_op is not None:
            output = mroute_op
            group = group
            try:
                mroute_path = output['vrf'][vrf]['address_family']['ipv4']['multicast_group'][group]['source_address']
                mroute_exists = True
            except KeyError:
                mroute_exists = False
            mroutes = []
            if mroute_exists is not False:
                for sources in mroute_path:
                    source = sources
                    outgoinglist = []
                    uptime = mroute_path[sources]['uptime']
                    expire = mroute_path[sources]['expire']
                    flags = mroute_path[sources]['flags']
                    msdplearned = mroute_path[sources]['msdp_learned']
                    rp_bit = mroute_path[sources]['rp_bit']
                    if sources == "*":
                        rp = mroute_path[sources]['rp']
                    else:
                        rp = 'N/A'
                    rpfneighbor = mroute_path[sources]['rpf_nbr']
                    incominginterface = mroute_path[sources]['incoming_interface_list']
                    for interface in incominginterface:
                        incominginterface = interface
                    oils = mroute_path[sources]['outgoing_interface_list']
                    for oil in oils:
                        oilinterface = oil
                        oiluptime = oils[oilinterface]['uptime']
                        oilexpire = oils[oilinterface]['expire']
                        oilstate = oils[oilinterface]['state_mode']
                        oilinfo = {
                            'interface': oilinterface,
                            'uptime': oiluptime,
                            'expire': oilexpire,
                            'state': oilstate
                        }
                        outgoinglist.append(oilinfo)
                    mroute_info = {
                        'source': source,
                        'uptime': uptime,
                        'expire': expire,
                        'flags': flags,
                        'msdplearned': msdplearned,
                        'rp_bit': rp_bit,
                        'rp': rp,
                        'rpfneighbor': rpfneighbor,
                        'incominginterface': incominginterface,
                        'outgoinginterfacelist': outgoinglist
                    }
                    mroutes.append(mroute_info)
                self.mrouteinfo = mroutes
            else:
                self.mrouteinfo = None

    def mfib_verbose(self,group,source,service):
        if self.vrf == "default":
            vrf_mode = ""
            vrf = 'Default'
        elif self.vrf is None:
            vrf_mode = ""
            vrf = 'Default'
        else:
            vrf = self.vrf
            vrf_mode = "vrf "+self.vrf+" "

        mfibverb_cmd = "show ip mfib {} {} {} verbose".format(vrf_mode,group,source)
        mfibverb_output = radkit_cli.get_single_output_genie(self.hostname,mfibverb_cmd,service)

        if mfibverb_output is not None:
            mfib_main_path = mfibverb_output['vrf'][vrf]['address_family']['ipv4']
            if len(mfib_main_path) == 0:
                self.mfibstate = False
            else:
                self.mfibstate = True
                mfib_main_path = mfib_main_path['multicast_group'][group]['source_address'][source]
                self.mfibflags = mfib_main_path['flags']
                self.sw_packets_per_second = mfib_main_path['sw_packets_per_second']
                self.sw_packet_count = mfib_main_path['sw_packet_count']
                self.sw_rpf_failed = mfib_main_path['sw_rpf_failed']
                self.sw_other_drops = mfib_main_path['sw_other_drops']
                self.hw_packet_count = mfib_main_path['hw_packet_count']
                self.hw_packets_per_second = mfib_main_path['hw_packets_per_second']
                self.hw_rpf_failed = mfib_main_path['hw_rpf_failed']
                self.hw_other_drops = mfib_main_path['hw_other_drops']
                iifpath = mfib_main_path['incoming_interfaces']
                iifinterface = None
                for interface in iifpath:
                    iifinterface = interface
                self.iif = iifinterface
                self.iifflags = mfib_main_path['incoming_interfaces'][iifinterface]['ingress_flags']
                oilpath = mfib_main_path['outgoing_interfaces']
                oils = []
                for interface in oilpath:
                    oilinterface = interface
                    egress_flags = mfib_main_path['outgoing_interfaces'][oilinterface]['egress_flags']
                    egress_adj_mac = mfib_main_path['outgoing_interfaces'][oilinterface]['egress_adj_mac']
                    adjacency = egress_adj_mac.split(":")[1].strip()
                    oilinfo = {
                        'interface' : oilinterface,
                        'oilflags' : egress_flags,
                        'adjacency' : adjacency
                    }
                    oils.append(oilinfo)
                self.oils = oils



