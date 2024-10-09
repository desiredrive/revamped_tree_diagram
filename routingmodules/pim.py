import radkit_cli
import re
from routingmodules.iprouting import  IPRoute
from routingmodules.cef import IPCef
from traffic_flows.operational_tests import Ping

class PimConfiguration:

    def __init__(self, vrf, device):
        self.hostname = device
        self.vrf = vrf

    def pim_interfaces(self,service):
        vrf = None
        if self.vrf == "default":
            vrf_mode = ""
            vrf = ''
        elif self.vrf is None:
            vrf_mode = ""
            vrf = ''
        else:
            vrf_mode = "vrf "+self.vrf+" "
        #Information about PIM interfaces on a device:
        pimintf_cmd = "show ip pim {} interface detail".format(vrf_mode)
        pimintf_op = radkit_cli.get_single_output_genie(self.hostname,pimintf_cmd,service)
        interface_list = []
        if pimintf_op is not None:
            pimintf_path = pimintf_op['vrf'][vrf]['interfaces']
            for i in pimintf_path:
                interface_name = i
                oper_status = pimintf_path[i]['address_family']['ipv4']['oper_status']
                enabled = pimintf_path[i]['address_family']['ipv4']['enable']
                try:
                    pim_mode = pimintf_path[i]['address_family']['ipv4']['mode']
                except KeyError:
                    pim_mode = None
                pim_status = pimintf_path[i]['address_family']['ipv4']['pim_status']
                pim_dr = pimintf_path[i]['address_family']['ipv4']['dr_address']
                neighbor_count = pimintf_path[i]['address_family']['ipv4']['neighbor_count']
                hello_in = pimintf_path[i]['address_family']['ipv4']['hello_packets_in']
                hello_out = pimintf_path[i]['address_family']['ipv4']['hello_packets_out']
                jp_interval = pimintf_path[i]['address_family']['ipv4']['jp_interval']
                pim_interface = {
                    'interface_name': interface_name,
                    'oper_status': oper_status,
                    'enabled': enabled,
                    'pim_status': pim_status,
                    'pim_dr': pim_dr,
                    'pim_mode': pim_mode,
                    'neighbor_count': neighbor_count,
                    'hello_in': hello_in,
                    'hello_out': hello_out,
                    'jp_interval': jp_interval
                }
                interface_list.append(pim_interface)
            self.piminterfaces = interface_list

    def pim_neighbors(self,service):
        vrf = None
        #For now this module does not support LISP interfaces/Overlay Multicast
        if self.vrf == "default":
            vrf_mode = ""
            vrf = 'default'
        elif self.vrf is None:
            vrf_mode = ""
            vrf = 'default'
        else:
            vrf_mode = "vrf "+self.vrf+" "
        # Information about PIM interfaces on a device:
        pimneig_cmd = "show ip pim {} neighbor".format(vrf_mode)
        pimneig_op = radkit_cli.get_single_output_genie(self.hostname,pimneig_cmd,service)
        pimneighlist = []
        if pimneig_op is not None:
            pimneighpath = pimneig_op['vrf']['default']['interfaces']
            for interface in pimneighpath:
                interfacename = interface
                pimintfneighpath = pimneighpath[interfacename]['address_family']['ipv4']['neighbors']
                for neighbor in pimintfneighpath:
                    neighbor_ip = neighbor
                    dr_priority = pimintfneighpath[neighbor]['dr_priority']
                    up_time = pimintfneighpath[neighbor]['up_time']
                    interface = pimintfneighpath[neighbor]['interface']
                    neighbor = {
                        'interface': interface,
                        'neighbor_ip': neighbor_ip,
                        'dr_priority': dr_priority,
                        'up_time': up_time,
                    }
                    pimneighlist.append(neighbor)
            self.pimneighbors = (pimneighlist)
        else:
            self.pimneighbors = None
        self.neighborcount = len(pimneighlist)

    def pim_rp(self,group,service):
        vrf = None
        if self.vrf == "default":
            vrf_mode = ""
            vrf = 'default'
        elif self.vrf is None:
            vrf_mode = ""
            vrf = 'default'
        else:
            vrf_mode = "vrf "+self.vrf+" "
        #Identify the RP using non-dns lookup command:
        pimrp_cmd = "show ip pim {} rp {}".format(vrf_mode,group)
        pimrp_op = radkit_cli.get_any_single_output(self.hostname, pimrp_cmd, service)

        self.rp = None
        matches = ['#', 'show']
        for rps in pimrp_op.splitlines():
            if not any(x in rps for x in matches):
                if "uptime" in rps:
                    rp_ip = re.compile("(?<=RP: )(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?=, uptime)").search(rps).group().strip()
                    self.rp = rp_ip

        if self.rp is None:
            return None
        else:
            #Route to RP:
            rp_route = IPRoute(self.rp, vrf,self.hostname)
            rp_route.iproute_prefix(service)
            cef_route = IPCef(self.rp, vrf, self.hostname)
            cef_route.get_cef_internal(service)
            self.rproute = rp_route
            self.rpcef = cef_route

            #Tunnel To IP
            pimtunnels = []
            pimtunnel_cmd = "show ip pim {} tunnel".format(vrf_mode)
            pimtunne_op = radkit_cli.get_single_output_genie(self.hostname,pimtunnel_cmd,service)
            if pimtunne_op is not None:
                path = pimtunne_op['tunnels']
                pimtunnels = []
                for i in path:
                    index = i
                    tunnelpath = path[i]
                    tunnel_interface = 'Tunnel'+index
                    tunnel_type = tunnelpath['type']
                    tunnel_rp = tunnelpath['rp']
                    tunnel_source = tunnelpath['source']
                    tunnel_state = tunnelpath['state']
                    tunnel_uptime = tunnelpath['uptime']
                    tunnel_info = {
                        'tunnel_interface' : tunnel_interface,
                        'tunnel_type': tunnel_type,
                        'tunnel_rp': tunnel_rp,
                        'tunnel_source': tunnel_source,
                        'tunnel_state': tunnel_state,
                        'tunnel_uptime': tunnel_uptime
                    }
                    pimtunnels.append(tunnel_info)
                self.pimtunnels = pimtunnels
            #Ping to RP IP using TunnelSource IP:
            #RP IP identification:
            electedsource = None
            if len(pimtunnels) !=0:
                for tunnel in pimtunnels:
                    if (tunnel['tunnel_rp'] == self.rp+'*') and (tunnel['tunnel_type'] == 'PIM Encap'):
                        electedsource = tunnel['tunnel_source']
                        self.isrplocal = True
                        self.maintunnel = tunnel['tunnel_interface']
                    if (tunnel['tunnel_rp'] == self.rp) and (tunnel['tunnel_type'] == 'PIM Encap'):
                        electedsource = tunnel['tunnel_source']
                        self.isrplocal = False
                        self.maintunnel = tunnel['tunnel_interface']

            pingstatus = Ping(self.rp,self.hostname)
            pingstatus.ping_with_source(None,electedsource,None,False,service)
            self.pingstatus = pingstatus

    def pim_rpf_neighbor(self,ip,service):
        vrf = None
        if self.vrf == "default":
            vrf_mode = ""
            vrf = ''
        elif self.vrf is None:
            vrf_mode = ""
            vrf = ''
        else:
            vrf_mode = "vrf "+self.vrf+" "

        #Identify the RPF neighbor for a source
        rpf_cmd = "show ip rpf {} {}".format(vrf_mode,ip)
        rpf_op = radkit_cli.get_single_output_genie(self.hostname, rpf_cmd, service)
        if rpf_op is not None:
            path = rpf_op['vrf'][vrf]['path']
            for i in path:
                ip_path = i
            path = path[ip_path]
            self.rpfinterface = path['interface_name']
            self.rpfneighborip = path['neighbor_address']
            prefix = path['route_mask'].split("/")
            self.rpfprefix = prefix[0]
            self.rpfmask = prefix[1]
            self.rpfinterface = path['interface_name']
            self.rpffailure = False
        else:
            self.rpffailure = True
