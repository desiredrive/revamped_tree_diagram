import radkit_cli
from switchingmodules import etherchannel
from switchingmodules.arp import arp_modules
from switchingmodules.maclearning import mac_learning
from re import compile

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

