import radkit_cli
from re import compile

class multicast_configuration():
    def __init__(self, vrf, device):
        self.hostname = device
        self.vrf = vrf

    def multicast_enabled(self, service):
        if self.vrf == "default" or self.vrf is None:
            vrf_mode = ""
            vrf = ''
        else:
            vrf_mode = "vrf "+self.vrf+" "

        ipmcast_cmd = "show ip multicast {}".format(vrf_mode)
        ipmcast_op = radkit_cli.get_single_output_genie(self.hostname,ipmcast_cmd,service)
        mcast_path = ipmcast_op['vrf'][vrf]
        self.multicastenabled = mcast_path['enable']
        self.multipath = mcast_path['multipath']
        self.fallbackmode = mcast_path['fallback_group_mode']

