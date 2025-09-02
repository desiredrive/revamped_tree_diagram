import radkit_cli

class arp_modules():
    
    def __init__(self, vrf, device):
        self.hostname = device
        self.vrf = vrf 

    def arp_resolution_single_ip(self, ip, interface, service):
        
        #Identify if VRF is in use or not:
        if self.vrf == "default":
            vrf_mode = ""
            vrf = ''
        elif self.vrf is None:
            vrf_mode = ""
            vrf = ''
        else:
            vrf_mode = "vrf "+self.vrf+" "

        if vrf_mode == "":
            arp_cmd = "show arp {}".format(ip)
        else:
            arp_cmd = "show arp {} {} {}".format(vrf_mode, ip, interface)
        
        arp_op = radkit_cli.get_single_output_genie(self.hostname, arp_cmd, service)
        arp_path = arp_op['interfaces'][interface]['ipv4']['neighbors'][ip]

        self.ip = ip
        self.mac = arp_path['link_layer_address']
        self.age = arp_path['age']
        self.origin = arp_path['origin']
