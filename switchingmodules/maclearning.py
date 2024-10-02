import radkit_cli

class mac_learning():

    def __init__(self, device):
        self.hostname = device
    
    
    def mac_learning_mac(self, mac, vlan, service):
        mac_cmd = "show mac address-table address {} {}".format(mac, vlan)
        mac_op = radkit_cli.get_single_output_genie(self.hostname, mac_cmd, service)

        if mac_op == None:
            return None
        else:
            self.mac = mac
            self.vlan = vlan
            
            mac_path = mac_op['macAddress'][mac]
            self.type = mac_path['Type']
            self.port = mac_path['Ports']
            
