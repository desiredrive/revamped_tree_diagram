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

    def mac_learning_interface(self, interface, vlan, service):
        mac_intf_cmd = "show mac address-table interface {} ".format(interface)
        mac_op = radkit_cli.get_single_output_genie(self.hostname, mac_intf_cmd, service)

        if mac_op is None:
            return None
        else:
            self.interface = interface
            self.vlan = vlan

            mac_path = mac_op['mac_table']['vlans'][str(vlan)]['mac_addresses']
            mac_list = []
            mac_info = []
            for macs in mac_path:
                mac_list.append(macs)
            for macs in mac_list:
                mac_address = macs
                interfaces = mac_path[mac_address]['interfaces']
                for interface in interfaces:
                    interface_name = interface
                entry_type = mac_path[mac_address]['interfaces'][interface_name]['entry_type']
                mac_information = {
                    "mac": mac_address,
                    "interface": interface_name,
                    "entry_type": entry_type
                }
                mac_info.append(mac_information)
            self.mac_information = mac_info