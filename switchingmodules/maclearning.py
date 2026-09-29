import radkit_cli

class mac_learning:

    def __init__(self, device):
        self.hostname = device

    def mac_learning_mac(self, mac, vlan, service):
        # When vlan is unknown (e.g. FEW WLC LISP DB omits vlan_id), drop the
        # `vlan` qualifier entirely — the IOS CLI rejects `vlan None` literally.
        if vlan is None or str(vlan).strip().lower() in ("", "none"):
            mac_cmd = "show mac address-table address {}".format(mac)
        else:
            mac_cmd = "show mac address-table address {} vlan {}".format(mac, vlan)
        mac_op = radkit_cli.get_single_output_genie(self.hostname, mac_cmd, service)
        self.type = None
        self.port = None
        self.mac = None
        self.vlan = None
        # The parsed entry as the device reported it, for callers that need more
        # than Type and Ports (e.g. platform-dependent verification, which
        # compares hardware against exactly what IOS said).
        self.entry = None
        if mac_op == None:
            return None
        else:
            # A MAC that is not in the table parses to an empty dict -- the
            # command returns its header and no rows. That is a normal outcome,
            # not an error, so it leaves port/type as None rather than raising
            # KeyError out of the lookup below.
            mac_path = (mac_op.get('macAddress') or {}).get(mac)
            if not mac_path:
                return None

            self.mac = mac
            self.entry = dict(mac_path)
            self.type = mac_path['Type']
            self.port = mac_path['Ports']
            # Prefer the VLAN the device reported: with no `vlan` qualifier the
            # argument is None, and the parsed entry is then the only source.
            # Kept as an int so callers that were passed one see no change --
            # genie reports VlanID as a string.
            reported = mac_path.get('VlanID')
            if reported is None or str(reported).strip() == "":
                self.vlan = vlan
            else:
                try:
                    self.vlan = int(str(reported).strip())
                except ValueError:
                    self.vlan = reported

    def mac_learning_interface(self, interface, vlan, service):
        mac_intf_cmd = "show mac address-table interface {} ".format(interface)
        mac_op = radkit_cli.get_single_output_genie(self.hostname, mac_intf_cmd, service)

        self.type = None
        self.port = None
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