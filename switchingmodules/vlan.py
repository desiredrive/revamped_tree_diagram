import radkit_cli

class VlanInformation:
    def __init__(self,vlan,device):
        self.hostname = device
        self.vlan = vlan

    def vlanbrief(self,service):
        vlanid_cmd = "show vlan id {}".format(self.vlan)
        vlanid_op = radkit_cli.get_single_output_genie(self.hostname, vlanid_cmd, service)
        if vlanid_op is not None:
            self.vlanname = vlanid_op['vlan-name']
            self.status = vlanid_op['status']
            self.ports = vlanid_op['ports']
            if self.status != 'active':
                print("WARNING!: VLAN {} is not active on device: {}".format(self.vlan, self.hostname))

