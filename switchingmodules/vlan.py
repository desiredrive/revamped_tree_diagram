import radkit_cli
import re

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
                #print("WARNING!: VLAN {} is not active on device: {}".format(self.vlan, self.hostname))
                return

    def vlanbrief_manual(self,service):
        vlanid_cmd = "show vlan id {}".format(self.vlan)
        vlanid_op = radkit_cli.get_any_single_output(self.hostname, vlanid_cmd, service)
        self.status = "lshut"
        if vlanid_op is not None:
            for line in vlanid_op.splitlines():
                matches = ['#',"show","enet"]
                if not any(x in line for x in matches):
                    if "active" in line:
                        self.status = "active"
                        vlan_match = re.compile(r'^\d+\s+([\w-]+)').search(line)
                        vlan_name = vlan_match.group(1)
                        self.vlanname = vlan_name
                        pattern = re.compile(r'active\s+([\w:/\s,-]+)')
                        match = pattern.search(line)
                        if match:
                            # Extract the ports from the matched group
                            self.ports = [port.strip() for port in match.group(1).split(',') if port.strip()]