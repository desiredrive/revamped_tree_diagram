import re
import sys
import radkit_cli

#Platform Independent = IOS 
'''
This module validates the following parameters in Platfrom Independent for Layer 2 information of an Interface
*Access VLAN
*Voice VLAN 
*Mode: Access, Trunk
*Administrative Mode
*Operational Mode
*DTP parameters
*ACL configuration - Linked to pending ACL module
*Authentication Template (Validated through a different module)
*Native VLAN
*IPDT enablement
*Autoconf status
*Macro status
*Port Security Status

Support for this module is only applicable for the following interface types:

Physical Layer 2 : GigabitEthernet, TenGigabit, Forty..etc
Standalone Port-Channel Members
Port-Channels
App-Hosting Interface
*Not SVL interfaces
*Not Tunnels (Tunnel, VPN Interfaces, Dialers, Access-Tunnels, LISP, NVE, L2LISP)
'''

def port_security(cmd):
    for line in cmd.splitlines():
        if "Port Security" in line:
            state = re.compile("(?<=: ).*").search(line).group()
        if "Port Status" in line:
            status = re.compile("(?<=: ).*").search(line).group()
        if "Violation" in line:
            violationmode = re.compile("(?<=: ).*").search(line).group()
        if "Maximum MAC" in line:
            maxmacs = re.compile("(?<=: ).*").search(line).group()
        if "Last" in line:
            lmac = re.compile("(?<=: ).*").search(line).group().split(":")
    
    portsec = {"Status" : state,
               "State" : status,
               "Violation Mode" : violationmode,
               "Maximum MACs" : maxmacs,
               "Last MAC" : lmac}
    return (portsec)


class interface_switchport:

    def __init__(self, intf, device):
        self.hostname  = device
        self.interface = intf

    def switchport_status(self,service):
        intfswport_cmd = "show interface {} switchport".format(self.interface)
        intfswport_op = radkit_cli.get_single_output_genie(self.hostname, intfswport_cmd, service)
        
        if intfswport_op is not None:
            for i in intfswport_op:
                if "exclude" not in i:
                    interface = i
            interface_path = intfswport_op[interface]
            interface_encap_path = interface_path['encapsulation']
            self.switchport_enable = interface_path['switchport_enable']

            if self.switchport_enable == True:
                self.adminmode = interface_path['switchport_mode']
                self.opermode = interface_path['operational_mode']
                if "trunk" in self.opermode:
                    self.istrunking = True
                else:
                    self.istrunking = False
                self.trunknegotiation = interface_path['negotiation_of_trunk']
                self.accessvlan = interface_path['access_vlan']
                self.voicevlan = interface_path['voice_vlan']
                self.nativevlan = interface_encap_path['native_vlan']
                self.nativetagging = interface_path['native_vlan_tagging']
                self.allowedvlanstrunk = interface_path['trunk_vlans']
        else: 
            return None