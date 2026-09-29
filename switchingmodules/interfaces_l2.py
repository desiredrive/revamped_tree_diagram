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
            interface_encap_path = interface_path.get('encapsulation', {}) or {}
            self.switchport_enable = interface_path['switchport_enable']

            if self.switchport_enable == True:
                self.adminmode = interface_path['switchport_mode']
                self.opermode = interface_path['operational_mode']
                if "trunk" in self.opermode:
                    self.istrunking = True
                else:
                    self.istrunking = False
                # Genie only emits these when the device reports them: an access
                # port with no voice VLAN has no 'voice_vlan' key, and a port that
                # is not trunking has no 'trunk_vlans'. Absent means not
                # configured, so read them as optional rather than raising.
                self.trunknegotiation = interface_path.get('negotiation_of_trunk')
                self.accessvlan = interface_path.get('access_vlan')
                self.voicevlan = interface_path.get('voice_vlan')
                self.nativevlan = interface_encap_path.get('native_vlan')
                self.nativetagging = interface_path.get('native_vlan_tagging')
                self.allowedvlanstrunk = interface_path.get('trunk_vlans')
        else: 
            return None