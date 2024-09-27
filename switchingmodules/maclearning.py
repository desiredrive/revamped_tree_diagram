from dataclasses import dataclass
import re
import sys
import radkit_cli

#Platform Independent = IOS 
'''
This module validates the following parameters in Platfrom Independent for Layer 2 information of an Interface 

the module works with two principles:

1) The input MAC address is known for trobuleshooting purposes and there is a targetted interface from where this MAC should be known
2) The input MAC address is unknown and there is a targetted interface from where the MAC should be known.

Naturally, Option 1 gives the most accurate flow of information to match the learning against the interface, potentially discovering the MAC learning over an unexpected interface
In contrast, Option 2 will attempt to discover a MAC address against the interface and the targetted VLAN, with the following results:

    a) The expected MAC address is found (requires confirmation/user input) and it is the single MAC learned on the port
    b) The expected MAC address is found (requires confirmation/user input) but there are multiple MACs learned (requires selection)
    c) The expected MAC address is not found but others are - requires double confirmation/triggers rest of troubleshooting flows
    d) Not a single MAC address is found - triggers rest of troubleshooting flows

For scenario 1, we consider the targetted MAC and Port are deterministic, the only required input is the MAC address itself.
    module is called "deterministic_mac_learning"
For secnario 2, only the targetted port is deterministic, the rest of values requires input/confirmation... (need to be tested in BDB)

        
* MAC address learning on a given interface
* MAC address learning on a given VLAN 
* MAC address learning limits
* MAC move
* MAC device-tracking MAC 
+ All of queries must be excempt of errors (No MAC found, Empty outputs equals None in the class attribute.)

Support for this module is only applicable for the following interface types:

Physical Layer 2 : GigabitEthernet, TenGigabit, Forty..etc
Standalone Port-Channel Members
Port-Channels
App-Hosting Interface
*Not SVL interfaces
*Not Tunnels (Tunnel, VPN Interfaces, Dialers, Access-Tunnels, LISP, NVE, L2LISP) FEW interfaces will be covered by the FEW modules.
Remote MAC learning via L2LISP can be handled in a different module, this is for local mac learning.
'''

def mac_conversion(normalized_mac_address, symbol):
    if symbol == '.':
        return symbol.join([normalized_mac_address[i:i + 4] for i in range(0, len(normalized_mac_address), 4)])
    return symbol.join(a + b for a, b in zip(normalized_mac_address[::2], normalized_mac_address[1::2]))

def mac_input_type(current_mac_address, mac_address_format):
    normalized_mac_address = re.sub(r'\W+', '', current_mac_address)

    dict_mac_formats = {
        'none': '',
        'dot': '.',
        'colon': ':',
        'dash': '-'
    }
    symbol = dict_mac_formats.get(mac_address_format, 'Invalid format')
    if symbol == 'Invalid format':
        return 'Invalid format. Should be none | dot |  colon | dash '

    if len(normalized_mac_address) == 12:
        symbol = dict_mac_formats.get(mac_address_format, 'Invalid format')
        return mac_conversion(normalized_mac_address, symbol)
    else:
        return "Invalid format. Should be 01-23-45-67-89-AB | 01:23:45:67:89:AB | 0123456789AB | 0123.4567.89AB or " \
               "any combination "

class mac_learning:

    def __init__(self, mac, tintf, tvlan, device):
        #mac = targetted mac address, converted to xxxx.xxxx.xxxx
        #tvlan = targetted VLAN, required VLAN.
        #tintf = targetted interface, expecting to see MAC learning on it
        self.mac = None
        self.vlan = tvlan
        self.interafce = tintf
        self.maclearningstate = False
        self.controlplanelearning = False
        self.vlaninterface = None
        self.macsininterface = None
        self.foundinvlans = False
        self.iscplearn = False
        self.istunnellearn = False 
        self.dynamic = None
        self.static = None
        self.totalcount = None
        self.totalavailable = None
        self.hostname  = device

        validatedmac = mac_input_type(mac,'dot')
        self.mac = validatedmac

    def switchport_status(self,service):
        cmd1 = "show mac addres-table learning vlan {}".format(self.vlan)
        cmd2 = "show mac address-table control-placket-learn"
        cmd3 = "show mac address-table "
        cmd4 = 'show ip protocols | i lisp'
        cmd5 = 'show run | i route-import'
        cmd6 = 'show device-tracking policies | i DT-GUARD-VLAN'
        cmd7 = 'show lisp service ipv4 | se Map-Server'
        cmd8 = 'show ver | i IOS Soft|bytes of memory'
        cmd9 = 'show cdp neighbor detail | i Device ID|Interface'
        cmd10 = 'show run | i IPv4-interface|affinity'

        try:
            commands1 = self.device_inventory.exec([cmd1,cmd2,cmd3,cmd4]).wait()
            commands2 = self.device_inventory.exec([cmd5,cmd6,cmd7,cmd8]).wait()
            cdp = self.device_inventory.exec([cmd9]).wait()
            loopdef = self.device_inventory.exec([cmd10]).wait()
        except (IndexError, ValueError):
            sys.exit("Unable to fetch configuration from device {}".format(self.mgmtip))  
        try: 
            lo0 = commands1.result["{}".format(cmd1)].data
            fabric_role = commands1.result["{}".format(cmd3)].data
            lisp_enabled = commands1.result["{}".format(cmd4)].data
            internal_border = commands2.result["{}".format(cmd5)].data
            fe_ipdtcheck = commands2.result["{}".format(cmd6)].data
            map_servers = commands2.result["{}".format(cmd7)].data
            model_ios = commands2.result ["{}".format(cmd8)].data
            cdpneiop = cdp.result["{}".format(cmd9)].data
            loopres = loopdef.result["{}".format(cmd10)].data
        except:
            sys.exit("Unable to profile device {}".format(self.hostname))