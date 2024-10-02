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
        self.intf = intf
        self.switchport = None
        self.admode = None
        self.opmode = None
        self.istrunking = False
        self.swnegotiation = None
        self.accessvlan = None 
        self.voicevlan = None
        self.nativevlan = None
        self.nativetagging = False
        self.trunkallowed = None
        self.l3pacls = None
        self.l2pacls = None
        self.authentemplate = None
        self.ipdtintfpolicy = None
        self.macrodisabled = False
        self.autoconfdisabled = False
        self.portsecuritystatus = None 
        self.hostname  = device

    def switchport_status(self,service):
        intf_sp_cmd = "show interface {} switchport".format(self.intf)
        intf_sp_op = radkit_cli.get_any_single_output(self.hostname,intf_sp_cmd,service)  
        if intf_sp_op == None:
                print ("\nNo Port information was found for {}\n".format(self.intf))
                return
        else:  
            for line in intf_sp_op.splitlines():
                #Interface Switchport Definition
                if "Switchport: Disabled" in line:
                    print("\n Interface {} not configured as L2 Interface, \"no switchport\" is configured on it".format(self.intf))
                    break
                if "Switchport: Enabled" in line:
                    self.switchport = True 
                #Administrative/Operational Mode Definition
                if "ative Mode:" in line:
                    self.admode = re.compile("(?<=Mode: )[A-Za-z].*[A-Za-z]+").search(line).group()
                if "ional Mode:" in line:
                    self.opmode = re.compile("(?<=Mode: )[A-Za-z].*[A-Za-z]+").search(line).group()
                    if self.opmode == "trunk":
                        self.istrunking = True 
                if "Negotiation" in line:
                    if "Off" in line:
                        self.swnegotiation = False
                    if "On" in line:
                        self.swnegotiation = True 
                #VLANs
                if "Access Mode" in line:
                    self.accessvlan = re.compile("(?<=VLAN: )\d+").search(line).group()
                if "Voice VLAN" in line:
                    try:
                        self.voicevlan = re.compile("(?<=VLAN: )\d+").search(line).group()
                    except:
                        self.voicevlan = None
                if "Native Mode" in line:
                    self.nativevlan = re.compile("(?<=VLAN: )\d+").search(line).group()
                if "ve Native VLAN" in line:
                    if "enabled" in line:
                        self.nativetagging = True
                
                #Trunking
                if "Trunking VLAN" in line:
                    vlanlist = re.compile("(?<=Enabled: ).*").search(line).group().strip()
                    if vlanlist == "ALL":
                        self.trunkallowed = "1-4094"
                    elif vlanlist == "NONE":
                        self.trunkallowed = 0
                    else:
                        vlanlist = vlanlist.replace(" ","").split(",")
                        self.trunkallowed = vlanlist

    def run_params(self,service):
        intf_run_cmd = "show run interface {}".format(self.intf)
        intf_run_op = radkit_cli.get_any_single_output(self.hostname, intf_run_cmd,service)
        l3pacls = {}
        l2pacls = {}
        l3paclpointer = 0
        l2paclpointer = 0
        if intf_run_op == None:
                print ("\nNo Port information was found for {}\n".format(self.intf))
                return
        else:  
            for line in intf_run_op.splitlines():
                if "ip access-group" in line:
                    aclcomp = re.compile("(?<=access-group ).*").search(line).group().split(" ")
                    acldir = {'ACLName' : aclcomp[0], 'Direction' : aclcomp[1]}
                    l3pacls[l3paclpointer] = acldir
                    l3paclpointer+=1
                if "mac access-group" in line:
                    aclcomp = re.compile("(?<=access-group ).*").search(line).group().split(" ")
                    acldir = {'ACLName' : aclcomp[0], 'Direction' : aclcomp[1]}
                    l2pacls[l2paclpointer] = acldir
                    l2paclpointer+=1
                if "source template" in line:
                    self.authentemplate = re.compile("(?<=source template ).*").search(line).group().strip()
                if "device-tracking attach" in line:
                    self.ipdtintfpolicy = re.compile("(?<=policy).*").search(line).group().strip()
                if "disable autoconf" in line:
                    self.autoconfdisabled = True 
                if "no macro auto processing" in line:
                    self.macrodisabled = True
                if "port-security" in line:
                    port_security_cmd = "show port-security interface {}".format(self.intf)
                    port_security_op = radkit_cli.get_any_single_output(self.hostname, port_security_cmd,service)
                    result = port_security(port_security_op)
                    self.portsecuritystatus = result
            self.l3pacls = l3pacls
            self.l2pacls = l2pacls

                
                
class interfaces():

    def __init__(self, interface, device):
        self.hostname = device
        self.interface = interface 

    def show_interface(self, service):

        print ("Collecting Interface Parameters and Information: \n")

        intf_cmd = "show interface {}".format(self.interface)
        intf_op = radkit_cli.get_single_output_genie(self.hostname,intf_cmd,service)

        for i in intf_op:
            if "exclude" in i:
                continue
            else:
                interface = i
        interface_path = intf_op[interface]
        interface_queues_path = intf_op[interface]['queues']
        interface_counters_path = intf_op[interface]['counters']

        self.linestate = interface_path['line_protocol']
        self.operstate = interface_path['oper_status']
        self.connected = interface_path['connected']
        self.errdisabled = interface_path['err_disabled']
        self.intfmac = interface_path['mac_address']
        self.description = interface_path['description']
        self.mtu = interface_path['mtu']
        self.txload = interface_path['txload']
        self.rxload = interface_path['rxload']
        self.speed = interface_path['port_speed']
        #IP and Subnet Information (if any)
        try:
            self.intfsubnet = interface_path['ipv4']
            ips = []
            for i in self.intfsubnet:
                subnet = i
                ip = self.intfsubnet[subnet][ip]
                ips.append(ip)
            self.intfips = ips
        except:
            pass
        #Queues
        self.iqdrops = interface_queues_path['input_queue_drops']
        self.outputdrops = interface_queues_path['total_output_drop']
        #Counters
        self.crcerrors = interface_counters_path['in_crc_errors']
        self.giants = interface_counters_path['in_giants']
        self.runts = interface_counters_path['in_runts']
        self.inputpps = interface_counters_path['rate']['in_rate_pkts']
        self.outputpps = interface_counters_path['rate']['out_rate_pkts']