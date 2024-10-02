import re
import sys
import radkit_cli

#Platform Independent = IOS 

class stp_intf:

    def __init__(self, vlan, intf, device):
        self.port = intf
        self.vlan = vlan 
        self.role = None
        self.state = None
        self.cost = None
        self.portpriority = None
        self.transitions = None
        self.portfast = "Disabled" 
        self.bpduguard = False
        self.bpdufilter = False
        self.bpdusent = None
        self.bpdurcvd = None
        self.hostname  = device

    def stp_intf_detail(self, service):
        #Define main IOS Commands
        unsupported_type = ["LISP", "Tu", "nve"]
        if not any(x  in self.port for x in unsupported_type):
            stp_intf_cmd = "show spanning-tree vlan {} interface {} detail".format(self.vlan,self.port)
            stp_intf_op = radkit_cli.get_any_single_output(self.hostname,stp_intf_cmd,service)
            if stp_intf_op == None:
                print ("\nNo STP information was found for this port\n")
            else:
                for line in stp_intf_op.splitlines():
                    #Port state and role definition
                    if ("Port" in line) and ("of" in line):
                        if "designated forwarding" in line:
                            self.role = "Designated"
                            self.state = "Forwarding"
                        if "designated blocking" in line:
                            self.role = "Designated"
                            self.state = "Blocking"
                        if "root forwarding" in line:
                            self.role = "Root"
                            self.state = "Forwarding"
                        if "alternate" in line:
                            self.role = "Alternate"
                            self.state = "Blocking"
                        if "backup" in line:
                            self.role = "Backup"
                            self.state ="Blocking"
                    #Port Cost and Priority Definition
                    if "Identifier" in line:
                        self.cost = re.compile("(?<=cost )\d+(?=,)").search(line).group()
                        self.portpriority = re.compile("(?<=priority )\d+(?=,)").search(line).group()
                    #Transitions to Forwading State
                    if "transitions" in line:
                        self.transitions = re.compile("\d+").search(line).group()
                    #Portfast Enabled:
                    if "portfast" in line:
                        if "trunk" in line:
                            self.portfast = "Enabled - Trunk"
                        else:
                            self.portfast = "Enabled"
                    if "Bpdu guard is enabled" in line:
                        self.bpduguard = True
                    if "Bpdu filter is enabled" in line:
                        self.bpdufilter = True
                    if "BPDU" in line:
                        self.bpdusent = re.compile("(?<=sent )\d+(?=,)").search(line).group()
                        self.bpdurcvd = re.compile("(?<=ved )\d+").search(line).group()

        elif "Ac" in self.port:
            print("\nAccess-Tunnel Interfaces Are not supported for STP states\n")
        else:
            sys.exit("\n Unsupported interface type, interface name is: {}\n".format(self.port))

class stp_vlan:

    def __init__(self, vlan, device):
        self.vlan = vlan 
        self.mode = None
        self.priority = None
        self.sysmac = None
        self.hello = None
        self.maxage = None
        self.fwddelay = None 
        self.isroot = False
        self.rootpriority = None
        self.tcncount = None
        self.tcnlastintf = None
        self.tcnlastdate = None
        self.hostname  = device

    def stp_vlan_detail(self,service):
        stp_vlan_cmd = "show spanning-tree vlan {} detail | se exec|exist".format(self.vlan)
        stp_vlan_op = radkit_cli.get_any_single_output(self.hostname,stp_vlan_cmd,service)
        for line in stp_vlan_op.splitlines():
            if "does not exist" in line:
                print ("\n WARNING: Spanning-Tree instance for VLAN {} is not runnig or does not exist, is there at least one port enabled and active for this VLAN?\n")
                break
            #STP Mode Definition
            if "executing" in line:
                self.mode = re.compile("(?<=the )[A-Za-z]+(?= compat)").search(line).group()
            #BID Priority and  MAC defintion
            if "Bridge" in line:
                self.priority = re.compile("(?<=rity )\d+(?=,)").search(line).group()
                self.sysmac = re.compile("(?<=address).*").search(line).group().strip()
            #STP Timers definition
            if "Configured" in line:
                self.hello = re.compile("(?<=time )\d+(?=,)").search(line).group()
                self.maxage = re.compile("(?<=age )\d+(?=,)").search(line).group()
                self.fwddelay = re.compile("(?<=delay )\d+(?=,)").search(line).group()
            #Root Status
            if "We are the root" in line:
                self.isroot = True
                self.rootpriority = self.priority
            if "Current root" in line:
                self.rootpriority = re.compile("(?<=rity )\d+(?=,)").search(line).group()
            if "Number" in line:
                self.tcncount = re.compile("(?<=changes )\d+").search(line).group()
                if self.tcncount != 0:
                    self.tcnlastdate = re.compile("(?<=rred).*(?=ago)").search(line).group().strip()
            if "from" in line:
                try:
                    self.tcnlastintf = re.compile("(?<=from ).*").search(line).group().strip()           
                except:
                    pass