import radkit_cli

#Platform Independent = IOS 
def show_run_interface(interface, pattern, device, service):
        intf_cmd = "show running-config interface {} | i {}".format(interface,pattern)
        intf_op = radkit_cli.get_any_single_output(device,intf_cmd,service)
        matches = ['#', 'show']

        #Parsed without #show line
        parsedstring = ''
        for i in intf_op.splitlines():
            if not any(x in i for x in matches):
                parsedstring = parsedstring+"\n"+i
        
        return parsedstring

class Interfaces:

    def __init__(self, interface, device):
        self.hostname = device
        self.interface = interface 

    def show_interface(self, service):
        intf_cmd = "show interface {}".format(self.interface)
        intf_op = radkit_cli.get_single_output_genie(self.hostname,intf_cmd,service)
        interface = None
        for i in intf_op:
            if "exclude" in i:
                continue
            else:
                interface = i
        interface_path = intf_op[interface]
        self.linestate = interface_path['line_protocol']
        self.operstate = interface_path['oper_status']
        self.encapsulations = interface_path['encapsulations']
        self.bw = interface_path['bandwidth']
        self.delay = interface_path['delay']
        try:
            self.connected = interface_path['connected']
        except KeyError:
            pass
        try:
            self.errdisabled = interface_path['err_disabled']
        except KeyError:
            pass
        try:
            self.intfmac = interface_path['mac_address']
        except KeyError:
            pass
        try:
            self.description = interface_path['description']
        except KeyError:
            pass
        self.mtu = interface_path['mtu']
        self.txload = interface_path['txload']
        self.rxload = interface_path['rxload']
        try:
            self.speed = interface_path['port_speed']
        except KeyError:
            pass
        #IP and Subnet Information (if any)
        ip = None
        try:
            self.intfsubnet = interface_path['ipv4']
            ips = []
            for i in self.intfsubnet:
                subnet = i
                ip = self.intfsubnet[subnet][ip]
                ips.append(ip)
            self.intfips = ips
        except KeyError:
            pass
        #Queues
        try:
            interface_queues_path = intf_op[interface]['queues']
            self.iqdrops = interface_queues_path['input_queue_drops']
            self.outputdrops = interface_queues_path['total_output_drop']
        except KeyError:
            pass
        #Counters
        try:
            interface_counters_path = intf_op[interface]['counters']
            self.crcerrors = interface_counters_path['in_crc_errors']
            self.giants = interface_counters_path['in_giants']
            self.runts = interface_counters_path['in_runts']
            self.inputpps = interface_counters_path['rate']['in_rate_pkts']
            self.outputpps = interface_counters_path['rate']['out_rate_pkts']
        except KeyError:
            pass

    def show_interface_counters(self,service):
        intfc_cmd = "show interface {} counter".format(self.interface)
        intfc_op = radkit_cli.get_single_output_genie(self.hostname, intfc_cmd, service)
        if intfc_op is not None:
            intfcounterpath = intfc_op['interface'][self.interface]
            self.inoctets = intfcounterpath['in']['octets']
            self.inunicastpackets = intfcounterpath['in']['ucast_pkts']
            self.inmulticastpackets = intfcounterpath['in']['mcast_pkts']
            self.inbroadcastpackets = intfcounterpath['in']['bcast_pkts']
            self.outoctets = intfcounterpath['out']['octets']
            self.outunicastpackets = intfcounterpath['out']['ucast_pkts']
            self.outmulticastpackets = intfcounterpath['out']['mcast_pkts']
            self.outbroadcastpackets = intfcounterpath['out']['bcast_pkts']

    def show_controllers_ethernet_controllers(self,service):
        ethcon_cmd = "show controllers ethernet-controller {}".format(self.interface)
        ethcon_op = radkit_cli.get_single_output_genie(self.hostname,ethcon_cmd,service)
        if ethcon_op is not None:
            ethpath = ethcon_op['interface']
            for interface in ethpath:
                interfacename = interface
            new_path = ethpath[interfacename]
            self.ethcontrollers_info = new_path
        else:
            self.ethcontrollers_info = None