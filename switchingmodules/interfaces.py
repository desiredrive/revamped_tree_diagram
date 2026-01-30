import radkit_cli

#Platform Independent = IOS 
def show_run_interface(interface, pattern, device, service):
    intf_cmd = f"show running-config interface {interface} | i {pattern}"
    intf_op = radkit_cli.get_any_single_output(device, intf_cmd, service)

    # 1. Guard Clause: If command failed or device is unreachable, return empty string
    if intf_op is None:
        return ""

    # 2. Filter out command echo and prompt lines
    # We use a list comprehension for better performance
    exclude_markers = ['#', 'show']

    filtered_lines = [
        line for line in intf_op.splitlines()
        if not any(marker in line for marker in exclude_markers)
    ]

    # 3. Join the lines back into a single string
    return "\n".join(filtered_lines).strip()


class Interfaces:
    def __init__(self, interface, device):
        self.hostname = device
        self.interface = interface
        # Initialize attributes with defaults to prevent AttributeError elsewhere
        self.linestate = None
        self.operstate = None
        self.encapsulations = None
        self.bw = None
        self.delay = None
        self.connected = None
        self.errdisabled = None
        self.intfmac = None
        self.description = None
        self.mtu = None
        self.txload = None
        self.rxload = None
        self.speed = None
        self.intfsubnet = {}
        self.intfips = []
        self.iqdrops = 0
        self.outputdrops = 0
        self.crcerrors = 0
        self.giants = 0
        self.runts = 0
        self.inputpps = 0
        self.outputpps = 0

    def show_interface(self, service):
        intf_cmd = f"show interface {self.interface}"
        # Safely get the dictionary from Genie
        intf_op = radkit_cli.get_single_output_genie(self.hostname, intf_cmd, service)

        # 1. Guard clause: if Genie returned None, exit early
        if not intf_op:
            return

        # 2. Identify the correct interface key in the returned dictionary
        # Genie returns a dict where the key is the interface name (e.g., {"TenGigabitEthernet1/0/5": {...}})
        interface_key = None
        for key in intf_op:
            if "exclude" not in key.lower() and key != "info":
                interface_key = key
                break

        if not interface_key:
            return

        interface_path = intf_op[interface_key]

        # 3. Extract basic info using .get() for safety
        self.linestate = interface_path.get('line_protocol')
        self.operstate = interface_path.get('oper_status')
        self.encapsulations = interface_path.get('encapsulations')
        self.bw = interface_path.get('bandwidth')
        self.delay = interface_path.get('delay')
        self.connected = interface_path.get('connected')
        self.errdisabled = interface_path.get('err_disabled')
        self.intfmac = interface_path.get('mac_address')
        self.description = interface_path.get('description')
        self.mtu = interface_path.get('mtu')
        self.txload = interface_path.get('txload')
        self.rxload = interface_path.get('rxload')
        self.speed = interface_path.get('port_speed')

        # 4. IP and Subnet Information
        ipv4_data = interface_path.get('ipv4', {})
        self.intfsubnet = ipv4_data
        if ipv4_data:
            # Extract IPs from the nested subnets
            self.intfips = [details.get('ip') for subnet, details in ipv4_data.items() if 'ip' in details]

        # 5. Queues and Counters
        queues = interface_path.get('queues', {})
        self.iiqdrops = queues.get('input_queue_drops', 0)
        self.outputdrops = queues.get('total_output_drop', 0)

        counters = interface_path.get('counters', {})
        self.crcerrors = counters.get('in_crc_errors', 0)
        self.giants = counters.get('in_giants', 0)
        self.runts = counters.get('in_runts', 0)

        # Rate counters
        rate = counters.get('rate', {})
        self.inputpps = rate.get('in_rate_pkts', 0)
        self.outputpps = rate.get('out_rate_pkts', 0)

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