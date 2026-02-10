import re
import radkit_cli

class etherchannel_parse():

    def __init__(self, intf, device):
         self.hostname = device
         self.portchannel = intf
    
    def get_active_interfaces(self, service):
        #Returns physical interfaces ONLY in UP state
        ponumb = re.compile( "\d+" ).search(self.portchannel).group().strip()

        #L2 Definition:
        po_cmd = "show etherchannel {} port | i Port:".format(ponumb)
        po_op = radkit_cli.get_single_output_genie(self.hostname, po_cmd, service)
        port_channel_path = po_op['port_channel']
        for i in port_channel_path:
            ponumber = i
        port_channel_path = port_channel_path[ponumber]

        self.protocol = port_channel_path['protocol']
        port_list = []
        ports_path = port_channel_path['ports']
        for i in ports_path:
             port = i
             port_state = ports_path[i]['ec_state']
             if port_state == 'Active':
                  port_list.append(port)
        
        self.port_list = port_list


    def get_active_etherchannel_ports(self,service):
        """
        Parses 'show etherchannel <id> port' and returns a list of ports
        that are currently 'In-Bndl' (Active).
        """
        active_ports = []

        # Split the output into individual blocks starting with "Port: "
        # This ensures we process each port's data independently
        ponumb = re.compile("\d+").search(self.portchannel).group().strip()
        po_cmd = "show etherchannel {} port".format(ponumb)
        po_op = radkit_cli.get_any_single_output(self.hostname, po_cmd, service)
        port_blocks = re.split(r'Port:\s+', po_op)
        if not po_op or not isinstance(po_op, str):
            self.port_list = active_ports
            return
        for block in port_blocks:
            if not block.strip():
                continue

            # 1. Extract the Port Name (e.g., Twe1/0/3)
            # It's always at the very beginning of the block
            lines = block.splitlines()
            port_name = lines[0].strip()

            # 2. Check for the "In-Bndl" status in the "Port state" line
            # We look for the line starting with "Port state"
            is_active = False
            for line in lines:
                if "Port state" in line:
                    # 'In-Bndl' indicates the port is active in the etherchannel
                    if "In-Bndl" in line:
                        is_active = True
                    break  # Found the state line, no need to check further lines in this block

            if is_active:
                active_ports.append(port_name)

        self.port_list = active_ports