import re
import radkit_cli

class etherchannel_parse():

    def __init__(self, intf, device):
         self.hostname = device
         self.portchhannel = intf
    
    def get_active_interfaces(self, service):
        #Returns physical interfaces ONLY in UP state
        ponumb = re.compile( "\d+" ).search(self.portchhannel).group().strip()

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
