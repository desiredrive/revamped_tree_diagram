import radkit_cli

class CDPinfo:
    def __init__(self,device):
        self.hostname = device

    def cdpneighborinterface(self,interface,service):
        #CDP neighbor output for a single interface (physical).
        hostname = self.hostname
        cdpintf_cmd = "show cdp neighbors {} detail".format(interface)
        cdpintf_op = radkit_cli.get_single_output_genie(hostname,cdpintf_cmd,service)

        if cdpintf_op is not None:
            cdpneighbors = []
            for i in cdpintf_op['index']:
                device_id = cdpintf_op['index'][i]['device_id']
                management_addresses = cdpintf_op['index'][i]['management_addresses']
                platform = cdpintf_op['index'][i]['platform']
                localinterface = cdpintf_op['index'][i]['local_interface']
                remoteinterface = cdpintf_op['index'][i]['port_id']
                capabilities = cdpintf_op['index'][i]['capabilities']
                cdpneighborinfo = {
                    'device_id': device_id,
                    'management_addresses': management_addresses,
                    'platform': platform,
                    'localinterface': localinterface,
                    'remoteinterface': remoteinterface,
                    'capabilities' : capabilities
                }
                cdpneighbors.append(cdpneighborinfo)
            self.cdpneighbors = cdpneighbors
        else:
            self.cdpneighbors = []
        self.numberofneighbors = len(self.cdpneighbors)