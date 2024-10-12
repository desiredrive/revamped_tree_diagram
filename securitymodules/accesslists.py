import radkit_cli
import re
class AccessList:
    def __init__(self,device):
        self.hostname = device
        self.aclname = None
        self.acltype = None
        self.aclaftype = None
        self.aces = None
    def aclbyidname(self,aclname,service):
        aclid_cmd ="show access-lists {}".format(aclname)
        aclid_op = radkit_cli.get_single_output_genie(self.hostname,aclid_cmd,service)
        if aclid_op is not None:
            for acl in aclid_op:
                if '_exclude' not in acl:
                    aclname = acl
            self.aclname = aclname
            self.acltype = aclid_op[aclname]['acl_type']
            self.aclaftype = aclid_op[aclname]['type']
            aclpath = aclid_op[aclname]['aces']
            aces = []
            source_network = None
            destination_network = None
            operator_type = None
            for index in aclpath:
                protomatches = ['udp', 'tcp']
                ace_sourcenetwork = aclpath[index]['matches']['l3']['ipv4']['source_network']

                for network in ace_sourcenetwork:
                    source_network = network
                ace_source = aclpath[index]['matches']['l3']['ipv4']['source_network'][source_network]['source_network']
                ace_protocol = aclpath[index]['matches']['l3']['ipv4']['protocol']
                ace_type = aclpath[index]['actions']['forwarding']
                # Source ACEs
                try:
                    ace_srcoperator = aclpath[index]['matches']['l4'][ace_protocol]['source_port']
                    for operator in ace_srcoperator:
                        operator_type = operator
                    ace_srcports = aclpath[index]['matches']['l4'][ace_protocol]['source_port'][operator_type]
                    ace_srcoperator_type = operator_type
                    if operator_type == 'operator':
                        ace_srcoperator_type = ace_srcports['operator']
                        ace_srcports = ace_srcports['port']
                except KeyError:
                    ace_srcoperator_type = None
                    ace_srcports = "Any"
                # Destination ACEs (Extended Only)
                try:
                    ace_destination = aclpath[index]['matches']['l3']['ipv4']['destination_network']
                    for network in ace_destination:
                        destination_network = network
                    ace_destination = \
                    aclpath[index]['matches']['l3']['ipv4']['destination_network'][destination_network][
                        'destination_network']
                    if any(x in ace_protocol for x in protomatches):
                        ace_dstoperator = aclpath[index]['matches']['l4'][ace_protocol]['destination_port']
                        for operator in ace_dstoperator:
                            operator_type = operator
                        ace_dstports = aclpath[index]['matches']['l4'][ace_protocol]['destination_port'][operator_type]
                        ace_dstoperator_type = operator_type
                        if operator_type == 'operator':
                            ace_dstoperator_type = ace_dstports['operator']
                            ace_dstports = ace_dstports['port']
                    else:
                        ace_dstoperator_type = None
                        ace_dstports = "Any"
                except KeyError:
                    ace_destination = None
                    ace_dstoperator_type = None
                    ace_dstports = "Any"
                ace = {
                    'index': index,
                    'forwarding': ace_type,
                    'ace_source': ace_source,
                    'ace_destination': ace_destination,
                    'ace_srcoperator_type': ace_srcoperator_type,
                    'ace_srcports': ace_srcports,
                    'ace_dstoperator_type': ace_dstoperator_type,
                    'ace_dstports': ace_dstports
                }
                aces.append(ace)
            aces = aces
            self.aces = aces

    def aclbyinterface(self,interface,service):
        hostname = self.hostname

        aclsbyintf_cmd= "show ip access-list interface {}".format(interface)
        aclsbyintf_op = radkit_cli.get_any_single_output(hostname,aclsbyintf_cmd,service)

        if aclsbyintf_op is not None:
            aclnames = []
            for line in aclsbyintf_op.splitlines():
                if "IP access" in line:
                    regex = "(?<=access list ).*"
                    aclname = re.compile(regex).search(line).group()
                    aclnames.append(aclname)
            aclnames = list(set(aclnames))
            self.aclnames = aclnames
