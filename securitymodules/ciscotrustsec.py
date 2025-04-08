import radkit_cli
import re
import ipaddress
from ipverifications import inside_subnet
from ipverifications import ipsubnet_validator_no_return
from switchingmodules.interfaces_l2 import interface_switchport
from switchingmodules.interfaces import show_run_interface
from radkit_cli import logging_info,logging_error,logging_warning

def cts_ep_collection(cts_ep,step):
    hostname = cts_ep.hostname
    collection_summary = "IP: {}, VRF: {}, SGT: {}, Source: {}, GlobalEnforcement: {}".format(cts_ep.endpoint_ip,cts_ep.vrf,cts_ep.sgt,cts_ep.source,cts_ep.globalenforcement)
    string = "Result: Success"
    logging_info(step, "CTS", "[Endpoint]",hostname, collection_summary)
    logging_info(step, "CTS", "[Endpoint]",hostname, string)
def cts_rule_collection(cts_policy,step):
    hostname = cts_policy.hostname
    collection_summary = "SGT: {}, DGT: {}, IsDefaultRule: {}, RBACL: {}, HWPermit: {}, HWDeny: {}".format(cts_policy.srcsgt,cts_policy.dstsgt,cts_policy.isdefaultrule,cts_policy.rbacl,cts_policy.hw_permit_count,cts_policy.hw_denied_count)
    string = "Result: Success"
    logging_info(step, "CTS", "[Policy]",hostname, collection_summary)
    logging_info(step, "CTS", "[Policy]",hostname, string)

def cts_all_parser(output):
    #Binding Format = {'ip': x.x.x.x, 'sgt': x, 'source' : }
    bindings = []
    #Regex for IP: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
    #Regex for SGT between IP and Source: \s{3,}[0-9]\s{1,}(?=\s{1,})
    #Regex for IPv6 '/^(?>(?>([a-f0-9]{1,4})(?>:(?1)){7}|(?!(?:.*[a-f0-9](?>:|$)){8,})((?1)(?>:(?1)){0,6})?::(?2)?)|(?>(?>(?1)(?>:(?1)){5}:|(?!(?:.*[a-f0-9]:){6,})(?3)?::(?>((?1)(?>:(?1)){0,4}):)?)?(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?>\.(?4)){3}))$/iD'
    for i in output.splitlines():
        try:
            ip = re.compile("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").search(i).group().strip()
            #If:Subnet:
            try:
                if ip is not None:
                    maskregex = "[\/][0-9]+"
                    mask = re.compile(maskregex).search(i).group().strip()
                    ip=ip+mask
            except:
                pass
            sgtsource = re.compile("[0-9]+\s{3,}[a-zA-Z'-]+").search(i).group()
            sgtstring = list(set(sgtsource.split(" ")))
            sgtstring.remove('')
            sgtstring.sort()
            binding = {'ip': ip, 'sgt': sgtstring[0], 'source': sgtstring[1]}
            bindings.append(binding)
        except AttributeError:
            continue
    for i in output.splitlines():
        if ":" in i:
            ipstring = (i.split(" "))
            ipstring = list(filter(None, ipstring))
            binding = {'ip': ipstring[0], 'sgt': ipstring[1], 'source': ipstring[2]}
            bindings.append(binding)
    return bindings

def rbaclparser(aclop):
    aces=[]
    matches = ["#", "show", "ACEs:"]
    for line in aclop.splitlines():
        if not any(x  in line for x in matches):
            line = line.strip()
            if line != '':
                aces.append(line)
    return (aces)


def cts_inside_subnet(bind,ip):
    #Validate if Destinatip IP is inside a subnet rather than a host binding
    valid_mappings = []
    for i in bind:
        current_binding = (i['ip'])
        isipv4 = ipsubnet_validator_no_return(current_binding)
        if isipv4 is True:
            is_inside_subnet = inside_subnet(current_binding,ip)
            if is_inside_subnet is True:
                valid_mappings.append(current_binding)

    for i in range (len(valid_mappings)):
        if "/" not in (valid_mappings[i]):
            valid_mappings[i] = valid_mappings[i]+"/32"
    sorted_list = (sorted(valid_mappings, key=lambda x: ipaddress.ip_network(x)))
    try:
        prefix = sorted_list[-1]
        if "/32" in prefix:
            prefix = prefix.split("/32")
            prefix = prefix[0]
    except IndexError:
        prefix = None

    #Find the elected binding for this destination IP
    elected_binding = None
    for i in bind:
        if i['ip'] == prefix:
            elected_binding = i
    return elected_binding


def cts_interface_parser(output):
    for i in output['interfaces']:
        interface = i
    cts_path = output['interfaces'][interface]
    if cts_path['cts']['cts_status'] == 'disabled':
        cts_state = False
        sgt_classification = 'DYNAMIC'
        propagation = False
        trust = False
    else:
        cts_authpath = cts_path['authorization']
        cts_state = True
        sgt_classification = 'STATIC'
        propagation = cts_path['propagate_sgt']
        if propagation == 'Disabled':
            propagation = False
        else:
            propagation = True
        trust = cts_authpath['peer_sgt_assignment']
        if trust == 'Untrusted':
            trust = False
        else:
            trust = True
    return (cts_state, sgt_classification, propagation, trust)

class cts_endpoint_info():

    def __init__ (self, ip, vrf, device):
        self.hostname = device
        self.endpoint_ip = ip 
        self.vrf = vrf
    #Retrieval of CTS Information at CTS and CEF level

    def cts_sgt_mapping(self,service):

        #Identify if VRF is in use or not:
        if self.vrf == "default":
            vrf_mode = ""
            vrf = ''
        elif self.vrf is None:
            vrf_mode = ""
            vrf = ''
        else:
            vrf_mode = "vrf "+self.vrf+" "
        
        #CTS For /32 Hosts
        ctssgtmap_cmd = "show cts role-based sgt-map {} {}".format(vrf_mode, self.endpoint_ip)
        ctssgtmap_op = radkit_cli.get_single_output_genie(self.hostname, ctssgtmap_cmd, service)
        if ctssgtmap_op is not None:
            ctspath = ctssgtmap_op[self.endpoint_ip]
            self.sgt = ctspath['sgt']
            self.source = ctspath['source']
        else:
            #RAW CTS Processing:
            ctssgtmap_cmd = "show cts role-based sgt-map {} all".format(vrf_mode)
            ctssgtmap_op = radkit_cli.get_any_single_output(self.hostname, ctssgtmap_cmd, service)
            if ctssgtmap_op is None:
                print ("No SGTs found for any Endpoint in device: {} for vrf {}".format(self.hostname, vrf_mode))
            else:
                bindings = cts_all_parser(ctssgtmap_op)
                elected_binding = cts_inside_subnet(bindings,self.endpoint_ip)
                if elected_binding is None:
                    self.sgt = 0
                    self.source = None
                else:
                    self.sgt = elected_binding['sgt']
                    self.source = elected_binding['source']
        
        #CEF SGT Perspective (manual parsing)
        cefinternal_cmd = "show ip cef {} {} internal | i SGT".format(vrf_mode, self.endpoint_ip)
        cefinternal_op = radkit_cli.get_any_single_output(self.hostname, cefinternal_cmd, service)
        self.cefsgt = 0
        for line in cefinternal_op.splitlines():
            if "RBAC" in line:
                self.cefsgt = re.compile("(?<=SGT).*(?=S)").search(line).group().strip()

    def cts_class_method(self,interface, binding, service):
        #Binding format must be:     #Binding Format = {'ip': x.x.x.x, 'sgt': x, 'source' : }
        if binding['source'] == 'LOCAL':
            #Parser for LOCAL mode (CTS Manual or RADIUS)
            ctssgtmap_cmd = "show cts interface {}".format(interface)
            ctssgtmap_op = radkit_cli.get_single_output_genie(self.hostname, ctssgtmap_cmd, service)
            cts_interface_states = cts_interface_parser(ctssgtmap_op)
            self.ctsintf_state = cts_interface_states[0]
            self.sgt_classificaiton = cts_interface_states[1]
            self.propagation = cts_interface_states[2]
            self.trust = cts_interface_states[3]

    def cts_enforcement(self, vlan, interface, service):
        if vlan is None:
            vlan_flag = False
        else:
            vlan_flag = True
        
        #Interfaces are CTS enabled by Default:
        self.ctsportenabled = True
        #Unless CTS is removed with "no cts role-based enforcement"
        pattern = "no cts role-based enforcement"
        cts_interface_enforcement = show_run_interface(interface,pattern,self.hostname, service)
        for i in cts_interface_enforcement:
            if "pattern" in i:
                self.ctsportenabled = False 
        #Global Enforcement Enablement

        ctsenforcementcmd = "show cts"
        ctsenforcementop = radkit_cli.get_single_output_genie(self.hostname, ctsenforcementcmd,service)

        globalenforcement = ctsenforcementop['ip_sgt_bindings']['cts_role_based_enforcement']
        vlanenforcement = ctsenforcementop['ip_sgt_bindings']['cts_role_based_vlan_enforcement']

        if globalenforcement == 'Enabled':
            self.globalenforcement = True
        else:
            self.globalenforcement = False
        if vlanenforcement == 'Enabled':
            self.vlanenforcement = True
            if vlan_flag is True:
                #Validate if the required VLAN is on the enforcement list
                ctsvlanlistcmd = "show running-config | i cts role-based enforcement vlan"
                ctsvlanlistop = radkit_cli.get_any_single_output(self.hostname, ctsvlanlistcmd,service)    
                matches = ['#', ""]    
                for i in ctsvlanlistop.splitlines():
                    if not any(x in i for x in matches):
                        vlan_list = i.split('vlan-list')[1]
                        vlans_to_check = vlan
                        allowed_vlans = set()
                        parts = vlan_list.split(',')
                        for part in parts:
                            if '-' in part:
                                start, end = map(int, part.split('-'))
                                allowed_vlans.update(range(start, end + 1))
                            else:
                                allowed_vlans.add(int(part))
                        self.enforcingvlan = False
                        for i in allowed_vlans:
                            if vlans_to_check == i:
                                self.enforcingvlan = True        
        else:
            self.vlanenforcement = False

class cts_rules():
    
    def __init__(self, device):
        self.hostname = device
    
    def cts_rbac_permissions(self, sgt, dgt, service):
        
        ctsrbacperm_cmd = "show cts role-based permissions from {} to {}".format(sgt,dgt)
        ctsrbacperm_op = radkit_cli.get_single_output_genie(self.hostname, ctsrbacperm_cmd, service)

        if ctsrbacperm_op is not None:
            ctsrbacpath = ctsrbacperm_op['indexes']
            matches = ["#"]
            for i in ctsrbacpath:
                if type(i) == int:
                    index = i
                    self.srcsgt = ctsrbacpath[index]['src_grp_id']
                    self.dstsgt = ctsrbacpath[index]['dst_group_id']
                    self.sgtname = ctsrbacpath[index]['src_grp_name']
                    self.dgtname = ctsrbacpath[index]['dst_group_name']
                    rbacls = ctsrbacpath[index]['policy_groups']
                    self.isdefaultrule = False
                    for j in rbacls:
                        if not any (x in j for x in matches):
                            try:
                                rbacl = re.compile(".*(?=-[0-9]+)").search(j).group().strip()
                            except:
                                pass
                    self.rbacl = rbacl
        else:
            ctsrbacperm_cmd = "show cts role-based permissions default"
            ctsrbacperm_op = radkit_cli.get_single_output_genie(self.hostname, ctsrbacperm_cmd, service)
            ctsrbacpath = ctsrbacperm_op['indexes']
            for i in ctsrbacpath:
                if type(i) == int:
                    index = i
                    self.srcsgt = sgt
                    self.dstsgt = dgt
                    self.isdefaultrule = True
                    try:
                        self.rbacl = ctsrbacpath[index]['action_policy']+" IP"
                    except:
                        matches = ["#"]
                        rbacls = ctsrbacpath[index]['policy_groups']
                        for j in rbacls:
                            if not any(x in j for x in matches):
                                try:
                                    rbacl = re.compile(".*(?=-[0-9]+)").search(j).group().strip()
                                except:
                                    rbacl = None
                        self.rbacl = rbacl

    def cts_rbac_rbacls(self, rbacl, service):
        rbaclcmd = "show cts rbacl \"{}\" | se ACEs".format(rbacl)
        rbaclop = radkit_cli.get_any_single_output(self.hostname, rbaclcmd,service)
        aces = rbaclparser(rbaclop)
        self.aces = aces
    
    def cts_rbac_counters(self,sgt,dgt,service):
        ctsrbaccounter_cmd = "show cts role-based counters from {} to {}".format(sgt,dgt)
        ctsrbaccounter_op = radkit_cli.get_single_output_genie(self.hostname, ctsrbaccounter_cmd, service)

        if ctsrbaccounter_op is not None:
           ctscount_path = ctsrbaccounter_op['cts_rb_count']
           for i in ctscount_path:
                self.sw_denied_count = ctscount_path[i]['sw_denied_count']
                self.hw_denied_count = ctscount_path[i]['hw_denied_count']
                self.sw_permit_count = ctscount_path[i]['sw_permit_count']
                self.hw_permit_count = ctscount_path[i]['hw_permit_count']
                self.sw_monitor_count = ctscount_path[i]['sw_monitor_count']
                self.hw_monitor_count = ctscount_path[i]['hw_monitor_count']
        else:
            ctsrbaccounter_cmd = "show cts role-based counters default".format()
            ctsrbaccounter_op = radkit_cli.get_single_output_genie(self.hostname, ctsrbaccounter_cmd, service)
            ctscount_path = ctsrbaccounter_op['cts_rb_count']
            for i in ctscount_path:
                self.sw_denied_count = ctscount_path[i]['sw_denied_count']
                self.hw_denied_count = ctscount_path[i]['hw_denied_count']
                self.sw_permit_count = ctscount_path[i]['sw_permit_count']
                self.hw_permit_count = ctscount_path[i]['hw_permit_count']
                self.sw_monitor_count = ctscount_path[i]['sw_monitor_count']
                self.hw_monitor_count = ctscount_path[i]['hw_monitor_count']
 
