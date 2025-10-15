from radkit_cli import get_any_single_output, get_single_output_genie
import re

#Parsers in this file:
#Enablement of service dhcp*
#DHCP Snooping configuration*
#DHCP Relay configuration*
#DHCP Helper Address configuration*
#DHCP Trust Interfaces*
#DHCP Snooping Rate Limiter interfaces*
#Current IP DHCP Snooping Binding*
#DHCP Snooping Stats*
#DHCP Snooping MAC ACL*

def expand_vlans(vlan_str):
    """Expand comma-separated VLANs with ranges into a list of integers."""
    vlans = []
    for part in vlan_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            vlans.extend(range(int(start), int(end)+1))
        elif part:
            vlans.append(int(part))
    return vlans

def dhcpsnoopingparser(show_output):

    # Parse global and gleaning enabled states
    dhcpsnoop_global_enabled = "Switch DHCP snooping is enabled" in show_output
    dhcpsnoop_gleaning_enabled = "Switch DHCP gleaning is enabled" in show_output

    # Use regex to match relevant lines, ignoring leading spaces
    conf_vlans = re.search(r"DHCP snooping is configured on following VLANs:\s*\n([0-9,\- ]+)", show_output)
    oper_vlans = re.search(r"DHCP snooping is operational on following VLANs:\s*\n([0-9,\- ]+)", show_output)
    conf_proxy_vlans = re.search(r"Proxy bridge is configured on following VLANs:\s*\n([0-9,\- ]+)", show_output)
    oper_proxy_vlans = re.search(r"Proxy bridge is operational on following VLANs:\s*\n([0-9,\- ]+)", show_output)

    dhcpsnoop_configured_vlans = expand_vlans(conf_vlans.group(1)) if conf_vlans else []
    dhcpsnoop_operational_vlans = expand_vlans(oper_vlans.group(1)) if oper_vlans else []
    dhcpsnoop_configured_vlans_proxy = expand_vlans(conf_proxy_vlans.group(1)) if conf_proxy_vlans else []
    dhcpsnoop_operational_vlans_proxy = expand_vlans(oper_proxy_vlans.group(1)) if oper_proxy_vlans else []

    option82_insertion = 'Insertion of option 82 is enabled' in show_output
    circuitid_match = re.search(r"circuit-id default format:\s*([^\n]+)", show_output)
    circuitid_format = circuitid_match.group(1).strip() if circuitid_match else None
    remote_id_match = re.search(r"remote-id:\s*([^\n]+)", show_output)
    remote_id = remote_id_match.group(1).strip() if remote_id_match else None
    hwaddr_verification = 'Verification of hwaddr field is enabled' in show_output
    option82_untrusted_port = 'Option 82 on untrusted port is not allowed' not in show_output
    giaddr_verification = 'Verification of giaddr field is enabled' in show_output

    # Find trust interfaces
    trust_interfaces = []
    lines = show_output.splitlines()

    # Find all header line indices; we'll use the last one
    header_regex = re.compile(r"^Interface\s+Trusted", re.IGNORECASE)
    header_indices = [i for i, line in enumerate(lines) if header_regex.match(line.strip())]

    if header_indices:
        start_idx = header_indices[-1] + 2  # Skip header and separator
        for line in lines[start_idx:]:
            stripped = line.strip()
            # Stop at next section, prompt, or custom
            if (not stripped or
                stripped.startswith("Custom") or
                re.match(r".*[\#\>]\s*$", stripped)):
                break
            parts = stripped.split()
            if len(parts) >= 2 and parts[1].lower() == "yes":
                trust_interfaces.append(parts[0])

    dhcp_snoop_summary = {
        "dhcpsnoop_global_enabled": dhcpsnoop_global_enabled,
        "dhcpsnoop_gleaning_enabled": dhcpsnoop_gleaning_enabled,
        "dhcpsnoop_configured_vlans": dhcpsnoop_configured_vlans,
        "dhcpsnoop_operational_vlans": dhcpsnoop_operational_vlans,
        "dhcpsnoop_configured_vlans_proxy": dhcpsnoop_configured_vlans_proxy,
        "dhcpsnoop_operational_vlans_proxy": dhcpsnoop_operational_vlans_proxy,
        "option82_insertion": option82_insertion,
        "circuitid_format": circuitid_format,
        "remote_id": remote_id,
        "hwaddr_verification": hwaddr_verification,
        "option82_untrusted_port": option82_untrusted_port,
        "giaddr_verification": giaddr_verification,
        "trust_interfaces": trust_interfaces
    }

    return dhcp_snoop_summary

class DHCPDevice:
    def __init__(self,device):
        self.device = device

    def service_dhcp(self,service):
        # Enablement of service dhcp, service dhcp is enabled by default, if disabled, servicedhcp attr is set to False
        device = self.device
        servicedhcpcmd = "show run | i service dhcp"
        servicedhcpop = get_any_single_output(device,servicedhcpcmd,service)
        self.servicedhcp = True
        if servicedhcpop is None:
            return None
        else:
            for line in servicedhcpop.splitlines():
                if "no service dhcp" in line:
                    self.servicedhcp = False

    def dhcpsnooping(self,service):
        # DHCP Snooping configuration
        # DHCP Trust Interfaces
        device = self.device
        dhcpsnoopingcmd = "show ip dhcp snooping"
        dhcpsnoopingop = get_any_single_output(device,dhcpsnoopingcmd,service)
        if dhcpsnoopingop is None:
            self.dhcpsnoop_global_enabled = None
            self.dhcpsnoop_gleaning_enabled = None
            self.dhcpsnoop_configured_vlans = None
            self.dhcpsnoop_operational_vlans = None
            self.dhcpsnoop_configured_vlans_proxy = None
            self.dhcpsnoop_operational_vlans_proxy = None
            self.option82_insertion = None
            self.circuitid_format = None
            self.remote_id = None
            self.hwaddr_verification = None
            self.option82_untrusted_port = None
            self.giaddr_verification = None
            self.trust_interfaces = None
        else:
            dhcp_snooping_summary = dhcpsnoopingparser(dhcpsnoopingop)
            self.dhcpsnoop_global_enabled = dhcp_snooping_summary['dhcpsnoop_global_enabled']
            self.dhcpsnoop_gleaning_enabled = dhcp_snooping_summary['dhcpsnoop_gleaning_enabled']
            self.dhcpsnoop_configured_vlans = dhcp_snooping_summary['dhcpsnoop_configured_vlans']
            self.dhcpsnoop_operational_vlans = dhcp_snooping_summary['dhcpsnoop_operational_vlans']
            self.dhcpsnoop_configured_vlans_proxy = dhcp_snooping_summary['dhcpsnoop_configured_vlans_proxy']
            self.dhcpsnoop_operational_vlans_proxy = dhcp_snooping_summary['dhcpsnoop_operational_vlans_proxy']
            self.option82_insertion = dhcp_snooping_summary['option82_insertion']
            self.circuitid_format = dhcp_snooping_summary['circuitid_format']
            self.remote_id = dhcp_snooping_summary['remote_id']
            self.hwaddr_verification = dhcp_snooping_summary['hwaddr_verification']
            self.option82_untrusted_port = dhcp_snooping_summary['option82_untrusted_port']
            self.giaddr_verification = dhcp_snooping_summary['giaddr_verification']
            self.trust_interfaces = dhcp_snooping_summary['trust_interfaces']

    def dhcpsnoopingacl(self,service):
        # DHCP Snooping ACL Configuration
        device = self.device
        dhcpsnoopingaclcmd = "show run | i ip dhcp snooping acl"
        dhcpsnoopingaclop = get_any_single_output(device,dhcpsnoopingaclcmd,service)
        self.dhcpsnoopacl = None
        if dhcpsnoopingaclop is not None:
            match = re.search(r"ip dhcp snooping acl (\S+)", dhcpsnoopingaclop)
            acl_name = match.group(1) if match else None
            self.dhcpsnoopacl = acl_name

    def dhcpsnoopingstats(self,service):
        # DHCP Snooping Stats
        device = self.device
        dhcpsnoopingstatscmd = "show ip dhcp snooping statistics detail"
        dhcpsnoopingstatsop = get_single_output_genie(device,dhcpsnoopingstatscmd,service)
        if dhcpsnoopingstatsop is None:
            self.dhcp_snooping_packets = None
            self.packets_dropped_because = None
        else:
            self.dhcp_snooping_packets = dhcpsnoopingstatsop['dhcp_snooping_packets']
            self.packets_dropped_because = dhcpsnoopingstatsop['packets_dropped_because']

    def dhcpsnoopingbindings(self,vlan,service):
        # Current IP DHCP Snooping Binding
        device = self.device
        dhcpsnoopbindcmd = "show ip dhcp snooping binding vlan {}".format(vlan)
        dhcpsnoopbindop = get_single_output_genie(device,dhcpsnoopbindcmd,service)
        interfaces = []
        self.bindings = []
        if dhcpsnoopbindop is not None:
            try:
                interfaces = dhcpsnoopbindop['interfaces']
                self.bindings = interfaces
            except:
                self.bindings = []

    def dhcprelayconfiguration(self,service):
        #DHCP Relay Configuration, if VPN option is enabled, it will be set to True
        device = self.device
        dhcprelayglobalcmd = "show run | i dhcp relay"
        dhcprelayglobalop = get_any_single_output(device,dhcprelayglobalcmd,service)
        self.dhcprelayinformationoption = False
        self.dhcprelayinformationoptionvpn = False
        self.dhcprelayinformationtrustall = False
        if dhcprelayglobalop is not None:
            global_cmds = []
            per_interface_cmds = []
            matches = ['#', 'show']
            for line in dhcprelayglobalop.splitlines():
                if not any(x in line for x in matches):
                    stripped = line.rstrip()
                    if not stripped:
                        continue
                    if stripped.startswith(" "):  # Per-interface if indented
                        per_interface_cmds.append(stripped.strip())
                    else:
                        global_cmds.append(stripped.strip())

            dhcp_relay_commands = {
                "global": global_cmds,
                "per_interface": per_interface_cmds
            }
            for global_cmd in dhcp_relay_commands['global']:
                if "information option vpn" in global_cmd:
                    self.dhcprelayinformationoptionvpn = True
                if global_cmd == "ip dhcp relay information option":
                    self.dhcprelayinformationoption = True
                if "trust-all" in global_cmd:
                    self.dhcprelayinformationtrustall = True

    def svi_configuration(self,vlan,service):
        #DHCP Relay Configuration, if VPN option is enabled, it will be set to True
        #SVI values. State, Oper State, IP/MASK (Primary), Helper Addresses, ip_route_cache flags, vrf, ACLs
        device = self.device
        helperaddresscmd  = "show ip interface vlan {}".format(vlan)
        helperaddressop = get_single_output_genie(device,helperaddresscmd,service)
        self.svi = None
        self.svienabled = False
        self.svioperational = 'down'
        self.prefix = None
        self.vrf = None
        self.mask = None
        self.helper_address = None
        self.cef_state = False
        self.inboundacl = None
        self.outboundacl = None
        if helperaddressop is not None:
            sviname = None
            for interface in helperaddressop:
                if "Vlan" in interface:
                    sviname = interface
            self.svi = sviname
            self.svienabled = helperaddressop[sviname]['enabled']
            self.svioperational = helperaddressop[sviname]['oper_status']
            try:
                ips = helperaddressop[sviname]['ipv4']
                try:
                    self.svivrf = helperaddressop[sviname]['vrf']
                except KeyError:
                    self.svivrf = 'default'
                try:
                    self.helper_address = helperaddressop[sviname]['helper_address']
                except KeyError:
                    self.helper_address = []
                route_cache_flags = helperaddressop[sviname]['ip_route_cache_flags']
                for i in route_cache_flags:
                    if 'CEF' in i:
                        self.cef_state = True
                for ip in ips:
                    ip_details = ips[ip]
                    try:
                        if ip_details['secondary'] is False:
                            self.prefix = ip_details['ip']
                            self.mask = ip_details['prefix_length']
                    except KeyError:
                        pass
            except KeyError:
                pass
            # Inbound ACL
            try:
                self.inboundacl = helperaddressop[sviname]['inbound_access_list']
            except KeyError:
                self.inboundacl = None
            # Outbound ACL
            try:
                self.outboundacl = helperaddressop[sviname]['inbound_access_list']
            except KeyError:
                self.outboundacl = None

    def svi_running_config(self,vlan,service):
        device = self.device
        svishworuncmd  = "show run interface vlan {}".format(vlan)
        svishworunop = get_any_single_output(device,svishworuncmd,service)

        self.ip_dhcp_commands = []
        self.vrf = "default"
        self.helper_addresses = []
        self.lisp_mobility_entries = []
        if svishworunop is not None:
            for line in svishworunop.splitlines():
                stripped = line.strip()
                # VRF
                m_vrf = re.match(r"vrf forwarding (\S+)", stripped)
                if m_vrf:
                    vrf = m_vrf.group(1)
                # ip dhcp
                if stripped.startswith("ip dhcp"):
                    self.ip_dhcp_commands.append(stripped)
                # ip helper-address
                m_helper = re.match(r"ip helper-address(?: vrf (\S+))? (\d+\.\d+\.\d+\.\d+)", stripped)
                if m_helper:
                    helper_vrf = m_helper.group(1) if m_helper.group(1) else vrf
                    helper_ip = m_helper.group(2)
                    self.helper_addresses.append({"dhcpserverip": helper_ip, "vrf": helper_vrf})
                # lisp mobility
                m_lisp = re.match(r"lisp mobility (.+)", stripped)
                if m_lisp:
                    self.lisp_mobility_entries.append(m_lisp.group(1))

            self.ip_dhcp_commands
            self.vrf
            self.helper_addresses
            self.lisp_mobility_entries

