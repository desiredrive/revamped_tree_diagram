from radkit_cli import get_any_single_output, get_single_output_genie, logging_info, logging_warning
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any

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

def generate_ios_pipe(clock_dict):
    # 1. Reconstruct the date string from the dictionary
    # Format: 2026 Jan 14 00:55:21.907
    date_str = f"{clock_dict['year']} {clock_dict['month']} {clock_dict['day']} {clock_dict['time']}"

    # 2. Convert to a datetime object
    # %b parses the short month name (Jan, Feb, etc.)
    now = datetime.strptime(date_str, "%Y %b %d %H:%M:%S.%f")

    # 3. Calculate one hour ago
    one_hour_ago = now - timedelta(minutes=30)

    # 4. Format both into the log's timestamp style: YYYY/MM/DD HH:
    current_hour_pattern = now.strftime("%Y/%m/%d %H:")
    previous_hour_pattern = one_hour_ago.strftime("%Y/%m/%d %H:")

    # 5. Create the IOS regex pipe string
    ios_pipe = f"| include ({current_hour_pattern}|{previous_hour_pattern})"

    return ios_pipe

def analyze_dhcp_snooping_trace(log_output: str, anycast_gw: str, helpers: List[str], step: int):
    process = "dhcpTroubleshooting"
    subprocess = "snoopingTraceAnalysis"
    hostname = "edge-1-jalejand-cisco-com"

    # 1. Initial check for completely empty output
    if not log_output.strip():
        message = "No DHCP events were captured in the past 30 minutes. The endpoint may already have an IP address."
        logging_info(step, process, subprocess, hostname, message)
        return step + 1, "NO_DATA", "No logs"

    lines = log_output.strip().splitlines()
    vlan_set = set()
    packets_found = False  # Track if we actually found any DHCP packets

    dora_tracker = {
        "DISCOVER": {"seen": False, "relayed": False, "internal_ok": False},
        "OFFER": {"seen": False, "intercepted": False, "punt_ok": False},
        "REQUEST": {"seen": False, "relayed": False, "internal_ok": False},
        "ACK": {"seen": False, "intercepted": False, "punt_ok": False}
    }

    internal_stages = {
        "PUNT:RECEIVED": False, "PUNT:TO_DHCPSN": False, "BRIDGE:RECEIVED": False,
        "BRIDGE:TO_DHCPD": False, "BRIDGE:TO_INJECT": False, "INJECT:RECEIVED": False,
        "INJECT:TO_L2FWD": False
    }

    for line in lines:
        parts = line.split()
        # 2. Filter out command echo and headers (Must start with Date and have numeric VLAN)
        if len(parts) < 7 or not (re.match(r"\d{4}/\d{2}/\d{2}", parts[0]) and parts[4].isdigit()):
            continue

        packets_found = True  # We found at least one valid log entry
        vlan = parts[4]
        msg_type = parts[5]
        action = parts[6]
        dest_ip = parts[3]

        if "INFORM" in msg_type or "NACK" in msg_type:
            continue

        if vlan != "0":
            vlan_set.add(vlan)

        # Outbound Handshake
        if "DHCPDISCOVER" in msg_type or "DHCPREQUEST" in msg_type:
            stage_key = "DISCOVER" if "DISCOVER" in msg_type else "REQUEST"
            dora_tracker[stage_key]["seen"] = True
            if action == "PUNT:RECEIVED": internal_stages["PUNT:RECEIVED"] = True
            if action == "PUNT:TO_DHCPSN": internal_stages["PUNT:TO_DHCPSN"] = True
            if action == "BRIDGE:RECEIVED": internal_stages["BRIDGE:RECEIVED"] = True
            if action == "BRIDGE:TO_DHCPD": internal_stages["BRIDGE:TO_DHCPD"] = True
            if action == "BRIDGE:TO_INJECT":
                internal_stages["BRIDGE:TO_INJECT"] = True
                dora_tracker[stage_key]["internal_ok"] = True
            if action == "INJECT:RECEIVED" and dest_ip in helpers:
                internal_stages["INJECT:RECEIVED"] = True
            if action == "INJECT:TO_L2FWD" and dest_ip in helpers:
                internal_stages["INJECT:TO_L2FWD"] = True
                dora_tracker[stage_key]["relayed"] = True

        # Inbound Handshake
        elif "DHCPOFFER" in msg_type or "DHCPACK" in msg_type:
            stage_key = "OFFER" if "OFFER" in msg_type else "ACK"
            dora_tracker[stage_key]["seen"] = True
            if action == "PUNT:RECEIVED" and dest_ip == anycast_gw:
                dora_tracker[stage_key]["punt_ok"] = True
            if action == "INTERCEPT:TO_DHCPSN":
                dora_tracker[stage_key]["intercepted"] = True

    # 3. If no DHCP packets were found in the output, exit before printing warnings
    if not packets_found:
        message = "No DHCP handshake packets were found in the trace. The endpoint may have already completed the DORA process."
        logging_info(step, process, subprocess, hostname, message)
        return step + 1, "NO_DATA", "No packets found"

    # --- Analysis & Warnings (Only runs if packets_found is True) ---

    if len(vlan_set) > 1:
        logging_warning(step, process, subprocess, hostname, f"VLAN Bouncing detected: {vlan_set}.")
        step += 1

    for stage, seen in internal_stages.items():
        if not seen:
            logging_warning(step, process, subprocess, hostname, f"Missing internal processing stage: {stage}.")
            step += 1

    # Determine DORA Final Status
    final_status = ""
    summary_msg = ""

    if dora_tracker["ACK"]["intercepted"]:
        final_status = "FINALIZED"
        summary_msg = "The DORA process completed successfully."
    elif dora_tracker["ACK"]["seen"]:
        final_status = "STUCK at ACK"
        summary_msg = "The DHCPACK was received but not delivered to the client."
    elif dora_tracker["REQUEST"]["relayed"]:
        final_status = "STUCK at REQUEST"
        summary_msg = "The DHCPREQUEST was relayed, but no ACK was received."
    elif dora_tracker["OFFER"]["intercepted"]:
        final_status = "STUCK at REQUEST"
        summary_msg = "The DHCPOFFER was delivered, but no REQUEST followed."
    elif dora_tracker["OFFER"]["seen"]:
        final_status = "STUCK at OFFER"
        summary_msg = "The DHCPOFFER was received but not delivered to the client."
    elif dora_tracker["DISCOVER"]["relayed"]:
        final_status = "STUCK at DISCOVER"
        summary_msg = "The DHCPDISCOVER was relayed, but no OFFER was received."
    else:
        final_status = "STUCK at DISCOVER"
        summary_msg = "DHCPDISCOVER was detected but failed to reach the relay stage."

    msg1 = f"DORA Process Summary: {final_status}"
    logging_info(step, process, subprocess, hostname, f"{msg1} | {summary_msg}")
    step += 1

    return step, final_status, summary_msg

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

    def svi_running_config(self, vlan, service):
        device = self.device
        svishworuncmd = "show run interface vlan {}".format(vlan)
        svishworunop = get_any_single_output(device, svishworuncmd, service)

        self.ip_dhcp_commands = []
        self.vrf = "default"  # This is your safety fallback
        self.helper_addresses = []
        self.lisp_mobility_entries = []

        if svishworunop is not None:
            for line in svishworunop.splitlines():
                stripped = line.strip()
                
                # VRF: Update the instance attribute if found
                m_vrf = re.match(r"vrf forwarding (\S+)", stripped)
                if m_vrf:
                    self.vrf = m_vrf.group(1)
                
                # ip dhcp
                if stripped.startswith("ip dhcp"):
                    self.ip_dhcp_commands.append(stripped)
                
                # ip helper-address
                m_helper = re.match(r"ip helper-address(?: vrf (\S+))? (\d+\.\d+\.\d+\.\d+)", stripped)
                if m_helper:
                    # Use the VRF from the helper command if present, 
                    # otherwise use the SVI's VRF (self.vrf)
                    helper_vrf = m_helper.group(1) if m_helper.group(1) else self.vrf
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

    def dhcpsnoopclientstat(self, mac, anycastgw, helpers, service, step):
        hostname = self.device
        showclockcmd = "show clock"
        showclockop = get_single_output_genie(hostname, showclockcmd, service)
        pipe_string = generate_ios_pipe(showclockop)
        dhcpsnoocmd = f"show platform dhcpsnooping client stat {mac} {pipe_string}"
        dhcpsnoopop = get_any_single_output(hostname, dhcpsnoocmd, service)
        # Capture the 3 values from the analysis function
        step, final_status, summary_msg = analyze_dhcp_snooping_trace(dhcpsnoopop, anycastgw, helpers, step)
        # Return the 2 values the main script is expecting
        return step, final_status


