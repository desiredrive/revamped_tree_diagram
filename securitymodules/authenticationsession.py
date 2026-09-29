from radkit_cli import get_single_output_genie, get_any_single_output
import re
from typing import List, Dict, Any

def parse_show_auth_sessions_detail(output: str) -> Dict[str, Any]:
    """
    Parses 'show authentication sessions interface <intf> detail' output.
    Detects standard fields, SGTs, and Downloadable ACLs (ACS ACL).
    """
    result = {"interfaces": {}}

    if not output or not isinstance(output, str):
        return result

    # Split output into individual session blocks based on the separator line
    blocks = re.split(r'-{20,}', output)

    for block in blocks:
        if not block.strip():
            continue

        # Simple Key-Value extraction
        patterns = {
            "interface": r"Interface:\s+(.*)",
            "iif_id": r"IIF-ID:\s+(.*)",
            "mac_address": r"MAC Address:\s+(.*)",
            "ipv6_address": r"IPv6 Address:\s+(.*)",
            "ipv4_address": r"IPv4 Address:\s+(.*)",
            "user_name": r"User-Name:\s+(.*)",
            "device_type": r"Device-type:\s+(.*)",
            "device_name": r"Device-name:\s+(.*)",
            "status": r"Status:\s+(.*)",
            "domain": r"Domain:\s+(.*)",
            "oper_host_mode": r"Oper host mode:\s+(.*)",
            "oper_control_dir": r"Oper control dir:\s+(.*)",
            "session_timeout": r"Session timeout:\s+(.*)",
            "common_session_id": r"Common Session ID:\s+(.*)",
            "acct_session_id": r"Acct Session ID:\s+(.*)",
            "handle": r"Handle:\s+(.*)",
            "current_policy": r"Current Policy:\s+(.*)",
        }

        temp_vals = {}
        for key, pattern in patterns.items():
            match = re.search(pattern, block, re.IGNORECASE)
            temp_vals[key] = match.group(1).strip() if match else "Unknown"

        intf_name = temp_vals.get("interface", "Unknown")
        mac = temp_vals.get("mac_address", "Unknown")

        if intf_name not in result["interfaces"]:
            result["interfaces"][intf_name] = {"mac_address": {}}

        entry = {
            "ipv6_address": temp_vals["ipv6_address"],
            "iif_id": temp_vals["iif_id"],
            "ipv4_address": temp_vals["ipv4_address"],
            "user_name": temp_vals["user_name"] if temp_vals["user_name"] != "Unknown" else mac.replace('.', '-').upper(),
            "device_type": temp_vals["device_type"],
            "device_name": temp_vals["device_name"],
            "status": temp_vals["status"],
            "domain": temp_vals["domain"],
            "oper_host_mode": temp_vals["oper_host_mode"],
            "oper_control_dir": temp_vals["oper_control_dir"],
            "session_timeout": {"type": temp_vals["session_timeout"]},
            "common_session_id": temp_vals["common_session_id"],
            "acct_session_id": temp_vals["acct_session_id"],
            "handle": temp_vals["handle"],
            "current_policy": temp_vals["current_policy"],
            "local_policies": {},
            "server_policies": {},
            "method_status": {}
        }

        # --- Updated Server Policies Logic ---
        policy_index = 1

        # Parse SGT Value
        sgt_match = re.search(r"SGT Value:\s+(.*)", block, re.IGNORECASE)
        if sgt_match:
            entry["server_policies"][policy_index] = {"name": "SGT Value", "policies": sgt_match.group(1).strip()}
            policy_index += 1

        # Parse ACS ACL (Downloadable ACL)
        # Using a flexible regex to handle "ACS ACL" or "ACS-ACL"
        acs_acl_match = re.search(r"ACS[- ]ACL:\s+(.*)", block, re.IGNORECASE)
        if acs_acl_match:
            entry["server_policies"][policy_index] = {"name": "ACS ACL", "policies": acs_acl_match.group(1).strip()}
            policy_index += 1

        # Parse Local Policies (VLAN)
        vlan_match = re.search(r"Vlan Group:\s+Vlan:\s+(\d+)", block, re.IGNORECASE)
        if vlan_match:
            entry["local_policies"]["vlan_group"] = {"vlan": int(vlan_match.group(1))}

        # Any locally-assigned VLAN, whatever line carries it. A critical-auth
        # fallback prints "Voice Vlan: Vlan: 4096" rather than "Vlan Group:",
        # so the stricter pattern above misses exactly the case where knowing
        # the VLAN matters most. Recorded separately so `vlan_group` keeps its
        # existing meaning for callers that already read it.
        any_vlan = re.search(r"Vlan:\s+(\d+)", block, re.IGNORECASE)
        if any_vlan:
            entry["local_policies"]["assigned_vlan"] = int(any_vlan.group(1))

        # Service templates applied locally. The names are what identify a
        # critical-auth fallback (DefaultCriticalAuthVlan_SRV_TEMPLATE), which
        # authorizes a port without the endpoint ever passing authentication --
        # a state that otherwise reads as a clean "Authorized".
        templates = re.findall(
            r"Service Template:\s+(\S+)(?:\s+\(priority\s+(\d+)\))?",
            block, re.IGNORECASE)
        if templates:
            entry["local_policies"]["templates"] = {
                name: {"priority": int(pri)} if pri else {}
                for name, pri in templates
            }

        # Parse Method Status List
        method_section = re.search(r"Method status list:(.*)", block, re.DOTALL | re.IGNORECASE)
        if method_section:
            methods_text = method_section.group(1).strip()
            if "empty" not in methods_text.lower():
                for method in ["dot1x", "mab"]:
                    m_match = re.search(rf"{method}\s+(.*)", methods_text, re.IGNORECASE)
                    if m_match:
                        entry["method_status"][method] = {
                            "method": method,
                            "state": m_match.group(1).strip()
                        }

        result["interfaces"][intf_name]["mac_address"][mac] = entry

    return result
def parse_ios_templates(output: str) -> Dict[str, List[str]]:
    """
    Parses Cisco IOS template definitions into a dictionary.
    Key: Template Name
    Value: List of configuration commands
    """
    templates = {}

    # Regex to find 'template <name>' and capture all subsequent indented lines
    # Pattern explanation:
    # ^template\s+(\S+) -> Matches line starting with 'template' and captures the name
    # (?:\n\s+(.*))+    -> Captures one or more lines that start with a space
    pattern = re.compile(r"^template\s+(\S+)(?:\n\s+(.*))+", re.MULTILINE)

    matches = pattern.finditer(output)

    for match in matches:
        name = match.group(1)
        # Extract the full block and split into individual stripped commands
        block = match.group(0)
        commands = [line.strip() for line in block.splitlines()[1:] if line.strip()]
        templates[name] = commands

    return templates

def parse_acro_bvm_session(output: str) -> List[Dict[str, Any]]:
    """
    Parses 'show acro_bvm session' output.
    Returns a list of dictionaries containing session details.
    """
    sessions = []

    if not output or not isinstance(output, str):
        return sessions

    # Regex to match the data row:
    # Group 1: VLAN (digits)
    # Group 2: MAC Address (xxxx.xxxx.xxxx)
    # Group 3: Authorized (TRUE/FALSE)
    # Group 4: Session ID (Alpha-numeric string)
    pattern = re.compile(r"^\s*(\d+)\s+([0-9a-fA-F\.]{14})\s+(\w+)\s+(\w+)")

    for line in output.splitlines():
        line = line.strip()

        # Skip headers and separator lines
        if not line or "VLAN" in line or "----" in line or "Bridge mode" in line:
            continue

        match = pattern.match(line)
        if match:
            sessions.append({
                "vlan": int(match.group(1)),
                "mac_address": match.group(2).lower(),
                "authorized": match.group(3).upper() == "TRUE",
                "session_id": match.group(4)
            })

    return sessions

def parse_show_dot1x_interface(output: str) -> Dict[str, Any]:
    """
    Parses 'show dot1x interface <intf>' output.
    Returns a dictionary of the parameters.
    """
    result = {
        "interface": None,
        "parameters": {}
    }

    if not output or not isinstance(output, str):
        return result

    lines = output.splitlines()

    for line in lines:
        line = line.strip()

        # 1. Parse the Interface Name from the header
        # Matches: "Dot1x Info for TenGigabitEthernet1/0/5"
        intf_match = re.search(r"Dot1x Info for\s+(.*)", line, re.IGNORECASE)
        if intf_match:
            result["interface"] = intf_match.group(1).strip()
            continue

        # 2. Parse Key = Value pairs
        # Matches: "PAE = AUTHENTICATOR" or "QuietPeriod = 60"
        if "=" in line:
            parts = line.split("=")
            if len(parts) == 2:
                key = parts[0].strip()
                val = parts[1].strip()

                # Convert to integer if numeric, otherwise keep as string
                if val.isdigit():
                    val = int(val)

                result["parameters"][key] = val

    return result

def parse_show_mab_interface(output: str) -> Dict[str, Any]:
    """Parses `show mab interface <intf> details`.

    Returns {"interface", "configured", "enabled", "clients"}.

    This command is worth more than the dot1x one for a negative verdict: when
    MAB is absent the device says so in a sentence -- "MAC-Auth-Bypass is not
    configured on this interface" -- where `show dot1x interface` on the same
    port simply prints nothing. Empty output is ambiguous (it also looks like a
    failed collection); an explicit sentence is not.

    `configured` is None when neither the positive nor the negative form was
    recognised, so a caller can tell "the device said no" from "we could not
    tell", and never report the second as the first.
    """
    result = {"interface": None, "configured": None, "enabled": None,
              "clients": []}

    if not output or not isinstance(output, str):
        return result

    client = None
    for line in output.splitlines():
        line = line.strip()

        m = re.search(r"MAB details for\s+(.*)", line, re.IGNORECASE)
        if m:
            result["interface"] = m.group(1).strip()
            result["configured"] = True
            continue

        if re.search(r"not configured on this interface", line, re.IGNORECASE):
            result["configured"] = False
            result["enabled"] = False
            continue

        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip()

        if key.lower() == "mac-auth-bypass":
            result["enabled"] = val.strip().lower() == "enabled"
            continue

        # Each client block restarts at its MAC, so a port holding more than
        # one authenticated MAC is reported as more than one client rather
        # than collapsing into whichever line came last.
        if key.lower() == "my client mac":
            client = {"mac": val}
            result["clients"].append(client)
            continue
        if client is not None:
            client[key.strip().lower().replace(" ", "_")] = val

    return result


# Example usage:
# parsed_output = parse_show_auth_sessions_detail(cli_text)

def authen_session_for_interface(hostname, interface, service):
    # 1. Skip if the interface is an Access Tunnel or similar (starts with 'A')
    if interface.upper().startswith('Ac'):
        # AcroSession
        authensessionstatus = AuthenticationSession(hostname)
        authensessionstatus.acrosessions(service)
        return authensessionstatus
    # 2. Initialize the class and collect template binding/config
    authensessionstatus = AuthenticationSession(hostname)
    authensessionstatus.templateinterface(interface, service)
    # 2. Extract the template name safely from the collected data
    # We use the same logic as inside your class method to find the name
    binding_data = getattr(authensessionstatus, "templateinterface", {}) or {}
    # Any binding method counts, not just `static`: a CatC-provisioned AP port
    # binds `dynamic / Modified Built-in`. Reading only `static` returned None
    # on those ports, which skipped everything below and left the caller with
    # no session and no dot1x state to judge.
    _methods = next(iter((binding_data or {}).get('interface', {}).values()), {}).get('method', {}) or {}
    template_name = None
    for _m, _d in _methods.items():
        template_name = (_d or {}).get('template_name')
        if template_name:
            break

    # 3. Session details, when a template is bound.
    if template_name:
        # Command to get the detailed session info for the specific interface
        authensessionstatus.authenticationsessioninterface(interface,service)

    # dot1x state is collected unconditionally, and deliberately outside the
    # template test. It is the only positive evidence that a port does or does
    # not run authentication: `show dot1x interface` prints a PAE block when an
    # authenticator is running and nothing at all when it is not. Gating it on
    # a template meant the ports most likely to have no authentication -- the
    # ones where no template resolved -- were exactly the ports we never asked.
    # Without it "no authentication" is an inference from an absent config line;
    # with it, it is what the device said.
    authensessionstatus.dot1xinterfaceparameters(interface,service)
    # MAB is collected for the same reason and states the negative outright:
    # an unconfigured port answers "MAC-Auth-Bypass is not configured on this
    # interface", which is evidence, where empty dot1x output is only absence.
    # Together the two cover both methods a port could authenticate with.
    authensessionstatus.mabinterfaceparameters(interface,service)

    return authensessionstatus

class AuthenticationSession:
    def __init__(self, device):
        self.hostname = device

    def authenticationsessions(self,service):
        hostname = self.hostname
        cmd = "show authentication sessions"
        op = get_single_output_genie(hostname,cmd,service)
        self.authsessions = op

    def authenticationsessioninterface(self,interface,service):
        hostname = self.hostname
        cmd = f"show authentication sessions interface {interface} detail"
        op = get_any_single_output(hostname, cmd, service)
        op = parse_show_auth_sessions_detail(op)
        self.authsessionintf = op

    def authenticationsessionmac(self,mac,service):
        hostname = self.hostname
        cmd = f"show authentication sessions mac {mac} detail"
        op = get_single_output_genie(hostname, cmd, service)
        self.authsessionmac = op

    def acrosessionmac(self,service):
        hostname = self.hostname
        cmd = "show acro_bvm session"
        op = get_any_single_output(hostname, cmd, service)
        op = parse_acro_bvm_session(op)
        self.acrosessions = op

    def dot1xinterfaceparameters(self,interface,service):
        hostname = self.hostname
        cmd = f"show dot1x interface {interface}"
        op = get_any_single_output(hostname, cmd, service)
        op = parse_show_dot1x_interface(op)
        self.dot1xinterfaceparameter = op

    def mabinterfaceparameters(self,interface,service):
        hostname = self.hostname
        cmd = f"show mab interface {interface} details"
        op = get_any_single_output(hostname, cmd, service)
        op = parse_show_mab_interface(op)
        self.mabinterfaceparameter = op

    def accountingattributes(self,service,list_name="Def_Acct_List"):
        hostname = self.hostname
        cmd = f"show run | se {list_name}"
        op = get_any_single_output(hostname, cmd, service)
        self.accountingconfig = op

    def deviceclassifierinterface(self,interface,service):
        hostname = self.hostname
        cmd = f"show device classifier attached interface {interface} detail"
        op = get_single_output_genie(hostname, cmd, service)
        self.deviceclassifier = op

    def templateinterface(self,interface,service):
        hostname = self.hostname
        cmd = f"show template interface binding target {interface}"
        op = get_single_output_genie(hostname, cmd, service)
        self.templateinterface = op
        # A template can be bound by any method, and all of them are real: a
        # CatC-provisioned AP port binds `dynamic / Modified Built-in`, not
        # `static`. Reading only `static` left template_name None on those
        # ports, so the config below was never fetched and the caller reported
        # the template as unreadable -- which it then treated as open mode.
        methods = next(iter((op or {}).get('interface', {}).values()), {}).get('method', {}) or {}
        template_name = None
        for _method, data in methods.items():
            template_name = (data or {}).get('template_name')
            if template_name:
                break
        if template_name is not None:
            cmd = f"show run | section ^template {template_name}"
            op = get_any_single_output(hostname, cmd, service)
            op = parse_ios_templates(op)
            self.templateconfig = op


