from radkit_cli import get_any_single_output, get_single_output_genie
import re
import ipaddress
from typing import Any, Dict, List, Optional

def _safe_int(s: str) -> Optional[int]:
    try:
        return int(s)
    except (TypeError, ValueError):
        return None

def _age_to_seconds(age_raw: str) -> Optional[int]:
    if not age_raw:
        return None
    s = age_raw.strip().lower()

    m = re.fullmatch(r"(\d+)\s*s", s)
    if m:
        return int(m.group(1))

    m = re.fullmatch(r"(\d+)\s*(mn|m)", s)
    if m:
        return int(m.group(1)) * 60

    m = re.fullmatch(r"(\d+)\s*h", s)
    if m:
        return int(m.group(1)) * 3600

    m = re.search(r"(\d+)", s)
    return int(m.group(1)) if m else None

def parse_device_tracking_entries(output: str) -> List[Dict[str, Any]]:
    """
    Returns a list of per-entry dicts like:
      {
        'dev_code': 'DH4',
        'network_layer_address': '172.19.10.17',
        'link_layer_address': '00c0.cab6.4642',
        'interface': 'Ac0',
        'vlan_id': 1021,
        'pref_level_code': 24,
        'age': '165s',
        'state': 'REACHABLE',
        'time_left': '84 s try 0(...)'
      }
    """
    entries: List[Dict[str, Any]] = []
    if not output or not isinstance(output, str):
        return entries

    for ln in output.splitlines():
        tokens = ln.split()
        if len(tokens) < 8:
            continue

        dev_code = tokens[0]
        if dev_code not in {"DH4", "DH6", "ND", "ARP", "PKT", "API", "L", "S"}:
            continue

        nla = tokens[1]
        lla = tokens[2]
        intf = tokens[3]
        vlan_raw = tokens[4]
        prlvl_raw = tokens[5]
        age_raw = tokens[6]
        state = tokens[7]
        time_left = " ".join(tokens[8:]) if len(tokens) > 8 else ""

        # normalize IP strings (keep original if not a valid IP)
        try:
            nla = str(ipaddress.ip_address(nla))
        except ValueError:
            pass

        vlan_id = _safe_int(vlan_raw)
        pref_level_code = _safe_int(prlvl_raw)  # "0024" -> 24

        age_sec = _age_to_seconds(age_raw)
        age = f"{age_sec}s" if age_sec is not None else age_raw

        entries.append(
            {
                "dev_code": dev_code,
                "network_layer_address": nla,
                "link_layer_address": lla.lower(),
                "interface": intf,
                "vlan_id": vlan_id if vlan_id is not None else vlan_raw,
                "pref_level_code": pref_level_code if pref_level_code is not None else prlvl_raw,
                "age": age,
                "state": state,
                "time_left": time_left,
            }
        )

    return entries

def parse_device_tracking_mac_table(output: str) -> list[dict]:
    rows = []
    for line in (output or "").splitlines():
        line = line.strip()
        if not line or line.lower().startswith("mac "):
            continue

        # Example:
        # 00c0.cab6.4642  Ac0  1021  TRUSTED  MAC-REACHABLE  120 s  LISP-DT...  143
        parts = re.split(r"\s{2,}|\s+", line)
        if len(parts) < 6:
            continue

        rows.append(
            {
                "mac": parts[0].lower(),
                "interface": parts[1],
                "vlan_id": int(parts[2]) if parts[2].isdigit() else parts[2],
                "prlvl": parts[3],
                "state": parts[4],
                "time_left": " ".join(parts[5:7]).strip() if len(parts) >= 7 and parts[6].lower() == "s" else parts[5],
                "policy": " ".join(parts[7:-1]).strip() if len(parts) > 8 else None,
                "input_index": parts[-1] if len(parts) > 7 else None,
            }
        )
    return rows

def device_tracking_policies(data):
    results = []

    for line in data.strip().splitlines():
        if line.startswith("Target") or not line.strip():
            continue  # skip header or blank lines
        # Use regex to get the first three columns, then the rest is Feature/Target range
        m = re.match(r"(\S+\s+\S+)\s+(\S+)\s+(\S+)\s+(.*)", line)
        if not m:
            continue
        target, type_, policy, rest = m.groups()
        # Now, split Feature and Target range intelligently
        # If 'vlan all' is at the end, it's Target range; else, entire rest is Feature
        if rest.endswith("vlan all"):
            feature, target_range = rest.rsplit("vlan all", 1)
            feature = feature.strip()
            target_range = "vlan all"
        else:
            feature = rest.strip()
            target_range = ""
        results.append({
            "target": target,
            "type": type_,
            "policy": policy,
            "feature": feature,
            "target_range": target_range
        })
    return results

class SISF:
    def __init__(self,device):
        self.device = device

    def device_tracking_policies(self,vlan,service):
        # Enablement of service dhcp, service dhcp is enabled by default, if disabled, servicedhcp attr is set to False
        device = self.device
        devicetrackingpoliciescmd = "show device-tracking policies vlan {}".format(vlan)
        devicetrackingpoliciesop = get_any_single_output(device,devicetrackingpoliciescmd,service)
        self.policies = None
        if devicetrackingpoliciesop is None:
            return None
        else:
            policies = device_tracking_policies(devicetrackingpoliciesop)
            self.policies = policies
    def device_tracking_database_address(self,ip,service):
        device = self.device
        devicetrackingdatabasecmd = "show device-tracking database address {}".format(ip)
        devicetrackingdatabaseop = get_single_output_genie(device,devicetrackingdatabasecmd,service)
        devicetrackingdatabasecmd_log = "show device-tracking database address {} detail".format(ip)
        devicetrackingdatabaseop_log = get_any_single_output(device,devicetrackingdatabasecmd,service)
        entries = []
        if  devicetrackingdatabaseop is not None:
            path = devicetrackingdatabaseop['device']
            for entry in path:
                entries.append(path[entry])
        self.dbentries = entries
    def device_tracking_database_interface(self,interface,service):
        device = self.device
        devicetrackingdatabasecmd = "show device-tracking database interface {}".format(interface)
        devicetrackingdatabaseop = get_single_output_genie(device,devicetrackingdatabasecmd,service)
        devicetrackingdatabasecmd_log = "show device-tracking database address {} detail".format(interface)
        devicetrackingdatabaseop_log = get_any_single_output(device,devicetrackingdatabasecmd,service)
        entries = []
        if  devicetrackingdatabaseop is not None:
            path = devicetrackingdatabaseop['device']
            for entry in path:
                entries.append(path[entry])
        self.dbentries = entries
    def device_tracking_database_history(self,service):
        device = self.device
        devicetrackingdatabasehistcmd = "show device-tracking database history"
        devicetrackingdatabasehistop = get_any_single_output(device,devicetrackingdatabasehistcmd,service)
        #Just to append to the logs

    def device_tracking_database_mac(self,mac,service):
        device = self.device
        devicetrackingdatabasecmd = "show device-tracking database mac {}".format(mac)
        devicetrackingdatabaseop = get_any_single_output(device,devicetrackingdatabasecmd,service)
        devicetrackingdatabasecmd_log = "show device-tracking database mac {} detail".format(mac)
        devicetrackingdatabaseop_log = get_any_single_output(device,devicetrackingdatabasecmd,service)
        entries = parse_device_tracking_entries(devicetrackingdatabaseop)
        self.dbentries = entries

    def device_tracking_database_mac_l2(self,mac,service):
        device = self.device
        devicetrackingdatabasecmd = "show device-tracking database mac | i {}|prlvl".format(mac)
        devicetrackingdatabaseop = get_any_single_output(device,devicetrackingdatabasecmd,service)
        entries = parse_device_tracking_mac_table(devicetrackingdatabaseop)
        self.dbentries = entries