from radkit_cli import get_any_single_output, get_single_output_genie
import re

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
