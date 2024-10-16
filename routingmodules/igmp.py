from genie.libs.sdk.apis.iosxe.cts.configure import enable_cts_enforcement

import radkit_cli

class IGMP:
    def __init__(self,vrf,device):
        self.hostname = device
        self.vrf = vrf

    def igmp_groups_interface_interface(self,interface,service):
        if self.vrf == "default":
            vrf_mode = ""
            vrf = 'default'
        elif self.vrf is None:
            vrf_mode = ""
            vrf = 'default'
        else:
            vrf_mode = "vrf "+self.vrf+" "
            vrf = self.vrf

        igmpintf_cmd = "show ip igmp {} interface".format(vrf_mode)
        igmpintf_op = radkit_cli.get_single_output_genie(self.hostname, igmpintf_cmd, service)

        if igmpintf_op is not None:
            try:
                ipigmpinterfacepath = igmpintf_op['vrf'][vrf]['interface'][interface]
                self.igmpinterface = interface
                self.operstatus = ipigmpinterfacepath['oper_status']
                self.enable = ipigmpinterfacepath['enable']
                self.host_version = ipigmpinterfacepath['host_version']
                self.query_interval = ipigmpinterfacepath['query_interval']
                self.querier_timeout = ipigmpinterfacepath['querier_timeout']
                self.query_max_response_time = ipigmpinterfacepath['query_max_response_time']
                self.designated_router = ipigmpinterfacepath['multicast']['designated_router']
                self.dr_this_system = ipigmpinterfacepath['multicast']['dr_this_system']
                self.querier = ipigmpinterfacepath['querier']
                self.query_this_system = ipigmpinterfacepath['query_this_system']
                self.joined_group = ipigmpinterfacepath['joined_group']

            except (KeyError,AttributeError,TypeError):
                return None


    def igmp_groups_group(self,group,service):
        if self.vrf == "default":
            vrf_mode = ""
        elif self.vrf is None:
            vrf_mode = ""
        else:
            vrf_mode = "vrf "+self.vrf+" "

        igmpgroups_cmd = "show ip igmp {} groups {}".format(vrf_mode, group)
        igmpgroups_op = radkit_cli.get_any_single_output(self.hostname,igmpgroups_cmd,service)

        if igmpgroups_op is not None:
            igmp_entries = []
            self.group = group
            self.interfaces = None
            for entry in igmpgroups_op.splitlines():
                matches = ["#", "show", "IGMP", "Group"]
                if not any(x in entry for x in matches):
                    entry = entry.split()
                    group = entry[0]
                    interface = entry[1]
                    uptime = entry[2]
                    expires = entry[3]
                    last_reporter = entry[4]
                    igmp_group_entry = {
                        'interface': interface,
                        'uptime': uptime,
                        'expires': expires,
                        'last_reporter': last_reporter
                    }
                    igmp_entries.append(igmp_group_entry)
            #RAW Parser
            self.interfaces = igmp_entries
            igmp_groups = {"igmp_groups": {group: {}}}
            if len(igmp_entries) != 0:
                uptime, expires, last_reporter = None, None, None
                for entries in igmp_entries:
                    interface = entries['interface']
                    values = {
                        uptime: entries['uptime'],
                        expires: entries['expires'],
                        last_reporter: entries['last_reporter'],
                    }
                    igmp_groups['igmp_groups'][group][interface] = values

            else:
                return None
        else:
            return None