import sys
from pprint import pformat

from radkit_cli import logging_info,logging_error,logging_warning,get_single_output_genie
from routingmodules.cef import IPCef, physical_recursion


def ip_route_collection(iproute,step):
    hostname = iproute.hostname
    collection_summary = "Prefix: {}, Mask: {}, VRF: {}, NextHop(s): {}, Protocol: {}, Metric: {}".format(iproute.route,iproute.mask,iproute.vrf,iproute.nexthop,iproute.protocol,iproute.metric)
    string = "Result: Success"
    logging_info(step, "Underlay", "IPRouting",hostname, collection_summary)
    logging_info(step, "Underlay", "IPRouting",hostname, string)


class IPRoute:
    def __init__(self,route,vrf,device):
        self.hostname = device        #Device Name
        self.route = route            #IPv4 RLOC 
        self.vrf = vrf

    def iproute_prefix(self,service,step):

        #Route_Inspection:
        #print("Collecting RIB Information for prefix: {}\n".format(self.route))
        process = "ipRouting"
        if self.vrf == "default":
            vrf_mode = ""
        elif self.vrf is None:
            vrf_mode = ""
        elif self.vrf == "None":
            vrf_mode = ""
        else:
            vrf_mode = "vrf "+self.vrf+" "
    
        #show ip route command:
        iproute_cmd = "show ip route {} {}".format(vrf_mode, self.route)
        iproute_output = get_single_output_genie(self.hostname,iproute_cmd,service)
        #If specific route exists:
        if iproute_output is not None:
            route_path = iproute_output['entry']
            for i in route_path:
                route_path = route_path[i]
            self.prefix = route_path['ip']
            self.mask = route_path['mask']
            self.metric = route_path['metric']
            self.distance = route_path['distance']
            self.protocol = route_path['known_via'].strip()
            paths = route_path['paths']
            nexthops = []
            try:
                for i in paths:
                    index = i
                interface = paths[index]['interface']
                specialintf = interface
            except KeyError:
                specialintf = True
            if self.protocol == 'connected':
                self.nexthop = specialintf
            elif specialintf != "Null0":
                for i in paths:
                    nexthops.append(paths[i]['nexthop'])
                self.nexthop = nexthops
            else:
                self.nexthop = "Null0"
        else:
         #If specific route does not exist: aka, validate if default route exists:
            prefix = "0.0.0.0 0.0.0.0"
            iproute_cmd = "show ip route {} {}".format(vrf_mode,prefix)
            iproute_output = get_single_output_genie(self.hostname,iproute_cmd,service)
            if iproute_output is None:
                subprocess = "[rib]"
                hostname = self.hostname
                error = "IP Routing - No Route"
                message = "No route to prefix {} (not even default-route) traffic will be dropped, fix the route to {} in device: {}".format(
                    self.route, self.route, hostname)
                logging_error(step, process, subprocess, hostname, error)
                logging_info(step, process, subprocess, hostname, message)
                #raise BDBTaskError("Error: {} | {}".format(error, message))
                sys.exit("Error: {} | {}".format(error, message))

            else:
                route_path = iproute_output['entry']
                for i in route_path:
                    route_path = route_path[i]
                self.prefix = route_path['ip']
                self.mask = route_path['mask']
                self.metric = route_path['metric']
                self.distance = route_path['distance']
                self.protocol = route_path['known_via'].strip()
                paths = route_path['paths']
                nexthops = []
                try:
                    for i in paths:
                        index = i
                    interface = paths[index]['interface']
                    specialintf = interface
                except KeyError:
                    specialintf = True
                if self.protocol == 'connected':
                    self.nexthop = specialintf
                elif specialintf != "Null0":
                    for i in paths:
                        nexthops.append(paths[i]['nexthop'])
                    self.nexthop = nexthops
                else:
                    self.nexthop = "Null0"

    def iproute_prefix_soft(self, service, step):
        """
        Best-effort: never raises/exit; on any failure it sets attributes to None.
        Populates (when available):
          self.prefix, self.mask, self.metric, self.distance, self.protocol, self.nexthop
        """
        process = "ipRouting"

        # Defaults (null-fill)
        self.prefix = None
        self.mask = None
        self.metric = None
        self.distance = None
        self.protocol = None
        self.nexthop = None

        vrf = (self.vrf or "").strip()
        vrf_mode = "" if vrf in {"", "default", "none", "None"} else f"vrf {vrf} "

        def _extract_route_fields(iproute_output):
            if not isinstance(iproute_output, dict):
                return None

            entry = iproute_output.get("entry")
            if not isinstance(entry, dict) or not entry:
                return None

            # Genie format: entry -> { "<prefix>": { ... route data ... } }
            route_key = next(iter(entry.keys()), None)
            route_path = entry.get(route_key) if route_key else None
            if not isinstance(route_path, dict):
                return None

            prefix = route_path.get("ip")
            mask = route_path.get("mask")
            metric = route_path.get("metric")
            distance = route_path.get("distance")
            protocol = (route_path.get("known_via") or "").strip() or None

            paths = route_path.get("paths") or {}
            nexthop = None

            # Pick last path entry (consistent with your original code)
            if isinstance(paths, dict) and paths:
                path_key = next(reversed(paths))  # last key
                path = paths.get(path_key, {}) or {}

                interface = path.get("interface")
                if protocol == "connected":
                    nexthop = interface or None
                else:
                    if interface == "Null0":
                        nexthop = "Null0"
                    else:
                        nhs = []
                        for _, p in paths.items():
                            nh = (p or {}).get("nexthop")
                            if nh:
                                nhs.append(nh)
                        nexthop = nhs or interface or None

            return {
                "prefix": prefix,
                "mask": mask,
                "metric": metric,
                "distance": distance,
                "protocol": protocol,
                "nexthop": nexthop,
            }

        # 1) Try exact route
        iproute_cmd = f"show ip route {vrf_mode}{self.route}"
        iproute_output = get_single_output_genie(self.hostname, iproute_cmd, service)
        fields = _extract_route_fields(iproute_output)

        # 2) Fallback to default route
        if not fields:
            iproute_cmd = f"show ip route {vrf_mode}0.0.0.0 0.0.0.0"
            iproute_output = get_single_output_genie(self.hostname, iproute_cmd, service)
            fields = _extract_route_fields(iproute_output)

        # 3) Populate if found (otherwise remain None)
        if fields:
            self.prefix = fields["prefix"]
            self.mask = fields["mask"]
            self.metric = fields["metric"]
            self.distance = fields["distance"]
            self.protocol = fields["protocol"]
            self.nexthop = fields["nexthop"]

        return step

class IGPInfo():
    def __init__(self,device):
        self.device = device
    def igp_neighbors(self,igp,service):
        step = "X"
        hostname = self.device
        if igp == 'isis':
            command = "show isis neighbor"
            output = get_single_output_genie(hostname,command,service)
            if output is not None:
                interfaces = []
                neighbors = output.get("isis", {}).get("null", {}).get("neighbors", {})
                for neighbor in neighbors.values():
                    types = neighbor.get("type", {})
                    for t in ["L2", "L1L2", "L1"]:
                        if t in types and "interfaces" in types[t]:
                            interfaces.extend(types[t]["interfaces"].keys())
            self.neighbor_interfaces = interfaces
        if igp == 'ospf':
            command = 'show ip ospf neighbor'
            output = get_single_output_genie(hostname, command, service)
            if output is not None:
                self.neighbor_interfaces = list(output.get("interfaces", {}).keys())
        if igp == 'eigrp':
            command = "show ip eigrp neighbor"
            output = get_single_output_genie(hostname, command, service)
            if output is not None:
                try:
                    self.neighbor_interfaces = list(
                        output['eigrp_instance']['100']['vrf']['default']['address_family']['ipv4']['eigrp_interface'].keys()
                    )
                except KeyError:
                    return None
        if igp == 'connected'.casefold():
            return None
        if igp == 'static':
            return None
        if 'bgp' in igp:
            command =  "show ip bgp summary"
            output = get_single_output_genie(hostname,command,service)
            if output is not None:
                neighbors = output.get('vrf', {}).get('default', {}).get('neighbor', {})
                neighbor_nexthops = list(neighbors.keys())
                interfaces = []
                for nexthop in neighbor_nexthops:
                    cef = IPCef(nexthop, None,hostname)
                    cef.get_cef_internal(service)
                    phys = physical_recursion(cef,hostname)
                    phys.get_physical_interfaces(service,step)
                    for interface in phys.total_phys[0]:
                        interfaces.append(interface)
                self.neighbor_interfaces = interfaces

