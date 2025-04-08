import sys
import radkit_cli
from radkit_cli import logging_info,logging_error,logging_warning

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

        if self.vrf == "default":
            vrf_mode = ""
            vrf = ''
        elif self.vrf is None:
            vrf_mode = ""
            vrf = ''
        else:
            vrf_mode = "vrf "+self.vrf+" "
    
        #show ip route command:
        iproute_cmd = "show ip route {} {}".format(self.route, vrf_mode, self.vrf)
        iproute_output = radkit_cli.get_single_output_genie(self.hostname,iproute_cmd,service)
        #If specific route exists:
        if iproute_output is not None:
            route_path = iproute_output['entry']
            for i in route_path:
                route_path = route_path[i]
            self.prefix = route_path['ip']
            self.mask = route_path['mask']
            self.metric = route_path['metric']
            self.distance = route_path['distance']
            self.protocol = route_path['known_via']
            paths = route_path['paths']
            nexthops = []
            try:
                for i in paths:
                    index = i
                interface = paths[index]['interface']
                specialintf = interface
            except KeyError:
                specialintf = True

            if specialintf != "Null0":
                for i in paths:
                    nexthops.append(paths[i]['nexthop'])
                self.nexthop = nexthops
            else:
                self.nexthop = "Null0"
        else:
         #If specific route does not exist: aka, validate if default route exists:
            prefix = "0.0.0.0 0.0.0.0"
            iproute_cmd = "show ip route {} {}".format(prefix, vrf_mode, self.vrf)
            iproute_output = radkit_cli.get_single_output_genie(self.hostname,iproute_cmd,service)
            if iproute_output is None:
                logging_error(step, "IPRouting", "[RIB]", self.hostname,"No route to prefix {}! (not even default-route) traffic will be dropped".format(self.route))
                sys.exit("No route to prefix {}! (not even default-route) traffic will be dropped".format(self.route))
            else:
                route_path = iproute_output['entry']
                for i in route_path:
                    route_path = route_path[i]
                self.prefix = route_path['ip']
                self.mask = route_path['mask']
                self.metric = route_path['metric']
                self.distance = route_path['distance']
                self.protocol = route_path['known_via']
                paths = route_path['paths']
                nexthops = []
                try:
                    for i in paths:
                        index = i
                    interface = paths[index]['interface']
                    specialintf = interface
                except KeyError:
                    specialintf = True
                if specialintf != "Null0":
                    for i in paths:
                        nexthops.append(paths[i]['nexthop'])
                    self.nexthop = nexthops
                else:
                    self.nexthop = "Null0"