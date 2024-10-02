import sys
import radkit_cli

class ip_route_get:
    def __init__(self,route,vrf,device):
        self.hostname = device        #Device Name
        self.route = route            #IPv4 RLOC 
        self.vrf = vrf

    def iproute_prefix(self,service):

        #Route_Inspection:
        print("Processing RIB Information")

        if self.vrf == "default" or self.vrf is None:
            vrf_mode = ""
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
            for i in paths:
                nexthops.append(paths[i]['nexthop'])  
            self.nexthop = nexthops
        else:
         #If specific route does not exist: aka, validate if default route exists:
            prefix = "0.0.0.0 0.0.0.0"
            iproute_cmd = "show ip route {} {}".format(prefix, vrf_mode, self.vrf)
            iproute_output = radkit_cli.get_single_output_genie(self.hostname,iproute_cmd,service)
            if iproute_output is None:
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
                for i in paths:
                    nexthops.append(paths[i]['nexthop'])  
                self.nexthop = nexthops           
       
