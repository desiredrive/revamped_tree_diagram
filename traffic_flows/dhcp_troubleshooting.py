from pprint import pformat

import radkit_cli
from device_profiler import Device
from switchingmodules.maclearning import mac_learning

class EdgeNodeClassifier:
    def __init__(self, mgmtip, interface):
        self.mgmtip = mgmtip
        self.client_interface = interface

    def device_profiler(self, catc,service):
        devprof = Device(self.mgmtip,catc)
        devprof.profile_device(service)
        self.profiled_device = devprof

    def maclearning(self, vlan, service):
        hostname = self.profiled_device.hostname
        print("Verifying Mac Address: {} ...\n".format(hostname))
        mac_learning_info = mac_learning(hostname)
        interface = self.client_interface
        mac_learning_info.mac_learning_interface(interface, vlan, service)
        self.mac_learning_info = mac_learning_info


def edge_node_profiler(mgmtip, interface, catc_name, vlan, service):
        print("Edge Node Validation...\n")

        edge_node_device = EdgeNodeClassifier(mgmtip, interface)
        edge_node_device.device_profiler(catc_name, service)
        hostname = edge_node_device.profiled_device.hostname
        print("Profiled device {}:\n".format(hostname))
        print(pformat(vars(edge_node_device.profiled_device), indent=4, width=1, sort_dicts=False))

        if edge_node_device.profiled_device.isfabric is True and edge_node_device.profiled_device.edge is True:
            edge_node_device.maclearning(vlan, service)


            print(edge_node_device)

