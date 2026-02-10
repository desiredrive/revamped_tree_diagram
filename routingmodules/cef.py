from pprint import pformat

from switchingmodules import etherchannel
from switchingmodules.arp import arp_modules
from switchingmodules.maclearning import mac_learning
from re import compile, search, IGNORECASE
from radkit_cli import logging_info, logging_error, get_single_output_genie, get_any_single_output
import sys
from typing import Optional

def ip_cef_collection(ipcef,step):
    hostname = ipcef.hostname
    collection_summary = "Prefix: {}, VRF: {}, NextHop(s): {}, Sources: {}".format(ipcef.ip,ipcef.vrf,ipcef.nexthops,ipcef.sources)
    string = "Result: Success"
    logging_info(step, "Underlay", "[CEF]",hostname, collection_summary)
    logging_info(step, "Underlay", "[CEF]",hostname, string)

def phy_cef_collection(interface,step):
    hostname = interface.hostname
    collection_summary = "Interface: {}, OperState: {}, MTU: {}, OutputDrops: {}, IQDrops: {}".format(interface.interface,interface.operstate,interface.mtu,interface.outputdrops,interface.iqdrops)
    string = "Result: Success"
    logging_info(step, "Underlay", "[PHY]",hostname, collection_summary)
    logging_info(step, "Underlay", "[PHY]",hostname, string)

def parse_cef_sgt(output: str) -> Optional[int]:
    """
    Extracts SGT from lines like:
      ... [SGT 15 S D]
    Returns int SGT or None if not present.
    """
    for line in (output or "").splitlines():
        m = search(r"\[\s*SGT\s+(\d+)\b", line, IGNORECASE)
        if m:
            return int(m.group(1))
    return 0

def parse_mpls_nexthops(output):
    nh_list = []

    # 1. Safely navigate to the prefix level
    # We use next(iter(...)) to get the first VRF and Prefix found in the dict
    vrf_dict = output.get('vrf', {})
    vrf_name = next(iter(vrf_dict.keys()), None)
    if not vrf_name:
        return []

    af_dict = vrf_dict[vrf_name].get('address_family', {}).get('ipv4', {})
    prefix_dict = af_dict.get('prefix', {})
    prefix_val = next(iter(prefix_dict.keys()), None)
    if not prefix_val:
        return []

    # 2. Access the path_list
    path_list = prefix_dict[prefix_val].get('path_list', {})

    # 3. Iterate through each path group and individual path
    for pl_id, pl_data in path_list.items():
        paths = pl_data.get('path', {})

        for p_id, p_data in paths.items():
            # Extract Nexthop IP (often stored as 'address' or 'nexthop')
            nh_ip = p_data.get('address') or p_data.get('nexthop')

            # Extract OIF (Handle if it's a dict or a string)
            oif_raw = p_data.get('interface')
            if isinstance(oif_raw, dict):
                oif_name = next(iter(oif_raw.keys()), None)
            else:
                oif_name = oif_raw

            # 4. Construct the entry
            entry = {
                "nexthop": nh_ip,
                "oif": oif_name
            }

            # 5. Check for 'unusable' status in flags or type
            flags = str(p_data.get('flags', '')).lower()
            p_type = str(p_data.get('type', '')).lower()

            if 'unusable' in flags or 'unusable' in p_type:
                entry["unusable"] = True

            nh_list.append(entry)

    return nh_list

def is_mpls_labeled(cef_dict):
    """
    Precisely detects if a CEF entry is currently being MPLS-labeled in the data plane.
    Returns True only if the output chain contains labels or the path is marked as 'must-be-lbld'.
    """
    # 1. Navigate to the prefix data safely
    vrf_dict = cef_dict.get('vrf', {})
    vrf_name = next(iter(vrf_dict.keys()), None)
    if not vrf_name:
        return False

    af_dict = vrf_dict[vrf_name].get('address_family', {}).get('ipv4', {})
    prefix_dict = af_dict.get('prefix', {})
    prefix_val = next(iter(prefix_dict.keys()), None)
    if not prefix_val:
        return False

    prefix_data = prefix_dict[prefix_val]

    # 2. Check the Output Chain (The most accurate indicator)
    output_chain = prefix_data.get('output_chain', {})

    # If 'label' is present, the packet is being encapsulated with MPLS
    if 'label' in output_chain:
        return True

    # If 'IP adj' is present, it's a standard IP path (even if rlbls is in the header)
    # We check the keys of the output_chain for the string "IP adj"
    if any("IP adj" in str(key) for key in output_chain.keys()):
        return False

    # 3. Check for mandatory labeling flag in the path list
    # This is the definitive signal from the BGP VPNv4 process
    path_list = prefix_data.get('path_list', {})
    for pl_data in path_list.values():
        for p_data in pl_data.get('path', {}).values():
            flags = str(p_data.get('flags', '')).lower()
            if 'must-be-lbld' in flags:
                return True

    # 4. Default to False (rlbls is ignored as it can appear on valid VLAN paths)
    return False


class IPCef:

    def __init__(self, ip, vrf, device):
        self.ip = ip
        self.vrf = vrf
        self.hostname = device

    def get_cef_internal(self,service):
        #Route_Inspection:
        #print("Processing CEF Internal Information for prefix: {}\n".format(self.ip))

        if self.vrf == "default":
            vrf_mode = ""
        elif self.vrf is None:
            vrf_mode = ""
        elif self.vrf == "None":
            vrf_mode = ""
        else:
            vrf_mode = "vrf "+self.vrf+" "
        
        #show ip route command:
        ipcefint_cmd = "show ip cef {} {} internal".format(vrf_mode,self.ip)
        ipcefint_op = get_single_output_genie(self.hostname,ipcefint_cmd,service)
        ismpls = is_mpls_labeled(ipcefint_op)
        #VRF utilization
        prefix = None
        if vrf_mode == "":
            vrf = 'default'
        else:
            vrf = self.vrf
        addipv4 = 'ipv4'
        cefpath = ipcefint_op['vrf'][vrf]['address_family'][addipv4]['prefix']
        for i in cefpath:
            prefix = i
            self.prefix = prefix
        cefpath = cefpath[prefix]

        #CEF sources
        try:
            self.sources = cefpath['sources']
        except KeyError:
            self.sources = None
        
        try:
            subblocks = cefpath['subblocks']
        except KeyError:
            subblocks = []

        #LISP SMR detection

        try:
            if any(x in "LISP" for x in subblocks):
                self.lispsmr = (cefpath['subblocks']['LISP']['smr_enabled'])
        except TypeError:
            new_subblock = None
            for i in subblocks:
                new_subblock = i
            if any(x in "LISP" for x in subblocks[new_subblock]):
                self.lispsmr = (cefpath['subblocks'][new_subblock]['LISP']['smr_enabled'])

        #Ifnums readily available?
        try:
            ifnums = cefpath['ifnums']
            no_ifnums = False
        except KeyError:
            no_ifnums = True
            ifnums = []

        #CEF Special Type exclusion:
        special_types = ['Spc','DRH']
        special_flag = False
        self.ismpls = False
        #Next Hop Calculation
        if self.sources is not None:
            if ismpls is True:
                self.ismpls = True
                nhlist = parse_mpls_nexthops(ipcefint_op)
                self.nexthops = nhlist
            if any (x in self.sources for x in special_types):
                special_flag = True
            if (no_ifnums is True) and (special_flag is False):
                path_list = None
                paths = []
                nexthops = []
                nhlist = []
                cefpath_list = cefpath['path_list']
                for i in cefpath_list:
                    path_list = i
                cefpath_list = cefpath_list[path_list]
                for i in cefpath_list['path']:
                    paths.append(i)
                cefpath_list = cefpath_list['path']
                for i in paths:
                    nexthops.append(cefpath_list[i]['nexthop'])
                for i in nexthops:
                    for j in i:
                        oif = i[j]['outgoing_interface']
                        nexthop_format = {'nexthop' : j, 'oif': oif}
                        nhlist.append(nexthop_format)
                self.nexthops = nhlist
            elif (special_flag is False):
                nhlist = []
                for i in ifnums:
                    oif = i
                    try:
                        j = ifnums[oif]['address']
                        nexthop_format = {'nexthop' : j, 'oif': oif}
                        nhlist.append(nexthop_format)
                    except KeyError:
                        nexthop_format = {'nexthop' : None, 'oif': oif}
                        nhlist.append(nexthop_format)
                self.nexthops = nhlist
            elif any("LISP" in x for x in self.sources):
                # LISP Glean Scenario
                ipcef_cmd = "show ip cef {} {}".format(vrf_mode, self.ip)
                ipcef_op = get_single_output_genie(self.hostname, ipcef_cmd, service)
                if ipcef_op is not None:
                    vanillacefpath = ipcef_op['vrf'][vrf]['address_family'][addipv4]['prefix']
                    nexthops = []
                    nhlist = []
                    for prefix in vanillacefpath:
                        cefpath_list = vanillacefpath[prefix]
                        for i in cefpath_list:
                            nexthops.append(cefpath_list[i])
                        for i in nexthops:
                            for j in i:
                                oif = i[j]['outgoing_interface']
                                nexthop_format = {'nexthop': j, 'oif': oif}
                                nhlist.append(nexthop_format)
                    self.nexthops = nhlist
            elif len(ifnums) != 0:
                nhlist = []
                for oif in (ifnums or {}):
                    oif_raw = oif
                    if isinstance(oif_raw, dict):
                        oif_name = next(iter(oif_raw.keys()), None)  # e.g. "Vlan3002"
                    else:
                        oif_name = oif_raw
                    try:
                        j = ifnums[oif_raw].get("address")
                        nexthop_format = {"nexthop": j, "oif": oif_name}
                    except (KeyError, AttributeError, TypeError):
                        nexthop_format = {"nexthop": None, "oif": oif_name}
                    nhlist.append(nexthop_format)
                self.nexthops = nhlist
            else:
                # Empty next hop! (Special Adjacency???)
                self.nexthops = None
        else:
            rib_flag = cefpath['rib']
            # CEF Type: Connected
            if "C" in rib_flag:
                ipcef_cmd = "show ip cef {} {}".format(vrf_mode,self.ip)
                ipcef_op = get_single_output_genie(self.hostname, ipcef_cmd, service)
                if ipcef_op is not None:
                    vanillacefpath = ipcef_op['vrf'][vrf]['address_family'][addipv4]['prefix']
                    nexthops = []
                    nhlist = []
                    for prefix in vanillacefpath:
                        cefpath_list = vanillacefpath[prefix]
                        for i in cefpath_list:
                            nexthops.append(cefpath_list[i])
                        for i in nexthops:
                            for j in i:
                                oif = i[j]['outgoing_interface']
                                nexthop_format = {'nexthop': j, 'oif': oif}
                                nhlist.append(nexthop_format)
                    self.nexthops = nhlist

    def get_cef_detail(self, service):

        if self.vrf == "default":
            vrf_mode = ""
            self.vrf = 'default'
        elif self.vrf is None:
            vrf_mode = ""
            self.vrf  = 'default'
        elif self.vrf == "None":
            vrf_mode = ""
            self.vrf  = 'default'
        else:
            vrf_mode = "vrf " + self.vrf + " "

        # show ip route command:
        ipcefint_cmd = "show ip cef {} {} detail".format(vrf_mode, self.ip)
        ipcefint_op = get_single_output_genie(self.hostname, ipcefint_cmd, service)
        cef_data = ipcefint_op
        vrf_container = cef_data.get("vrf", {})

        for vrf_name, vrf_content in vrf_container.items():
            prefixes_dict = (
                vrf_content.get("address_family", {})
                .get("ipv4", {})
                .get("prefix", {})
            )

            for prefix_str, prefix_data in prefixes_dict.items():
                flags = prefix_data.get("flags", [])

                formatted_nexthops = []
                raw_nexthops = prefix_data.get("nexthop", {})

                for nh_ip, nh_info in raw_nexthops.items():
                    oif_dict = nh_info.get("outgoing_interface", {})

                    oif_name = next(iter(oif_dict)) if oif_dict else "Unknown"

                    formatted_nexthops.append({
                        "nexthop": nh_ip,
                        "oif": oif_name
                    })


                self.prefix = prefix_str
                self.flags = flags
                self.nexthops = formatted_nexthops

    def sgtfromcef(self,service):
        hostname = self.hostname
        if self.vrf == "default":
            vrf_mode = ""
        elif self.vrf is None:
            vrf_mode = ""
        elif self.vrf == "None":
            vrf_mode = ""
        else:
            vrf_mode = "vrf " + self.vrf + " "
        ip = self.ip
        # show ip route command:
        ipcefint_cmd = "show ip cef {} {} internal | i SGT".format(vrf_mode, ip)
        ipcefint_op = get_any_single_output(self.hostname, ipcefint_cmd, service)
        ipcefint_op = parse_cef_sgt(ipcefint_op)
        self.sgt = ipcefint_op

class physical_recursion():

    def __init__(self, cef_hops, device):
        self.hostname = device
        self.vrf = cef_hops.vrf
        self.nexthops = cef_hops.nexthops

    def get_physical_interfaces(self, service, step):
        process = 'CEF'
        hostname = self.hostname
        total_phys = []

        for i in self.nexthops:
            nhphys = []
            interface = i['oif']

            if "LISP" in interface:
                # LISP Interface has no physical interface
                continue

            elif "channel" in interface:
                phys = etherchannel.etherchannel_parse(interface, self.hostname)
                phys.get_active_etherchannel_ports(service)
                phys = phys.port_list
                if isinstance(phys, list):
                    nhphys.extend(phys)
                else:
                    nhphys.append(phys)

            elif "Vlan" in interface:
                nhop = i['nexthop']
                intf = i['oif']
                vid_match = search(r"(?<=Vlan)[0-9]{1,4}", intf)
                vid = vid_match.group() if vid_match else None

                arp = arp_modules(self.vrf, self.hostname)
                arp.arp_resolution_single_ip(nhop, intf, service)

                try:
                    mac = arp.mac
                except (KeyError, AttributeError):
                    subprocess = "[ARP]"
                    error = "CEF - Incomplete Adjacency"
                    message = f"ARP Is Incomplete for next hop {nhop}, fix the ARP entry for this IP address in device: {hostname}"
                    logging_error(step, process, subprocess, hostname, error)
                    logging_info(step, process, subprocess, hostname, message)
                    sys.exit(f"Error: {error} | {message}")

                mac_ports = mac_learning(self.hostname)
                mac_ports.mac_learning_mac(mac, vid, service)

                if mac_ports is None:
                    subprocess = "[macLearning]"
                    error = "CEF - No Layer2 Recursion"
                    message = f"MAC address {mac} is not learnt in any port, troubleshoot the MAC learning event in device: {hostname}"
                    logging_error(step, process, subprocess, hostname, error)
                    logging_info(step, process, subprocess, hostname, message)
                    sys.exit(f"Error: {error} | {message}")

                # --- FIX: Robust Port Extraction ---
                # This ensures strings like "Te1/0/17" aren't iterated character-by-character
                ports = []
                if hasattr(mac_ports, 'port') and mac_ports.port:
                    val = mac_ports.port
                    ports = [val] if isinstance(val, str) else val
                elif hasattr(mac_ports, 'ports') and mac_ports.ports:
                    val = mac_ports.ports
                    ports = [val] if isinstance(val, str) else val
                elif isinstance(mac_ports, list):
                    ports = mac_ports
                elif isinstance(mac_ports, str):
                    ports = [mac_ports]

                for port in ports:
                    if "Po" in port:
                        phys = etherchannel.etherchannel_parse(port, self.hostname)
                        phys.get_active_etherchannel_ports(service)
                        phys = phys.port_list
                        if isinstance(phys, list):
                            nhphys.extend(phys)
                        else:
                            nhphys.append(phys)
                    else:
                        nhphys.append(port)

            else:
                # Direct physical interface (e.g., Gi1/0/1)
                nhphys.append(interface)

            # Validation and final assignment
            if len(nhphys) == 0:
                subprocess = "[physicalPort]"
                error = "CEF - No Physical Port Recursion"
                message = f"Unable to resolve the physical port for next-hop {i}, validate the physical port recursion for ARP and MAC in device: {hostname}"
                logging_error(step, process, subprocess, hostname, error)
                logging_info(step, process, subprocess, hostname, message)
                sys.exit(f"Error: {error} | {message}")
            else:
                total_phys.append(nhphys)

        self.total_phys = total_phys
        return total_phys



class VRF:
    def __init__(self,device,vrf):
        self.hostname = device
        self.vrf = vrf
    def vrfdetail(self,service):
        hostname = self.hostname
        vrfdetcmd = f"show vrf detail {self.vrf}"
        vrfdetop = get_single_output_genie(hostname,vrfdetcmd,service)
        vrf_data = next(iter((vrfdetop or {}).values()), {})
        self.vrfdetailed = vrf_data

