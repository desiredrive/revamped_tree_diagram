from radkit_cli import get_single_output_genie, get_any_single_output

import re
from typing import Any, Dict, List
from typing import Optional, Tuple

def parse_bgp_neighbor_route_maps(output: str, neighbor_ip: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Parses neighbor route-maps from CLI text and returns:
      (inbound_route_map, outbound_route_map)

    Matches lines like:
      neighbor <ip> route-map <NAME> in
      neighbor <ip> route-map <NAME> out
    """
    inbound = None
    outbound = None

    if not output or not isinstance(output, str):
        return inbound, outbound

    ip = re.escape(neighbor_ip)

    for line in output.splitlines():
        line = line.strip()

        m = re.match(rf"^neighbor\s+{ip}\s+route-map\s+(\S+)\s+in$", line, re.IGNORECASE)
        if m:
            inbound = m.group(1)
            continue

        m = re.match(rf"^neighbor\s+{ip}\s+route-map\s+(\S+)\s+out$", line, re.IGNORECASE)
        if m:
            outbound = m.group(1)
            continue

    return inbound, outbound

def parse_show_ip_protocols_vrf(output: str, vrf: str = "default") -> dict:
    """
    Parses:
      show ip protocols vrf <VRF>

    Includes:
      - BGP section into a structure aligned with Genie-style output
      - Neighbor route-map column (if present)
      - BGP summary-only attribute-map names from "Unicast Aggregate Generation"
      - IGP sync status (igp_sync)
      - Redistributing values
      - Distance values (external/internal/local) via preference.multi_values
    """
    result = {
        "protocols": {
            "bgp": {
                "instance": {
                    "default": {
                        "bgp_id": None,
                        "vrf": {
                            vrf: {
                                "address_family": {
                                    "ipv4": {
                                        "outgoing_filter_list": None,
                                        "incoming_filter_list": None,
                                        "igp_sync": None,
                                        "automatic_route_summarization": None,
                                        "redistributing": [],  # <- added
                                        "neighbors": {},
                                        "maximum_path": None,
                                        "routing_information_sources": {},
                                        "preference": {"multi_values": {}},
                                        "unicast_aggregate_generation": [],
                                    }
                                }
                            }
                        },
                    }
                }
            }
        }
    }

    af = result["protocols"]["bgp"]["instance"]["default"]["vrf"][vrf]["address_family"]["ipv4"]

    in_bgp = False
    in_neighbors_table = False
    in_routing_sources = False
    in_unicast_agg = False

    for raw in (output or "").splitlines():
        line = raw.rstrip()

        # Enter BGP section
        m = re.match(r'^\s*Routing Protocol is "bgp\s+(\d+)"\s*$', line)
        if m:
            in_bgp = True
            in_neighbors_table = False
            in_routing_sources = False
            in_unicast_agg = False
            result["protocols"]["bgp"]["instance"]["default"]["bgp_id"] = int(m.group(1))
            continue

        if not in_bgp:
            continue

        # Filter lists
        m = re.match(r"^\s*Outgoing update filter list for all interfaces is (.+)$", line)
        if m:
            af["outgoing_filter_list"] = m.group(1).strip()
            continue

        m = re.match(r"^\s*Incoming update filter list for all interfaces is (.+)$", line)
        if m:
            af["incoming_filter_list"] = m.group(1).strip()
            continue

        # IGP sync + autosummary booleans
        if "IGP synchronization is" in line:
            af["igp_sync"] = "disabled" not in line.lower()
            continue

        if "Automatic route summarization is" in line:
            af["automatic_route_summarization"] = "disabled" not in line.lower()
            continue

        # Redistributing
        m = re.match(r"^\s*Redistributing:\s*(.+)$", line, re.IGNORECASE)
        if m:
            items = [x.strip() for x in m.group(1).split(",") if x.strip()]
            # de-dup preserve order
            seen = set(af["redistributing"])
            for it in items:
                if it not in seen:
                    af["redistributing"].append(it)
                    seen.add(it)
            continue

        # Unicast Aggregate Generation block
        if re.match(r"^\s*Unicast Aggregate Generation:\s*$", line):
            in_unicast_agg = True
            continue

        if in_unicast_agg:
            if re.match(r"^\s*Neighbor\(s\):\s*$", line) or re.match(r"^\s*Maximum path:\s*\d+\s*$", line):
                in_unicast_agg = False
            else:
                m = re.match(r"^\s*(\S+)\s+summary-only\s+attribute-map\s+(\S+)\s*$", line)
                if m:
                    af["unicast_aggregate_generation"].append(
                        {"prefix": m.group(1), "attribute_map": m.group(2), "summary_only": True}
                    )
                continue

        # Neighbor table starts
        if re.match(r"^\s*Neighbor\(s\):\s*$", line):
            in_neighbors_table = True
            in_routing_sources = False
            continue

        # Skip neighbor table header lines
        if in_neighbors_table and ("Address" in line and "RouteMap" in line):
            continue

        # Neighbor table row
        if in_neighbors_table:
            m = re.match(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+.*\s+(\S+)\s*$", line)
            if m:
                nbr = m.group(1)
                last_col = m.group(2)
                af["neighbors"].setdefault(nbr, {})["route_map"] = last_col
                continue

            m = re.match(r"^\s*Maximum path:\s*(\d+)\s*$", line)
            if m:
                in_neighbors_table = False
                af["maximum_path"] = int(m.group(1))
                continue

        # Maximum path
        m = re.match(r"^\s*Maximum path:\s*(\d+)\s*$", line)
        if m:
            af["maximum_path"] = int(m.group(1))
            continue

        # Routing Information Sources
        if re.match(r"^\s*Routing Information Sources:\s*$", line):
            in_routing_sources = True
            in_neighbors_table = False
            continue

        if in_routing_sources:
            if "Gateway" in line and "Distance" in line and "Last Update" in line:
                continue
            m = re.match(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+(\S+)\s*$", line)
            if m:
                gw = m.group(1)
                af["routing_information_sources"][gw] = {
                    "neighbor_id": gw,
                    "distance": int(m.group(2)),
                    "last_update": m.group(3),
                }
                continue

        # Distance preferences (external/internal/local)
        m = re.match(r"^\s*Distance:\s*external\s+(\d+)\s+internal\s+(\d+)\s+local\s+(\d+)\s*$", line)
        if m:
            af["preference"]["multi_values"] = {
                "external": int(m.group(1)),
                "internal": int(m.group(2)),
                "local": int(m.group(3)),
            }
            continue

    return result

def parse_bgp_update_groups(output: str) -> Dict[str, Any]:
    """
    Parses:
      show bgp vpnv4 unicast vrf <vrf> update-group

    Returns:
      {
        "update_groups": [
          {
            "update_group": 2,
            "session_type": "external",
            "address_family": "VPNv4 Unicast",
            "topology": "Campus",
            "members": ["172.19.254.6"]
          }
        ]
      }
    """
    res: Dict[str, Any] = {"update_groups": []}
    if not output or not isinstance(output, str):
        return res

    current = None
    in_members = False

    for line in output.splitlines():
        line = line.rstrip()

        m = re.match(r"^BGP version\s+\d+\s+update-group\s+(\d+),\s*([^,]+),\s*Address Family:\s*(.+)$", line)
        if m:
            if current:
                res["update_groups"].append(current)
            current = {
                "update_group": int(m.group(1)),
                "session_type": m.group(2).strip(),
                "address_family": m.group(3).strip(),
                "topology": None,
                "members": [],
            }
            in_members = False
            continue

        if current is None:
            continue

        m = re.search(r"Topology:\s*([^,]+),", line)
        if m:
            current["topology"] = m.group(1).strip()
            continue

        if re.match(r"^\s*Has\s+\d+\s+member", line):
            in_members = True
            continue

        if in_members:
            # member lines are typically indented IPs
            mm = re.match(r"^\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s*$", line)
            if mm:
                current["members"].append(mm.group(1))
            elif line.strip() and not line.startswith(" "):
                in_members = False  # conservative end

    if current:
        res["update_groups"].append(current)

    return res

class BGP:
    def __init__(self,device, vrf):
        self.hostname = device
        self.vrf = vrf
    def bgp_sum_vrf(self,service):
        hostname = self.hostname
        vrf = self.vrf
        bgpsumcmd = f"show bgp vpnv4 unicast vrf {vrf} summary"
        bgpsumop = get_single_output_genie(hostname,bgpsumcmd,service)
        self.bgsum = bgpsumop

    def bgp_rib_vrf(self,route,service):
        hostname = self.hostname
        vrf = self.vrf
        bgproutecmd =  f"show bgp vpnv4 unicast vrf {vrf} {route}"
        bgprouteop = get_single_output_genie(hostname,bgproutecmd,service)
        self.route = bgprouteop

    def bgp_defaultroute_vrf(self,service):
        hostname = self.hostname
        vrf = self.vrf
        bgproutecmd =  f"show bgp vpnv4 unicast vrf {vrf} 0.0.0.0/0"
        bgprouteop = get_single_output_genie(hostname,bgproutecmd,service)
        self.defroute = bgprouteop

    def bgp_updategroups_vrf(self,service):
        hostname = self.hostname
        vrf = self.vrf
        bgpupdcmd =  f"show bgp vpnv4 unicast vrf {vrf} update-group"
        bgpupdcop = get_any_single_output(hostname,bgpupdcmd,service)
        self.bgpupdgroups = parse_bgp_update_groups(bgpupdcop)

    def bgp_ipprotocols(self,service):
        hostname = self.hostname
        vrf = self.vrf
        ipprotocmd =  f"show ip protocols vrf {vrf}"
        ipprotoop = get_any_single_output(hostname,ipprotocmd,service)
        ipprotoop = parse_show_ip_protocols_vrf(ipprotoop)
        self.ipprotocols = ipprotoop

class BGPNeighbor:
    def __init__(self,device, neighborip, vrf):
        self.hostname = device
        self.vrf = vrf
        self.neighborip = neighborip

    def bgp_neighbor_vrf(self, service):
        hostname = self.hostname
        vrf = self.vrf
        neighborip = self.neighborip
        bgpneicmd = f"show bgp vpnv4 unicast vrf {vrf} neighbor {neighborip}"
        bgpneiop = get_single_output_genie(hostname,bgpneicmd,service)
        bgpneicmd = f"show bgp vpnv4 unicast vrf {vrf} neighbor {neighborip} | i Default weight|Route map for incoming"
        bgpweightop = get_any_single_output(hostname,bgpneicmd,service)
        m = re.search(r"\bDefault weight\s+(\d+)\b", bgpweightop or "", re.IGNORECASE)
        weight = int(m.group(1)) if m else 0
        bgpneiop["default_weight"] = weight
        self.bgpneighbor = bgpneiop

    def bgp_neighbor_route_maps(self,service):
        hostname = self.hostname
        vrf = self.vrf
        neighborip = self.neighborip
        bgpneicmd = f"show run vrf {vrf} | i {neighborip}"
        bgpneiop = get_any_single_output(hostname,bgpneicmd,service)
        bgpneiop = parse_bgp_neighbor_route_maps(bgpneiop, neighborip)
        self.bgpneiroutemaps = bgpneiop

    def bgp_advroutes_vrf(self, service):
        hostname = self.hostname
        vrf = self.vrf
        neighborip = self.neighborip
        bgpneicmd = f"show bgp vpnv4 unicast vrf {vrf} neighbor {neighborip} advertised-routes"
        bgpneiop = get_single_output_genie(hostname,bgpneicmd,service)
        self.advertisdedroutes = bgpneiop