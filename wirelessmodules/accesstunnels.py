from pprint import pformat

from radkit_cli import get_any_single_output, get_single_output_genie
import re

from routingmodules.cef import IPCef, physical_recursion
from switchingmodules.cdp import CDPinfo


class AccessTunnel:
    def __init__(self,device):
        self.hostname = device
        self.accesstunnelstate = 'down'
        self.accesstunnelname = None
        self.accesstunnelsrcip = None
        self.accesstunneldstip = None
        self.accesstunnelsrcport = None
        self.accesstunneldstport = None
        self.accesstunnelapname = None
        self.accesstunnelphyport = None
        self.accesstunneliifid = None
        self.accesstunneluptime = None
        self.accesstunnelradiomac = None
        self.apcdpneighbor = None

    def accesstunnelinterface(self,acintf,service):
        hostname = self.hostname
        showintfcmd = f"show interface {acintf}"
        showintfop = get_single_output_genie(hostname, showintfcmd,service)
        # Find the first AccessTunnel* interface in the dict
        data = showintfop
        tunnel_name = next((k for k in data if isinstance(k, str) and k.lower().startswith("accesstunnel")), None)
        intf = (data.get(tunnel_name, {}) or {}) if tunnel_name else {}

        # tunnel endpoints (split ip:port)
        src = (intf.get("tunnel_source_ip") or "")
        dst = (intf.get("tunnel_destination_ip") or "")

        tunnel_source_ip, source_port = (src.split(":", 1) + [""])[:2]
        tunnel_destination_ip, dst_port = (dst.split(":", 1) + [""])[:2]

        source_port = int(source_port) if str(source_port).isdigit() else None
        dst_port = int(dst_port) if str(dst_port).isdigit() else None

        # radio MAC from description
        desc = intf.get("description") or ""
        m = re.search(r"Radio\s+MAC:\s*([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})", desc, re.IGNORECASE)
        radio_mac = m.group(1).lower() if m else None

        # is up
        state = (str(intf.get("oper_status") or "").lower() == "up") and (
                    str(intf.get("line_protocol") or "").lower() == "up")

        #print (tunnel_name,tunnel_source_ip,source_port,tunnel_destination_ip,dst_port,radio_mac,state)
        showatsumcmd = f"show access-tunnel summary"
        showatsumop = get_single_output_genie(hostname, showatsumcmd,service)

        name = None
        if_id = None
        uptime = None
        for if_name, attrs in (showatsumop.get("name", {}) or {}).items():
            if (attrs.get("ap_ip") or "").strip() == tunnel_destination_ip:
                name = if_name
                if_id = attrs.get("ifid")
                uptime = attrs.get("up_time")

        #print (name,if_id,uptime)
        route = IPCef(tunnel_destination_ip, None,hostname)
        route.get_cef_internal(service)

        phy = physical_recursion(route,hostname)
        phy.get_physical_interfaces(service,"X")
        interface = phy.total_phys

        cdp_neighbor = CDPinfo(hostname)
        cdp_neighbor.cdpneighborinterface(interface[0],service)
        cdpinfo = cdp_neighbor.cdpneighbors

        self.accesstunnelstate = state
        self.accesstunnelname = tunnel_name
        self.accesstunnelsrcip = tunnel_source_ip
        self.accesstunneldstip = tunnel_destination_ip
        self.accesstunnelsrcport = source_port
        self.accesstunneldstport = dst_port
        self.accesstunnelapname = name
        self.accesstunnelphyport = interface
        self.accesstunneliifid = if_id
        self.accesstunneluptime = uptime
        self.accesstunnelradiomac = radio_mac
        self.apcdpneighbor = cdpinfo

    def accesstunnelbyip(self,apip,service):
        hostname = self.hostname
        showatsumcmd = f"show access-tunnel summary"
        showatsumop = get_single_output_genie(hostname, showatsumcmd, service)
        accesstunneldstip = apip
        name = None
        if_id = None
        uptime = None
        for if_name, attrs in (showatsumop.get("name", {}) or {}).items():
            if (attrs.get("ap_ip") or "").strip() == accesstunneldstip:
                name = if_name
                if_id = attrs.get("ifid")
                uptime = attrs.get("up_time")

        acintf = name
        showintfcmd = f"show interface {acintf}"
        showintfop = get_single_output_genie(hostname, showintfcmd, service)
        # Find the first AccessTunnel* interface in the dict
        data = showintfop
        tunnel_name = next((k for k in data if isinstance(k, str) and k.lower().startswith("accesstunnel")), None)
        intf = (data.get(tunnel_name, {}) or {}) if tunnel_name else {}

        # tunnel endpoints (split ip:port)
        src = (intf.get("tunnel_source_ip") or "")
        dst = (intf.get("tunnel_destination_ip") or "")

        tunnel_source_ip, source_port = (src.split(":", 1) + [""])[:2]
        tunnel_destination_ip, dst_port = (dst.split(":", 1) + [""])[:2]

        source_port = int(source_port) if str(source_port).isdigit() else None
        dst_port = int(dst_port) if str(dst_port).isdigit() else None

        # radio MAC from description
        desc = intf.get("description") or ""
        m = re.search(r"Radio\s+MAC:\s*([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})", desc, re.IGNORECASE)
        radio_mac = m.group(1).lower() if m else None

        # is up
        state = (str(intf.get("oper_status") or "").lower() == "up") and (
                str(intf.get("line_protocol") or "").lower() == "up")

        route = IPCef(tunnel_destination_ip, None, hostname)
        route.get_cef_internal(service)

        phy = physical_recursion(route, hostname)
        phy.get_physical_interfaces(service, "X")
        interface = phy.total_phys

        if isinstance(interface, list):
            interface = interface[0]

        cdp_neighbor = CDPinfo(hostname)
        cdp_neighbor.cdpneighborinterface(interface[0], service)
        cdpinfo = cdp_neighbor.cdpneighbors

        self.accesstunnelstate = state
        self.accesstunnelname = tunnel_name
        self.accesstunnelsrcip = tunnel_source_ip
        self.accesstunneldstip = tunnel_destination_ip
        self.accesstunnelsrcport = source_port
        self.accesstunneldstport = dst_port
        self.accesstunnelapname = name
        self.accesstunnelphyport = interface
        self.accesstunneliifid = if_id
        self.accesstunneluptime = uptime
        self.accesstunnelradiomac = radio_mac
        self.apcdpneighbor = cdpinfo

        return None



def parse_access_tunnel_statistics(output):
    """Parse `show access-tunnel statistics`.

    The counters sit under a `Statistics:` block, and the max is carried in
    the counter's own label rather than on a line of its own::

        Statistics:
            Number of Created Access Tunnels (max 200): 1
            Number of Deleted Access Tunnels: 0
            Number of Active Access Tunnels (max 200): 1

    Three tables follow -- active tunnels, the last AP IP/MAC changes, and
    deleted tunnels -- sharing one row shape. A leading `*` on the AP IP
    means that tunnel's AP IP and MAC have changed at least once during this
    switch's uptime; the device says so in its own legend above the table.

    Returns {"created", "deleted", "active", "max", "tunnels": [...]}, where
    each tunnel is {"name", "ifid", "ap_ip", "ip_changed", "vrf_id", "mac",
    "uptime", "times"}. Counters are None when absent rather than 0, so a
    parse failure never reads as an empty fabric.
    """
    res = {"created": None, "deleted": None, "active": None, "max": None,
           "tunnels": []}
    if not output or not isinstance(output, str):
        return res

    def _count(label):
        m = re.search(r"Number of " + label + r" Access Tunnels"
                      r"(?:\s*\(max\s+(\d+)\))?\s*:\s*(\d+)", output)
        if not m:
            return None, None
        return int(m.group(2)), (int(m.group(1)) if m.group(1) else None)

    res["created"], cmax = _count("Created")
    res["deleted"], _ = _count("Deleted")
    res["active"], amax = _count("Active")
    # Both counters carry the same platform limit; either will do.
    res["max"] = amax if amax is not None else cmax

    # Only the ACTIVE table is read. "Last AP IP and MAC Changes" repeats
    # rows already listed there, and "Deleted Access Tunnels" is a different
    # thing entirely -- its last column is Downtime, not Uptime -- so folding
    # them together would double-count a live tunnel and mix a dead one in.
    m = re.search(r"Active Access Tunnels:(.*?)(?:Last AP IP|Deleted Access"
                  r" Tunnels:|\Z)", output, re.S)
    body = m.group(1) if m else ""

    row = re.compile(
        r"^(?P<name>\S+)\s+"
        r"(?P<ifid>0x[0-9a-fA-F]+)\s+"
        # The `*` is attached to the address with no space between them.
        r"(?P<star>\*?)(?P<ap_ip>\d+\.\d+\.\d+\.\d+)\s+"
        r"(?P<vrf>\d+)\s+"
        r"(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
        r"(?P<uptime>\d+\s+day,\s+[\d:]+)"
        r"(?:\s*\((?P<times>\d+)\))?")

    for line in body.splitlines():
        mm = row.match(line.strip())
        if not mm:
            continue
        res["tunnels"].append({
            "name": mm.group("name"),
            "ifid": mm.group("ifid"),
            "ap_ip": mm.group("ap_ip"),
            # The device's own legend: "* denotes AP IP and MAC change".
            "ip_changed": mm.group("star") == "*",
            "vrf_id": int(mm.group("vrf")),
            "mac": mm.group("mac").lower(),
            "uptime": re.sub(r"\s+", " ", mm.group("uptime")).strip(),
            "times": int(mm.group("times")) if mm.group("times") else None,
        })
    return res
