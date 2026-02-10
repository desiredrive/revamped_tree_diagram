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

