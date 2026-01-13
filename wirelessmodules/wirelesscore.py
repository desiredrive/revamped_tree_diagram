from radkit_cli import get_single_output_genie, get_any_single_output
import re
import ipaddress
from typing import Any, Dict, List, Optional

#Variable handling

def _safe_int(value: str) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

def _safe_bool_from_true_false(value: str) -> Optional[bool]:
    if value is None:
        return None
    v = value.strip().upper()
    if v == "TRUE":
        return True
    if v == "FALSE":
        return False
    return None

def _parse_supported_rates(raw: str) -> List[float]:
    if not raw:
        return []
    rates = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            rates.append(float(part))
        except ValueError:
            continue
    return rates

def _first_int(raw: str) -> Optional[int]:
    if not raw:
        return None
    m = re.search(r"-?\d+", raw)
    return _safe_int(m.group(0)) if m else None

def _is_ipv4(s: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv4Address)
    except ValueError:
        return False

def _safe_ipv4(s: str) -> Optional[str]:
    try:
        ip = ipaddress.ip_address(s.strip())
        return str(ip) if isinstance(ip, ipaddress.IPv4Address) else None
    except ValueError:
        return None

def _to_int(s: str):
    try:
        return int(s)
    except (TypeError, ValueError):
        return None

def _to_float_list(csv: str):
    vals = []
    for part in csv.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            vals.append(float(part))
        except ValueError:
            pass
    return vals

def _clean(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip())

def _coerce_value(v: str) -> Any:
    v = v.strip()
    if not v:
        return ""
    up = v.upper()

    if up in {"ENABLED", "DISABLED", "ALLOWED", "DENIED", "UP", "DOWN"}:
        return v  # keep original wording

    # integers
    if re.fullmatch(r"\d+", v):
        try:
            return int(v)
        except ValueError:
            return v

    return v

def _coerce(v: str) -> Any:
    v = v.strip()
    if v == "":
        return ""
    u = v.upper()
    if u in {"ENABLED", "DISABLED"}:
        return u
    if re.fullmatch(r"-?\d+", v):
        try:
            return int(v)
        except ValueError:
            return v
    return v

def _put(target: Dict[str, Any], path: List[str], key: str, value: Any) -> None:
    cur = target
    for p in path:
        cur = cur.setdefault(p, {})
    cur[key] = value

def _looks_like_policy_acl_row(line: str) -> bool:
    # Rows have 3 columns separated by multiple spaces and end with ENABLED/DISABLED
    s = line.strip()
    if not s or ":" in s:
        return False
    if not re.search(r"\s{2,}", s):
        return False
    return bool(re.search(r"\b(ENABLED|DISABLED)\s*$", s))
#Parsers

def parse_show_wlan_id(output: str) -> Dict[str, Any]:
    """
    Best-effort parser for:
      show wlan id <id>

    Includes:
      - Common WLAN fields
      - Configured/Operational radio bands
      - Security blocks
      - Fast Transition (FT) attributes
      - mDNS Gateway Status
    """
    result: Dict[str, Any] = {
        "wlan": {},
        "radio_bands": {"configured": {}, "operational": {}},
        "security": {"global": {}, "band_2_4_5": {}, "band_6": {}},
        "fast_transition": {},
        "mdns": {},
    }

    if not output or not isinstance(output, str):
        return {"error": "empty_or_invalid_output", **result}

    lines = [ln.rstrip("\n") for ln in output.splitlines()]

    section: Optional[str] = None
    subsec: Optional[str] = None

    for ln in lines:
        if not ln.strip():
            continue

        m = re.match(r"^\S+#show wlan id\s+(\d+)\s*$", ln.strip())
        if m:
            result["wlan"]["requested_id"] = int(m.group(1))
            continue

        m = re.match(r"^WLAN Profile Name\s*:\s*(.+)$", ln)
        if m:
            result["wlan"]["profile_name"] = m.group(1).strip()
            continue

        # Section detection
        if re.match(r"^\s*Security\s*$", ln):
            section = "security"
            subsec = "global"
            continue

        if re.match(r"^\s*Security-2\.4GHz/5GHz\s*$", ln):
            section = "security"
            subsec = "band_2_4_5"
            continue

        if re.match(r"^\s*Security-6GHz\s*$", ln):
            section = "security"
            subsec = "band_6"
            continue

        if re.match(r"^\s*Configured Radio Bands\s*$", ln):
            section = "radio_configured"
            subsec = None
            continue

        if re.match(r"^\s*Operational State of Radio Bands\s*$", ln):
            section = "radio_operational"
            subsec = None
            continue

        kv = re.match(r"^\s*([^:={}\n\r]+?)\s*:\s*(.*)$", ln)
        if not kv:
            continue

        key = re.sub(r"\s+", " ", kv.group(1).strip())
        val = kv.group(2).strip()
        val_c = _coerce_value(val)

        # mDNS (top-level in your sample)
        if key == "mDNS Gateway Status":
            result["mdns"]["gateway_status"] = val
            # continue processing other routing too (safe)

        # Fast Transition fields (appear under Security in your output)
        if section == "security" and subsec == "global":
            if key == "FT Support":
                result["fast_transition"]["support"] = val
            elif key == "FT Reassociation Timeout (secs)":
                result["fast_transition"]["reassociation_timeout_secs"] = val_c
            elif key == "FT Over-The-DS mode":
                result["fast_transition"]["over_the_ds_mode"] = val

        # Route the rest
        if section is None:
            if key == "Identifier":
                result["wlan"]["id"] = val_c
            elif key == "Network Name (SSID)":
                result["wlan"]["ssid"] = val
            elif key in {
                "Status",
                "Broadcast SSID",
                "Max Associated Clients per WLAN",
                "Max Associated Clients per AP per WLAN",
                "Max Associated Clients per AP Radio per WLAN",
                "OKC",
                "Number of Active Clients",
                "WMM",
                "Mac Filter Authorization list name",
                "802.1x authentication list name",
                "802.1x authorization list name",
                "Web Based Authentication",
                "Band Select",
                "Load Balancing",
                "IP Source Guard",
            }:
                normalized = (
                    key.lower()
                    .replace(" ", "_")
                    .replace("-", "_")
                    .replace("(", "")
                    .replace(")", "")
                    .replace("/", "_")
                    .replace(".", "")
                )
                result["wlan"][normalized] = val_c
            else:
                result["wlan"].setdefault("other", {})[key] = val_c

        elif section == "radio_configured":
            result["radio_bands"]["configured"][key] = val_c

        elif section == "radio_operational":
            result["radio_bands"]["operational"][key] = val_c

        elif section == "security":
            result["security"].setdefault(subsec or "global", {})[key] = val_c

    # Cleanup empty containers
    if not result["wlan"].get("other"):
        result["wlan"].pop("other", None)

    if not result["radio_bands"]["configured"]:
        result["radio_bands"].pop("configured", None)
    if not result["radio_bands"]["operational"]:
        result["radio_bands"].pop("operational", None)
    if result.get("radio_bands") == {}:
        result.pop("radio_bands", None)

    for k in ("global", "band_2_4_5", "band_6"):
        if k in result.get("security", {}) and not result["security"][k]:
            result["security"].pop(k, None)
    if result.get("security") == {}:
        result.pop("security", None)

    if not result.get("fast_transition"):
        result.pop("fast_transition", None)
    if not result.get("mdns"):
        result.pop("mdns", None)

    return result

def parse_wireless_interface_summary(output):
    interfaces = []
    lines = output.strip().splitlines()
    # Find the line index where the table header starts
    header_line_index = None
    for i, line in enumerate(lines):
        if line.strip().startswith("Interface Name"):
            header_line_index = i
            break
    if header_line_index is None:
        # No interface data found
        return {"interfaces": interfaces}
    # The actual data starts two lines after the header line (skipping separator line)
    data_start = header_line_index + 2
    for line in lines[data_start:]:
        if not line.strip():
            # Empty line indicates end of data
            break
        # Split line by whitespace but keep MAC address intact (last field)
        parts = line.split()
        if len(parts) < 7:
            # Skip malformed lines
            continue
        # Interface Name may contain no spaces, so parts[0]
        # Interface Type may be one word, parts[1]
        # VLAN ID parts[2]
        # IP Address parts[3]
        # IP Netmask parts[4]
        # NAT-IP Address parts[5]
        # MAC Address parts[6] (may contain dots)
        interface = {
            "interfacename": parts[0],
            "interfacetype": parts[1],
            "vlanid": int(parts[2]),
            "ipaddress": parts[3],
            "netmask": parts[4],
            "natip": parts[5],
            "macaddress": parts[6]
        }
        interfaces.append(interface)
    return {"interfaces": interfaces}

def parse_show_wireless_client_detail(output: str) -> Dict[str, Any]:
    """
    Error-tolerant parser for:
      show wireless client mac-address <mac> detail

    Includes:
    - Session Manager -> Resultant Policies (captures indented key/value pairs)
    """
    parsed: Dict[str, Any] = {
        "client": {},
        "ap": {},
        "wlan": {},
        "mobility": {},
        "session_manager": {"resultant_policies": {}},
        "statistics": {},
        "fabric": {},
    }

    if not output or not isinstance(output, str):
        return {"error": "empty_or_invalid_output", **parsed}

    lines = [ln.rstrip("\n") for ln in output.splitlines()]

    # Track when we're inside "Resultant Policies:" block
    in_resultant_policies = False
    resultant_indent: Optional[int] = None

    # Regex map: (pattern, section, field)
    patterns = [
        (r"^Client MAC Address\s*:\s*(.+)$", "client", "mac_address"),
        (r"^Client MAC Type\s*:\s*(.+)$", "client", "mac_type"),
        (r"^Client DUID\s*:\s*(.+)$", "client", "duid"),
        (r"^Client IPv4 Address\s*:\s*(.+)$", "client", "ipv4_address"),
        (r"^Client IPv6 Addresses\s*:\s*(.+)$", "client", "ipv6_addresses_raw"),
        (r"^Client Username\s*:\s*(.+)$", "client", "username"),
        (r"^Client State\s*:\s*(.+)$", "client", "state"),
        (r"^Client Active State\s*:\s*(.+)$", "client", "active_state"),
        (r"^Connected For\s*:\s*(.+)$", "client", "connected_for_raw"),
        (r"^Protocol\s*:\s*(.+)$", "client", "protocol"),
        (r"^Channel\s*:\s*(.+)$", "client", "channel_raw"),
        (r"^Client IIF-ID\s*:\s*(.+)$", "client", "client_iif_id"),
        (r"^Association Id\s*:\s*(.+)$", "client", "association_id_raw"),
        (r"^Authentication Algorithm\s*:\s*(.+)$", "client", "authentication_algorithm"),
        (r"^Session Timeout\s*:\s*(.+)$", "client", "session_timeout_raw"),
        (r"^WMM Support\s*:\s*(.+)$", "client", "wmm_support"),
        (r"^U-APSD Support\s*:\s*(.+)$", "client", "uapsd_support"),
        (r"^Fastlane Support\s*:\s*(.+)$", "client", "fastlane_support"),
        (r"^Power Save\s*:\s*(.+)$", "client", "power_save"),
        (r"^Current Rate\s*:\s*(.+)$", "client", "current_rate"),
        (r"^Supported Rates\s*:\s*(.+)$", "client", "supported_rates_raw"),
        (r"^Encryption Cipher\s*:\s*(.+)$", "client", "encryption_cipher"),
        (r"^Protected Management Frame\s*-\s*802\.11w\s*:\s*(.+)$", "client", "pmf_80211w"),
        (r"^EAP Type\s*:\s*(.+)$", "client", "eap_type"),
        (r"^VLAN\s*:\s*(.+)$", "client", "vlan_name"),
        (r"^Central NAT\s*:\s*(.+)$", "client", "central_nat"),
        (r"^\s*Join Time Of Client\s*:\s*(.+)$", "client", "join_time_utc"),
        (r"^AP MAC Address\s*:\s*(.+)$", "ap", "mac_address"),
        (r"^AP Name:\s*(.+)$", "ap", "name"),
        (r"^AP slot\s*:\s*(.+)$", "ap", "slot_raw"),
        (r"^BSSID\s*:\s*(.+)$", "ap", "bssid"),
        (r"^Wireless LAN Id:\s*(.+)$", "wlan", "wlan_id_raw"),
        (r"^WLAN Profile Name:\s*(.+)$", "wlan", "wlan_profile_name"),
        (r"^Wireless LAN Network Name \(SSID\)\s*:\s*(.+)$", "wlan", "ssid"),
        (r"^Policy Profile\s*:\s*(.+)$", "wlan", "policy_profile"),
        (r"^Flex Profile\s*:\s*(.+)$", "wlan", "flex_profile"),
        # Mobility
        (r"^\s*Move Count\s*:\s*(.+)$", "mobility", "move_count_raw"),
        (r"^\s*Mobility Role\s*:\s*(.+)$", "mobility", "role"),
        (r"^\s*Mobility Roam Type\s*:\s*(.+)$", "mobility", "roam_type"),
        (r"^\s*Mobility Complete Timestamp\s*:\s*(.+)$", "mobility", "complete_timestamp_utc"),
        # Session manager
        (r"^\s*Point of Attachment\s*:\s*(.+)$", "session_manager", "point_of_attachment"),
        (r"^\s*IIF ID\s*:\s*(.+)$", "session_manager", "iif_id"),
        (r"^\s*Authorized\s*:\s*(.+)$", "session_manager", "authorized_raw"),
        (r"^\s*Common Session ID\s*:\s*(.+)$", "session_manager", "common_session_id"),
        (r"^\s*Acct Session ID\s*:\s*(.+)$", "session_manager", "acct_session_id"),
        # Statistics (subset)
        (r"^\s*Number of Bytes Received from Client\s*:\s*(.+)$", "statistics", "bytes_received_from_client_raw"),
        (r"^\s*Number of Bytes Sent to Client\s*:\s*(.+)$", "statistics", "bytes_sent_to_client_raw"),
        (r"^\s*Number of Packets Received from Client\s*:\s*(.+)$", "statistics", "packets_received_from_client_raw"),
        (r"^\s*Number of Packets Sent to Client\s*:\s*(.+)$", "statistics", "packets_sent_to_client_raw"),
        (r"^\s*Radio Signal Strength Indicator\s*:\s*(.+)$", "statistics", "rssi_raw"),
        (r"^\s*Signal to Noise Ratio\s*:\s*(.+)$", "statistics", "snr_raw"),
        # Fabric
        (r"^Fabric status\s*:\s*(.+)$", "fabric", "status"),
        (r"^\s*RLOC\s*:\s*(.+)$", "fabric", "rloc"),
        (r"^\s*VNID\s*:\s*(.+)$", "fabric", "vnid_raw"),
        (r"^\s*SGT\s*:\s*(.+)$", "fabric", "sgt_raw"),
        (r"^\s*Control plane name\s*:\s*(.+)$", "fabric", "control_plane_name"),
    ]
    compiled = [(re.compile(p), section, field) for p, section, field in patterns]

    for ln in lines:
        # Detect start of Resultant Policies block
        if re.match(r"^\s*Resultant Policies\s*:\s*$", ln):
            in_resultant_policies = True
            resultant_indent = None
            continue

        # Capture Resultant Policies indented key/value pairs
        if in_resultant_policies:
            # End conditions: blank line or a less/equal indent section header (no reliable marker)
            if not ln.strip():
                in_resultant_policies = False
                continue

            # If we hit another top-level-ish line without indentation and without ":" key/value, stop
            # (keeps it conservative and avoids swallowing other sections)
            if ln.lstrip() == ln and ":" in ln and not ln.startswith(" "):
                # A new non-indented key:val line likely means we're out of the nested block
                in_resultant_policies = False
                # fall through to normal parsing of this line

            if in_resultant_policies:
                # Determine base indent on first content line
                if resultant_indent is None:
                    resultant_indent = len(ln) - len(ln.lstrip())

                # If indentation drops below base, consider block ended
                if (len(ln) - len(ln.lstrip())) < (resultant_indent or 0):
                    in_resultant_policies = False
                else:
                    m = re.match(r"^\s*([^:]+?)\s*:\s*(.+)$", ln)
                    if m:
                        k = m.group(1).strip()
                        v = m.group(2).strip()
                        parsed["session_manager"]["resultant_policies"][k] = v
                    continue  # don't double-parse within block

        # Normal parsing (single-line key/value)
        for rx, section, field in compiled:
            m = rx.match(ln)
            if not m:
                continue
            parsed[section][field] = m.group(1).strip()
            break

    # Post-processing / normalization

    # IPv6 list
    raw_v6 = parsed["client"].pop("ipv6_addresses_raw", None)
    if raw_v6 and raw_v6.strip().lower() != "none":
        parsed["client"]["ipv6_addresses"] = [x.strip() for x in raw_v6.split(",") if x.strip()]
    else:
        parsed["client"]["ipv6_addresses"] = []

    # Connected for seconds
    cf_raw = parsed["client"].pop("connected_for_raw", None)
    parsed["client"]["connected_for_seconds"] = _first_int(cf_raw) if cf_raw else None

    # Channel/int conversions
    ch_raw = parsed["client"].pop("channel_raw", None)
    parsed["client"]["channel"] = _first_int(ch_raw) if ch_raw else None

    assoc_raw = parsed["client"].pop("association_id_raw", None)
    parsed["client"]["association_id"] = _first_int(assoc_raw) if assoc_raw else None

    # Session timeout parsing
    st_raw = parsed["client"].pop("session_timeout_raw", None)
    if st_raw:
        m = re.search(r"(\d+)\s*sec.*Remaining time:\s*(\d+)\s*sec", st_raw)
        parsed["client"]["session_timeout_sec"] = _safe_int(m.group(1)) if m else _first_int(st_raw)
        parsed["client"]["session_timeout_remaining_sec"] = _safe_int(m.group(2)) if m else None

    # Supported rates
    rates_raw = parsed["client"].pop("supported_rates_raw", None)
    parsed["client"]["supported_rates_mbps"] = _parse_supported_rates(rates_raw) if rates_raw else []

    # Authorized bool
    auth_raw = parsed["session_manager"].pop("authorized_raw", None)
    auth_bool = _safe_bool_from_true_false(auth_raw) if auth_raw else None
    if auth_bool is not None:
        parsed["session_manager"]["authorized"] = auth_bool

    # ints: ap slot, wlan id, mobility move_count, fabric vnid/sgt
    slot_raw = parsed["ap"].pop("slot_raw", None)
    if slot_raw:
        parsed["ap"]["slot"] = _first_int(slot_raw)

    wlan_id_raw = parsed["wlan"].pop("wlan_id_raw", None)
    if wlan_id_raw:
        parsed["wlan"]["wlan_id"] = _first_int(wlan_id_raw)

    move_raw = parsed["mobility"].pop("move_count_raw", None)
    if move_raw:
        parsed["mobility"]["move_count"] = _first_int(move_raw)

    vnid_raw = parsed["fabric"].pop("vnid_raw", None)
    if vnid_raw:
        parsed["fabric"]["vnid"] = _first_int(vnid_raw)

    sgt_raw = parsed["fabric"].pop("sgt_raw", None)
    if sgt_raw:
        parsed["fabric"]["sgt"] = _first_int(sgt_raw)

    # Validate IPv4
    ipv4 = parsed["client"].get("ipv4_address")
    if ipv4 and not _is_ipv4(ipv4):
        parsed["client"]["ipv4_address_raw"] = ipv4
        parsed["client"].pop("ipv4_address", None)

    # Drop empty sections / empty resultant policies container
    if not parsed["session_manager"]["resultant_policies"]:
        parsed["session_manager"].pop("resultant_policies", None)

    return {k: v for k, v in parsed.items() if v}

def parse_show_wireless_client_detail(output: str) -> dict:
    d = {"client": {}, "ap": {}, "wlan": {}, "mobility": {}, "session_manager": {}, "statistics": {}, "fabric": {}}
    lines = [ln.rstrip() for ln in output.splitlines()]

    # Simple key: value lines
    kv_patterns = [
        (r"^Client MAC Address\s*:\s*(.+)$", ("client", "mac_address")),
        (r"^Client MAC Type\s*:\s*(.+)$", ("client", "mac_type")),
        (r"^Client DUID:\s*(.+)$", ("client", "duid")),
        (r"^Client IPv4 Address\s*:\s*(.+)$", ("client", "ipv4_address")),
        (r"^Client IPv6 Addresses\s*:\s*(.+)$", ("client", "ipv6_addresses_raw")),
        (r"^Client Username:\s*(.+)$", ("client", "username")),
        (r"^Client State\s*:\s*(.+)$", ("client", "state")),
        (r"^Client Active State\s*:\s*(.+)$", ("client", "active_state")),
        (r"^Connected For\s*:\s*(\d+)\s+seconds", ("client", "connected_for_seconds")),
        (r"^Protocol\s*:\s*(.+)$", ("client", "protocol")),
        (r"^Channel\s*:\s*(\d+)\s*$", ("client", "channel")),
        (r"^Client IIF-ID\s*:\s*(.+)$", ("client", "client_iif_id")),
        (r"^Association Id\s*:\s*(\d+)\s*$", ("client", "association_id")),
        (r"^Authentication Algorithm\s*:\s*(.+)$", ("client", "authentication_algorithm")),
        (r"^Session Timeout\s*:\s*(\d+)\s*sec\s*\(Remaining time:\s*(\d+)\s*sec\)", ("client", "session_timeout_pair")),
        (r"^WMM Support\s*:\s*(.+)$", ("client", "wmm_support")),
        (r"^U-APSD Support\s*:\s*(.+)$", ("client", "uapsd_support")),
        (r"^Fastlane Support\s*:\s*(.+)$", ("client", "fastlane_support")),
        (r"^Power Save\s*:\s*(.+)$", ("client", "power_save")),
        (r"^Current Rate\s*:\s*(.+)$", ("client", "current_rate")),
        (r"^Supported Rates\s*:\s*(.+)$", ("client", "supported_rates_raw")),
        (r"^Encryption Cipher\s*:\s*(.+)$", ("client", "encryption_cipher")),
        (r"^Policy Manager State\s*:\s*(.+)$", ("client", "policy_manager_state")),
        (r"^Protected Management Frame\s*-\s*802\.11w\s*:\s*(.+)$", ("client", "pmf_80211w")),
        (r"^EAP Type\s*:\s*(.+)$", ("client", "eap_type")),
        (r"^VLAN\s*:\s*(.+)$", ("client", "vlan_name")),
        (r"^Central NAT\s*:\s*(.+)$", ("client", "central_nat")),
        (r"^AP MAC Address\s*:\s*(.+)$", ("ap", "mac_address")),
        (r"^AP Name:\s*(.+)$", ("ap", "name")),
        (r"^AP slot\s*:\s*(\d+)\s*$", ("ap", "slot")),
        (r"^BSSID\s*:\s*(.+)$", ("ap", "bssid")),
        (r"^Wireless LAN Id:\s*(\d+)\s*$", ("wlan", "wlan_id")),
        (r"^WLAN Profile Name:\s*(.+)$", ("wlan", "wlan_profile_name")),
        (r"^Wireless LAN Network Name \(SSID\):\s*(.+)$", ("wlan", "ssid")),
        (r"^Policy Profile\s*:\s*(.+)$", ("wlan", "policy_profile")),
        (r"^Flex Profile\s*:\s*(.+)$", ("wlan", "flex_profile")),
        (r"^Fabric status\s*:\s*(.+)$", ("fabric", "status")),
        (r"^\s*RLOC\s*:\s*(.+)$", ("fabric", "rloc")),
        (r"^\s*VNID\s*:\s*(\d+)\s*$", ("fabric", "vnid")),
        (r"^\s*SGT\s*:\s*(\d+)\s*$", ("fabric", "sgt")),
        (r"^\s*Control plane name\s*:\s*(.+)$", ("fabric", "control_plane_name")),
        (r"^\s*Move Count\s*:\s*(\d+)\s*$", ("mobility", "move_count")),
        (r"^\s*Mobility Role\s*:\s*(.+)$", ("mobility", "role")),
        (r"^\s*Mobility Roam Type\s*:\s*(.+)$", ("mobility", "roam_type")),
        (r"^\s*Mobility Complete Timestamp\s*:\s*(.+)$", ("mobility", "complete_timestamp_utc")),
        (r"^\s*Join Time Of Client\s*:\s*(.+)$", ("client", "join_time_utc")),
        (r"^\s*Point of Attachment\s*:\s*(.+)$", ("session_manager", "point_of_attachment")),
        (r"^\s*IIF ID\s*:\s*(.+)$", ("session_manager", "iif_id")),
        (r"^\s*Authorized\s*:\s*(.+)$", ("session_manager", "authorized_raw")),
        (r"^\s*Common Session ID:\s*(.+)$", ("session_manager", "common_session_id")),
        (r"^\s*Acct Session ID\s*:\s*(.+)$", ("session_manager", "acct_session_id")),
        (r"^\s*Number of Bytes Received from Client\s*:\s*(\d+)\s*$", ("statistics", "bytes_received_from_client")),
        (r"^\s*Number of Bytes Sent to Client\s*:\s*(\d+)\s*$", ("statistics", "bytes_sent_to_client")),
        (r"^\s*Number of Packets Received from Client\s*:\s*(\d+)\s*$", ("statistics", "packets_received_from_client")),
        (r"^\s*Number of Packets Sent to Client\s*:\s*(\d+)\s*$", ("statistics", "packets_sent_to_client")),
        (r"^\s*Radio Signal Strength Indicator\s*:\s*([-]?\d+)\s*dBm\s*$", ("statistics", "rssi_dbm")),
        (r"^\s*Signal to Noise Ratio\s*:\s*(\d+)\s*dB\s*$", ("statistics", "snr_db")),
    ]

    for ln in lines:
        for pat, (section, key) in kv_patterns:
            m = re.match(pat, ln)
            if not m:
                continue
            val = m.group(1).strip()
            if key in {"connected_for_seconds", "channel", "association_id", "vnid", "sgt", "move_count"}:
                d[section][key] = _to_int(val)
            elif key == "slot":
                d[section][key] = _to_int(val)
            elif key == "session_timeout_pair":
                d["client"]["session_timeout_sec"] = _to_int(m.group(1))
                d["client"]["session_timeout_remaining_sec"] = _to_int(m.group(2))
            else:
                d[section][key] = val

    # Post-processing for lists/booleans
    raw_v6 = d["client"].pop("ipv6_addresses_raw", None)
    if raw_v6 and raw_v6 != "None":
        d["client"]["ipv6_addresses"] = [x.strip() for x in raw_v6.split(",") if x.strip()]
    else:
        d["client"]["ipv6_addresses"] = []

    raw_rates = d["client"].pop("supported_rates_raw", None)
    d["client"]["supported_rates_mbps"] = _to_float_list(raw_rates) if raw_rates else []

    auth_raw = d["session_manager"].pop("authorized_raw", None)
    if auth_raw is not None:
        d["session_manager"]["authorized"] = auth_raw.strip().upper() == "TRUE"

    # Remove empty sections for cleaner output (optional)
    return {k: v for k, v in d.items() if v}

def parse_resultant_policies(session_output: str) -> Dict[str, Any]:
    """
    Extracts the 'Resultant Policies' block from a 'show wireless client ... | sec Session'
    style output and returns it as a dict of key/value pairs.

    Error-tolerant:
      - Returns {} if block not present
      - Ignores malformed lines
      - Preserves values containing ':' (e.g., https://...)
    """
    if not session_output or not isinstance(session_output, str):
        return {}

    lines = session_output.splitlines()

    # Find the "Resultant Policies:" line
    start_idx = None
    for i, ln in enumerate(lines):
        if re.match(r"^\s*Resultant Policies\s*:\s*$", ln):
            start_idx = i
            break
    if start_idx is None:
        return {}

    policies: Dict[str, Any] = {}

    # Parse subsequent indented "key : value" lines until the next section header or EOF
    for ln in lines[start_idx + 1 :]:
        if not ln.strip():
            continue

        # Stop when a new section header begins (e.g., "Client Statistics:", "Mobility:", etc.)
        if re.match(r"^\S[^:]*:\s*$", ln):  # non-indented "Something:" line
            break

        # Expect indented "key : value"
        m = re.match(r"^\s+([^:]+?)\s*:\s*(.+)\s*$", ln)
        if not m:
            continue

        key = re.sub(r"\s+", " ", m.group(1).strip())
        value = m.group(2).strip()
        policies[key] = value

    return policies

def parse_show_wireless_exclusionlist_client_detail(output: str) -> Dict[str, Any]:
    """
    Parses:
      show wireless exclusionlist client mac <mac> detail

    Error-tolerant:
      - Ignores unknown lines
      - Treats N/A as None
      - Converts numeric fields to int when possible
    """
    result: Dict[str, Any] = {
        "client": {},
        "ap": {},
        "wlan": {},
        "raw": {},
    }

    if not output or not isinstance(output, str):
        return {"error": "empty_or_invalid_output", **result}

    patterns = [
        (r"^Client State\s*:\s*(.+)$", ("client", "state")),
        (r"^Client MAC Address\s*:\s*(.+)$", ("client", "mac_address")),
        (r"^Client IPv4 Address\s*:\s*(.+)$", ("client", "ipv4_address")),
        (r"^Client IPv6 Address\s*:\s*(.+)$", ("client", "ipv6_address")),
        (r"^Client Username\s*:\s*(.+)$", ("client", "username")),
        (r"^Exclusion Reason\s*:\s*(.+)$", ("client", "exclusion_reason")),
        (r"^Authentication Method\s*:\s*(.+)$", ("client", "authentication_method")),
        (r"^Protocol\s*:\s*(.+)$", ("client", "protocol")),
        (r"^AP MAC Address\s*:\s*(.+)$", ("ap", "mac_address")),
        (r"^AP Name\s*:\s*(.+)$", ("ap", "name")),
        (r"^AP slot\s*:\s*(.+)$", ("ap", "slot")),
        (r"^Wireless LAN Id\s*:\s*(.+)$", ("wlan", "wlan_id")),
        (r"^Wireless LAN Name\s*:\s*(.+)$", ("wlan", "wlan_name")),
        (r"^VLAN Id\s*:\s*(.+)$", ("wlan", "vlan_id")),
    ]
    compiled = [(re.compile(p), path) for p, path in patterns]

    for line in output.splitlines():
        line = line.rstrip()
        if not line.strip():
            continue

        matched = False
        for rx, (section, key) in compiled:
            m = rx.match(line)
            if not m:
                continue

            val = _clean(m.group(1))
            # Normalize N/A
            if val.upper() in {"N/A", "NA", "NONE"}:
                val_norm: Any = None
            else:
                val_norm = val

            # Type conversions
            if key in {"slot", "wlan_id", "vlan_id"} and val_norm is not None:
                val_norm = _safe_int(str(val_norm))

            # IPv4 validation
            if key == "ipv4_address" and isinstance(val_norm, str) and not _is_ipv4(val_norm):
                # keep raw but set ipv4_address to None
                result["raw"]["client_ipv4_address"] = val_norm
                val_norm = None

            result[section][key] = val_norm
            matched = True
            break

        if not matched:
            # Keep unparsed lines if you want troubleshooting visibility
            result["raw"].setdefault("unparsed_lines", []).append(line)

    # Drop empty "raw" if nothing useful was stored
    if result.get("raw") == {} or result["raw"] == {"unparsed_lines": []}:
        result.pop("raw", None)

    # Drop empty sections
    return {k: v for k, v in result.items() if v}

def parse_wireless_policy_profile_detailed(output: str) -> Dict[str, Any]:
    """
    Parses:
      show wireless profile policy detailed <policy_profile>
    """
    res: Dict[str, Any] = {"policy_profile": {}}
    if not output or not isinstance(output, str):
        return {"error": "empty_or_invalid_output", **res}

    section: Optional[str] = None
    target = res["policy_profile"]

    for raw_ln in output.splitlines():
        ln = raw_ln.rstrip("\n")
        if not ln.strip():
            continue

        # Reset/ignore command echo lines
        if re.match(r"^\S+#show wireless profile policy detailed\b", ln):
            section = None
            continue

        # Section header lines (no ":" and not separator)
        if ":" not in ln and ln.strip() and not re.match(r"^[=\-]{3,}$", ln.strip()):
            section = ln.strip()
            continue

        kv = re.match(r"^\s*([^:]+?)\s*:\s*(.*)$", ln)
        if not kv:
            continue

        key = re.sub(r"\s+", " ", kv.group(1).strip())
        val = kv.group(2).strip()
        val_c = _coerce(val)

        # Top-level keys
        if section is None:
            if key == "Policy Profile Name":
                target["name"] = val
            elif key == "Status":
                target["status"] = val_c
            elif key in {
                "Description",
                "VLAN",
                "Multicast VLAN",
                "Wireless management interface VLAN",
                "Multicast Filter",
                "QBSS Load",
                "Passive Client",
                "ET-Analytics",
                "StaticIP Mobility",
                "AVC VISIBILITY",
                "NBAR Protocol Discovery",
                "Reanchoring",
                "Autoqos Mode",
                "Call Snooping",
                "Link-local bridging",
                "IP mac-binding",
                "User Defined (Private) Network",
                "User Defined (Private) Network Unicast Drop",
            }:
                target[key.lower().replace(" ", "_").replace("-", "_")] = val_c
            else:
                target.setdefault("other", {})[key] = val_c
        else:
            _put(target, ["sections", section], key, val_c)

    if not target.get("other"):
        target.pop("other", None)
    if not target.get("sections"):
        target.pop("sections", None)

    return res

def parse_wireless_flex_profile_detailed(output: str) -> Dict[str, Any]:
    res: Dict[str, Any] = {"flex_profile": {}}
    if not output or not isinstance(output, str):
        return {"error": "empty_or_invalid_output", **res}

    target = res["flex_profile"]
    section: Optional[str] = None

    in_policy_acl = False
    policy_acl_rows: List[Dict[str, str]] = []
    policy_acl_header_seen = False

    for raw_ln in output.splitlines():
        ln = raw_ln.rstrip("\n")
        if not ln.strip():
            continue

        # command echo
        if re.match(r"^\S+#show wireless profile flex detailed\b", ln):
            section = None
            in_policy_acl = False
            policy_acl_header_seen = False
            continue

        # Enter Policy ACL block
        if re.match(r"^\s*Policy ACL\s*:\s*$", ln):
            section = "Policy ACL"
            in_policy_acl = True
            policy_acl_header_seen = False
            continue

        # If we're inside Policy ACL, parse header/separator/rows
        if in_policy_acl:
            if re.search(r"\bACL Name\b", ln) and re.search(r"\bCentral Webauth\b", ln):
                policy_acl_header_seen = True
                continue
            if re.match(r"^\s*-{3,}\s*$", ln):
                continue

            # Exit Policy ACL block when we hit a normal key:value line
            if re.match(r"^\s*[^:]+?\s*:\s*.*$", ln):
                in_policy_acl = False
                section = None
                # fall through to normal KV parsing for this line

            else:
                # parse table row
                if policy_acl_header_seen and _looks_like_policy_acl_row(ln):
                    parts = ln.split()
                    acl_name = parts[0]
                    central_webauth = parts[-1]
                    url_filter = " ".join(parts[1:-1])
                    policy_acl_rows.append(
                        {
                            "acl_name": acl_name,
                            "url_filter_list_name": url_filter,
                            "central_webauth": central_webauth,
                        }
                    )
                continue

        # Key/value line
        kv = re.match(r"^\s*([^:]+?)\s*:\s*(.*)$", ln)
        if kv:
            key = re.sub(r"\s+", " ", kv.group(1).strip())
            val = kv.group(2).strip()
            val_c = _coerce(val)

            if key == "Flex Profile Name":
                target["name"] = val
            elif key == "Description":
                target["description"] = val
            elif key in {
                "Local DHCP Pool",
                "Fallback Radio shut",
                "ARP caching",
                "Efficient Image Upgrade",
                "OfficeExtend AP",
                "Join min latency",
                "IP overlap status",
                "DHCP broadcast",
                "VLAN Name - VLAN ID mapping",
                "HTTP-Proxy IP Address",
                "HTTP-Proxy Port",
                "Native vlan ID",
                "Flex resilient",
                "Local Roaming",
                "Umbrella Profiles",
                "mDNS Flex Profile Name",
                "AP PMK propagation",
            }:
                target[key.lower().replace(" ", "_").replace("-", "_")] = val_c
            else:
                # keep other kvs (including "CTS Policy:" lines etc.)
                target.setdefault("other", {})[key] = val_c
            continue

        # Section headings (only if it doesn't look like a Policy ACL row)
        if ":" not in ln and ln.strip() and not _looks_like_policy_acl_row(ln):
            section = ln.strip()
            continue

    if policy_acl_rows:
        target.setdefault("sections", {}).setdefault("Policy ACL", {})["rows"] = policy_acl_rows

    if not target.get("other"):
        target.pop("other", None)
    if not target.get("sections"):
        target.pop("sections", None)

    return res

def parse_show_wireless_profile_fabric_detailed(output: str) -> Dict[str, Any]:
    """
    Parses:
      show wireless profile fabric detailed <profile>

    Returns:
      {
        "fabric_profile": {
          "profile_name": "...",
          "vnid": 8192,
          "sgt": 6
        }
      }
    """
    res: Dict[str, Any] = {"fabric_profile": {}}
    if not output or not isinstance(output, str):
        return {"error": "empty_or_invalid_output", **res}

    for ln in output.splitlines():
        ln = ln.strip()
        if not ln:
            continue

        m = re.match(r"^Profile-name\s*:\s*(.+)$", ln, re.IGNORECASE)
        if m:
            res["fabric_profile"]["profile_name"] = m.group(1).strip()
            continue

        m = re.match(r"^VNID\s*:\s*(.+)$", ln, re.IGNORECASE)
        if m:
            raw = m.group(1).strip()
            res["fabric_profile"]["vnid"] = _safe_int(raw) if raw else None
            continue

        m = re.match(r"^SGT\s*:\s*(.+)$", ln, re.IGNORECASE)
        if m:
            raw = m.group(1).strip()
            res["fabric_profile"]["sgt"] = _safe_int(raw) if raw else None
            continue

    return res

def parse_show_wireless_tag_site_detailed(output: str) -> Dict[str, Any]:
    """
    Parses:
      show wireless tag site detailed <site_tag>

    Returns:
      {
        "site_tag": {
          "name": "...",
          "description": "...",
          "ap_profile": "...",
          "local_site": "Yes",
          "image_download_profile": "...",
          "fabric_ap_dhcp_broadcast": "Enabled",
          "fabric_multicast_group_ipv4": "232.255.255.1",
          "load": 0
        }
      }
    """
    res: Dict[str, Any] = {"site_tag": {}}
    if not output or not isinstance(output, str):
        return {"error": "empty_or_invalid_output", **res}

    st = res["site_tag"]

    for line in output.splitlines():
        line = line.rstrip()
        if not line.strip():
            continue

        m = re.match(r"^\s*Site Tag Name\s*:\s*(.+)$", line)
        if m:
            st["name"] = m.group(1).strip()
            continue

        m = re.match(r"^\s*Description\s*:\s*(.+)$", line)
        if m:
            st["description"] = m.group(1).strip()
            continue

        m = re.match(r"^\s*AP Profile\s*:\s*(.+)$", line)
        if m:
            st["ap_profile"] = m.group(1).strip()
            continue

        m = re.match(r"^\s*Local-site\s*:\s*(.+)$", line)
        if m:
            st["local_site"] = m.group(1).strip()
            continue

        m = re.match(r"^\s*Image Download Profile\s*:\s*(.+)$", line)
        if m:
            st["image_download_profile"] = m.group(1).strip()
            continue

        m = re.match(r"^\s*Fabric AP DHCP Broadcast\s*:\s*(.+)$", line)
        if m:
            st["fabric_ap_dhcp_broadcast"] = m.group(1).strip()
            continue

        m = re.match(r"^\s*Fabric Multicast Group IPv4 Address\s*:\s*(.+)$", line)
        if m:
            st["fabric_multicast_group_ipv4"] = _safe_ipv4(m.group(1)) or m.group(1).strip()
            continue

        # "<SiteTagName> Load : 0"
        m = re.match(r"^\s*(.+?)\s+Load\s*:\s*(\d+)\s*$", line)
        if m:
            st["load"] = _safe_int(m.group(2))
            continue

    return res

def parse_wireless_fabric_client_history(output: str, limit: int = 5) -> Dict[str, Any]:
    """
    Parses:
      show wireless fabric client mac-address <mac> history

    Returns up to the last `limit` entries (top of table = most recent).
    Tolerates duplicated command echo/noise in the output.
    """
    res: Dict[str, Any] = {"events": []}
    if not output or not isinstance(output, str):
        return res

    # Lines that look like table rows start with AP MAC xxxx.xxxx.xxxx
    row_re = re.compile(
        r"^\s*(?P<ap_mac>[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+"
        r"(?P<assoc_time>\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<xtr_ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
        r"(?P<vnid>\d+)\s+"
        r"(?P<sgt>\d+)\s+"
        r"(?P<ms_ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
        r"(?P<msg>No MESSAGE SENT|REGISTRATION|[A-Za-z0-9_-]+)\s+"
        r"(?P<entry_time>\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})\s*$",
        re.IGNORECASE,
    )

    for line in output.splitlines():
        line = line.rstrip()
        m = row_re.match(line)
        if not m:
            continue

        res["events"].append(
            {
                "ap_mac": m.group("ap_mac").lower(),
                "assoc_time": m.group("assoc_time"),
                "xtr_ip": m.group("xtr_ip"),
                "vnid": int(m.group("vnid")),
                "sgt": int(m.group("sgt")),
                "ms_ip": m.group("ms_ip"),
                "message": m.group("msg"),
                "entry_time": m.group("entry_time"),
            }
        )

        if len(res["events"]) >= limit:
            break

    return res

class WirelessControllerInfo:

    def __init__(self, device):
        self.hostname = device

    def initial_commands(self, service):
        hostname = self.hostname
        commands = [
            "show version",
            "show redundancy",
            "show wireless management trustpoint",
            "show wireless fabric summary"
        ]

        outputs = []
        for command in commands:
            op = get_single_output_genie(hostname, command, service)
            outputs.append(op)

        wmi_op = get_any_single_output(hostname,"show wireless interface summary", service)
        wmi_op_parsed = parse_wireless_interface_summary(wmi_op)
        version = outputs[0]['version']
        redundancy = outputs[1]['red_sys_info']
        trustpoint = outputs[2]
        fabric_state = outputs[3]

        self.platform_information = version
        self.ha_information = redundancy
        self.wmi_information = wmi_op_parsed
        self.trustpoint_information = trustpoint
        self.fabric_state = fabric_state

        model = version['platform']
        ewlc_flag = False
        if "98" not in model:
            ewlc_flag = True

        self.ewlc = ewlc_flag


class WirelessEndpointMac:
    def __init__(self, device,mac):
        self.hostname = device
        self.mac = mac

    def endpoint_info(self, service):
        hostname = self.hostname
        mac = self.mac

        wcm_cmd = f"show wireless client mac-address {mac} detail"
        wcm_op = get_any_single_output(hostname,wcm_cmd, service)
        wcm_op = parse_show_wireless_client_detail(wcm_op)

        self.endpointinfo = wcm_op

        sessmgr = f"show wireless client mac-address {mac} detail | se Session Manager"
        sessmgrop = get_any_single_output(hostname,sessmgr, service)
        sessmgrop = parse_resultant_policies(sessmgrop)
        self.endpoint_policies = sessmgrop

        wcm_exclusion = f"show wireless exclusionlist client mac {mac} detail"
        wcm_exclusionop = get_any_single_output(hostname,wcm_exclusion,service)
        wcm_exclusionop = parse_show_wireless_exclusionlist_client_detail(wcm_exclusionop)
        self.exclusionlist = wcm_exclusionop

    def fabric_roamming(self,service):
        hostname = self.hostname
        mac = self.mac
        fabricclienthistorycmd = f"show wireless fabric client mac-address {mac} history"
        fabricclienthistoryop =  get_any_single_output(hostname, fabricclienthistorycmd, service)
        fabricclienthistoryop = parse_wireless_fabric_client_history(fabricclienthistoryop)
        self.roaminghistory =  fabricclienthistoryop

class WLANProfile:

    def __init__(self, device):
        self.hostname = device

    def wlanprofile(self, id, service):
        hostname = self.hostname
        wlancmd = f"show wlan id {id}"
        wlanop = get_any_single_output(hostname,wlancmd, service)
        wlanop = parse_show_wlan_id(wlanop)
        self.wlanprofile = wlanop

    def policyprofile(self, profile_name,service):
        hostname = self.hostname
        pprofilecmd = f"show wireless profile policy detailed {profile_name}"
        pprofileop = get_any_single_output(hostname,pprofilecmd, service)
        pprofileop = parse_wireless_policy_profile_detailed(pprofileop)
        self.policyprofile = pprofileop

    def fabricprofile(self, fabricprofilename, service):
        hostname = self.hostname
        fprofilecmd = f"show wireless profile fabric detailed {fabricprofilename}"
        fprofileop = get_any_single_output(hostname,fprofilecmd, service)
        fprofileop = parse_show_wireless_profile_fabric_detailed(fprofileop)
        self.fabricprofile = fprofileop

    def flexprofile(self, flexprofilename, service):
        hostname = self.hostname
        flprofilecmd = f"show wireless profile flex detailed {flexprofilename}"
        flprofileop = get_any_single_output(hostname,flprofilecmd, service)
        flprofileop = parse_wireless_flex_profile_detailed(flprofileop)
        self.flexprofile = flprofileop

    def sitetag(self,sitetagname,service):
        hostname = self.hostname
        sitetagcmd = f"show wireless tag site detailed {sitetagname}"
        sitetagop = get_any_single_output(hostname,sitetagcmd, service)
        sitetagop = parse_show_wireless_tag_site_detailed(sitetagop)
        self.stag = sitetagop

