from radkit_cli import get_any_single_output
import re


def parse_msdp_summary(output):
    """
    Parses the 'show ip msdp summary' IOS output and extracts MSDP peer information.

    Args:
        output (str): The raw output string from the 'show ip msdp summary' command.

    Returns:
        list: A list of dictionaries, where each dictionary represents an MSDP peer
              and contains the extracted fields.
    """
    peers_data = []
    # Defensive: get_any_single_output() returns None on command/exec failure.
    # Callers expect a list, so a missing/empty output collapses to an empty
    # peer list rather than blowing up with `'NoneType' object has no
    # attribute 'strip'`.
    if not output:
        return peers_data
    # Regex to capture the fields: Peer Address, AS, State, Uptime/Downtime, Reset Count, SA Count, Peer Name
    # It handles cases where AS or Peer Name might be '?'
    # Group 1: Peer Address (IP)
    # Group 2: AS (number or '?')
    # Group 3: State (Up/Down)
    # Group 4: Uptime/Downtime
    # Group 5: Reset Count
    # Group 6: SA Count
    # Group 7: Peer Name (any string, including '?')
    pattern = re.compile(
        r"^(?P<peer_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
        r"(?P<asn>\S+)\s+"
        r"(?P<state>(?:Up|Down))\s+"
        r"(?P<uptime_downtime>\S+)\s+"
        r"(?P<reset_count>\d+)\s+"
        r"(?P<sa_count>\d+)\s+"
        r"(?P<peer_name>.*)$"
    )

    lines = output.strip().split('\n')

    # Iterate through lines, skipping header and summary lines
    for line in lines:
        if "MSDP Peer Status Summary" in line or \
                "Peer Address" in line or \
                "--------" in line or \
                not line.strip():  # Skip empty lines
            continue

        match = pattern.match(line.strip())
        if match:
            data = match.groupdict()

            # Convert AS to int or None
            as_number = int(data['asn']) if data['asn'] != '?' else None

            # Convert counts to int
            reset_count = int(data['reset_count'])
            sa_count = int(data['sa_count'])

            # Set peer name to None if it's '?'
            peer_name = data['peer_name'].strip()
            peer_name = peer_name if peer_name != '?' else None

            peers_data.append({
                'peer_address': data['peer_address'],
                'as': as_number,
                'uptime': data['uptime_downtime'],
                'reset_count': reset_count,
                'sa_count': sa_count,
                'peer_name': peer_name
            })
    return peers_data

def parse_msdp_peer_detail(output):
    """
    Parses the 'show ip msdp peer detail' IOS output and extracts MSDP peer information,
    separating SA filtering maps/filters into individual fields.

    Args:
        output (str): The raw output string from the 'show ip msdp peer detail' command.

    Returns:
        list: A list of dictionaries, where each dictionary represents an MSDP peer
              and contains the extracted fields.
    """
    peers_data = []
    if not output:
        return peers_data

    # Split the output into individual peer blocks
    # Each block starts with "MSDP Peer X.X.X.X"
    # Using re.DOTALL to ensure '.' matches newlines within a block
    # The lookahead `(?=MSDP Peer|\Z)` ensures we split before the next "MSDP Peer" or at the end of the string.
    peer_blocks = re.split(r"(MSDP Peer \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*?)(?=MSDP Peer|\Z)", output,
                           flags=re.IGNORECASE | re.DOTALL)

    # Iterate over the actual peer blocks, which are at even indices starting from 1
    # The split operation can create empty strings or leading non-peer text, so we filter.
    for block_text in peer_blocks:
        block = block_text.strip()
        if not block or not block.startswith("MSDP Peer"):
            continue

        current_peer = {}

        # Peer IP (from the first line of the block)
        peer_ip_match = re.search(r"MSDP Peer (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", block)
        if peer_ip_match:
            current_peer['peer_ip'] = peer_ip_match.group(1)
        else:
            continue  # Skip if peer IP cannot be found, as it's a critical identifier

        # Connection state
        state_match = re.search(r"State: (\w+)", block)
        if state_match:
            current_peer['connection_state'] = state_match.group(1)
        else:
            current_peer['connection_state'] = None

        #Mesh Group
        mesh_group_match = re.search(r"Peer is member of mesh-group (\w+)", block)
        if mesh_group_match:
            current_peer['mesh_group'] = mesh_group_match.group(1)
        else:
            current_peer['mesh_group'] = None

        # Connection source - Refined regex to exclude (IP_ADDRESS) part
        conn_source_match = re.search(r"Connection source: (\S+)\s*\(", block)
        if conn_source_match:
            current_peer['connection_source'] = conn_source_match.group(1).strip()
        else:
            current_peer['connection_source'] = None

        # SA filtering maps or filters (now flattened)
        sa_filtering_match = re.search(
            r"SA Filtering:\s+"
            + r"\s*Input \(S,G\) filter: (.*?)(?:, route-map: (.*?))?\s*\n"
            + r"\s*Input RP filter: (.*?)(?:, route-map: (.*?))?\s*\n"
            + r"\s*Output \(S,G\) filter: (.*?)(?:, route-map: (.*?))?\s*\n"
            + r"\s*Output RP filter: (.*?)(?:, route-map: (.*?))?\s*",
            # Last line doesn't need \n if it's the end of the block
            block, re.DOTALL
        )
        if sa_filtering_match:
            current_peer['input_sg_filter'] = sa_filtering_match.group(1).strip() if sa_filtering_match.group(
                1) else None
            current_peer['input_sg_route_map'] = sa_filtering_match.group(2).strip() if sa_filtering_match.group(
                2) else None
            current_peer['input_rp_filter'] = sa_filtering_match.group(3).strip() if sa_filtering_match.group(
                3) else None
            current_peer['input_rp_route_map'] = sa_filtering_match.group(4).strip() if sa_filtering_match.group(
                4) else None
            current_peer['output_sg_filter'] = sa_filtering_match.group(5).strip() if sa_filtering_match.group(
                5) else None
            current_peer['output_sg_route_map'] = sa_filtering_match.group(6).strip() if sa_filtering_match.group(
                6) else None
            current_peer['output_rp_filter'] = sa_filtering_match.group(7).strip() if sa_filtering_match.group(
                7) else None
            current_peer['output_rp_route_map'] = sa_filtering_match.group(8).strip() if sa_filtering_match.group(
                8) else None
        else:
            # Set all to None if the SA Filtering section is not found
            current_peer['input_sg_filter'] = None
            current_peer['input_sg_route_map'] = None
            current_peer['input_rp_filter'] = None
            current_peer['input_rp_route_map'] = None
            current_peer['output_sg_filter'] = None
            current_peer['output_sg_route_map'] = None
            current_peer['output_rp_filter'] = None
            current_peer['output_rp_route_map'] = None

        # SA request input filter
        sa_req_input_filter_match = re.search(r"SA-Requests:\s+\s*Input filter: (.*?)\n", block)
        if sa_req_input_filter_match:
            current_peer['sa_request_input_filter'] = sa_req_input_filter_match.group(1).strip()
        else:
            current_peer['sa_request_input_filter'] = None

        # Peer TTL threshold
        ttl_threshold_match = re.search(r"Peer ttl threshold: (\d+)", block)
        if ttl_threshold_match:
            current_peer['peer_ttl_threshold'] = int(ttl_threshold_match.group(1))
        else:
            current_peer['peer_ttl_threshold'] = None

        # SAs learned from peer
        sas_learned_match = re.search(r"SAs learned from this peer: (\d+)", block)
        if sas_learned_match:
            current_peer['sas_learned_from_peer'] = int(sas_learned_match.group(1))
        else:
            current_peer['sas_learned_from_peer'] = None

        # If MD5 or password is enabled
        md5_enabled = False
        if re.search(r"MD5 signature protection on MSDP TCP connection: enabled", block, re.IGNORECASE) or \
                re.search(r"MD5 authentication enabled", block, re.IGNORECASE) or \
                re.search(r"authentication-key", block, re.IGNORECASE) or \
                re.search(r"password enabled", block, re.IGNORECASE):
            md5_enabled = True
        current_peer['md5_or_password_enabled'] = md5_enabled

        # RPF failure count
        rpf_failure_match = re.search(r"RPF Failure count: (\d+)", block)
        if rpf_failure_match:
            current_peer['rpf_failure_count'] = int(rpf_failure_match.group(1))
        else:
            current_peer['rpf_failure_count'] = None

        # SA in / SA out
        sa_messages_match = re.search(r"SA Messages in/out: (\d+)/(\d+)", block)
        if sa_messages_match:
            current_peer['sa_in'] = int(sa_messages_match.group(1))
            current_peer['sa_out'] = int(sa_messages_match.group(2))
        else:
            current_peer['sa_in'] = None
            current_peer['sa_out'] = None

        # SA request in
        sa_request_in_match = re.search(r"SA Requests in: (\d+)", block)
        if sa_request_in_match:
            current_peer['sa_request_in'] = int(sa_request_in_match.group(1))
        else:
            current_peer['sa_request_in'] = None

        # SA response out
        sa_response_out_match = re.search(r"SA Responses out: (\d+)", block)
        if sa_response_out_match:
            current_peer['sa_response_out'] = int(sa_response_out_match.group(1))
        else:
            current_peer['sa_response_out'] = None

        # Data in / Data out (Data Packets in/out)
        data_packets_match = re.search(r"Data Packets in/out: (\d+)/(\d+)", block)
        if data_packets_match:
            current_peer['data_out'] = int(data_packets_match.group(1))  # Sent
            current_peer['data_in'] = int(data_packets_match.group(2))  # Received
        else:
            current_peer['data_in'] = None
            current_peer['data_out'] = None

        peers_data.append(current_peer)

    return peers_data

def parse_msdp_sa_cache(output):
    pattern = r"\(([\d\.]+), ([\d\.]+)\), RP ([\d\.]+).*(?:p|P)eer ([\d\.]+)"

    results = []
    for match in re.finditer(pattern, output):
        source, group, rp, peer_ip = match.groups()
        results.append({
            "source": source,
            "group": group,
            "rp": rp,
            "peer_ip": peer_ip
        })
    return results

def parse_msdp_acceptedsas(output):
    pattern = r"(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\(\?\)\s+RP:\s+(\d{1,3}(?:\.\d{1,3}){3})"
    results = []

    for match in re.finditer(pattern, output):
        group, source, rp = match.groups()
        results.append({
            "group": group,
            "source": source,
            "rp": rp
        })
    return results

def parse_msdp_advertisedsas(output):
    pattern = r"(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\(\?\)"
    results = []

    for match in re.finditer(pattern, output):
        group, source = match.groups()
        results.append({
            "group": group,
            "source": source
        })

    return results

class MSDP:
    def __init__(self,device,vrf):
        self.hostname = device
        self.vrf = vrf

        if self.vrf == "default":
            vrf_mode = ""
        elif self.vrf is None:
            vrf_mode = ""
        elif self.vrf == "None":
            vrf_mode = ""
        else:
            vrf_mode = "vrf "+self.vrf+" "
        self.vrf_mode = vrf_mode

    def msdpsummary(self, service):
        msdpsummarycmd = "show ip msdp {} summary".format(self.vrf_mode)
        msdpsummaryop = get_any_single_output(self.hostname,msdpsummarycmd,service)
        self.peers = parse_msdp_summary(msdpsummaryop)
        msdpglobalconfigcmd = "show run | i ip msdp"
        msdpglobalconfigop = get_any_single_output(self.hostname,msdpglobalconfigcmd,service)

        self.rfc3618 = False
        self.originatorid = None
        if msdpglobalconfigop is not None:
            for line in msdpglobalconfigop.splitlines():
                if "rpf rfc3618" in line:
                    self.rfc3618 = True
                if "originator-id" in line:
                    match = re.search(r"originator-id\s+(\S+)", line)
                    if match:
                        self.originatorid = match.group(1)

    def msdppeer(self,  service):
        msdpsummarycmd = "show ip msdp {} peer".format(self.vrf_mode)
        msdpsummaryop = get_any_single_output(self.hostname,msdpsummarycmd,service)
        self.peer_details = parse_msdp_peer_detail(msdpsummaryop)

    def msdpgroupstate(self, group,service):
        msdpsacache = "show ip msdp {} sa-cache".format(self.vrf_mode)
        msdpsacacheop = get_any_single_output(self.hostname,msdpsacache,service)
        self.sa_cache = None
        if msdpsacacheop is not None:
            self.sa_cache = parse_msdp_sa_cache(msdpsacacheop)

    def msdpacceptedsas(self,peer,service):
        msdpacceptedsascmd = "show ip msdp {} peer {} accepted-SAs".format(self.vrf_mode, peer)
        msdpacceptedsasop = get_any_single_output(self.hostname,msdpacceptedsascmd,service)
        self.peer = peer
        self.accepted_sas = None
        if msdpacceptedsasop is not None:
            self.accepted_sas = parse_msdp_acceptedsas(msdpacceptedsasop)

    def msdpadvertisedsas(self, peer, service):
        msdpadvertisedsascmd = "show ip msdp {} peer {} advertised-SAs".format(self.vrf_mode, peer)
        msdpadvertisedsasop = get_any_single_output(self.hostname,msdpadvertisedsascmd,service)
        self.peer = peer
        self.advertised_sas = None
        if msdpadvertisedsasop is not None:
            self.advertised_sas = parse_msdp_advertisedsas(msdpadvertisedsasop)