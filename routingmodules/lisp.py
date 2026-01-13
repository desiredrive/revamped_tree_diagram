import re
import sys
import ipaddress
from asn1crypto.pkcs12 import AttributeType
from typing import List, Tuple
from routingmodules.cef import IPCef, physical_recursion
from securitymodules.type7decryptor import decrypt_password
from switchingmodules.interfaces import Interfaces
from switchingmodules.spanning_tree import SpanningTree
from switchingmodules.vlan import VlanInformation
from radkit_cli import logging_info, logging_error, logging_warning, get_any_single_output,get_single_output_genie
from typing import Any, Dict, Optional, List, Union
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

def _is_ipv4(s: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv4Address)
    except ValueError:
        return False

def extract_ip_and_sgt_fixed_positions(metadata_hex: str) -> Tuple[Optional[str], Optional[int]]:
    """
    Fixed-position extraction (based on your observed metadata layout):
      - IP  = bytes 9-12  (1-based)  -> indices 8..11
      - SGT = bytes 17-18 (1-based)  -> indices 16..17  (e.g., 00 0A => 10)

    Returns (ip, sgt). If not enough bytes, returns (None, None/sgt None).
    """
    tokens = re.findall(r"\b[0-9A-Fa-f]{2}\b", metadata_hex or "")
    if len(tokens) < 12:
        return None, None

    # IP from bytes 9-12
    ip_bytes = tokens[8:12]
    try:
        ip_str = ".".join(str(int(x, 16)) for x in ip_bytes)
        ip_val = str(ipaddress.IPv4Address(ip_str))
    except Exception:
        ip_val = None

    # SGT from bytes 65535 in size
    sgt_val = None
    if len(tokens) >= 18:
        try:
            sgt_val = int("".join(tokens[20:22]), 16)
        except Exception:
            sgt_val = None

    return ip_val, sgt_val

def parse_lisp_session(output):
    result = {}
    # Peer address and port
    peer_match = re.search(r"Peer address:\s+([\d\.]+):(\d+)", output)
    if peer_match:
        result['peer_addr'] = peer_match.group(1)
        result['peer_port'] = int(peer_match.group(2))
    else:
        # If port is missing, try without port
        peer_match = re.search(r"Peer address:\s+([\d\.]+)", output)
        if peer_match:
            result['peer_addr'] = peer_match.group(1)
            result['peer_port'] = None
    # Local address and port (port may be missing)
    local_match = re.search(r"Local address:\s+([\d\.]+)(?::(\d+))?", output)
    if local_match:
        result['local_address'] = local_match.group(1)
        result['local_port'] = int(local_match.group(2)) if local_match.group(2) else None
    # Session Type
    session_type_match = re.search(r"Session Type:\s+(\S+)", output)
    if session_type_match:
        result['session_type'] = session_type_match.group(1)
    # Session State and uptime
    session_state_match = re.search(r"Session State:\s+(\S+)(?: \(([^)]+)\))?", output)
    if session_state_match:
        result['session_state'] = session_state_match.group(1)
        result['session_state_time'] = session_state_match.group(2) if session_state_match.group(2) else None
    # Messages in/out
    messages_match = re.search(r"Messages in/out:\s+(\d+)/(\d+)", output)
    if messages_match:
        result['messages_in'] = int(messages_match.group(1))
        result['messages_out'] = int(messages_match.group(2))
    # Fatal errors
    fatal_errors_match = re.search(r"Fatal errors:\s+(\d+)", output)
    if fatal_errors_match:
        result['fatal_errors'] = int(fatal_errors_match.group(1))
    # Rcvd unsupported
    rcvd_unsupported_match = re.search(r"Rcvd unsupported:\s+(\d+)", output)
    if rcvd_unsupported_match:
        result['rcvd_unsupported'] = int(rcvd_unsupported_match.group(1))
    # Rcvd invalid VRF
    rcvd_invalid_vrf_match = re.search(r"Rcvd invalid VRF:\s+(\d+)", output)
    if rcvd_invalid_vrf_match:
        result['rcvd_invalid_vrf'] = int(rcvd_invalid_vrf_match.group(1))
    # Rcvd override
    rcvd_override_match = re.search(r"Rcvd override:\s+(\d+)", output)
    if rcvd_override_match:
         result['rcvd_override'] = int(rcvd_override_match.group(1))
    #Rcvd malformed
    rcvd_malformed_match = re.search(r"Rcvd malformed:\s+(\d+)", output)
    if rcvd_malformed_match:
        result['rcvd_malformed'] = int(rcvd_malformed_match.group(1))
    # Sent deferred
    sent_deferred_match = re.search(r"Sent deferred:\s+(\d+)", output)
    if sent_deferred_match:
        result['sent_defferred'] = int(sent_deferred_match.group(1))
    return result

def lisp_map_servers(device,servicetype,service):
    lisp_cmd = "show run | section service {}".format(servicetype)
    lisp_op = get_any_single_output(device,lisp_cmd,service)
    return (lisp_op)

def parse_lisp_ethernet_statistics(cli_output):
    """
    Parses the 'show lisp instance-id <id> ethernet statistics' CLI output
    and returns a dictionary similar to the specified structure.
    """
    data = {}
    lines = cli_output.strip().split('\n')

    # Helper function to extract in/out values (e.g., "4/0")
    def parse_in_out(line_text):
        match = re.search(r'(\d+)/(\d+)', line_text)
        if match:
            return {'in': int(match.group(1)), 'out': int(match.group(2))}
        return {'in': 0, 'out': 0} # Default if not found

    # Helper function to extract 5 sec/1 min/5 min values (e.g., "0/0/0")
    def parse_time_stats(line_text):
        match = re.search(r'\((\d+) sec/(\d+) min/(\d+) min\)', line_text)
        if match:
            return {'5_sec': int(match.group(1)), '1_min': int(match.group(2)), '5_min': int(match.group(3))}
        return {'5_sec': 0, '1_min': 0, '5_min': 0} # Default if not found

    current_section = None
    instance_id = None
    last_cleared_eid = "never"

    # Find instance ID and initial last cleared from the first relevant line
    for line in lines:
        match = re.search(r'LISP EID Statistics for instance ID (\d+) - last cleared: (.*)', line)
        if match:
            instance_id = int(match.group(1))
            last_cleared_eid = match.group(2)
            break

    if instance_id is None:
        return {} # Could not find instance ID, return empty dict

    # Initialize the main dictionary structure with default values
    # This ensures all expected keys from the example are present.
    data = {
        'lisp_id': {
            0: {
                'instance_id': {
                    instance_id: {
                        'last_cleared': last_cleared_eid,
                        'control_packets': {},
                        'errors': {}, # EID errors
                        'cache_related': {},
                        'forwarding': {},
                        'itr_map_resolvers': {}, # Not in CLI output, but in example structure
                        'etr_map_servers': {},   # Not in CLI output, but in example structure
                        'rloc_statistics': {},
                        'misc_statistics': {}
                    }
                }
            }
        }
    }
    instance_data = data['lisp_id'][0]['instance_id'][instance_id]

    # Initialize nested structures with default values (0 or 'never')
    instance_data['control_packets'] = {
        'map_requests': {
            'in': 0, 'out': 0, '5_sec': 0, '1_min': 0, '5_min': 0,
            'encapsulated': {'in': 0, 'out': 0},
            'rloc_probe': {'in': 0, 'out': 0},
            'smr_based': {'in': 0, 'out': 0},
            'expired': {'on_queue': 0, 'no_reply': 0},
            'map_resolver_forwarded': 0,
            'map_server_forwarded': 0
        },
        'map_reply': {
            'in': 0, 'out': 0,
            'authoritative': {'in': 0, 'out': 0},
            'non_authoritative': {'in': 0, 'out': 0},
            'negative': {'in': 0, 'out': 0},
            'rloc_probe': {'in': 0, 'out': 0},
            'map_server_proxy_reply': {'out': 0}
        },
        'wlc_map_subscribe': {'in': 0, 'out': 0, 'failures': {'in': 0, 'out': 0}},
        'wlc_map_unsubscribe': {'in': 0, 'out': 0, 'failures': {'in': 0, 'out': 0}},
        'map_register': {
            'in': 0, 'out': 0, '5_sec': 0, '1_min': 0, '5_min': 0,
            'map_server_af_disabled': 0,
            'not_valid_site_eid_prefix': 0,
            'authentication_failures': 0,
            'disallowed_locators': 0,
            'misc': 0
        },
        'wlc_map_registers': {
            'in': 0, 'out': 0,
            'ap': {'in': 0, 'out': 0},
            'client': {'in': 0, 'out': 0},
            'failures': {'in': 0, 'out': 0}
        },
        'map_notify': {'in': 0, 'out': 0, 'authentication_failures': 0},
        'wlc_map_notify': {
            'in': 0, 'out': 0,
            'ap': {'in': 0, 'out': 0},
            'client': {'in': 0, 'out': 0},
            'failures': {'in': 0, 'out': 0}
        },
        'publish_subscribe': {
            'subscription_request': {
                'in': 0, 'out': 0,
                'iid': {'in': 0, 'out': 0},
                'pub_refresh': {'in': 0, 'out': 0},
                'policy': {'in': 0, 'out': 0},
                'failures': {'in': 0, 'out': 0}
            },
            'subscription_status': {
                'in': 0, 'out': 0,
                'end_of_publication': {'in': 0, 'out': 0},
                'subscription_rejected': {'in': 0, 'out': 0},
                'subscription_removed': {'in': 0, 'out': 0},
                'failures': {'in': 0, 'out': 0}
            },
            'solicit_subscription': {'in': 0, 'out': 0, 'failures': {'in': 0, 'out': 0}},
            'publication': {'in': 0, 'out': 0, 'failures': {'in': 0, 'out': 0}}
        }
    }

    instance_data['errors'] = {
        'mapping_rec_ttl_alerts': 0,
        'map_request_invalid_source_rloc_drops': 0,
        'map_register_invalid_source_rloc_drops': 0,
        'ddt_requests_failed': 0,
        'ddt_itr_map_requests': {'dropped': 0, 'nonce_collision': 0, 'bad_xtr_nonce': 0}
    }

    instance_data['cache_related'] = {
        'cache_entries': {'created': 0, 'deleted': 0},
        'nsf_cef_replay_entry_count': 0,
        'eid_prefix_map_cache': 0,
        'rejected_eid_prefix_due_to_limit': 0,
        'times_signal_suppresion_turned_on': 0,
        'time_since_last_signal_suppressed': 'never',
        'negative_entries_map_cache': 0,
        'total_rlocs_map_cache': 0,
        'average_rlocs_per_eid_prefix': 0,
        'policy_active_entries': 0
    }

    instance_data['forwarding'] = {
        'data_signals': {'processed': 0, 'dropped': 0},
        'reachability_reports': {'count': 0, 'dropped': 0},
        'smr_signals': {'dropped': 0}
    }

    instance_data['rloc_statistics'] = {
        'last_cleared': 'never',
        'control_packets': {
            'rtr': {'map_requests_forwarded': 0, 'map_notifies_forwarded': 0},
            'ddt': {'map_requests': {'in': 0, 'out': 0}, 'map_referrals': {'in': 0, 'out': 0}}
        },
        'errors': {
            'map_request_format': 0,
            'map_reply_format': 0,
            'map_referral': 0
        }
    }

    instance_data['misc_statistics'] = {
        'invalid': {
            'ip_version_drops': 0,
            'ip_header_drops': 0,
            'ip_proto_field_drops': 0,
            'packet_size_drops': 0,
            'lisp_control_port_drops': 0,
            'lisp_checksum_drops': 0
        },
        'unsupported_lisp_packet_drops': 0,
        'unknown_packet_drops': 0
    }

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Section headers and state management
        if "LISP EID Statistics" in line:
            current_section = "eid_stats_header"
            continue
        elif "Control Packets:" in line and current_section == "eid_stats_header":
            current_section = "control_packets"
            continue
        elif line == "Errors:" and current_section in ["control_packets", "eid_stats_header"]: # EID Errors
            current_section = "eid_errors"
            continue
        elif line == "Cache Related:":
            current_section = "cache_related"
            continue
        elif line == "Forwarding:":
            current_section = "forwarding"
            continue
        elif "LISP RLOC Statistics" in line:
            current_section = "rloc_statistics_header"
            match = re.search(r'last cleared: (.*)', line)
            if match:
                instance_data['rloc_statistics']['last_cleared'] = match.group(1)
            continue
        elif "Control Packets:" in line and current_section == "rloc_statistics_header":
            current_section = "rloc_control_packets"
            continue
        elif line == "Errors:" and current_section == "rloc_control_packets": # RLOC Errors
            current_section = "rloc_errors"
            continue
        elif "LISP Miscellaneous Statistics" in line:
            current_section = "misc_statistics_header"
            match = re.search(r'last cleared: (.*)', line)
            if match:
                instance_data['misc_statistics']['last_cleared'] = match.group(1)
            continue
        elif line == "Errors:" and current_section == "misc_statistics_header": # Misc Errors
            current_section = "misc_errors"
            continue
        elif line.startswith("Control-Plane#"):
            current_section = None # End of statistics

        # Parsing logic based on current_section
        if current_section == "control_packets":
            if "Map-Requests in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['map_requests'].update(stats)
            elif "Map-Requests in (5 sec/1 min/5 min):" in line:
                stats = parse_time_stats(line)
                instance_data['control_packets']['map_requests'].update(stats)
            elif "Encapsulated Map-Requests in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['map_requests']['encapsulated'].update(stats)
            elif "RLOC-probe Map-Requests in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['map_requests']['rloc_probe'].update(stats)
            elif "SMR-based Map-Requests in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['map_requests']['smr_based'].update(stats)
            elif "Map-Requests expired on-queue/no-reply" in line:
                match = re.search(r'expired on-queue/no-reply\s+(\d+)/(\d+)', line)
                if match:
                    instance_data['control_packets']['map_requests']['expired']['on_queue'] = int(match.group(1))
                    instance_data['control_packets']['map_requests']['expired']['no_reply'] = int(match.group(2))
            elif "Map-Resolver Map-Requests forwarded:" in line:
                match = re.search(r'forwarded:\s*(\d+)', line)
                if match: instance_data['control_packets']['map_requests']['map_resolver_forwarded'] = int(match.group(1))
            elif "Map-Server Map-Requests forwarded:" in line:
                match = re.search(r'forwarded:\s*(\d+)', line)
                if match: instance_data['control_packets']['map_requests']['map_server_forwarded'] = int(match.group(1))

            elif "Map-Reply records in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['map_reply'].update(stats)
            elif "Authoritative records in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['map_reply']['authoritative'].update(stats)
            elif "Non-authoritative records in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['map_reply']['non_authoritative'].update(stats)
            elif "Negative records in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['map_reply']['negative'].update(stats)
            elif "RLOC-probe records in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['map_reply']['rloc_probe'].update(stats)
            elif "Map-Server Proxy-Reply records out:" in line:
                match = re.search(r'out:\s*(\d+)$', line)
                if match: instance_data['control_packets']['map_reply']['map_server_proxy_reply']['out'] = int(match.group(1))

            elif "WLC Map-Subscribe records in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['wlc_map_subscribe'].update(stats)
            elif "Map-Subscribe failures in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['wlc_map_subscribe']['failures'].update(stats)

            elif "WLC Map-Unsubscribe records in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['wlc_map_unsubscribe'].update(stats)
            elif "Map-Unsubscribe failures in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['wlc_map_unsubscribe']['failures'].update(stats)

            elif "Map-Register records in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['map_register'].update(stats)
            elif "Map-Registers in (5 sec/1 min/5 min):" in line:
                stats = parse_time_stats(line)
                instance_data['control_packets']['map_register'].update(stats)
            elif "Map-Server AF disabled:" in line:
                match = re.search(r'disabled:\s*(\d+)', line)
                if match: instance_data['control_packets']['map_register']['map_server_af_disabled'] = int(match.group(1))
            elif "Not valid site eid prefix:" in line:
                match = re.search(r'prefix:\s*(\d+)', line)
                if match: instance_data['control_packets']['map_register']['not_valid_site_eid_prefix'] = int(match.group(1))
            elif "Authentication failures:" in line and "Map-Register" in line:
                match = re.search(r'failures:\s*(\d+)', line)
                if match: instance_data['control_packets']['map_register']['authentication_failures'] = int(match.group(1))
            elif "Disallowed locators:" in line:
                match = re.search(r'locators:\s*(\d+)', line)
                if match: instance_data['control_packets']['map_register']['disallowed_locators'] = int(match.group(1))
            elif "Miscellaneous:" in line and "Map-Register" in line:
                match = re.search(r'Miscellaneous:\s*(\d+)', line)
                if match: instance_data['control_packets']['map_register']['misc'] = int(match.group(1))

            elif "WLC Map-Register records in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['wlc_map_registers'].update(stats)
            elif "WLC AP Map-Register in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['wlc_map_registers']['ap'].update(stats)
            elif "WLC Client Map-Register in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['wlc_map_registers']['client'].update(stats)
            elif "WLC Map-Register failures in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['wlc_map_registers']['failures'].update(stats)

            elif "Map-Notify records in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['map_notify'].update(stats)
            elif "Authentication failures:" in line and "Map-Notify" in line:
                match = re.search(r'failures:\s*(\d+)', line)
                if match: instance_data['control_packets']['map_notify']['authentication_failures'] = int(match.group(1))

            elif "WLC Map-Notify records in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['wlc_map_notify'].update(stats)
            elif "WLC AP Map-Notify in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['wlc_map_notify']['ap'].update(stats)
            elif "WLC Client Map-Notify in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['wlc_map_notify']['client'].update(stats)
            elif "WLC Map-Notify failures in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['wlc_map_notify']['failures'].update(stats)

            # Publish-Subscribe section
            elif "Subscription Request records in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['publish_subscribe']['subscription_request'].update(stats)
            elif "IID subscription requests in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['publish_subscribe']['subscription_request']['iid'].update(stats)
            elif "Pub-refresh subscription requests in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['publish_subscribe']['subscription_request']['pub_refresh'].update(stats)
            elif "Policy subscription requests in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['publish_subscribe']['subscription_request']['policy'].update(stats)
            elif "Subscription Request failures in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['publish_subscribe']['subscription_request']['failures'].update(stats)

            elif "Subscription Status records in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['publish_subscribe']['subscription_status'].update(stats)
            elif "End of Publication records in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['publish_subscribe']['subscription_status']['end_of_publication'].update(stats)
            elif "Subscription rejected records in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['publish_subscribe']['subscription_status']['subscription_rejected'].update(stats)
            elif "Subscription removed records in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['publish_subscribe']['subscription_status']['subscription_removed'].update(stats)
            elif "Subscription Status failures in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['publish_subscribe']['subscription_status']['failures'].update(stats)

            elif "Solicit Subscription records in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['publish_subscribe']['solicit_subscription'].update(stats)
            elif "Solicit Subscription failures in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['publish_subscribe']['solicit_subscription']['failures'].update(stats)

            elif "Publication records in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['publish_subscribe']['publication'].update(stats)
            elif "Publication failures in/out:" in line:
                stats = parse_in_out(line)
                instance_data['control_packets']['publish_subscribe']['publication']['failures'].update(stats)

        elif current_section == "eid_errors":
            if "Mapping record TTL alerts:" in line:
                match = re.search(r'alerts:\s*(\d+)', line)
                if match: instance_data['errors']['mapping_rec_ttl_alerts'] = int(match.group(1))
            elif "Map-Request invalid source rloc drops:" in line:
                match = re.search(r'drops:\s*(\d+)', line)
                if match: instance_data['errors']['map_request_invalid_source_rloc_drops'] = int(match.group(1))
            elif "Map-Register invalid source rloc drops:" in line:
                match = re.search(r'drops:\s*(\d+)', line)
                if match: instance_data['errors']['map_register_invalid_source_rloc_drops'] = int(match.group(1))
            elif "DDT Requests failed:" in line:
                match = re.search(r'failed:\s*(\d+)', line)
                if match: instance_data['errors']['ddt_requests_failed'] = int(match.group(1))
            elif "DDT ITR Map-Requests dropped:" in line:
                match = re.search(r'dropped:\s*(\d+)\s+\(nonce-collision:\s*(\d+),\s*bad-xTR-nonce:\s*(\d+)\)', line)
                if match:
                    instance_data['errors']['ddt_itr_map_requests']['dropped'] = int(match.group(1))
                    instance_data['errors']['ddt_itr_map_requests']['nonce_collision'] = int(match.group(2))
                    instance_data['errors']['ddt_itr_map_requests']['bad_xtr_nonce'] = int(match.group(3))

        elif current_section == "cache_related":
            if "Cache entries created/deleted:" in line:
                match = re.search(r'created/deleted:\s*(\d+)/(\d+)', line)
                if match:
                    instance_data['cache_related']['cache_entries']['created'] = int(match.group(1))
                    instance_data['cache_related']['cache_entries']['deleted'] = int(match.group(2))
            elif "NSF CEF replay entry count" in line:
                match = re.search(r'count\s+(\d+)', line)
                if match: instance_data['cache_related']['nsf_cef_replay_entry_count'] = int(match.group(1))
            elif "Number of EID-prefixes in map-cache:" in line:
                match = re.search(r'map-cache:\s*(\d+)', line)
                if match: instance_data['cache_related']['eid_prefix_map_cache'] = int(match.group(1))
            elif "Number of rejected EID-prefixes due to limit:" in line:
                match = re.search(r'limit:\s*(\d+)', line)
                if match: instance_data['cache_related']['rejected_eid_prefix_due_to_limit'] = int(match.group(1))
            elif "Number of times signal suppression was turned on:" in line:
                match = re.search(r'on:\s*(\d+)', line)
                if match: instance_data['cache_related']['times_signal_suppresion_turned_on'] = int(match.group(1))
            elif "Time since last signal suppressed change:" in line:
                match = re.search(r'change:\s*([a-zA-Z0-9\s]+)$', line)
                if match: instance_data['cache_related']['time_since_last_signal_suppressed'] = match.group(1).strip()
            elif "Number of negative entries in map-cache:" in line:
                match = re.search(r'map-cache:\s*(\d+)', line)
                if match: instance_data['cache_related']['negative_entries_map_cache'] = int(match.group(1))
            elif "Total number of RLOCs in map-cache:" in line:
                match = re.search(r'map-cache:\s*(\d+)', line)
                if match: instance_data['cache_related']['total_rlocs_map_cache'] = int(match.group(1))
            elif "Average RLOCs per EID-prefix:" in line:
                match = re.search(r'EID-prefix:\s*(\d+)', line)
                if match: instance_data['cache_related']['average_rlocs_per_eid_prefix'] = int(match.group(1))
            elif "Policy active entries:" in line:
                match = re.search(r'entries:\s*(\d+)', line)
                if match: instance_data['cache_related']['policy_active_entries'] = int(match.group(1))

        elif current_section == "forwarding":
            if "Number of data signals processed:" in line:
                match = re.search(r'processed:\s*(\d+)\s+\(\+ dropped\s*(\d+)\)', line)
                if match:
                    instance_data['forwarding']['data_signals']['processed'] = int(match.group(1))
                    instance_data['forwarding']['data_signals']['dropped'] = int(match.group(2))
            elif "Number of reachability reports:" in line:
                match = re.search(r'reports:\s*(\d+)\s+\(\+ dropped\s*(\d+)\)', line)
                if match:
                    instance_data['forwarding']['reachability_reports']['count'] = int(match.group(1))
                    instance_data['forwarding']['reachability_reports']['dropped'] = int(match.group(2))
            elif "Number of SMR signals dropped:" in line:
                match = re.search(r'dropped:\s*(\d+)', line)
                if match: instance_data['forwarding']['smr_signals']['dropped'] = int(match.group(1))

        elif current_section == "rloc_control_packets":
            if "RTR Map-Requests forwarded:" in line:
                match = re.search(r'forwarded:\s*(\d+)', line)
                if match: instance_data['rloc_statistics']['control_packets']['rtr']['map_requests_forwarded'] = int(match.group(1))
            elif "RTR Map-Notifies forwarded:" in line:
                match = re.search(r'forwarded:\s*(\d+)', line)
                if match: instance_data['rloc_statistics']['control_packets']['rtr']['map_notifies_forwarded'] = int(match.group(1))
            elif "DDT-Map-Requests in/out:" in line:
                stats = parse_in_out(line)
                instance_data['rloc_statistics']['control_packets']['ddt']['map_requests'].update(stats)
            elif "DDT-Map-Referrals in/out:" in line:
                stats = parse_in_out(line)
                instance_data['rloc_statistics']['control_packets']['ddt']['map_referrals'].update(stats)

        elif current_section == "rloc_errors":
            if "Map-Request format errors:" in line:
                match = re.search(r'errors:\s*(\d+)', line)
                if match: instance_data['rloc_statistics']['errors']['map_request_format'] = int(match.group(1))
            elif "Map-Reply format errors:" in line:
                match = re.search(r'errors:\s*(\d+)', line)
                if match: instance_data['rloc_statistics']['errors']['map_reply_format'] = int(match.group(1))
            elif "Map-Referral format errors:" in line:
                match = re.search(r'errors:\s*(\d+)', line)
                if match: instance_data['rloc_statistics']['errors']['map_referral'] = int(match.group(1))

        elif current_section == "misc_errors":
            if "Invalid IP version drops:" in line:
                match = re.search(r'drops:\s*(\d+)', line)
                if match: instance_data['misc_statistics']['invalid']['ip_version_drops'] = int(match.group(1))
            elif "Invalid IP header drops:" in line:
                match = re.search(r'drops:\s*(\d+)', line)
                if match: instance_data['misc_statistics']['invalid']['ip_header_drops'] = int(match.group(1))
            elif "Invalid IP proto field drops:" in line:
                match = re.search(r'drops:\s*(\d+)', line)
                if match: instance_data['misc_statistics']['invalid']['ip_proto_field_drops'] = int(match.group(1))
            elif "Invalid packet size drops:" in line:
                match = re.search(r'drops:\s*(\d+)', line)
                if match: instance_data['misc_statistics']['invalid']['packet_size_drops'] = int(match.group(1))
            elif "Invalid LISP control port drops:" in line:
                match = re.search(r'drops:\s*(\d+)', line)
                if match: instance_data['misc_statistics']['invalid']['lisp_control_port_drops'] = int(match.group(1))
            elif "Invalid LISP checksum drops:" in line:
                match = re.search(r'drops:\s*(\d+)', line)
                if match: instance_data['misc_statistics']['invalid']['lisp_checksum_drops'] = int(match.group(1))
            elif "Unsupported LISP packet type drops:" in line:
                match = re.search(r'drops:\s*(\d+)', line)
                if match: instance_data['misc_statistics']['unsupported_lisp_packet_drops'] = int(match.group(1))
            elif "Unknown packet drops:" in line:
                match = re.search(r'drops:\s*(\d+)', line)
                if match: instance_data['misc_statistics']['unknown_packet_drops'] = int(match.group(1))

    return data

def map_cache_manual_parse(output):
    result = {"lisp_id": {}}

    # Parse header
    header = re.search(
        r"LISP IPv4 Mapping Cache for LISP (\d+) EID-table vrf (\S+) \(IID (\d+)\), (\d+) entries",
        output
    )
    if not header:
        return result

    lisp_id = int(header.group(1))
    eid_table = header.group(2)
    iid = int(header.group(3))
    entries = int(header.group(4))

    result["lisp_id"][lisp_id] = {"instance_id": {iid: {}}}
    eid_prefix = None
    eid = None
    mask = None
    uptime = None
    expires = None
    via = None
    sources = None
    state = None
    last_modified = None
    map_source = None
    activity = None
    packets_out = None
    packets_out_bytes = None
    counters_not_accurate = False
    locators = {}

    lines = output.splitlines()
    for idx, line in enumerate(lines):
        line = line.strip()
        # EID prefix line
        m_eid = re.match(r"([\d\.]+)/(\d+), uptime: ([^,]+), expires: ([^,]+), via ([^,]+), (.+)", line)
        if m_eid:
            eid_prefix = f"{m_eid.group(1)}/{m_eid.group(2)}"
            eid = m_eid.group(1)
            mask = int(m_eid.group(2))
            uptime = m_eid.group(3)
            expires = m_eid.group(4)
            via = m_eid.group(5)
            activity = m_eid.group(6)
        # Sources
        m_sources = re.match(r"Sources: (.+)", line)
        if m_sources:
            sources = m_sources.group(1)
        # State
        m_state = re.match(r"State: ([^,]+), last modified: ([^,]+), map-source: (\S+)", line)
        if m_state:
            state = m_state.group(1)
            last_modified = m_state.group(2)
            map_source = m_state.group(3)
        # Packets out, counters
        m_packets = re.match(r"Exempt, Packets out: (\d+)\((\d+) bytes\), counters are not accurate", line)
        if m_packets:
            packets_out = int(m_packets.group(1))
            packets_out_bytes = int(m_packets.group(2))
            counters_not_accurate = True
        # Locator block
        m_locator = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)\s+(\d+)/(\d+)\s+(\S+)", line)
        if m_locator:
            loc_ip = m_locator.group(1)
            loc_uptime = m_locator.group(2)
            loc_state = m_locator.group(3)
            loc_priority = int(m_locator.group(4))
            loc_weight = int(m_locator.group(5))
            loc_encap_iid = m_locator.group(6)
            locators[loc_ip] = {
                "uptime": loc_uptime,
                "state": loc_state,
                "priority": loc_priority,
                "weight": loc_weight,
                "encap_iid": loc_encap_iid,
            }

    # Fill the result dictionary
    result["lisp_id"][lisp_id]["instance_id"][iid] = {
        "eid_table": eid_table,
        "entries": entries,
        "eid_prefix": eid_prefix,
        "eid": eid,
        "mask": mask,
        "uptime": uptime,
        "expires": expires,
        "via": via,
        "sources": sources,
        "state": state,
        "last_modified": last_modified,
        "map_source": map_source,
        "activity": activity,
        "packets_out": packets_out,
        "packets_out_bytes": packets_out_bytes,
        "counters_not_accurate": counters_not_accurate,
        "locators": locators
    }

    return result

def parse_wlc_locator_and_passive_open(output: str) -> Tuple[List[str], bool]:
    """
    Returns:
      1) wlc_locator_ips: all IPv4 addresses under 'locator-set WLC' (may be empty)
      2) passive_open_configured: True if 'map-server session passive-open WLC' is present
    """
    wlc_locator_ips: List[str] = []
    passive_open_configured = False
    in_wlc_locator_set = False

    for line in (output or "").splitlines():
        line = line.rstrip()

        if re.match(r"^\s*locator-set\s+WLC\s*$", line):
            in_wlc_locator_set = True
            continue

        if in_wlc_locator_set:
            if re.match(r"^\s*exit-locator-set\s*$", line):
                in_wlc_locator_set = False
                continue

            candidate = line.strip()
            try:
                if isinstance(ipaddress.ip_address(candidate), ipaddress.IPv4Address):
                    wlc_locator_ips.append(candidate)
            except ValueError:
                pass

        if re.match(r"^\s*map-server\s+session\s+passive-open\s+WLC\s*$", line):
            passive_open_configured = True

    # de-dup, stable order
    seen = set()
    wlc_locator_ips = [ip for ip in wlc_locator_ips if not (ip in seen or seen.add(ip))]

    return wlc_locator_ips, passive_open_configured

def parse_show_lisp_iid_ethernet_database_wlc(output: str) -> Dict[str, Any]:
    """
    Parses:
      show lisp instance-id <iid> ethernet database wlc <mac>

    Adds VLAN parsing from header:
      "... EID-table Vlan 1021 (IID 8192)"  -> vlan_id=1021
    """
    res: Dict[str, Any] = {"found": False, "entry": {}}
    if not output or not isinstance(output, str):
        return {"found": False, "entry": {}, "error": "empty_or_invalid_output"}

    # If no "Hardware Address", treat as not found (but still try to parse header)
    if "Hardware Address" not in output:
        m = re.search(r"EID-table\s+Vlan\s+(\d+)\s+\(IID\s+(\d+)\)", output, re.IGNORECASE)
        if m:
            res["entry"]["vlan_id"] = int(m.group(1))
            res["entry"]["iid"] = int(m.group(2))
            res["entry"]["eid_table"] = f"Vlan {m.group(1)}"
        return res

    res["found"] = True

    # Header: VLAN and IID
    m = re.search(r"EID-table\s+Vlan\s+(\d+)\s+\(IID\s+(\d+)\)", output, re.IGNORECASE)
    if m:
        res["entry"]["vlan_id"] = int(m.group(1))
        res["entry"]["iid"] = int(m.group(2))
        res["entry"]["eid_table"] = f"Vlan {m.group(1)}"

    patterns = {
        "hardware_address": r"^Hardware Address:\s*(.+)$",
        "type": r"^Type:\s*(.+)$",
        "sources": r"^Sources:\s*(.+)$",
        "tunnel_update": r"^Tunnel Update:\s*(.+)$",
        "source_ms": r"^Source MS:\s*(.+)$",
        "rloc": r"^RLOC:\s*(.+)$",
        "up_time": r"^Up time:\s*(.+)$",
        "metadata_length": r"^Metadata length:\s*(.+)$",
        "metadata_hex_first": r"^Metadata \(hex\):\s*(.+)$",
    }

    metadata_hex_parts = []

    for ln in output.splitlines():
        ln = ln.rstrip()

        for key, pat in patterns.items():
            m = re.match(pat, ln)
            if not m:
                continue

            val = m.group(1).strip()

            if key in {"sources", "metadata_length"}:
                mm = re.search(r"\d+", val)
                res["entry"][key] = int(mm.group(0)) if mm else val
            elif key in {"source_ms", "rloc"}:
                res["entry"][key] = val if _is_ipv4(val) else val
            elif key == "metadata_hex_first":
                metadata_hex_parts.append(val)
            else:
                res["entry"][key] = val
            break

        # continuation lines for metadata hex
        if re.match(r"^\s+[0-9A-Fa-f]{2}\s", ln):
            metadata_hex_parts.append(ln.strip())

    if metadata_hex_parts:
        res["entry"]["metadata_hex"] = " ".join(metadata_hex_parts).replace("  ", " ").strip()

    return res

def parse_show_l2lisp_statistics(output: str) -> Dict[str, Any]:
    """
    Parses:
      show l2lisp statistics

    Returns:
      {
        "control_messages": {
          "Add AP": {"received": 45, "succeeded": 45},
          "Add client": {"received": 573, "succeeded": 14},
          ...
        },
        "errors": {
          "Add AP: empty metadata": 0,
          ...
          "Update client rbm failed": 20
        },
        "reconciliation": {
          "marked_dirty": 0,
          "cleaned": 0,
          "deleted": 0,
          "dirty_client_count_in_hash": 0
        },
        "toggles": {
          "Use AP info in WLC metadata": 1
        },
        "totals": {
          "total_client_count_in_hash": 1,
          "incomplete_client_count_in_hash": 0
        }
      }
    """
    res: Dict[str, Any] = {
        "control_messages": {},
        "errors": {},
        "reconciliation": {},
        "toggles": {},
        "totals": {},
    }
    if not output or not isinstance(output, str):
        return {"error": "empty_or_invalid_output", **res}

    section = None

    for raw in output.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue

        if line.startswith("Control messages"):
            section = "control_messages"
            continue
        if line.startswith("Errors"):
            section = "errors"
            continue
        if line.startswith("Reconciliation statistics"):
            section = "reconciliation"
            continue
        if line.strip() == "Toggles":
            section = "toggles"
            continue

        # Totals lines exist outside sections too; parse them regardless
        m = re.match(r"^\s*Total client count in hash\s*=\s*(\d+)\s*$", line, re.IGNORECASE)
        if m:
            res["totals"]["total_client_count_in_hash"] = int(m.group(1))
            continue

        m = re.match(r"^\s*Incomplete client count in hash\s*=\s*(\d+)\s*$", line, re.IGNORECASE)
        if m:
            res["totals"]["incomplete_client_count_in_hash"] = int(m.group(1))
            continue

        # Reconciliation extra line
        m = re.match(r"^\s*Dirty client count in hash\s*=\s*(\d+)\s*$", line, re.IGNORECASE)
        if m:
            res["reconciliation"]["dirty_client_count_in_hash"] = int(m.group(1))
            continue

        # Skip separators / headers
        if re.match(r"^[=\-]{3,}\s*$", line.strip()):
            continue
        if "Received" in line and "Succeeded" in line:
            continue
        if "Marked dirty" in line and "Cleaned" in line and "Deleted" in line:
            continue
        if line.strip().startswith("----------"):
            continue

        # Control messages rows: "<name>  <received>  <succeeded>"
        if section == "control_messages":
            m = re.match(r"^\s*(.+?)\s+(\d+)\s+(\d+)\s*$", line)
            if m:
                name = m.group(1).strip()
                res["control_messages"][name] = {"received": int(m.group(2)), "succeeded": int(m.group(3))}
            continue

        # Errors rows: "<error name> = <count>"
        if section == "errors":
            m = re.match(r"^\s*(.+?)\s*=\s*(\d+)\s*$", line)
            if m:
                res["errors"][m.group(1).strip()] = int(m.group(2))
            continue

        # Reconciliation table row: "<marked> <cleaned> <deleted>"
        if section == "reconciliation":
            m = re.match(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s*$", line)
            if m:
                res["reconciliation"]["marked_dirty"] = int(m.group(1))
                res["reconciliation"]["cleaned"] = int(m.group(2))
                res["reconciliation"]["deleted"] = int(m.group(3))
            continue

        # Toggles: "<name>: <value>"
        if section == "toggles":
            m = re.match(r"^\s*(.+?)\s*:\s*(\d+)\s*$", line)
            if m:
                res["toggles"][m.group(1).strip()] = int(m.group(2))
            continue

    # Cleanup empty keys (optional)
    return {k: v for k, v in res.items() if v}

def parse_lisp_local_eids_and_overlaps(output: str) -> Dict[str, Any]:
    prefixes: List[str] = []
    nets: List[IPNetwork] = []

    for line in (output or "").splitlines():
        line = line.strip()
        if not line or line.lower() == "prefix" or "#" in line:
            continue

        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue

        prefixes.append(str(net))
        nets.append(net)

    overlaps: List[Dict[str, str]] = []
    for i in range(len(nets)):
        for j in range(i + 1, len(nets)):
            a, b = nets[i], nets[j]
            if a.overlaps(b) and a != b:
                overlaps.append({"a": str(a), "b": str(b)})

    return {
        "prefixes": prefixes,
        "overlapping_prefixes": overlaps,
    }

def parse_show_lisp_route_import_database(output: str) -> Dict[str, Any]:
    """
    Parses:
      show lisp instance-id <iid> ipv4 route-import database <prefix>

    Returns:
      {
        "iid": 4099,
        "vrf": "Campus",
        "prefix": "192.168.31.0/24",
        "config": 1,
        "entries": 5,
        "limit": 5000,
        "uptime": "1w2d",
        "source": "bgp 65001",
        "rloc_set": "rloc_9fa77",
        "cache_db": "installed",
        "state": None|"<state>"
      }
    """
    res: Dict[str, Any] = {
        "iid": None,
        "vrf": None,
        "prefix": None,
        "config": None,
        "entries": None,
        "limit": None,
        "uptime": None,
        "source": None,
        "rloc_set": None,
        "cache_db": None,
        "state": None,
    }
    if not output or not isinstance(output, str):
        return {"error": "empty_or_invalid_output", **res}

    # Header: "... (IID 4099)" and "vrf Campus"
    m = re.search(r"EID-table\s+vrf\s+(\S+)\s+\(IID\s+(\d+)\)", output, re.IGNORECASE)
    if m:
        res["vrf"] = m.group(1)
        res["iid"] = int(m.group(2))

    # Config line: "Config: 1, Entries: 5 (limit 5000)"
    m = re.search(r"Config:\s*(\d+),\s*Entries:\s*(\d+)\s*\(limit\s*(\d+)\)", output, re.IGNORECASE)
    if m:
        res["config"] = int(m.group(1))
        res["entries"] = int(m.group(2))
        res["limit"] = int(m.group(3))

    # Data row (best-effort spacing)
    # Prefix  Uptime  Source  RLOC-set  Cache/DB  State(optional)
    for line in output.splitlines():
        line = line.rstrip()
        m = re.match(
            r"^\s*(\d{1,3}(?:\.\d{1,3}){3}/\d+)\s+(\S+)\s+(.+?)\s+(\S+)\s+(\S+)\s*(\S+)?\s*$",
            line,
        )
        if m:
            res["prefix"] = m.group(1)
            res["uptime"] = m.group(2)
            res["source"] = m.group(3).strip()
            res["rloc_set"] = m.group(4)
            res["cache_db"] = m.group(5)
            res["state"] = m.group(6) if m.group(6) else None
            break

    return res

def parse_show_lisp_forwarding_eid_remote(output: str) -> Dict[str, Any]:
    """
    Parses:
      show lisp instance-id <iid> ipv4 forwarding eid remote <ip>

    Guarantees all keys exist; anything not found stays None (or [] where appropriate).
    """
    res: Dict[str, Any] = {
        "found": False,
        "iid": None,
        "vrf": None,
        "query": None,
        "prefix": None,
        "fwd_action": None,
        "locator_status_bits": None,
        "encap_iid": None,
        "packets": None,
        "bytes": None,
        "ifnums": [],             # list of {interface, ifnum, rloc}
        "adjacency_chain": [],    # list of interfaces seen in chain
        "error": None,
    }

    if not output or not isinstance(output, str):
        res["error"] = "empty_or_invalid_output"
        return res

    # Optional command echo
    m = re.search(
        r"show lisp instance-id\s+(\d+)\s+ipv4 forwarding eid remote\s+(\S+)",
        output,
        re.IGNORECASE,
    )
    if m:
        res["iid"] = int(m.group(1))
        res["query"] = m.group(2)

    # Not found case
    m = re.search(r"%\s+No remote EID prefix in\s+IPv4:([^\s]+)\s+matching\s+(\S+)", output)
    if m:
        res["found"] = False
        res["vrf"] = m.group(1)
        res["query"] = res["query"] or m.group(2)
        res["error"] = m.group(0).lstrip("% ").strip()
        return res

    # Parse body
    for line in output.splitlines():
        line = line.rstrip()

        # Prefix row
        m = re.match(
            r"^\s*(\d{1,3}(?:\.\d{1,3}){3}/\d+)\s+(\S+)\s+(0x[0-9A-Fa-f]+)\s+(\S+)\s*$",
            line,
        )
        if m:
            res["found"] = True
            res["prefix"] = m.group(1)
            res["fwd_action"] = m.group(2)
            res["locator_status_bits"] = m.group(3)
            res["encap_iid"] = m.group(4)
            continue

        # packets/bytes
        m = re.match(r"^\s*packets/bytes\s+(\d+)\s*/\s*(\d+)\s*$", line, re.IGNORECASE)
        if m:
            res["packets"] = int(m.group(1))
            res["bytes"] = int(m.group(2))
            continue

        # ifnums entries
        m = re.match(r"^\s*([A-Za-z0-9.]+)\((\d+)\)(?::\s*(\d{1,3}(?:\.\d{1,3}){3}))?\s*$", line)
        if m:
            res["ifnums"].append(
                {
                    "interface": m.group(1),
                    "ifnum": int(m.group(2)),
                    "rloc": m.group(3) if m.group(3) else None,
                }
            )
            continue

        # adjacency chain: "out of <interface>" or "glean for <interface>"
        m = re.search(r"\bout of\s+([A-Za-z]+[A-Za-z0-9/._-]+)\b", line)
        if m:
            res["adjacency_chain"].append(m.group(1))
        m = re.search(r"\bglean for\s+([A-Za-z0-9.]+)\b", line, re.IGNORECASE)
        if m:
            res["adjacency_chain"].append(m.group(1))

    # If we never found a prefix row but also didn't hit the explicit error string, treat as not found
    if not res["prefix"] and not res["error"]:
        res["found"] = False
        res["error"] = "no_matching_prefix_row_found"

    # de-dup adjacency chain preserving order
    seen = set()
    res["adjacency_chain"] = [x for x in res["adjacency_chain"] if not (x in seen or seen.add(x))]

    return res

def parse_lisp_site_config(output):
    """
    Parses 'show run | se site' output for LISP site configurations.
    Returns a dictionary containing site details, EID records, and allowed locators.
    """
    site_data = {
        "site_name": None,
        "description": None,
        "auth_key_type": None,
        "auth_key": None,
        "eid_records": {},
        "allow_locator_default_etr": {}
    }

    lines = output.strip().splitlines()

    for line in lines:
        line = line.strip()

        # Parse Site Name
        site_match = re.match(r"^site\s+(\S+)", line)
        if site_match:
            site_data["site_name"] = site_match.group(1)
            continue

        # Parse Description
        desc_match = re.match(r"^description\s+(.+)", line)
        if desc_match:
            site_data["description"] = desc_match.group(1)
            continue

        # Parse Auth Key
        auth_match = re.match(r"^authentication-key\s+(\d+)\s+(\S+)", line)
        if auth_match:
            site_data["auth_key_type"] = auth_match.group(1)
            site_data["auth_key"] = auth_match.group(2)
            continue

        # Parse EID Records (IP Prefixes)
        eid_ip_match = re.match(r"^eid-record\s+instance-id\s+(\d+)\s+(\S+)\s+accept-more-specifics", line)
        if eid_ip_match:
            iid = int(eid_ip_match.group(1))
            prefix = eid_ip_match.group(2)
            if iid not in site_data["eid_records"]:
                site_data["eid_records"][iid] = []
            site_data["eid_records"][iid].append(prefix)
            continue

        # Parse EID Records (any-mac)
        eid_mac_match = re.match(r"^eid-record\s+instance-id\s+(\d+)\s+any-mac", line)
        if eid_mac_match:
            iid = int(eid_mac_match.group(1))
            if iid not in site_data["eid_records"]:
                site_data["eid_records"][iid] = []
            site_data["eid_records"][iid].append("any-mac")
            continue

        # Parse Allow Locator Default ETR
        allow_loc_match = re.match(r"^allow-locator-default-etr\s+instance-id\s+(\d+)\s+(\S+)", line)
        if allow_loc_match:
            iid = int(allow_loc_match.group(1))
            af = allow_loc_match.group(2) # ipv4 or ipv6
            if iid not in site_data["allow_locator_default_etr"]:
                site_data["allow_locator_default_etr"][iid] = []
            site_data["allow_locator_default_etr"][iid].append(af)
            continue

    return site_data

# Example Usage:
# result = parse_lisp_site_config(your_cli_output_string)

class lisp_route_import:

    def __init__(self, iid, device):
        self.iid = iid
        self.hostname  = device
    
    def ridb_state(self, service):
        ridb_cmd = "show lisp instance-id {} ipv4 route-import database".format(self.iid)
        ridb_op = get_any_single_output(self.hostname,ridb_cmd,service)
        iids = []
        configflag = []
        limits = []
        for line in ridb_op.splitlines():
            if "Output for" in line:
                iid = re.compile("(?<=ce-id )[0-9]+").search(line).group().strip()
                iids.append(iid)
            if "There are no" in line:
                configflag.append(None)
                limits.append(None)
            if "Config" in line:
                configflag.append(True)
                limit = re.compile("(?<=limit )[0-9]+").search(line).group().strip()
                limits.append(limit)
            if "EID table not" in line:
                configflag.append(False)
                limits.append(False)

    def route_import_database_specific(self,prefix,service):
        hostname = self.hostname
        iid = self.iid
        routeimportcmd = f"show lisp instance-id {iid} ipv4 route-import database {prefix}"
        routeimportop = get_any_single_output(hostname,routeimportcmd,service)
        routeimportop = parse_show_lisp_route_import_database(routeimportop)
        self.routeimportprefix = routeimportop

class controlplane_eid:

    def __init__(self,eid, iid, queriedcp):
        #self.qtype = qtype  #Types: L3v4, L3v6, L2, L2AR
        self.eid = eid      #Can be : IPv4, MAC address (IPv6 not needed for now)
        self.iid = iid      #LISP Instance ID for the request
        self.protocol = "UDP" #Was this registered using UDP or TCP?
        self.queriedcp = queriedcp #What is the IP address of this queried CP?

    def address_q(self, service):
            hostname = self.queriedcp
            process = "LISP"
            subprocess = "[Control-Plane]"
            cmd = "sh lisp instance-id {} ethernet server address-resolution {}".format(self.iid, self.eid)
            cp_server_output = get_single_output_genie(self.queriedcp,cmd,service)
            #Address resolution is always registered using TCP
            self.protocol = "TCP"            
            #Parsing:
            if cp_server_output == None:
                logging_info("X",process,subprocess,hostname,
                             "ARP Registration not found in CP {}".format(self.queriedcp))
                #print("ARP Registration not found in CP {}".format(self.queriedcp))
            else:
                response_path = cp_server_output['lisp_id'][0]['instance_id'][self.iid]
                host = self.eid+"/32"
                host_path = response_path['host_address'][host]
                self.authenfailures = host_path['registration_errors']['authentication_failures']
                etrssession = []
                etrs = []
                for i in host_path['etr']:
                    j = i.split(":")
                    etrs.append(j[0])
                    etrssession.append(i)
                self.etrsessions = etrssession
                self.etrs = etrs
                self.arbinding = host_path['hardware_address'] 

    def ethernet_q(self, service):
        hostname = self.queriedcp
        process = "LISP"
        subprocess = "[Control-Plane]"
        wlc_cmd = "show run | se set WLC"
        wlc_op = get_any_single_output(self.queriedcp,wlc_cmd,service)
        wlcs = []
        wlc_match = ['locator-set', 'WLC', '#']
        for line in wlc_op.splitlines():
            if not any(x  in line for x in wlc_match):
                wlcs.append(line.strip())
        self.wlcip = wlcs

        etr_list = []
        cmd = "sh lisp instance-id {} ethernet server {}".format(self.iid, self.eid)
        cp_server_output = get_any_single_output(self.queriedcp,cmd,service)
        self.arbinding = "NA"

        auth_failures = 0
        allowed_locators_mismatch = 0
        if cp_server_output is None:
            logging_info("X", process, subprocess, hostname,
                         "MAC Registration not found in CP {}".format(self.queriedcp))
            #print("MAC Registration not found in CP {}".format(self.queriedcp))
        try:

            for line in cp_server_output.splitlines():
                if "ETR" in line:
                    etrs = re.compile( "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" ).search(line).group().strip()
                    etr_list.append(etrs) 

                if "sourced by reliable transport" in line:
                    self.protocol = "TCP"

                if "WLC AP bit:" in line:
                    self.regbywlc = "True" 
                    if "Set" in line:
                        self.isfewap = "True"
                    if "Clear" in line:
                        self.isfewap = "False"

                m = re.search(r"Authentication failures:\s*(\d+)", line, re.IGNORECASE)
                if m:
                    self.auth_failures = int(m.group(1))
                m = re.search(r"Allowed locators mismatch:\s*(\d+)", line, re.IGNORECASE)
                if m:
                    self.allowed_locators_mismatch = int(m.group(1))


        except:
            pass
        if auth_failures !=0:
            message = (
                f"Authentication failures detected for EID {self.eid} in VNID {self.iid} on control plane {hostname}. "
                f"These counters may be historic; if they continue to increment, remediate by correcting the LISP authentication key "
                f"between the ETR and the map-server."
            )
            logging_warning("X", process, subprocess, hostname, "LISP Authentication" + " | " + message)
        etrs_list = [i for i in etr_list if i not in wlcs]
        etr_wllist = [i for i in etr_list if i in wlcs]
        etrs_list = set(etrs_list)
        if len(etrs_list) > 1:
            logging_error("X", process, subprocess, hostname,
                          "Multiple RLOCs detected for this L2 Registration, triggering troubleshooting flow\n {}".format(etrs_list))
            sys.exit("Multiple RLOCs detected for this L2 Registration, triggering troubleshooting flow\n {}".format(etrs_list))
        self.etrs = etrs_list
        self.wlcetr = etr_wllist
        self.auth_failures = auth_failures
        self.allowed_locators_mismatch = allowed_locators_mismatch

class l2lisp_info:

    def l2_lisp_instance(self,device,vlan,service):
        self.sourcevlan = vlan
        self.hostname = device

        process = "LISP"
        subprocess = "[L2LISP]"
        # print ("Obtaining LISP-related information for L2 IID\n")
        lispdyneidcmd = "show lisp eid-table vlan {} dynamic-eid summary".format(self.sourcevlan)
        lispdyneidop = get_single_output_genie(device, lispdyneidcmd, service)
        try:
            instance = lispdyneidop['lisp_id'][0]['instance_id']
        except AttributeError:
            instance = 0
        for i in instance:
            self.l2lispiid = i
        if self.l2lispiid == 0 :
            self.l2lispiid = None

    def vlan_from_iid(self,device,iid,service):
        self.iid = iid
        self.hostname = device

        process = "LISP"
        subprocess = "[L2LISP]"
        # print ("Obtaining LISP-related information for L2 IID\n")
        lispvlancmd = "show lisp instance-id {} ethernet | i EID table".format(self.iid)
        lispvlancmd = get_any_single_output(device, lispvlancmd, service)
        vlan = None
        for line in (lispvlancmd or "").splitlines():
            m = re.search(r"\bEID table:\s*Vlan\s+(\d+)\b", line, re.IGNORECASE)
            if m:
                vlan = int(m.group(1))
        self.vlanfromiid = vlan

    def l2_lisp_parameters(self, xtr, ep, service):
        self.mgmtip = xtr.mgmtip
        hostname = xtr.hostname
        self.sourcemac = ep.sourcemac
        self.sourcevlan = ep.sourcevlan


        #L2 LISP Operations (Local DB, Local EID and DynEID)
        #Find the L2 instance-id

        if ep.isl3only==False:

            #Original Command = "show lisp eid-table vlan {vlan} dynamic-eid summary"
            process = "LISP"
            subprocess = "[L2LISP]"
            #print ("Obtaining LISP-related information for L2 IID\n")
            lispdyneidcmd = "show lisp eid-table vlan {} dynamic-eid summary".format(self.sourcevlan)
            lispdyneidop = get_single_output_genie(hostname,lispdyneidcmd,service)
            instance = lispdyneidop['lisp_id'][0]['instance_id']
            for i in instance:
                self.l2lispiid = i
            if self.l2lispiid==0:
                logging_error("X", process, subprocess, hostname,
                              "L2 LISP IID Not Found, Is this an L3 Only Subnet?")
                sys.exit("L2 LISP IID Not Found, Is this an L3 Only Subnet?")

            #L2LISPACL
            l2lispaclcmd = "show ip interface l2lisp0"
            l2lispaclop = get_single_output_genie(hostname, l2lispaclcmd, service)
            l2lispaclout = None
            l2lispaclin = None
            if l2lispaclop is not None:
                try:
                    l2lispaclout = l2lispaclop["L2LISP0"]["outbound_access_list"]
                except KeyError:
                    l2lispaclout = None
                try:
                    l2lispaclin = l2lispaclop["L2LISP0"]["inbound_access_list"]
                except KeyError:
                    l2lispaclin = None
            self.l2lispaclout = l2lispaclout
            self.l2lispaclin = l2lispaclin

            #Basic L2 LISP Information
            l2lispservice_cmd = "show lisp all instance-id {} ethernet".format(self.l2lispiid)
            l2lispservice_op = get_single_output_genie(hostname,l2lispservice_cmd,service)
            lispservicepath = l2lispservice_op['lisp_id'][0]['instance_id'][self.l2lispiid]

            if lispservicepath['itr']['enabled'] == True:
                self.l2itr = True
            else:
                logging_error("X", process, subprocess, hostname,
                              "LISP Ethernet Instance {} is not enabled as ITR!, configure \"itr\" under the global service ethernet instance".format(self.l2lispiid))
                sys.exit("LISP Ethernet Instance {} is not enabled as ITR!, configure \"itr\" under the global service ethernet instance".format(self.l2lispiid))
            if lispservicepath['etr']['enabled'] == True:
                self.l2etr = True
            else:
                logging_error("X", process, subprocess, hostname,
                              "LISP Ethernet Instance {} is not enabled as ETR!, configure \"etr\" under the global service ethernet instance".format(self.l2lispiid))
                sys.exit("LISP Ethernet Instance {} is not enabled as ETR!, configure \"etr\" under the global service ethernet instance".format(self.l2lispiid))

            self.l2lispsmrmode = lispservicepath['itr']['solicit_map_request']
            self.l2lispmcastfloodaccesstunnel = lispservicepath['mcast_flood_access_tunnel']

            map_resolvers = []
            for i in (lispservicepath['itr_map_resolvers']):
                if i != "found":
                    map_resolvers.append(i)
            self.l2cps = map_resolvers
            
            self.ipv4minmask = lispservicepath['locator_status_algorithms']['ipv4_rloc_min_mask_len']
            self.ipv6minmask = lispservicepath['locator_status_algorithms']['ipv6_rloc_min_mask_len']

            proxyeteronly_cmd = "show run | i ipv4 locator reachability"
            proxyeteronly_op = get_any_single_output(hostname,proxyeteronly_cmd,service)

            self.ipv4reachpetronly = False
            if proxyeteronly_op is not None:
                for line in proxyeteronly_op.splitlines():
                    if 'proxy-etr-only' in line:
                        self.ipv4reachpetronly = True

            self.l2mapcache_current = lispservicepath['map_cache']['size']
            self.l2mapcache_limit = lispservicepath['map_cache']['limit']

            current = (lispservicepath['map_cache']['size'])
            limit = (lispservicepath['map_cache']['limit'])
            threshold = 90
            percentage = round((current/limit)*100,2)

            if (percentage > threshold):
                logging_warning("X", process, subprocess, hostname,
                              "Current number of L2 Map-Caches is {} , limit is {}, capacity at {}%".format(current,limit,percentage))
                #print ("WARNING! Current number of L2 Map-Caches is {} , limit is {}, capacity at {}%".format(current,limit,percentage))
            #else:
            #    logging_info("X", process, subprocess, hostname,
            #                  "Current number of L2 Map-Caches is {} , limit is {}, capacity at {}%".format(current,limit,percentage))
            #    #print ("INFO: Current number of L2 Map-Caches is {} , limit is {}, capacity at {}%".format(current,limit,percentage))
            
            self.l2dbcache_current = lispservicepath['database']['total_database_mapping']
            self.l2dbcache_limit = lispservicepath['database']['dynamic_database']['limit']

            current = (lispservicepath['database']['total_database_mapping'])
            limit = (lispservicepath['database']['dynamic_database']['limit'])
            threshold = 90
            percentage = round((current/limit)*100,2)

            if (percentage > threshold):
                logging_warning("X", process, subprocess, hostname,
                              "Current number of L2 Database Entries is {} , limit is {}, capacity at {}%".format(current,limit,percentage))
                #print ("WARNING! Current number of L2 Database Entries is {} , limit is {}, capacity at {}%".format(current,limit,percentage))
            #else:
            #    logging_info("X", process, subprocess, hostname,
            #                  "Current number of L2 Database Entries is {} , limit is {}, capacity at {}%".format(current,limit,percentage))
            #    #print ("INFO: Current number of L2 Database Entries is {} , limit is {}, capacity at {}%".format(current,limit,percentage))

            self.l2signalsupressstate = lispservicepath['map_cache']['signal_supress']
            if self.l2signalsupressstate is True:
                logging_error("X", process, subprocess, hostname,
                              "WARNING! Signal Supression is enabled, no more map-requests will be created for this instance!")
                sys.exit("Signal Supression is enabled, no more map-requests will be created for this instance!")

            #Searching the source MAC in LISP L2 Dynamic EID
            eids = lispdyneidop['lisp_id'][0]['instance_id'][self.l2lispiid]['dynamic_eids']['Auto-L2-group-{}'.format(self.l2lispiid)]['eids']
            if any(x  in self.sourcemac for x in eids):
                self.l2dynstate = True
            else:
                logging_error("X", process, subprocess, hostname,
                              "Source MAC {} in IPDT but not in LISP {} Dynamic-EID, is LISP database-mapping configured for VLAN {}?".format(self.sourcemac,self.l2lispiid,self.sourcevlan))
                sys.exit("Source MAC {} in IPDT but not in LISP {} Dynamic-EID, is LISP database-mapping configured for VLAN {}?".format(self.sourcemac,self.l2lispiid,self.sourcevlan))

            #Searching the source MAC in LISP Database
            dbl2_cmd = "show lisp instance-id {} ethernet database".format(self.l2lispiid)
            dbl2_op = get_single_output_genie(hostname,dbl2_cmd,service)
            eids = dbl2_op['lisp_id'][0]['instance_id'][self.l2lispiid]['entries']['eids']
            mac = self.sourcemac+"/48"
            if any(x  in mac for x in eids):
                self.l2lispdbstate = True
            else:
                logging_error("X", process, subprocess, hostname,
                              "Source MAC {} in IPDT/ DynEID but not in LISP {} Database? Debug LISP".format(self.sourcemac, self.l2lispiid))
                sys.exit("Source MAC {} in IPDT/ DynEID but not in LISP {} Database? Debug LISP".format(self.sourcemac,self.l2lispiid))

class L2LISPInterface:
    def __init__(self,vlan,device):
        self.hostname = device
        self.vlan = vlan


    def l2lispinterfacestatus(self,service):
        process = "LISP"
        subprocess = "[L2LISPInterface]"
        hostname = self.hostname

        #STP Status for the VLAN
        stpstatus = SpanningTree(self.hostname)
        stpstatus.spt_vlan_active(self.vlan,service)
        if stpstatus is None:
            logging_error("X", process, subprocess, hostname,
                          "WARNING!: No Spanning Tree Information for VLAN {} in device: {} , is the VLAN created? There are no active in this VLAN".format(self.vlan, self.hostname))
            sys.exit("WARNING!: No Spanning Tree Information for VLAN {} in device: {} , is the VLAN created? There are no active in this VLAN".format(self.vlan, self.hostname))
        if stpstatus.number_of_fwd_interfaces == 0:
            sys.exit("WARNING!: No FWD enabled ports in VLAN {} in device: {} , are the ports assigned to the correct VLAN and connected?".format(self.vlan, self.hostname))
        self.stpstatus = stpstatus

        #VLAN Status and L2LISP type
        vlanstatus = VlanInformation(self.vlan,self.hostname)
        vlanstatus.vlanbrief_manual(service)
        l2lispparentintf = None
        l2lispparenttype = None
        l2lispiid = None
        for port in vlanstatus.ports:
            if "Tu" in port:
                l2lispparentintf = port
                l2lispparenttype = 'Tunnel'
            elif "L2LI0" in port:
                l2lispparentintf = port
                l2lispparenttype = 'L2LISP0'
                l2lispsubinterfacesplit = port.split(":")
                l2lispiid = l2lispsubinterfacesplit[1]
        if l2lispparentintf is None:
            logging_error("X", process, subprocess, hostname,
                          "WARNING!: No L2LISP (or Tunnel) interface found attached to VLAN {} in device: {}! - This might be the result of an unexpected switchover or ISSU upgrade; remove the affected L2LISP instance and create it again".format(self.vlan, self.hostname))
            sys.exit("WARNING!: No L2LISP (or Tunnel) interface found attached to VLAN {} in device: {}! - This might be the result of an unexpected switchover or ISSU upgrade; remove the affected L2LISP instance and create it again".format(self.vlan, self.hostname))
        self.vlanstatus = vlanstatus
        self.l2lispparenttype = l2lispparenttype

        #L2LISP0 Main Interface and L2LISP Subinterface (if applicable)
        if l2lispparenttype == 'L2LISP0':
            l2lisp0interface = Interfaces('L2LISP0', self.hostname)
            l2lisp0interface.show_interface(service)
            if l2lisp0interface.linestate != 'up':
                logging_error("X", process, subprocess, hostname,
                              "WARNING!: L2LISP Interface is DOWN in device: {}".format(self.hostname))
                sys.exit("WARNING!: L2LISP Interface is DOWN in device: {}".format(self.hostname))
            l2lispsubintf = "L2LISP0."+l2lispiid
            l2lispsubinterface = Interfaces(l2lispsubintf,self.hostname)
            l2lispsubinterface.show_interface(service)
            if l2lispsubinterface.linestate != 'up':
                logging_error("X", process, subprocess, hostname,
                              "WARNING!: {} Interface is DOWN in device: {}".format(l2lispsubintf,self.hostname))
                sys.exit("WARNING!: {} Interface is DOWN in device: {}".format(l2lispsubintf,self.hostname))
            self.l2lispparenstatus = l2lisp0interface
            self.l2lispsubinterfacestatus = l2lispsubinterface
            self.l2lispfinalinterface = l2lispsubinterface.interface
        if l2lispparenttype == 'Tunnel':
            tunnelinterface = Interfaces(l2lispparentintf, self.hostname)
            tunnelinterface.show_interface(service)
            if tunnelinterface.linestate != 'up':
                logging_error("X", process, subprocess, hostname,
                              "WARNING!: l2lispparentintf Interface is DOWN in device: {}".format(self.hostname))
                sys.exit("WARNING!: l2lispparentintf Interface is DOWN in device: {}".format(self.hostname))
            self.l2lispparenstatus = tunnelinterface
            self.l2lispfinalinterface = tunnelinterface.interface

        #L2LISP statistics

class L2LISPConfiguration:
    def __init__(self,iid,device):
        self.hostname = device
        self.iid = iid

    def l2flooding_configuration(self,service):
        hostname = self.hostname
        hostname = self.hostname
        iid = self.iid
        matches = ['#', 'show']
        self.floodunknownunicast = False
        self.broadcastunderlay = None
        self.floodarpnd = False
        self.floodaccesstunnel = False

        #Structure is {Type: Unicast|Multicast, Multicast Group : Group, Vlan: Vlan
        l2floodingconfig_cmd = "show run | se instance-id {}".format(iid)
        l2floodingconfig_op = get_any_single_output(hostname,l2floodingconfig_cmd,service)
        if l2floodingconfig_op is not None:
            for line in l2floodingconfig_op.splitlines():
                if not any(x in line for x in matches):
                    if "broadcast-underlay" in line:
                        self.broadcastunderlay = re.compile("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").search(line).group().strip()
                    if "flood unknown-unicast" in line:
                        self.floodunknownunicast = True
                    if "flood arp-nd" in line:
                        self.floodarpnd = True
                    if "flood access-tunnel" in line:
                        self.floodaccesstunnel = True
                        try:
                            mcasttunnelip = re.compile("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").search(line).group().strip()
                            self.floodaccesstunneltype = 'Multicast'
                            self.floodaccesstunnelgroup = mcasttunnelip
                            floodatmcaststringvlan = re.compile("vlan [0-9]{4}").search(line).group()
                            self.floodaccesstunnelvlan = int(floodatmcaststringvlan.split("vlan")[1].strip())
                        except:
                            pass

class l2_map_cache:

    def __init__(self,eid, iid, queriedev):
        self.eid = eid              #Can be : IPv4, MAC address (IPv6 not needed for now)
        self.iid = iid              #LISP Instance ID for the request
        self.queriedev = queriedev

    def l2map(self, service):
            process = "LISP"
            subprocess = "[Map-Cache]"
            eid = None
            map_cache_cmd = "sh lisp instance-id {} ethernet map-cache {}".format(self.iid, self.eid)
            map_cache_output = get_single_output_genie(self.queriedev,map_cache_cmd,service)
            if map_cache_output is None:
                logging_error("X", process,subprocess,self.queriedev,
                              "WARNING!: No map-cache found for EID {} in IID {} in device {}, maybe ARP is not working?".format(self.eid, self.iid, self.queriedev))
                sys.exit("WARNING!: No map-cache found for EID {} in IID {} in device {}, maybe ARP is not working?".format(self.eid, self.iid, self.queriedev) )
            else:
                try:
                    mapcache_path = map_cache_output['lisp_id'][0]['instance_id'][self.iid]['eid_prefix']
                except KeyError:
                    logging_error("X", process, subprocess, self.queriedev,
                                  "WARNING!: No map-cache found for EID {} in IID {} in device {}, maybe ARP is not working?".format(
                                      self.eid, self.iid, self.queriedev))
                    sys.exit(
                        "WARNING!: No map-cache found for EID {} in IID {} in device {}, maybe ARP is not working?".format(
                            self.eid, self.iid, self.queriedev))
                self.mask = 48
                for i in mapcache_path:
                    eid = i
                self.uptime = mapcache_path[eid]['uptime']
                self.expiration = mapcache_path[eid]['expiry_time']
                self.source = mapcache_path[eid]['source_type']
                i = None
                for i in mapcache_path[eid]['rloc_set']:
                    self.rloc = i
                self.rlocstate = mapcache_path[eid]['rloc_set'][i]['rloc_state']
                self.priority = mapcache_path[eid]['rloc_set'][i]['priority']
                self.weight = mapcache_path[eid]['rloc_set'][i]['weight']
            
class LISPLocalDB:

    def __init__(self,eid, iid, device):
        self.eid = eid              #Can be : IPv4, MAC address (IPv6 not needed for now)
        self.iid = iid              #LISP Instance ID for the request
        self.device = device

    def L3LISPDyn(self,service):
        l3lispdyncmd = "show lisp instance-id {} dynamic-eid detail".format(self.iid)
        l3lispdynop = get_single_output_genie(self.device,l3lispdyncmd,service)
        if l3lispdynop is not None:
            try:
                path = l3lispdynop['lisp_id'][0]['instance_id'][self.iid]['dynamic_eids']
            except KeyError:
                path = l3lispdynop['lisp_id']['default']['instance_id'][self.iid]['dynamic_eids']
            self.dynamic_eids = []
            for dynentry in path:
                dynentryname = dynentry
                eid = path[dynentry]['database_mapping']['eid_prefix']
                locator = path[dynentry]['database_mapping']['locator_set']
                try:
                    entries = path[dynentry]['eid_entries']
                except KeyError:
                    entries = None
                dynamic_eid = {
                    'dynamic_eid' : dynentryname,
                    'eid_subnet': eid,
                    'locator': locator,
                    'eid_entries': entries
                }
                self.dynamic_eids.append(dynamic_eid)

    def L3LISPDB(self,service):
        l3lispdbcmd = "show lisp instance-id {} ipv4 database".format(self.iid)
        l3lispdbop = get_single_output_genie(self.device,l3lispdbcmd,service)
        if l3lispdbop is not None:
            return None

    def L2LISPDyn(self,service):
        l2lispdyncmd = "show lisp instance-id {} dynamic-eid detail".format(self.iid)
        l2lispdynop = get_single_output_genie(self.device,l2lispdyncmd,service)
        try:
            path = l2lispdynop['lisp_id'][0]['instance_id'][self.iid]['dynamic_eids']
        except KeyError:
            path = []
        dynmacconfig = False
        for group in path:
            if 'Auto-L2' in group:
                dynmacconfig = True
        self.dynmacconfig = dynmacconfig

        dynmacs = []
        if dynmacconfig is True:
            striid = str(self.iid)
            autol2group ='Auto-L2-group-{}'.format(striid)
            path = path[autol2group]['eid_entries']
            for key in path:
                dynmacs.append(key)
        self.dynmacs = dynmacs

    def L2LISPStaticDB(self,service):
        static_mappings = []
        l2lispconfig = "show run | sec instance-id {}".format(self.iid)
        l2lispconfig_op = get_any_single_output(self.device,l2lispconfig,service)
        if l2lispconfig_op is not None:
            for line in l2lispconfig_op.splitlines():
                if 'database-mapping' in line:
                    if 'mac' not in line:
                        macregex = "([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})"
                        try:
                            mac = re.compile(macregex).search(line).group().strip()
                            static_mappings.append(mac)
                        except AttributeError:
                            mac = None
        self.static_mappings = static_mappings

    def LISPDBLimits(self,type,service):
        lispinstanceparameters = "show lisp instance-id {} {}".format(self.iid,type)
        lispinstanceparameters_op = get_single_output_genie(self.device,lispinstanceparameters,service)
        lispglobalparameters = "show lisp service {} summary".format(type)
        lispglobalparameters_op = get_single_output_genie(self.device,lispglobalparameters,service)

        try:
            path = lispinstanceparameters_op['lisp_id'][0]['instance_id'][self.iid]['database']
            gpath = lispglobalparameters_op['lisp_router_instances'][0]['service'][type]['etr']['summary']
            total_global_database = gpath['total_db_entries']
            total_global_maxdb = gpath['maximum_db_entries']
            total_database = path['total_database_mapping']
            inactive_database = path['inactive']
            static_database = path['static_database']
            dynamic_database = path['dynamic_database']
            rimport_database = path['route_import']
            sitereg_database = path['import_site_reg']
            publication_database = path['import_publication']
            static_database_pr = round((static_database['size'] / static_database['limit']) * 100, 2)
            dynamic_database_pr = round((dynamic_database['size'] / dynamic_database['limit']) * 100, 2)
            global_db_pr = round((total_global_database / total_global_maxdb) * 100, 2)
        except AttributeError:
            total_global_database = None
            total_global_maxdb = None
            total_database = None
            inactive_database = None
            static_database = None
            dynamic_database = None
            rimport_database = None
            sitereg_database = None
            publication_database = None
            static_database_pr =  None
            dynamic_database_pr = None
            global_db_pr = None

        self.global_total_db_entries = total_global_database
        self.global_maximum_db_entries = total_global_maxdb
        self.global_database_usage_pr = global_db_pr
        self.total_database = total_database
        self.inactive_database = inactive_database
        self.static_database = static_database
        self.static_database_pr = static_database_pr
        self.dynamic_database = dynamic_database
        self.dynamic_database_pr = dynamic_database_pr
        self.rimport_database = rimport_database
        self.sitereg_database = sitereg_database
        self.publication_database = publication_database

    def LISPDBEntry(self,type,service):
        lispdbeid = "show lisp instance-id {} {} database {}".format(self.iid,type,self.eid)
        lispdbeid_op = get_single_output_genie(self.device,lispdbeid,service)
        try:
            path = lispdbeid_op['lisp_id'][0]['instance_id'][self.iid]
            self.address_family = path['address_family']
            self.eid_table = path['eid_table']
            self.eid = path['eid_prefix']
            eid_info = path['eid_info']
            if "dynamic-eid" in eid_info:
                self.eid_origin = 'dynamic-eid'
            elif "route-import" in eid_info:
                self.eid_origin = 'route-import'
            elif 'publica' in eid_info:
                self.eid_origin = 'publication'
            else:
                self.eid_origin = 'static'
            rlocs = path['locators']
            locators = []
            for locator in rlocs:
                priority = rlocs[locator]['priority']
                weight = rlocs[locator]['weight']
                locators.append({'rloc': locator, 'priority': priority, 'weight': weight})
            mapservers = []
            dbmap_servers = path['map_servers']
            for map_server in dbmap_servers:
                ackstate = dbmap_servers[map_server]['ack']
                mapservers.append({'map_server': map_server, 'ack': ackstate})
            self.locators = locators
            self.mapservers = mapservers

        except (TypeError, AttributeError, KeyError):
            self.address_family = None
            self.eid_table = None
            self.eid = None
            self.eid_origin = None
            self.locators = None
            self.mapservers = None

    def lispdbwlcentry(self,service):
        lispdbeidfew = f"show lisp instance-id {self.iid} ethernet database wlc {self.eid}"
        lispdbeidfew_op = get_any_single_output(self.device, lispdbeidfew, service)
        lispdbeidfew_op = parse_show_lisp_iid_ethernet_database_wlc(lispdbeidfew_op)
        entry = (lispdbeidfew_op.get("entry", {}) or {})

        self.vlan = entry.get("vlan_id")
        self.hardware_address = entry.get("hardware_address")
        self.etype = entry.get("type")
        self.tunnel_update = entry.get("tunnel_update")
        self.source_ms = entry.get("source_ms")
        self.rloc = entry.get("rloc")
        self.metadata_hex = entry.get("metadata_hex")
        ap_ip_metadata, sgt_metadata = extract_ip_and_sgt_fixed_positions(self.metadata_hex)
        self.ap_ip_metadata = ap_ip_metadata
        self.sgt_metadata = sgt_metadata

class L2LISPControlPlane:
    def __init__(self, device):
        self.device = device
    def lisp_service_ethernet(self,service):
        hostname = self.device
        lispservethcmd = "show lisp service ethernet"
        lispservethop = get_single_output_genie(hostname,lispservethcmd,service)
        if lispservethop is not None:
            try:
                path = lispservethop['lisp_id'][0]
            except KeyError:
                path = lispservethop['lisp_id']['default']
            self.map_server = bool(path['map_server']['enabled'])
            self.map_resolver = bool(path['map_resolver']['enabled'])

    def site_uci(self,iid,service):
        hostname = self.device
        siteuciruncmd = "show run | se site_uci"
        siteucirunop = get_any_single_output(hostname,siteuciruncmd,service)
        self.iid_site = False
        self.site_uci = False
        self.authenkey = False
        self.decrypted = False
        self.authentication_key = None
        self.key_type = None
        if siteucirunop is not None:
            string = "eid-record instance-id {} any-mac".format(iid).strip()
            authenkey = "authentication-key"
            vnisite_flag = False
            for line in siteucirunop.splitlines():
                if string == line.strip():
                    vnisite_flag = True
                    self.site_uci = True
                if "site site_uci" in line:
                    self.site_uci = True
                if authenkey in line:
                    #Authenticaction Key Parse
                    parts = line.strip().split()
                    if len(parts) < 3 or parts[0] != "authentication-key":
                        raise ValueError("Invalid authentication-key format")
                    try:
                        password_type = int(parts[1])
                    except ValueError:
                        raise ValueError("Password type must be an integer")
                    encrypted_key = parts[2]
                    self.key_type = password_type
                    if password_type == 0:
                        self.decrypted = True
                        self.authentication_key = encrypted_key
                    elif password_type == 7:
                        self.decrypted = True
                        self.authentication_key = decrypt_password(encrypted_key)
                    else:
                        self.decrypted = False
                        self.authentication_key = encrypted_key
                    self.authenkey = True
            self.iid_site = vnisite_flag

            #Authentication Key Parse

    def rloc_members(self,service):
        hostname = self.device
        rlocmembercmd = "show run | i map-server rloc members"
        rlocmemberop = get_any_single_output(hostname,rlocmembercmd,service)
        self.rloc_members_distribute = False
        if rlocmemberop is not None:
            for line in rlocmemberop.splitlines():
                if "distribute" in line:
                    self.rloc_members_distribute = True

    def domains(self,service):
        hostname = self.device
        lispcmd = "show lisp"
        lispop = get_single_output_genie(hostname,lispcmd,service)
        self.domainid = 0
        self.multihomingid = 0
        if lispop is not None:
            try:
                path = lispop['lisp_id'][0]
            except KeyError:
                path = lispop['lisp_id']['default']
            # Try domainid
            try:
                domainid = int(path['domain_id'])
            except KeyError:
                domainid = 0
            # Try MultiHoming ID
            try:
                multihoming_id = int(path['multihoming_id'])
            except KeyError:
                multihoming_id = 0
            self.domainid = domainid
            self.multihomingid = multihoming_id
    def fewparameters(self,service):
        device = self.device
        lsetcmd = "show run | se locator-set WLC| WLC"
        lsetop = get_any_single_output(device, lsetcmd, service)
        if lsetop is not None:
            wlc_locator_ips ,passive_open_configured = parse_wlc_locator_and_passive_open(lsetop)
            try:
                self.wlc_locator_ips = wlc_locator_ips
                self.passive_open_configured = passive_open_configured
            except KeyError:
                self.wlc_locator_ips = []
                self.passive_open_configured = False

class LISPControlPlane:
    def __init__(self, device):
        self.device = device
    def lisp_service_ipv4(self,service):
        hostname = self.device
        lispservethcmd = "show lisp service ipv4"
        lispserverhop = get_single_output_genie(hostname,lispservethcmd,service)
        self.lispservice = lispserverhop
        #Retrieve the state of map_server and map_resolver

    def site_uci(self,service):
        hostname = self.device
        siteuciruncmd = "show run | se site_uci"
        siteucirunop = get_any_single_output(hostname,siteuciruncmd,service)
        siteucirunop = parse_lisp_site_config(siteucirunop)
        self.site_uci = siteucirunop
        ''' Sample Output for site_uci:
            {
        'site_name': 'site_uci',
        'description': 'map-server configured from Catalyst Center',
        'eid_records': {
            4097: ['0.0.0.0/0', '172.19.5.0/24', '172.19.6.0/24', '::/0'],
            4099: ['0.0.0.0/0', '10.199.221.0/24', '172.19.0.0/24', ...],
            8192: ['any-mac'],
            ...
        },
        'allow_locator_default_etr': {
            4097: ['ipv4', 'ipv6'],
            4099: ['ipv4', 'ipv6'],
            ...
        }
    }'''

    def rloc_members(self,service):
        hostname = self.device
        rlocmembercmd = "show run | i map-server rloc members"
        rlocmemberop = get_any_single_output(hostname,rlocmembercmd,service)
        self.rloc_members_distribute = False
        if rlocmemberop is not None:
            for line in rlocmemberop.splitlines():
                if "distribute" in line:
                    self.rloc_members_distribute = True

    def domains(self,service):
        hostname = self.device
        lispcmd = "show lisp"
        lispop = get_single_output_genie(hostname,lispcmd,service)
        self.domainid = 0
        self.multihomingid = 0
        if lispop is not None:
            try:
                path = lispop['lisp_id'][0]
            except KeyError:
                path = lispop['lisp_id']['default']
            # Try domainid
            try:
                domainid = int(path['domain_id'])
            except KeyError:
                domainid = 0
            # Try MultiHoming ID
            try:
                multihoming_id = int(path['multihoming_id'])
            except KeyError:
                multihoming_id = 0
            self.domainid = domainid
            self.multihomingid = multihoming_id

class LISPEIDWatch:
    def __init__(self,device,iid):
        self.iid = iid
        self.device = device
    def eidwatch_status(self,qtype, process, service):
        #Possible Processes: 'SISF Client', 'Multicast' and 'PDM-Steering'
        device = self.device
        iid = self.iid
        lispeidwatch = "show lisp instance-id {} {} eid-watch".format(iid, qtype)
        lispeidwatch_op = get_any_single_output(device,lispeidwatch,service)
        if lispeidwatch_op is not None:
                # Regex pattern
                pattern = r"Client\s*:\s*(.*?)\nProcess\s*ID\s*:\s*(\d+)\nConnection\s*to\s*LISP\s*control\s*process\s*:\s*(.*?)\nIPC\s*end\s*point\s*:\s*(\d+)\nClient\s*notifications\s*:\s*(.*?)\n"

                # Find all matches
                matches = re.findall(pattern, lispeidwatch_op)
                self.client = None
                self.processid = None
                self.connection_status = None
                self.ipc_endpoint = None
                self.client_notifications = None

                # Print extracted information
                for match in matches:
                    client, process_id, connection_status, ipc_endpoint, notifications = match
                    if client == process:
                        self.client = process
                        self.processid = int(process_id)
                        self.connection_status = connection_status
                        self.ipc_endpoint = int(ipc_endpoint)
                        self.client_notifications = notifications

class LISPInstanceStatus:

    def __init__(self,device,iid):
        self.iid = iid
        self.device = device
    def eidstatus(self,qtype,service):
        device = self.device
        iid = self.iid

        lispiidstatus_cmd = "show lisp instance-id {} {}".format(iid,qtype)
        lispiidstatus_op = get_single_output_genie(device,lispiidstatus_cmd,service)
        if lispiidstatus_op is not None:
            path = lispiidstatus_op['lisp_id'][0]['instance_id'][iid]
            # Parameter List
            self.locator_table = path['locator_table']
            self.eid = path['eid_table']
            self.itr = path['itr']['enabled']
            self.pitr = path['itr']['proxy_itr_router']
            self.rloc = path['itr']['local_rloc_last_resort']
            self.smr = path['itr']['solicit_map_request']
            self.etr = path['etr']['enabled']
            self.petr = path['etr']['proxy_etr_router']
            self.ms = path['map_server']
            self.mr = path['map_resolver']
            self.mapcache = path['map_cache']
            self.database = path['database']
            self.locatorstatus = path['locator_status_algorithms']
            self.mapresolvers = []
            try:
                usepetrs = path['itr']['use_proxy_etr_rloc']
            except KeyError:
                usepetrs = []
            self.usepetrs = usepetrs
            mresolvers = path['itr_map_resolvers']
            for i in mresolvers:
                if "found" not in i:
                    mapresolver = i
                    state = mresolvers[i]['reachable']
                    mapresolver = {'mapresolver': mapresolver, 'state': state}
                    self.mapresolvers.append(mapresolver)
            self.mapservers = []
            try:
                mservers = path['etr_map_servers']
                for i in mservers:
                    if "found" not in i:
                        mapserver = i
                        try:
                            transportstate = mservers[i]['last_map_register']['transport_state']
                        except KeyError:
                            transportstate = None
                        mapserver = {'mapserver': mapserver, 'transportstate': transportstate}
                        self.mapservers.append(mapserver)
            except KeyError:
                lispiidstatus_cmd = "show lisp instance-id {} {}".format(iid, qtype)
                lispiidstatus_op = get_any_single_output(device, lispiidstatus_cmd, service)
                if lispiidstatus_op is not None:
                    match = re.search(r"ETR Map-Server\(s\):\s*(.*)", lispiidstatus_op)
                    map_servers = []
                    if match:
                        # Split by comma, extract IPs
                        items = match.group(1).split(',')
                        for item in items:
                            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', item)
                            if ip_match:
                                map_servers.append(ip_match.group(1))
                    self.mapservers = map_servers
            self.xtrid = path['xtr_id']
            self.encapsulation = path['encapsulation_type']


        else:
            self.locator_table = None
            self.eid = None
            self.itr = None
            self.pitr = None
            self.rloc = None
            self.smr = None
            self.etr = None
            self.petr = None
            self.ms = None
            self.mr = None
            self.mapresolvers = None
            self.mapservers = None
            self.xtrid = None
            self.encapsulation = None


    def eidStatistics(self,qtype,service):
        device = self.device
        iid = self.iid

        lispiidstats_cmd = "show lisp instance-id {} {} statistics".format(iid,qtype)
        lispiidstats_op = get_single_output_genie(device,lispiidstats_cmd,service)
        if lispiidstats_op is not None:
            try:
                path = lispiidstats_op['lisp_id'][0]['instance_id'][iid]
            except KeyError:
                path = lispiidstats_op['lisp_id']['default']['instance_id'][iid]
            control_packets = path['control_packets']
            misc_errors = path['misc_statistics']['invalid']
            self.statisticscollected = True
            self.map_requests = control_packets['map_requests']
            self.map_reply = control_packets['map_reply']
            self.wlc_map_subscribe = control_packets['wlc_map_subscribe']
            self.wlc_map_unsubscribe = control_packets['wlc_map_unsubscribe']
            self.map_register = control_packets['map_register']
            self.map_notify = control_packets['map_notify']
            self.wlc_map_registers = control_packets['wlc_map_registers']
            self.wlc_map_notify = control_packets['wlc_map_notify']
            self.subscription_request = control_packets['publish_subscribe']['subscription_request']
            self.subscription_status = control_packets['publish_subscribe']['subscription_status']
            self.publication = control_packets['publish_subscribe']['publication']
            self.map_request_invalid_source_rloc_drops = path['errors']['map_request_invalid_source_rloc_drops']
            self.map_register_invalid_source_rloc_drops = path['errors']['map_register_invalid_source_rloc_drops']
            self.rejected_eid_prefix_due_to_limit = path['cache_related']['rejected_eid_prefix_due_to_limit']
            self.map_request_format_errors = path['rloc_statistics']['errors']['map_request_format']
            self.ip_version_drops = misc_errors['ip_version_drops']
            self.ip_header_drops = misc_errors['ip_header_drops']
            self.ip_proto_field_drops = misc_errors['ip_proto_field_drops']
            self.packet_size_drops = misc_errors['packet_size_drops']
            self.lisp_control_port_drops = misc_errors['lisp_control_port_drops']
            self.unsupported_lisp_packet_drops = path['misc_statistics']['unsupported_lisp_packet_drops']
            self.lisp_checksum_drops = path['misc_statistics']['unknown_packet_drops']
        else:
            lispiidstats_cmd = "show lisp instance-id {} {} statistics".format(iid, qtype)
            lispiidstats_op = get_any_single_output(device, lispiidstats_cmd, service)
            lispiidstats_op = parse_lisp_ethernet_statistics(lispiidstats_op)

            try:
                path = lispiidstats_op['lisp_id'][0]['instance_id'][iid]
            except KeyError:
                path = lispiidstats_op['lisp_id']['default']['instance_id'][iid]

            control_packets = path['control_packets']
            misc_errors = path['misc_statistics']['invalid']
            self.statisticscollected = True
            self.map_requests = control_packets['map_requests']
            self.map_reply = control_packets['map_reply']
            self.wlc_map_subscribe = control_packets['wlc_map_subscribe']
            self.wlc_map_unsubscribe = control_packets['wlc_map_unsubscribe']
            self.map_register = control_packets['map_register']
            self.map_notify = control_packets['map_notify']
            self.wlc_map_registers = control_packets['wlc_map_registers']
            self.wlc_map_notify = control_packets['wlc_map_notify']
            self.subscription_request = control_packets['publish_subscribe']['subscription_request']
            self.subscription_status = control_packets['publish_subscribe']['subscription_status']
            self.publication = control_packets['publish_subscribe']['publication']
            self.map_request_invalid_source_rloc_drops = path['errors']['map_request_invalid_source_rloc_drops']
            self.map_register_invalid_source_rloc_drops = path['errors']['map_register_invalid_source_rloc_drops']
            self.rejected_eid_prefix_due_to_limit = path['cache_related']['rejected_eid_prefix_due_to_limit']
            self.map_request_format_errors = path['rloc_statistics']['errors']['map_request_format']
            self.ip_version_drops = misc_errors['ip_version_drops']
            self.ip_header_drops = misc_errors['ip_header_drops']
            self.ip_proto_field_drops = misc_errors['ip_proto_field_drops']
            self.packet_size_drops = misc_errors['packet_size_drops']
            self.lisp_control_port_drops = misc_errors['lisp_control_port_drops']
            self.unsupported_lisp_packet_drops = path['misc_statistics']['unsupported_lisp_packet_drops']
            self.lisp_checksum_drops = path['misc_statistics']['unknown_packet_drops']

class LISPSession:

    def __init__(self,device):
        self.device = device

    def globallispsession(self,service):
        device = self.device
        lispsessionall = "show lisp session all"
        lispsessionallop = get_single_output_genie(device, lispsessionall, service)
        if lispsessionallop is not None:
            path = lispsessionallop['vrf']['default']
            self.totalsessions = int(path['total'])
            self.establishedsessions = int(path['established'])
            self.peers = path['peers']

    def specificlispsession(self,mapserver,service):
        device = self.device
        lispsessionspecific = "show lisp session {}".format(mapserver)
        lispsessionspecificop = get_single_output_genie(device, lispsessionspecific, service)
        if lispsessionspecificop is not None:
            path = lispsessionspecificop['lisp_id'][0]
            self.peer_addr = path["peer_addr"]
            self.peer_port = path["peer_port"]
            self.local_address = path["local_address"]
            self.local_port = path["local_port"]
            self.session_type = path["session_type"]
            self.session_state = path["session_state"]
            self.session_state_time = path["session_state_time"]
            self.messages_in = path["messages_in"]
            self.messages_out = path["messages_out"]
            self.fatal_errors = path["fatal_errors"]
            self.rcvd_unsupported = path["rcvd_unsupported"]
            self.rcvd_invalid_vrf = path["rcvd_invalid_vrf"]
            self.rcvd_override = path["rcvd_override"]
            self.rcvd_malformed = path["rcvd_malformed"]
            self.sent_defferred = path["sent_defferred"]
        if lispsessionspecificop is None:
            lispsessionspecific = "show lisp session {}".format(mapserver)
            lispsessionspecificop = get_any_single_output(device, lispsessionspecific, service)
            if lispsessionspecificop is not None:
                parsed_data = parse_lisp_session(lispsessionspecificop)
                try:
                    self.peer_addr = parsed_data["peer_addr"]
                    self.peer_port = parsed_data["peer_port"]
                    self.local_address = parsed_data["local_address"]
                    self.local_port = parsed_data["local_port"]
                    self.session_type = parsed_data["session_type"]
                    self.session_state = parsed_data["session_state"]
                    self.session_state_time = parsed_data["session_state_time"]
                    self.messages_in = parsed_data["messages_in"]
                    self.messages_out = parsed_data["messages_out"]
                    self.fatal_errors = parsed_data["fatal_errors"]
                    self.rcvd_unsupported = parsed_data["rcvd_unsupported"]
                    self.rcvd_invalid_vrf = parsed_data["rcvd_invalid_vrf"]
                    self.rcvd_override = parsed_data["rcvd_override"]
                    self.rcvd_malformed = parsed_data["rcvd_malformed"]
                    self.sent_defferred = parsed_data["sent_defferred"]
                except KeyError:
                    self.peer_addr = mapserver
                    self.peer_port = 4342
                    self.local_address = None
                    self.local_port = None
                    self.session_type = None
                    self.session_state = None
                    self.session_state_time = None
                    self.messages_in = None
                    self.messages_out = None
                    self.fatal_errors = None
                    self.rcvd_unsupported = None
                    self.rcvd_invalid_vrf = None
                    self.rcvd_override = None
                    self.rcvd_malformed = None
                    self.sent_defferred = None

    def lisp_prefix_list(self,service):
        hostname = self.device
        lispcmd = "show lisp prefix-list"
        lispop =  get_single_output_genie(hostname,lispcmd,service)
        self.lisp_prefixlist = lispop

    def lisp_subscribers(self,iid,service):
        hostname = self.device
        lispcmd = f"show lisp instance-id {iid} ipv4 subscriber"
        lispop = get_single_output_genie(hostname, lispcmd, service)
        self.lispsubscribers = lispop

    def lisp_publishers(self,iid,service):
        hostname = self.device
        lispcmd = f"show lisp instance-id {iid} ipv4 publisher"
        lispop = get_single_output_genie(hostname, lispcmd, service)
        self.lisppublishers = lispop

class LISPMapCache:
    def __init__(self,iid,device):
        self.device = device
        self.iid = iid
    def mapcache(self,qtype,eid,service):
        hostname = self.device
        iid = self.iid
        lispmapcachecmd = f"show lisp instance-id {iid} {qtype} map-cache {eid}"
        lispmapcacheop = get_single_output_genie(hostname,lispmapcachecmd,service)
        if lispmapcacheop is None:
            lispmapcachecmd = f"show lisp instance-id {iid} {qtype} map-cache {eid}"
            lispmapcacheop = get_any_single_output(hostname, lispmapcachecmd, service)
            lispmapcacheop = map_cache_manual_parse(lispmapcacheop)
        try:
            path = lispmapcacheop['lisp_id'][0]['instance_id'][iid]
        except KeyError:
            path = lispmapcacheop['lisp_id']['default']['instance_id'][iid]

        self.requested_eid = eid
        self.eid_table = path['eid_table']
        self.eid_prefix = path['eid_prefix']
        self.eid = path['eid']
        self.mask = path['mask']
        self.uptime = path['uptime']
        self.expires = path['expires']
        self.via = path['via']
        self.sources = path['sources']
        self.last_modified = path['last_modified']
        self.map_source = path['map_source']
        self.activity = path['activity']
        rlocs = []
        try:
            locators = path['locators']
            for locator in locators:
                rloc = locator
                uptime = path['locators'][rloc]['uptime']
                state = path['locators'][rloc]['state']
                priority = path['locators'][rloc]['weight']
                encap_iid = path['locators'][rloc]['encap_iid']
                rloc = {
                    'rloc': rloc,
                    'uptime': uptime,
                    'state': state,
                    'priority': priority,
                    'encap_iid': encap_iid
                }
                rlocs.append(rloc)
        except KeyError:
            pass
        self.rlocs = rlocs

class L2LISPStatistics:
    def __init__(self,device):
        self.hostname = device
    def l2lispstatistics(self,service):
        hostname = self.hostname

        l2lispstcmd = "show l2lisp statistics"
        l2lispop = get_any_single_output(hostname,l2lispstcmd,service)
        l2lispop = parse_show_l2lisp_statistics(l2lispop)
        self.l2lispstats = l2lispop

class LISPForwarding:
    def __init__(self,device,iid):
        self.hostname = device
        self.instanceid = iid
    def fwdingeidlocal(self,service):
        hostname = self.hostname
        iid = self.instanceid
        lispfwdcmd = f"show lisp instance-id {iid} ipv4 forwarding eid local"
        lispfwdcop = get_any_single_output(hostname,lispfwdcmd,service)
        lispfwdcop = parse_lisp_local_eids_and_overlaps(lispfwdcop)
        self.fwdeidlocal = lispfwdcop
    def fwdingeidremote(self,dstip,service):
        hostname = self.hostname
        iid = self.instanceid
        lispfwdcmd = f"show lisp instance-id {iid} ipv4 forwarding eid remote {dstip}"
        lispfwdcop = get_any_single_output(hostname,lispfwdcmd,service)
        lispfwdcop = parse_show_lisp_forwarding_eid_remote(lispfwdcop)
        self.fwdeidremote = lispfwdcop

class LISPRemoteDefault:
    def __init__(self,device):
        self.hostname = device
    def lispremotedefault(self,service):
        hostname = self.hostname

        lispdremtcmd = "show lisp remote-locator-set default-etrs"
        lispdremtop = get_single_output_genie(hostname,lispdremtcmd,service)
        data = lispdremtop or {}
        lisp_id = (data.get("lisp_id", {}) or {})
        first_lisp = next(iter(lisp_id.values()), {}) or {}
        rl_names = (first_lisp.get("remote_locator_name", {}) or {})

        ipv4_info = rl_names.get("default-etr-locator-set-ipv4", {}) or {}
        ipv6_info = rl_names.get("default-etr-locator-set-ipv6", {}) or {}

        self.remotelocatoripv4 = ipv4_info
        self.remotelocatoripv6 = ipv6_info

class LISPPublication:
    def __init__(self,device,iid):
        self.hostname = device
        self.iid = iid
    def v4publication(self,prefix,service):
        hostname = self.hostname
        iid = self.iid

        lisppubcmd = f"show lisp instance-id {iid} ipv4 publication {prefix}"
        lisppubop = get_single_output_genie(hostname,lisppubcmd,service)
        print (lisppubop)
# Operational #

class L3Device:
    def __init__(self,vrf,device):
        self.device = device
        self.vrf = vrf

    #LISP IID from VRF
    def lispiid(self,service):
        vrf = self.vrf
        hostname = self.device
        #Retrieve LISP IID for IPv4 and IPv6 if available
        lispvrfcmd = f"show lisp vrf {vrf}"
        lispvrfop = get_single_output_genie(hostname, lispvrfcmd,service)
        self.iid = None
        self.vrfid = None
        if lispvrfop is not None:
            path = lispvrfop['vrf'][vrf]
            self.vrfid = path['vrf_id']
            iids = path['iid']
            for entry in iids:
                iid = entry
            self.iid = int(iid)

    def instance_properties(self,service):
        hostname = self.device
        iid = self.iid
        iid_configuration = LISPInstanceStatus(hostname,iid)
        iid_configuration.eidstatus("ipv4",service)
        iid_configuration.eidStatistics("ipv4",service)
        self.instance_information = iid_configuration

    def lisp_database_information(self,service):
        hostname = self.device
        iid = self.iid
        lisp_local = LISPLocalDB('0.0.0.0',iid,hostname)
        lisp_local.L3LISPDyn(service)
        lisp_local.L3LISPDB(service)
        self.instance_local_parameters = lisp_local

    def map_cache(self,eids: list,service):
        hostname = self.device
        iid = self.iid
        map_caches = []
        eids.append("0.0.0.0/0")
        for eid in eids:
            map_cache = LISPMapCache(iid,hostname)
            map_cache.mapcache("ipv4",eid,service)
            map_caches.append(map_cache)
        self.map_cache_information = map_caches

    def cef_eids(self,eids: list, service,step):
        hostname = self.device
        vrf = self.vrf
        cef_internal_entries = []
        physical_next_hops = []
        for eid in eids:
            cef_internal = IPCef(eid,vrf,hostname)
            cef_internal.get_cef_internal(service)
            physical_ports = physical_recursion(cef_internal.nexthops,hostname)
            physical_ports.get_physical_interfaces(service,step)
            cef_internal_entries.append(cef_internal)
            physical_next_hops.append(physical_ports)
        self.cef_internal_entries = cef_internal_entries
        self.physical_next_hops = physical_next_hops

class CEFForwardingState:
    def __init__(self, vrf, device):
            self.device = device
            self.vrf = vrf

    def cef_resolution(self, prefixes: list, service, step):
            hostname = self.device
            vrf = self.vrf
            cefinternal_entries = []
            for prefix in prefixes:
                ip = prefix['prefix']
                expected_rloc = prefix['expectedrlocs']
                cef_internal = IPCef(ip, vrf, hostname)
                cef_internal.get_cef_internal(service)
                cef_internal.expected_rloc = expected_rloc
                cefinternal_entries.append(cef_internal)
            self.cef_internal_entries = cefinternal_entries

    def cef_underlay(self, underlay_prefixes: list, service):
        hostname = self.device
        cef_internal_underlay = []
        for prefix in underlay_prefixes:
            cef_internal = IPCef(prefix,None,hostname)
            cef_internal.get_cef_internal(service)
            cef_internal_underlay.append(cef_internal)
        self.cef_internal_underlay = cef_internal_underlay

    def underlay_phy(self, service):
        hostname = self.device
        cef_internal_underlay = self.cef_internal_underlay
        physical_interfaces = []
        for cef_internal_entry in cef_internal_underlay:
            phy = physical_recursion(cef_internal_entry,hostname)
            phy.get_physical_interfaces(service, "X")
            total_ports = phy.total_phys
            for port in total_ports:
                physical_interfaces.append(port)
        flat_list = [item for sublist in physical_interfaces for item in sublist]
        self.physical_interfaces = flat_list




