from radkit_cli import get_any_single_output
import re

def parse_log_line(line):
    # Pattern to match lines with TCB
    pattern_with_tcb = r'^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)$'
    # Pattern to match lines without TCB (e.g., starting with dashes)
    pattern_without_tcb = r'^(------------)\s+(\S+)\s+(\S+)\s+(\S+)$'

    match = re.match(pattern_with_tcb, line.strip())
    if match:
        tcb, src, dst, state = match.groups()
        if tcb == '------------':
            # Treat as no TCB
            tcb = None
    else:
        # Line does not match expected format
        return None

    def split_ip_port(ip_port):
        parts = ip_port.rsplit('.', 1)
        if len(parts) == 2:
            ip, port = parts
            try:
                port = int(port)
            except ValueError:
                port = None
            return ip, port
        else:
            return ip_port, None

    src_ip, src_port = split_ip_port(src)
    dst_ip, dst_port = split_ip_port(dst)

    return {
        'tcb': tcb,
        'source_ip': src_ip,
        'source_port': src_port,
        'destination_ip': dst_ip,
        'destination_port': dst_port,
        'state': state
    }

def parse_tcp_tcb(output):
    tcb_info = {}
    # Connection state
    match = re.search(r"Connection state is (\S+),", output)
    if match:
        tcb_info["Connection state"] = match.group(1)
    # Local host and port
    match = re.search(r"Local host: ([\d\.]+), Local port: (\d+)", output)
    if match:
        tcb_info["Local host"] = match.group(1)
        tcb_info["Local port"] = int(match.group(2))
    # Foreign host and port
    match = re.search(r"Foreign host: ([\d\.]+), Foreign port: (\d+)", output)
    if match:
        tcb_info["Foreign host"] = match.group(1)
        tcb_info["Foreign port"] = int(match.group(2))
    # VRF table id
    match = re.search(r"Connection tableid \(VRF\): (\d+)", output)
    if not match:
        # Sometimes it may appear as "VRF table id is: 0"
        match = re.search(r"VRF table id is: (\d+)", output)
    if match:
        tcb_info["VRF table"] = int(match.group(1))
    # Enqueued packets for retransmit
    match = re.search(r"Enqueued packets for retransmit: (\d+)", output)
    if match:
        tcb_info["Enqueued packets for retransmit"] = int(match.group(1))
    # Sent line: retransmit counter, fastretransmit, partialack, Second Congestion, with data, total data bytes
    match = re.search(
        r"Sent: (\d+) \(retransmit: (\d+), fastretransmit: (\d+), partialack: (\d+), Second Congestion: (\d+)\), with data: (\d+), total data bytes: (\d+)",
        output,
    )
    if match:
        tcb_info["Sent total"] = int(match.group(1))
        tcb_info["Sent retransmit counter"] = int(match.group(2))
        tcb_info["Sent fastretransmit"] = int(match.group(3))
        tcb_info["Sent partialack"] = int(match.group(4))
        tcb_info["Sent Second Congestion"] = int(match.group(5))
        tcb_info["Sent with data"] = int(match.group(6))
        tcb_info["Sent total data bytes"] = int(match.group(7))
    # Peer MSS
    match = re.search(r"max data segment is (\d+) bytes", output)
    if match:
        tcb_info["MSS"] = int(match.group(1))
    # Datagrams received line: received, out of order, with data, total data bytes
    match = re.search(
        r"Rcvd: (\d+) \(out of order: (\d+)\), with data: (\d+), total data bytes: (\d+)",
        output,
    )
    if match:
        tcb_info["Datagrams"] = {
            "Received": int(match.group(1)),
            "Received out of order": int(match.group(2)),
            "Received with data": int(match.group(3)),
            "Received total data bytes": int(match.group(4)),
        }
    return tcb_info

class TCPSocket:
    def __init__(self,device):
        self.device = device

    def tcpbrief(self,service):
        device = self.device
        tcpbriefcmd = "show tcp brief numeric"
        tcpbriefop = get_any_single_output(device,tcpbriefcmd,service)
        if tcpbriefop is None:
            return None
        else:
            tcbs = []
            matches = ['#', 'show']
            # Parsed without #show line
            for line in tcpbriefop.splitlines():
                if not any(x in line for x in matches):
                    parsed = parse_log_line(line)
                    if parsed:
                        tcbs.append(parsed)
            self.tcbs = tcbs
    def tcptcb(self,tcb,service):
        device = self.device
        tcptcbcmd = "show tcp tcb {}".format(tcb)
        tcptcbop = get_any_single_output(device,tcptcbcmd,service)
        if tcptcbop is None:
            return None
        else:
            parsed_result = parse_tcp_tcb(tcptcbop)
            self.connection_state = parsed_result["Connection state"]
            self.local_host = parsed_result["Local host"]
            self.local_port = parsed_result["Local port"]
            self.foreign_host = parsed_result["Foreign host"]
            self.foreign_port = parsed_result["Foreign port"]
            self.vrfid = parsed_result["VRF table"]
            self.retransmitqueue = parsed_result["Enqueued packets for retransmit"]
            self.senttotalpackets = parsed_result["Sent total"]
            self.retransmitcounter = parsed_result["Sent retransmit counter"]
            self.fastretransmitcounter = parsed_result["Sent fastretransmit"]
            self.sentpartialack = parsed_result["Sent partialack"]
            self.mss = parsed_result["MSS"]