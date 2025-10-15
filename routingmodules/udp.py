from radkit_cli import get_any_single_output
import re

def parse_udp_entries(showudp):
    # Clean and prepare data
    lines = showudp.strip().split('\n')
    # Find the header row
    header_idx = None
    for idx, line in enumerate(lines):
        if re.match(r'Proto\s+Remote\s+Port', line):
            header_idx = idx
            break
    if header_idx is None:
        raise ValueError("Header row not found.")
    # UDP entry lines follow the header, until a non-data line
    udp_lines = []
    for line in lines[header_idx + 1:]:
        if not line.strip() or line.startswith("Edge-1#"):
            break
        if not line.strip()[0].isdigit() and not line.strip().startswith('17'):
            continue  # Skip any non-data lines
        udp_lines.append(line)
    # Regex for the UDP entry lines
    entry_re = re.compile(
        r"(?P<proto>17(?:\(v6\))?)\s+"
        r"(?P<remote>[^\s]+)\s+"
        r"(?P<remote_port>\S*)\s+"
        r"(?P<local>[^\s]+)\s+"
        r"(?P<local_port>\d+)\s+"
        r"(?P<in>\d+)\s+"
        r"(?P<out>\d+)\s+"
        r"(?P<stat>\d+)\s+"
        r"(?P<tty>\d+)"
        r"(?:\s+(?P<output_if>\S+))?"
    )
    udp_entries = []
    for line in udp_lines:
        m = entry_re.match(line.strip())
        if m:
            entry = m.groupdict()
            # Clean up possible None values
            for key in entry:
                if entry[key] is None:
                    entry[key] = ""
            udp_entries.append(entry)
        else:
            print(f"Could not parse line: {line}")
    return udp_entries

class UDPports:
    def __init__(self,device):
        self.device = device
    def udpports(self,service):
        device = self.device
        udpcmd = "show udp"
        udpop = get_any_single_output(device,udpcmd,service)
        if udpop is None:
            self.udports = None
        else:
            udp_parsed_ports = parse_udp_entries(udpop)
            self.udports = udp_parsed_ports