import re
import radkit_cli

def ping_validation(ping_output):
        for line in ping_output.splitlines():
            if "Success" in line:
                percent = re.compile("(?<=is).*(?=percent)").search(line).group().strip()
        return percent

class Ping():

    def __init__ (self, dstip, device):
        self.hostname = device
        self.dstip = dstip

    def basic_ping(self, vrf, size: int, dfbit, service):
        #Identify if VRF is in use or not:
        if vrf == "default" or vrf is None:
            vrf_mode = ""
        else:
            vrf_mode = "vrf "+vrf+" "

        if (size is not None):
            size_mode = "size {}".format(size)
        else:
            size_mode = ""
        
        if (dfbit is True):
            dfbit = "df-bit"
        else:
            dfbit = ""

        ping_cmd = "ping {} {} {} {}".format(vrf_mode, self.dstip, size_mode, dfbit, service)
        ping_op = radkit_cli.get_any_single_output(self.hostname,ping_cmd,service)

        self.result = self.ping_validation(ping_op)
    
    def ping_with_source(self, vrf, source, size: int, dfbit, service):
        #Identify if VRF is in use or not:
        if vrf == "default":
            vrf_mode = ""
        elif vrf is None:
            vrf_mode = ""
        else:
            vrf_mode = "vrf "+vrf+" "
        if (size is not None):
            size_mode = "size {}".format(size)
        else:
            size_mode = ""
        if (dfbit is True):
            dfbit = "df-bit"
        else:
            dfbit = ""
        ping_cmd = "ping {} {} source {} {} {}".format(vrf_mode, self.dstip, source, size_mode, dfbit, service)
        ping_op = radkit_cli.get_any_single_output(self.hostname,ping_cmd,service)
        self.result = ping_validation(ping_op)
        
    def ping_validation(ping_output):
        for line in ping_output.splitlines():
            if "Success" in line:
                percent = re.compile("(?<=is).*(?=percent)").search(line).group().strip()
        return percent

class Mtrace():
    def __init__(self, source, hostname):
        self.hostname = hostname
        self.source = source

    def simple_mtrace(self,destination,group,vrf,service):
        # Identify if VRF is in use or not:
        if vrf == "default" or vrf is None:
            vrf_mode = ""
        else:
            vrf_mode = "vrf " + vrf + " "

        if destination is None:
            destination = ""
        if group is None:
            group = ""

        #Mtrace Format: mtrace (vrf_mode) (source) (destinaton) (group)
        mtrace_cmd = "mtrace{} {} {} {}".format(vrf_mode,self.source,destination,group)
        mtrace_op = radkit_cli.get_any_single_output(self.hostname,mtrace_cmd,service)
        print (mtrace_cmd)
        print (mtrace_op)
        #Output Parser:
        if mtrace_op is not None:
            matches = ["#", "mtrace", "Type escape", "From source", "Querying", "via RPF", "via group"]
            index_regex = re.compile(r'^\s*-?\d+')
            ip_regex = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
            protocol_regex = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?! ==>)(?:\s+)(\S+)(?:\s+)([\w\s]+)')

            # Iterating over the mtrace output
            mtrace_results = []
            for line in mtrace_op.splitlines():
                if not any(x in line for x in matches):
                    # Attributes to get: Index/Hop, Source IP (Must), Dest IP (Optional), Protocol (Optional), Code Reason
                    # 1 - Get Index (Regex)
                    index_match = index_regex.match(line)
                    if index_match:
                        index = int(index_match.group().strip().strip("-"))
                    # 2 - Get Source IP (Regex)
                    ips = ip_regex.findall(line)
                    if len(ips) > 1:
                        source = ips[0]
                        destination = ips[1]
                    else:
                        source = ips[0]
                        destination = "Local"
                    # 3 - Protocol Type:
                    match = protocol_regex.search(line)
                    if match:
                        protocol = match.group(1)
                        error_code = match.group(2)
                    else:
                        if index == 0:
                            protocol = "PIM"
                            error_code = ""
                        else:
                            protocol = ""
                            error_code = ""
                    if source == destination:
                        protocol = "PIM"
                    mtrace_dict = {
                        'index': index,
                        'origin': source,
                        'nexthop': destination,
                        'protocol': protocol,
                        'error_code': error_code
                    }
                    mtrace_results.append(mtrace_dict)
            self.mtrace_results = mtrace_results
        else:
            self.mtrace_results = None