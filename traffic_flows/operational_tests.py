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

