from radkit_cli import get_single_output_genie, get_any_single_output
import re
import ipaddress

class AccessPointInfo:
    def __init__(self, wlc):
        self.wlc = wlc
    def apconfiggeneral(self, apname, service):
        wlcname = self.wlc
        apcg_cmd = f"show ap name {apname} config general"
        apcg_op = get_single_output_genie(wlcname,apcg_cmd, service)
        self.apconfiggeneral = apcg_op

    def fabric_status(self,apname,service):
        wlcname = self.wlc
        apfabriccmd = f"show ap name {apname} config general | i Fabric|RLOC"
        apfabricop = get_any_single_output(wlcname,apfabriccmd, service)
        rloc = None
        for line in (apfabricop or "").splitlines():
            m = re.match(r"^\s*RLOC\s*:\s*(\S+)\s*$", line)
            if not m:
                continue
            candidate = m.group(1)
            try:
                rloc =  str(ipaddress.ip_address(candidate))
            except ValueError:
                rloc = None
        self.rloc = rloc
