from dataclasses import dataclass
import re
import sys
import radkit_cli

class lisp_route_import:

    def __init__(self, iid, device):
        self.iid = iid
        self.configured_iids = None 
        self.sourceprotocol = None
        self.limit = None
        self.rlocs = None
        self.hostname  = device
    
    def ridb_state(self, service):
        ridb_cmd = "show lisp instance-id {} ipv4 route-import database".format(self.iid)
        ridb_op = radkit_cli.get_any_single_output(self.hostname,ridb_cmd,service)
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
        print (iids)
        print (configflag)
        print (limits)
