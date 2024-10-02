from dataclasses import dataclass
import re
import sys
import radkit_cli
from routingmodules import lisp

def rloc_definition(hostname, uuid, dnac, service):
     # Verifying if the configured Loopback0 is defined as the SINGLE LISP RLOC.
    loopback_api = "/dna/intent/api/v1/interface/network-device/{}/interface-name?name=Loopback0".format(uuid)
    loopback_response = radkit_cli.get_catc_api(dnac,loopback_api,service)['response']
    
    try:
        if "Not found" in loopback_response['errorCode']:
            sys.exit("Error: Catalyst Center could NOT retrieve Loopback0 information for the device {}".format(hostname))
    except KeyError:
        pass

    #LoopbackState
    lo0state = loopback_response['status']
    if lo0state != 'up':
        sys.exit("Loopback0 is down at device: {} , unshut the interface".format(hostname))

    for i in loopback_response['addresses']:
        if "IPV4_PRIMARY" in i['type']:
            ip = (i['address']['ipAddress']['address'])
            mask = (i['address']['ipMask']['address'])
    
    #RLOC Configuration Validation
    showrun_lisp_cmd = 'show run | i IPv4-interface|affinity'
    showrun_lisp_op = radkit_cli.get_any_single_output(hostname,showrun_lisp_cmd,service)

    priority = ''
    weight = ''
    affinity = []
    loopbackstate = False
    rlocs = []
    for line in showrun_lisp_op.splitlines():
        if "IPv4-interface " in line:
            loopbackstate = True
            interface = re.compile("(?<=face).*(?=prio)").search(line).group().strip()
            if "priority" in line:
                priority = re.compile("(?<=priority\s)[0-9]+").search(line).group().strip()
            if "weight" in line:
                weight = re.compile("(?<=weight\s)[0-9]+").search(line).group().strip()                        
            if "affinity-id" in line:
                aff = re.compile("(?<=affinity-id\s)[0-9]+").search(line).group().strip()
                affinity.append(aff)
                aff = re.compile("(?<=,\s)[0-9]+").search(line).group().strip()
                affinity.append(aff)
            try:
                valoop = {'Interface': interface, 'Priority' : priority, 'Weight' : weight, 'Affinity' : affinity}
                rlocs.append(valoop)
            except KeyError:
                pass
    if len(rlocs) > 1:
        for i in rlocs:
            if (i['Interface']) != "Loopback0":
                sys.exit("More than 1 RLOC configured under \"router lisp\", unsupported SD-Access configuration, please correct it on device: {}".format(hostname))
    if loopbackstate == False:
        sys.exit("RLOC Interface Not Found, Verify if the Loopback0 is being used as RLOC.")
    return (ip,mask,rlocs[0])

def fabric_sites(siteNameHierarchy, dnac, service):
    sitev2_api = "/dna/intent/api/v2/site?groupNameHierarchy={}".format(siteNameHierarchy)
    fabricsite_api = "/dna/intent/api/v1/sda/fabricSites"
    sitev2_response = radkit_cli.get_catc_api(dnac,sitev2_api,service)['response']
    fabricsite_response = radkit_cli.get_catc_api(dnac,fabricsite_api,service)['response']
    grouphierarchy = sitev2_response[0]['groupHierarchy']
    fabric_id = None
    for i in fabricsite_response:
        if i['siteId'] in grouphierarchy:
            is_pubsub_site = i['isPubSubEnabled']
            fabric_id = i['id']
            site_id = i['siteId']
    if fabric_id is None:
        sys.exit("Unable to parse Fabric Site details!!")
    else:
        sitev2_finalsite_api = "/dna/intent/api/v2/site?id={}".format(site_id)
        sitev2_finalsite_api_response = radkit_cli.get_catc_api(dnac,sitev2_finalsite_api,service)['response']
        site_hierarchy = sitev2_finalsite_api_response[0]['groupNameHierarchy']
        return (is_pubsub_site,fabric_id,site_id,site_hierarchy)

class device:

    def __init__(self,mgmtip,catc):
        self.mgmtip = mgmtip
        self.dnac = catc


    def find_device(self, service):
            
            #Find device in inventory list
            try:
                self.device_inventory = service.inventory.filter('host', '^{}$'.format(self.mgmtip))
                device_name = list(self.device_inventory.keys())

                #Validation - Does this device exists?
                self.hostname = device_name[0]
                self.device_inventory = service.inventory[self.hostname]
                return (self.hostname)

            #If the Device does not exist  
            except (IndexError, ValueError):
                sys.exit("Device {} not in RADKIT inventory".format(self.mgmtip)) 


    def profile_device(self, service):
        device.find_device(self,service)

        #Main APIs: Network Device and Fabric Role
        netdevice_api = "/dna/intent/api/v1/network-device/ip-address/{}".format(self.mgmtip)
        fabricdevice_api = "/dna/intent/api/v1/business/sda/device?deviceManagementIpAddress={}".format(self.mgmtip)

        netdevice_response = radkit_cli.get_catc_api(self.dnac, netdevice_api,service)['response']
        fabricdevice_response = radkit_cli.get_catc_api(self.dnac, fabricdevice_api,service)

        if fabricdevice_response['status'] == "failed":
            print ("WARNING!: Device {} is not a fabric device".format(self.hostname))
    
        self.version = netdevice_response['softwareVersion']
        self.serialnubmers = netdevice_response['serialNumber']
        self.deviceuuid = netdevice_response['instanceUuid']
        self.platform = netdevice_response['platformId']
        self.siteNameHierarchy = fabricdevice_response['siteNameHierarchy']

        #Fabric Site Details
        fabric_details = fabric_sites(self.siteNameHierarchy,self.dnac,service)
        self.ispubsub = fabric_details[0]
        self.fabric_id = fabric_details[1]
        self.fabric_site_id = fabric_details[2]
        self.fabric_site_hierarchy = fabric_details[3]
        
        #Loopback Configuration and RLOC defintion - Is Loopback0 Configured as RLOC?
        #Only the following roles requires RLOC definition ['Edge Node', 'Border Node', 'Control Plane' ]

        fabric_role = fabricdevice_response['roles']
        
        #CP Flag
        fabric_roles_cp = ['Control Plane']
        if  any(x  in fabric_role for x in fabric_roles_cp):
            self.cp = True

        #Loopback validation (Edges and Borders)            
        #PITR Validation From: show lisp service ipv4 
        #ProxyETR Validation From: show lisp service ipv4

        fabric_roles_withlo0 = ['Edge Node', 'Border Node']
        if  any(x  in fabric_role for x in fabric_roles_withlo0):
            loopback_parameters = rloc_definition(self.hostname, self.deviceuuid, self.dnac, service)
            self.loopback = (loopback_parameters[0])
            self.mask = (loopback_parameters[1])
            self.rlocdef = loopback_parameters[2]
            lispsum = radkit_cli.get_single_output_genie(self.hostname,"show lisp service ipv4", service)
            pitr = (lispsum['lisp_id'][0]['itr']['proxy_itr_rloc'])
            if pitr!=self.loopback:
                sys.exit("Device {} PITR address is not the same as Loopback0, correct this configuration".format(self.hostname))
            petrflag = lispsum['lisp_id'][0]['etr']['proxy_etr_router']
            if petrflag is True:
                self.eborder = True

        #Internal Border Validation
        fabric_role_border = ['Border Node']
        if  any(x  in fabric_role for x in fabric_role_border):
            route_import_state = lisp.lisp_route_import("*",self.hostname)
            rdbstate = route_import_state.ridb_state(service)
            if rdbstate != None:
                for i in rdbstate:
                    flag = rdbstate[i]['configured']
                    if flag is True:
                        self.iborder = True
            #L2Handof Definition

        #Edge Role Assignment
        fabric_role_edge = ['Edge Node']
        if  any(x  in fabric_role for x in fabric_role_edge):
            self.edge = True
    
        #L2HandoffValidation
        l2handoff_api = "/dna/intent/api/v1/sda/fabricDevices/layer2Handoffs/count?fabricId={}&networkDeviceId={}".format(self.fabric_id,self.deviceuuid)
        l2handoff_response = radkit_cli.get_catc_api(self.dnac, l2handoff_api,service)['response']
        if l2handoff_response['count'] == 1:
            self.l2handoff = True
        else:
            self.l2handoff = False

