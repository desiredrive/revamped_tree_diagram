import re
import sys
from radkit_cli import logging_info,logging_error,logging_warning,get_catc_api,get_any_single_output,get_single_output_genie
from routingmodules.lisp import lisp_route_import
import time

def collection_success(xtr):
    hostname = xtr.hostname
    mgmtip = xtr.mgmtip
    invstatus = xtr.reachabilitystatus
    step = xtr.step
    try:
        lo0 = xtr.loopback
    except AttributeError:
        lo0 = None
    isfabric = xtr.isfabric
    collection_summary = "Hostname: {}, MgmtIP: {}, InventoryStatus: {}, Loopback0: {}, Fabric Device: {}".format(hostname,mgmtip,invstatus,lo0,isfabric)
    string = "Result: Success"
    logging_info(step, "Device-Profiling", None,hostname, collection_summary)
    logging_info(step, "Device-Profiling", None,hostname, string)

def rloc_definition(hostname, uuid, dnac, service,step):

    process = 'deviceProfiler'
    subprocess = '[rlocDefinition]'
     # Verifying if the configured Loopback0 is defined as the SINGLE LISP RLOC.
    loopback_api = "/dna/intent/api/v1/interface/network-device/{}/interface-name?name=Loopback0".format(uuid)
    loopback_response = get_catc_api(dnac,loopback_api,service)['response']
    ip, mask = None, None
    try:
        if "Not found" in loopback_response['errorCode']:
            error = "Catalyst Center could not retrieve the Loopback0 information for device {}".format(hostname)
            message = "Review the latest API retrieved in Catalyst Center in the GPS_SDA Collection"
            logging_error(step, process, subprocess, dnac, error)
            logging_info(step, process, subprocess, dnac, message)
            #raise BDBTaskError("Error: {} | {}".format(error, message))
            sys.exit("Error: {} | {}".format(error, message))
    except KeyError:
        pass

    #LoopbackState
    lo0state = loopback_response['status']
    if lo0state != 'up':
        error = "Error collecting Loopback0 information"
        message = "Loopback0 is down at device: {} , unshut the interface".format(hostname)
        logging_error(step, process, subprocess, hostname, error)
        logging_info(step, process, subprocess, hostname, message)
        #raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))

    for i in loopback_response['addresses']:
        if "IPV4_PRIMARY" in i['type']:
            ip = (i['address']['ipAddress']['address'])
            mask = (i['address']['ipMask']['address'])

    #RLOC Configuration Validation
    showrun_lisp_cmd = 'show run | i IPv4-interface|affinity'
    showrun_lisp_op = get_any_single_output(hostname,showrun_lisp_cmd,service)

    priority = ''
    weight = ''
    affinity = []
    loopbackstate = False
    rlocs = []
    if showrun_lisp_op is not None:
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
                    error = "Error determining Remote Locator information"
                    message = "More than 1 RLOC configured under \"router lisp\", unsupported SD-Access configuration, please correct it on device: {}".format(
                        hostname)
                    logging_error(step, process, subprocess, hostname, error)
                    logging_info(step, process, subprocess, hostname, message)
                    #raise BDBTaskError("Error: {} | {}".format(error, message))
                    sys.exit("Error: {} | {}".format(error, message))
        if loopbackstate is False:
            error = "Error determining Remote Locator information"
            message = "RLOC Interface Not Found, Verify if the Loopback0 is being used as RLOC under \"locator-set\", this problem might be caused by the BorderAffinity attribute under locator-set configuration on device: {}".format(
                hostname)
            logging_error(step, process, subprocess, hostname, error)
            logging_info(step, process, subprocess, hostname, message)
            #raise BDBTaskError("Error: {} | {}".format(error, message))
            sys.exit("Error: {} | {}".format(error, message))
    else:
        error = "Error determining Remote Locator information"
        message = f"Empty output when profiling RLOC information on device: {hostname}. Verify its 'Managed' state on Catalyst Center and ensure it is accessible via SSH/Telnet."
        logging_error(step, process, subprocess, hostname, error)
        logging_info(step, process, subprocess, hostname, message)
        #raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))
    return ip,mask,rlocs[0]

def cp_loopback(hostname, uuid, dnac, service,step):

    process = 'deviceProfiler'
    subprocess = '[rlocDefinition]'
     # Verifying if the configured Loopback0 is defined as the SINGLE LISP RLOC.
    loopback_api = "/dna/intent/api/v1/interface/network-device/{}/interface-name?name=Loopback0".format(uuid)
    loopback_response = get_catc_api(dnac,loopback_api,service)['response']
    ip, mask = None, None
    try:
        if "Not found" in loopback_response['errorCode']:
            error = "Catalyst Center could not retrieve the Loopback0 information for device {}".format(hostname)
            message = "Review the latest API retrieved in Catalyst Center in the GPS_SDA Collection"
            logging_error(step, process, subprocess, dnac, error)
            logging_info(step, process, subprocess, dnac, message)
            #raise BDBTaskError("Error: {} | {}".format(error, message))
            sys.exit("Error: {} | {}".format(error, message))
    except KeyError:
        pass

    #LoopbackState
    lo0state = loopback_response['status']
    if lo0state != 'up':
        error = "Error collecting Loopback0 information"
        message = "Loopback0 is down at device: {} , unshut the interface".format(hostname)
        logging_error(step, process, subprocess, hostname, error)
        logging_info(step, process, subprocess, hostname, message)
        #raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))

    for i in loopback_response['addresses']:
        if "IPV4_PRIMARY" in i['type']:
            ip = (i['address']['ipAddress']['address'])
            mask = (i['address']['ipMask']['address'])

    return ip,mask

def fabric_sites(siteNameHierarchy, dnac, service,step):

    process = 'deviceProfiler'
    subprocess = '[fabricSites]'
    isv1 = True  #Support for non v2 capable RADKIT Services
    #sitev2_api = "/dna/intent/api/v2/site?groupNameHierarchy={}".format(siteNameHierarchy)
    fabricsite_api = "/dna/intent/api/v1/sda/fabricSites"
    #sitev2_response = get_catc_api(dnac,sitev2_api,service)
    #if sitev2_response is None:
    sitev2_api = "/dna/intent/api/v1/site?name={}".format(siteNameHierarchy)
    sitev2_response = get_catc_api(dnac, sitev2_api, service)
    isv1 = True
    sitev2_response = sitev2_response['response']
    fabricsite_response = get_catc_api(dnac,fabricsite_api,service)['response']
    if isv1 is False:
        grouphierarchy = sitev2_response[0]['groupHierarchy']
    else:
        grouphierarchy = sitev2_response[0]['siteHierarchy']
    fabric_id,site_id,is_pubsub_site = None,None,False
    for i in fabricsite_response:
        if i['siteId'] in grouphierarchy:
            is_pubsub_site = i['isPubSubEnabled']
            fabric_id = i['id']
            site_id = i['siteId']
    if fabric_id is None:
        error = "Error Retrieving Fabric Site"
        message = "Review the latest API retrieved in Catalyst Center in the GPS_SDA Collection, API:{}".format(fabricsite_api)
        logging_error(step, process, subprocess, dnac, error)
        logging_info(step, process, subprocess, dnac, message)
        #raise BDBTaskError("Error: {} | {}".format(error, message))
        sys.exit("Error: {} | {}".format(error, message))
    else:
        if isv1 is False:
            sitev2_finalsite_api = "/dna/intent/api/v2/site?id={}".format(site_id)
            sitev2_finalsite_api_response = get_catc_api(dnac,sitev2_finalsite_api,service)['response']
            site_hierarchy = sitev2_finalsite_api_response[0]['groupNameHierarchy']
        else:
            sitev2_finalsite_api = "/dna/intent/api/v1/site?siteId={}".format(site_id)
            sitev2_finalsite_api_response = get_catc_api(dnac,sitev2_finalsite_api,service)['response']
            site_hierarchy = sitev2_finalsite_api_response['siteNameHierarchy']
        return is_pubsub_site,fabric_id,site_id,site_hierarchy

class Device:

    def __init__(self,mgmtip,catc,step):
        self.mgmtip = mgmtip
        self.dnac = catc
        self.step = step


    def find_device(self, service):

            process = 'deviceProfiler'
            subprocess = '[findDevice]'

            #Find device in inventory list
            try:
                self.device_inventory = service.inventory.filter('host', '^{}$'.format(self.mgmtip))
                device_name = list(self.device_inventory.keys())

                #Validation - Does this device exists?
                self.hostname = device_name[0]
                self.device_inventory = service.inventory[self.hostname]
                return self.hostname

            #If the Device does not exist
            except (IndexError, ValueError):
                error = "RADKIT Error, Finding Device"
                message = "Device {} not in RADKIT inventory, make sure this device is added as part of RADKIT Inventory".format(
                    self.mgmtip)
                logging_error(self.step, process, subprocess, self.mgmtip, error)
                logging_info(self.step, process, subprocess, self.mgmtip, message)
                #raise BDBTaskError("Error: {} | {}".format(error, message))
                sys.exit("Error: {} | {}".format(error, message))


    def profile_device(self, service):

        process = 'deviceProfiler'
        subprocess = '[profileDevice]'
        step = self.step
        dnac = self.dnac
        hostname = self.mgmtip

        Device.find_device(self,service)

        #Main APIs: Network Device and Fabric Role
        netdevice_api = "/dna/intent/api/v1/network-device/ip-address/{}".format(self.mgmtip)
        fabricdevice_api = "/dna/intent/api/v1/business/sda/device?deviceManagementIpAddress={}".format(self.mgmtip)
        netdevice_response = get_catc_api(self.dnac, netdevice_api,service)['response']
        if netdevice_response is None:
            error = "API Warning, Finding Device"
            message = "Unable to find network device. Review the latest API retrieved in Catalyst Center in the GPS_SDA Collection, API:{}".format(
                netdevice_api)
            logging_error(step, process, subprocess, hostname, error)
            logging_info(step, process, subprocess, hostname, message)
            sys.exit("Error: {} | {}".format(error, message))

        #1 Second of wait to avoid BAPI limit.
        time.sleep(1)

        fabricdevice_response = get_catc_api(self.dnac, fabricdevice_api,service)
        if fabricdevice_response is None:
            error = "API Warning, Finding Device"
            message = "Unable to find network device. Review the latest API retrieved in Catalyst Center in the GPS_SDA Collection, API:{}".format(
                fabricdevice_api)
            logging_error(step, process, subprocess, hostname, error)
            logging_info(step, process, subprocess, hostname, message)
            sys.exit("Error: {} | {}".format(error, message))

        if fabricdevice_response['status'] == "failed":
            warning = "API Warning, Finding Device"
            message = "WARNING!: Device {} is not a fabric device, could it be an Intermediate or Fusion Router device?".format(
                self.hostname)
            logging_warning(step, process, subprocess,dnac, warning)
            logging_warning(step, process, subprocess,dnac, message)


        try:
            self.version = netdevice_response['softwareVersion']
            self.serialnumbers = netdevice_response['serialNumber']
            self.deviceuuid = netdevice_response['instanceUuid']
            self.platform = netdevice_response['platformId']
            self.reachabilitystatus = netdevice_response['reachabilityStatus']
        except KeyError:
            error = "Error Retrieving Device Details from Catalyst Center API"
            message = "Review the latest API retrieved in Catalyst Center in the GPS_SDA Collection, API:{}".format(
                fabricdevice_api)
            logging_error(step, process, subprocess, hostname, error)
            logging_info(step, process, subprocess, hostname, message)
            #raise BDBTaskError("Error: {} | {}".format(error, message))
            sys.exit("Error: {} | {}".format(error, message))
        try:
            self.siteNameHierarchy = fabricdevice_response['siteNameHierarchy']
            self.isfabric = True
        except KeyError:
            warning = "API Warning, Finding Device"
            message = "WARNING!: Device {} is not a fabric device, could it be an Intermediate or Fusion Router device?".format(
                hostname)
            logging_warning(step, process, subprocess, hostname, warning)
            logging_warning(step, process, subprocess, hostname, message)

            netdevice_detail_api = "/dna/intent/api/v1/device-detail?searchBy={}&identifier=uuid".format(self.deviceuuid)
            netdevicedetail_response = get_catc_api(self.dnac, netdevice_detail_api, service)['response']
            self.isfabric = False
            self.siteNameHierarchy = netdevicedetail_response['location']


        fabric_details = fabric_sites(self.siteNameHierarchy,self.dnac,service,self.step)
        self.ispubsub = fabric_details[0]
        self.fabric_id = fabric_details[1]
        self.fabric_site_id = fabric_details[2]
        self.fabric_site_hierarchy = fabric_details[3]

            #Loopback Configuration and RLOC defintion - Is Loopback0 Configured as RLOC?
            #Only the following roles requires RLOC definition ['Edge Node', 'Border Node', 'Control Plane' ]
        if self.isfabric is True:
            fabric_role = fabricdevice_response['roles']
        else:
            fabric_role = 'NotFabric'

        #CP Flag
        fabric_roles_cp = ['Control Plane']
        if  any(x  in fabric_role for x in fabric_roles_cp):
            self.cp = True
            loopback_parameters = cp_loopback(self.hostname, self.deviceuuid, self.dnac, service, self.step)
            self.loopback = (loopback_parameters[0])
            self.mask = (loopback_parameters[1])

        #Loopback validation (Edges and Borders)
        #PITR Validation From: show lisp service ipv4
        #ProxyETR Validation From: show lisp service ipv4
        if self.reachabilitystatus != 'Unreachable':
            fabric_roles_withlo0 = ['Edge Node', 'Border Node']
            if  any(x  in fabric_role for x in fabric_roles_withlo0):
                loopback_parameters = rloc_definition(self.hostname, self.deviceuuid, self.dnac, service, self.step)
                self.loopback = (loopback_parameters[0])
                self.mask = (loopback_parameters[1])
                self.rlocdef = loopback_parameters[2]
                lispsum = get_single_output_genie(self.hostname,"show lisp service ipv4", service)
                pitr = (lispsum['lisp_id'][0]['itr']['proxy_itr_rloc'])
                if pitr!=self.loopback:
                    error = "Error Retrieving Device Details from Catalyst Center API"
                    message = "Device {} PITR address is not the same as Loopback0, correct this configuration with \"proxy-itr [loopback0] \" under router lisp, service ipv4".format(
                        self.hostname)
                    logging_error(step, process, subprocess, hostname, error)
                    logging_info(step, process, subprocess, hostname, message)
                    #raise BDBTaskError("Error: {} | {}".format(error, message))
                    sys.exit("Error: {} | {}".format(error, message))

                petrflag = lispsum['lisp_id'][0]['etr']['proxy_etr_router']
                if petrflag is True:
                    self.eborder = True

            #Internal Border Validation
            fabric_role_border = ['Border Node']
            if  any(x  in fabric_role for x in fabric_role_border):
                route_import_state = lisp_route_import("*",self.hostname)
                rdbstate = route_import_state.ridb_state(service)
                if rdbstate is not None:
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
            if self.isfabric is not False:
                l2handoff_api = "/dna/intent/api/v1/sda/fabricDevices/layer2Handoffs/count?fabricId={}&networkDeviceId={}".format(self.fabric_id,self.deviceuuid)
                l2handoff_response = get_catc_api(self.dnac, l2handoff_api,service)['response']
                if l2handoff_response['count'] == 1:
                    self.l2handoff = True
                else:
                    self.l2handoff = False

