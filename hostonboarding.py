from dataclasses import dataclass
import re
import sys
import radkit_cli

class endpoint_info:

    def __init__(self,sourceip):
        self.sourceip = sourceip
        self.sourcemac = None
        self.sourcevlan = None
        self.sourcevlanname = None
        self.sourcevrf = None
        self.sourceport = None
        self.ipdtmethod = None
        self.ipdtstate = None
        self.ipdtprivilege = None
        self.prefix = None
        self.mask = None
        self.l3lispiid = None 
        self.l2lispiid = None
        self.isl2only = False
        self.isl3only = False
        self.l3dynstate = False
        self.l3lispdbstate = False
        self.l2dynstate = False
        self.l2lispdbstate = False 
        self.l2cps = [] 
        self.l3cps = []
        self.sgt = 0
        self.isl2flood = False
        self.isipdb = False
        self.arpflood = False
        self.multiip = False
        self.iswirelesspool = False
        self.rloc = None
        self.mgmtip = None

    def host_onboarding_validation(self, xtr, service):
        self.mgmtip = xtr.mgmtip
        hostname = xtr.hostname
        dnac = xtr.dnac
        fabric_id = xtr.fabric_id
        fabric_site = xtr.fabric_site_hierarchy

        #Fabric Site Collection

        #IPDT Collection
        ipdt_cmd = "show device-tracking database"
        ipdt_output = radkit_cli.get_single_output_genie(hostname, ipdt_cmd, service)
        try:
            for i in ipdt_output['device']:
                if self.sourceip in (ipdt_output['device'][i]['network_layer_address']):
                    ipdt_flag = True
                    device_entry = ipdt_output['device'][i]
        except TypeError:
            sys.exit("No IPDT Entry for host {} !".format(self.sourceip))

        self.ipdtmethod = device_entry['dev_code']
        self.sourcemac = device_entry['link_layer_address']
        self.sourcevlan = device_entry['vlan_id']
        self.sourceport = device_entry['interface']
        self.ipdtstate = device_entry['state']
        self.ipdtprivilege = device_entry['pref_level_code']

        ipdt_problematic_conditions = ['DOWN', 'VERIFY', 'STALE', 'UNKNOWN', 'INCOMPLETE']
        if  any(x  in self.ipdtstate for x in ipdt_problematic_conditions):
            sys.exit("SISF/IPDT entry for host {} in device {} is in state {}, resolve this condition first".format(self.sourceip,hostname,self.ipdtstate))

        #Retrieving Pool Details...(L2 Only, FEW, L3 Only, L2 Flooding, BVM/Multiple, associated VRF)
        print ("Retrieving Pool Details for VLAN {} in Fabric Site {}".format(self.sourcevlan,fabric_site))
        l2vni_api = "/dna/intent/api/v1/sda/layer2VirtualNetworks?fabricId={}&vlanId={}".format(fabric_id,self.sourcevlan)
        l2vni_response = radkit_cli.get_catc_api(dnac, l2vni_api, service)['response'][0]

        self.sourcevlanname = l2vni_response['vlanName']
        self.iswirelesspool = l2vni_response['isFabricEnabledWireless']
        
        try:
            self.sourcevrf = l2vni_response['associatedLayer3VirtualNetworkName']
        except KeyError:
            self.sourcevrf = None
            self.l2flood = True
            self.arpflood = True
            self.isl2only = True
        if self.sourcevrf != None:
            l2vni_pool_api = "/dna/intent/api/v1/business/sda/virtualnetwork/ippool?siteNameHierarchy={}&virtualNetworkName={}&ipPoolName={}".format(fabric_site,self.sourcevrf,self.sourcevlanname)
            l2vni_pool_response = radkit_cli.get_catc_api(dnac,l2vni_pool_api,service)
            self.isl2only = l2vni_pool_response['isLayer2OnlyPool']
            self.isipdb = l2vni_pool_response['isIpDirectedBroadcast']
            self.isl2flood = l2vni_pool_response['isSelectiveFloodingEnabled']
            self.multiip = l2vni_pool_response['isBridgeModeVm']
        
        if self.isl2only is False:
            #Retrieve Anycast GW Information - CLI Parser : show ip interface (svi)
            print ("Endpoint found in VLAN {}, not L2 Only, retrieving Anycast Gateway information...\n".format(self.sourcevlan))
            sviip_cmd = "show ip interface vlan {}".format(self.sourcevlan)
            sviip_op = radkit_cli.get_single_output_genie(hostname, sviip_cmd, service)
            print (sviip_op)



