#!/usr/bin/env python

"""
Written by Livio Zanol Puppim https://github.com/liviozanol
Based on list_vlan_in_portgroups Written by David Martinez. Github: https://github.com/dx0xm

Script to list rules on portgroups

TODO:
    - Get more than one qualifier per rule.
    - Get qualifiers that are not IP qualifiers
    - Get "nagate" statements from qualifiers
    - Differentiate multiple PortGroupss with same name with specific dvs set by user by '-dvs'
"""


from __future__ import print_function
from pyVim.connect import SmartConnect, SmartConnectNoSSL, Disconnect
from pyVmomi import vim
import atexit
import argparse
import getpass
import sys
import json


def get_args():
    parser = argparse.ArgumentParser(
        description='Arguments for talking to vCenter')

    parser.add_argument('-s', '--host',
                        required=True,
                        action='store',
                        help='vSpehre service to connect to')

    parser.add_argument('-o', '--port',
                        type=int,
                        default=443,
                        action='store',
                        help='Port to connect on')

    parser.add_argument('-u', '--user',
                        required=True,
                        action='store',
                        help='User name to use')

    parser.add_argument('-p', '--password',
                        required=False,
                        action='store',
                        help='Password to use')

    parser.add_argument('-d', '--datacenter',
                        required=True,
                        help='name of the datacenter')

    parser.add_argument('-dvs', '--dvswitch',
                        required=False,
                        help='name of the dvswitch',
                        default='all')

    parser.add_argument('-pg', '--portgroup',
                        required=False,
                        help='name of the portgroup',
                        default='')

    parser.add_argument('-ri', '--rule_id',
                        required=False,
                        help='(opt) rule Id to get',
                        default='')


    parser.add_argument('-S', '--disable_ssl_verification',
                        required=False,
                        action='store_true',
                        help='Disable ssl host certificate verification')

    args = parser.parse_args()
    return args


def get_obj(content, vimtype, name=None, folder=None, recurse=True, byKey=False):
    if not folder:
        folder = content.rootFolder

    obj = None
    container = content.viewManager.CreateContainerView(folder,
                                                        vimtype, recurse)
    
    if byKey: #Get by Key
        obj = None
        for c in container.view:
            if c.key == name:
                obj = c
                break
    else: #Get by name
        if not name:
            obj = {}
            for managed_object_ref in container.view:
                obj.update({managed_object_ref: managed_object_ref.name})
        else:
            obj = None
            for c in container.view:
                if c.name == name:
                    obj = c
                    break

    return obj





def get_vlans_from_portgroup(pgObj):
    vlanInfo = pgObj.config.defaultPortConfig.vlan
    cl = vim.dvs.VmwareDistributedVirtualSwitch.TrunkVlanSpec
    join_char = ","
    if isinstance(vlanInfo, cl):
        #vlan = "trunk"
        vlanlist = []
        for item in vlanInfo.vlanId:
            if item.start == item.end:
                vlanlist.append(str(item.start))
            else:
                vlanlist.append(str(item.start)+'-'+str(item.end))
        #wd = " | Trunk | vlan id: " + ','.join(vlanlist)
        vlan = join_char.join(vlanlist)
    else:
        vlan = str(vlanInfo.vlanId)
        #wd = " | vlan id: " + str(vlanInfo.vlanId)
    return vlan





def format_rule(ruleObj,si): #need to pass the "si" connection to the function
    curr_rule_dict = {}
    curr_rule_dict['sourcePort'] = ''
    curr_rule_dict['destinationPort'] = ''
    curr_rule_dict['protocol'] = ''
    curr_rule_dict['squence'] = ''
    curr_rule_dict['description'] = ''
    curr_rule_dict['action'] = ''


    explodedKey = ruleObj.key.split('_')
    pg_moid = 'dvportgroup-' + str(explodedKey[1])
    dvs_moid = 'dvs-' + str(explodedKey[0])

    parent_pg = vim.dvs.DistributedVirtualPortgroup(pg_moid)
    parent_pg._stub = si._stub

    parent_dvs = vim.dvs.VmwareDistributedVirtualSwitch(dvs_moid)
    parent_dvs._stub = si._stub
    
    curr_rule_dict['vlan'] = get_vlans_from_portgroup(parent_pg)
    curr_rule_dict['pgName'] = parent_pg.config.name
    curr_rule_dict['dvsName'] = parent_dvs.config.name


    if (ruleObj.sequence):
        curr_rule_dict['squence'] = ruleObj.sequence
    if (ruleObj.key):
        curr_rule_dict['id'] = ruleObj.key
    if (ruleObj.description):
        curr_rule_dict['description'] = ruleObj.description
    if (ruleObj.action):
        if (isinstance (ruleObj.action, vim.dvs.TrafficRule.AcceptAction)): 
            curr_rule_dict['action']  = "accept"
        if (isinstance (ruleObj.action, vim.dvs.TrafficRule.DropAction)): 
            curr_rule_dict['action']  = "drop"

    if (ruleObj.direction):
        curr_rule_dict['direction']  = ruleObj.direction

    for qualifier in ruleObj.qualifier: #Can you have more than one qualifier per rule? For now get only the last on this for...
        
        #print(qualifier)
        #sys.exit()

        if (qualifier.key):
            curr_rule_dict['qualifier_id'] = qualifier.key       


        if (hasattr(qualifier, "sourceAddress")) and (qualifier.sourceAddress):  #Can be none! In this case we use the keyword "any"!
            if (isinstance (qualifier.sourceAddress, vim.IpRange)): #Its a range (ex.: /24)
                sourceAddress = qualifier.sourceAddress.addressPrefix + "/" + str(qualifier.sourceAddress.prefixLength)
            elif (isinstance (qualifier.sourceAddress, vim.MacRange)): #MAC! L2 ACL!
                sourceAddress = qualifier.sourceAddress.address + "/" + str(qualifier.sourceAddress.mask)
            else:
                sourceAddress = qualifier.sourceAddress.address
        else: #ANY!
            sourceAddress = "any"
        curr_rule_dict['sourceAddress'] = sourceAddress

        
        if (hasattr(qualifier, "destinationAddress")) and (qualifier.destinationAddress): #Can be none! In this case we use the keyword "any"!
            if (isinstance (qualifier.destinationAddress, vim.IpRange)): #Its a range (ex.: /24)
                destinationAddress = qualifier.destinationAddress.addressPrefix + "/" + str(qualifier.destinationAddress.prefixLength)
            elif (isinstance (qualifier.destinationAddress, vim.MacRange)): #MAC! L2 ACL!
                destinationAddress = qualifier.destinationAddress.address + "/" + str(qualifier.destinationAddress.mask)
            else:
                destinationAddress = qualifier.destinationAddress.address
        else: #ANY!
            destinationAddress = "any"
        curr_rule_dict['destinationAddress'] = destinationAddress

        if (isinstance (qualifier, vim.dvs.TrafficRule.IpQualifier)): #Check if qualifier is IP Type
            curr_rule_dict['ruleType'] = 'IP'
            if (hasattr(qualifier, "sourceIpPort")) and  (qualifier.sourceIpPort):
                if (isinstance (qualifier.sourceIpPort, vim.dvs.TrafficRule.IpPortRange)): #Eh um range de portas (ex: 1-65535)
                    sourcePort = str(qualifier.sourceIpPort.startPortNumber) + "-" + str(qualifier.sourceIpPort.endPortNumber)
                else:
                    sourcePort = qualifier.sourceIpPort.portNumber
                curr_rule_dict['sourcePort'] = sourcePort
                          
            if (hasattr(qualifier, "destinationIpPort")) and (qualifier.destinationIpPort):
                if (isinstance (qualifier.destinationIpPort, vim.dvs.TrafficRule.IpPortRange)): #Eh um range de portas (ex: 1-65535)
                    destinationPort = str(qualifier.destinationIpPort.startPortNumber) + "-" + str(qualifier.destinationIpPort.endPortNumber)
                else:
                    destinationPort = qualifier.destinationIpPort.portNumber
                curr_rule_dict['destinationPort'] = destinationPort
            print(qualifier)
            if (qualifier.tcpFlags): #tcpFlags
                #Returns a decimal number that represents the 'setted' bits on tcpflag field.
                #Bit map are on this order ont TCP header: NS  CWR  ECE  URG  ACK  PSH  RST  SYN  FIN
                #example: Matches only packets that have a SYN/ACK (SYN and ACK. the return from the 3 way handshake):
                # NS  CWR  ECE  URG  ACK  PSH  RST  SYN  FIN
                # 0    0    0    0    1    0    0    1    0 
                # Summary: 10010
                # To decimal: 18
                curr_rule_dict['tcpFlags'] = qualifier.tcpFlags.value
                
        



        
        if (isinstance (qualifier, vim.dvs.TrafficRule.MacQualifier)): #Check if qualifier is MAC Type
            curr_rule_dict['ruleType'] = 'MAC'
            if (qualifier.vlanId):
                curr_rule_dict['l2Rule_vlanId'] = qualifier.vlanId.value
            else:
                curr_rule_dict['l2Rule_vlanId'] = "any"
                
        
        
        
        if (hasattr(qualifier, "protocol")) and  (qualifier.protocol):
            curr_rule_dict['protocol'] = qualifier.protocol.value

    return curr_rule_dict





def main():
    args = get_args()
    returnObj = ""
    if args.password:
        password = args.password
    else:
        password = getpass.getpass(prompt='Enter password for host %s and '
                                   'user %s: ' % (args.host, args.user))
    if args.disable_ssl_verification:
        si = SmartConnectNoSSL(host=args.host,
                               user=args.user,
                               pwd=password,
                               port=int(args.port))
    else:
        si = SmartConnect(host=args.host,
                          user=args.user,
                          pwd=password,
                          port=int(args.port))

    if not si:
        print("Could not connect to the specified host using specified "
              "username and password")
        return -1

    atexit.register(Disconnect, si)

    content = si.RetrieveContent()

    dc = get_obj(content, [vim.Datacenter], args.datacenter)

    if dc is None:
        print("Failed to find the datacenter %s" % args.datacenter)
        return 0




    ################################# GET SPECIFIC RULE BY KEY (ID) ###########################################
    ################################# GET SPECIFIC RULE BY KEY (ID) ###########################################
    ################################# GET SPECIFIC RULE BY KEY (ID) ###########################################
    if args.rule_id != "": #Get specific Rule by its Key

        #split Key to get portgroup MOID
        explodedKey =  args.rule_id.split('_')
        pg_moid = 'dvportgroup-' + str(explodedKey[1])
        parent_pg = vim.dvs.DistributedVirtualPortgroup(pg_moid)
        parent_pg._stub = si._stub

        if parent_pg.config is None:
            print("Failed to find the Port Group from the rule ID ")
            return 0
        if (parent_pg.config.defaultPortConfig.filterPolicy): #Check if a Filter policy is applied on current PG
            for pg_filterConfig in parent_pg.config.defaultPortConfig.filterPolicy.filterConfig: # Get each filter from the PG
                if (pg_filterConfig.trafficRuleset): #Current filter has rules defined
                    for rule in pg_filterConfig.trafficRuleset.rules: #get each rule!
                        if (args.rule_id == rule.key): #found rule
                            returnObj = format_rule(rule,si)
                            #print (returnObj)
                            #return returnObj



        #print ("args.rule_id:"+args.rule_id)
        #ruleObject = get_obj(content, [vim.dvs.TrafficRule], args.rule_id, byKey=True)
        #if ruleObject is None:
        #    print("Failed to find the rule with ID (Key) %s" % args.rule_id)
        #    return 0
        #returnObj = format_rule(ruleObject,si)



    
    ################################# GET FROM SPECIFIC PORT GROUP ###########################################
    ################################# GET FROM SPECIFIC PORT GROUP ###########################################
    ################################# GET FROM SPECIFIC PORT GROUP ###########################################    
    elif args.portgroup != "": #Get specific port group by Name
        pgObject = get_obj(content, [vim.DistributedVirtualPortgroup], args.portgroup)
        if pgObject is None:
            print("Failed to find the Port Group with Name %s" % args.portgroup)
            return 0
        rules_array = []
        
        #if args.dvswitch != 'all': #Only one dvs! Filter PGs getted to get only from the specific dvs!
        #    print (pgObject.parent)
        #    sys.exit()

        if (pgObject.config.defaultPortConfig.filterPolicy): #Check if a Filter policy is applied on current PG
            for pg_filterConfig in pgObject.config.defaultPortConfig.filterPolicy.filterConfig: # Get each filter from the PG
                if (pg_filterConfig.trafficRuleset): #Current filter has rules defined
                    # IF YOU WANT TO DEBUG EVERY RULES FROM A SPECIFIC PG, AND PRINT ALL ATTRIBUTES, UNCOMMENT THIS
                    # IF YOU WANT TO DEBUG EVERY RULES FROM A SPECIFIC PG, AND PRINT ALL ATTRIBUTES, UNCOMMENT THIS
                    # IF YOU WANT TO DEBUG EVERY RULES FROM A SPECIFIC PG, AND PRINT ALL ATTRIBUTES, UNCOMMENT THIS
                    #print(pg_filterConfig.trafficRuleset)
                    # IF YOU WANT TO DEBUG EVERY RULES FROM A SPECIFIC PG, AND PRINT ALL ATTRIBUTES, UNCOMMENT THIS
                    # IF YOU WANT TO DEBUG EVERY RULES FROM A SPECIFIC PG, AND PRINT ALL ATTRIBUTES, UNCOMMENT THIS
                    # IF YOU WANT TO DEBUG EVERY RULES FROM A SPECIFIC PG, AND PRINT ALL ATTRIBUTES, UNCOMMENT THIS
                    for rule in pg_filterConfig.trafficRuleset.rules: #get each rule!
                        processed_ruled = ""
                        processed_ruled = format_rule(rule,si)
                        if (processed_ruled):
                            rules_array.append(processed_ruled)
        returnObj = rules_array




    ################################# GET FROM ALL SWITCHES ###########################################        
    ################################# GET FROM ALL SWITCHES ###########################################
    ################################# GET FROM ALL SWITCHES ###########################################
    else:
        if args.dvswitch == 'all':
            dvs_lists = get_obj(content, [vim.DistributedVirtualSwitch],
                                folder=dc.networkFolder)
        else:
            dvsn = get_obj(content, [vim.DistributedVirtualSwitch], args.dvswitch)
            if dvsn is None:
                print("Failed to find the dvswitch %s" % args.dvswitch)
                return 0
            else:
                dvs_lists = [dvsn]
        rules_array = []
        for dvs in dvs_lists:
            for dvs_pg in dvs.portgroup:
                if (dvs_pg.config.defaultPortConfig.filterPolicy): #Check if a Filter policy is applied on current PG
                    for pg_filterConfig in dvs_pg.config.defaultPortConfig.filterPolicy.filterConfig: # Get each filter from the PG
                        if (pg_filterConfig.trafficRuleset): #Current filter has rules defined
                            for rule in pg_filterConfig.trafficRuleset.rules: #get each rule!
                                processed_ruled = ""
                                processed_ruled = format_rule(rule,si)
                                if (processed_ruled):
                                    rules_array.append(processed_ruled)
        returnObj = rules_array

    print(json.dumps(returnObj))


if __name__ == "__main__":
    main()