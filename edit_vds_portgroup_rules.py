#!/usr/bin/env python

"""
Written by Livio Zanol Puppim https://github.com/liviozanol
Based on list_vlan_in_portgroups Written by David Martinez. Github: https://github.com/dx0xm

Script to create,update or delete rules on portgroups

TODO:
    - Differentiate multiple PortGroupss with same name with specific vDS set by user by '-dvs'
"""


from __future__ import print_function
from pyVim.connect import SmartConnect, SmartConnectNoSSL, Disconnect
from pyVmomi import vim
import atexit
import argparse
import getpass
import sys
import re
import json
from collections import namedtuple

def _json_object_hook(d): return namedtuple('X', d.keys())(*d.values())
def json2obj(data): return json.loads(data, object_hook=_json_object_hook)

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

    parser.add_argument('-ac', '--action',
                        required=True,
                        help='Action to do with the rule. Add: add rules to the end. Replace: replaces existing rules. To add/replace you MUST provide the portgroup name. To edit/delete you MUST provide the rule ID (KEY)',
                        default='',
                        choices=['add', 'replace', 'edit', 'delete'])

    parser.add_argument('-pg', '--portgroup',
                        required=True,
                        help='Name of the portgroup is required.',
                        default='')

    parser.add_argument('-ri', '--ruleid',
                        required=False,
                        help='Id(Key) of the rule to be edited or deleted. Its required if --action is edit or delete',
                        default='')
    
    parser.add_argument('-rj', '--rule_json_file',
                        required=False,
                        help='file containing array of jsons with rules to add/replace/edit. format/example: [{ "sourceAddress":"any","destinationAddress":"8.8.8.8/32","sourcePort":"1024-60000","destinationPort":"53","protocol":"6","action":"accept","direction":"both", "description":"DNS google" }]',
                        default='')

    parser.add_argument('-S', '--disable_ssl_verification',
                        required=False,
                        action='store_true',
                        help='Disable ssl host certificate verification')

    args = parser.parse_args()
    return args




def get_obj(content, vimtype, name=None, folder=None, recurse=True):
    if not folder:
        folder = content.rootFolder

    obj = None
    container = content.viewManager.CreateContainerView(folder,
                                                        vimtype, recurse)
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






def main():
    args = get_args()

    #Custom Args Check
    if ((args.action == "add") or (args.action == "replace")) and ((args.portgroup == "") or (args.rule_json_file == "")):
        print("When 'addind' or 'replacing' you MUST specifiy a portgroup (-pg or --portgroup) and a rule JSON (-rj --rule_json_file)")
        return 0
    if ((args.action == "edit") or (args.action == "delete")) and (args.ruleid == ""):
        print("When 'editing' or 'deleting' you MUST specifiy a portgroup (-pg or --portgroup) and a rule ID (-id or --ruleid).")
        return 0

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

    pgObject = get_obj(content, [vim.DistributedVirtualPortgroup], args.portgroup)
    if pgObject is None:
        print("Failed to find the Port Group with Name %s" % args.portgroup)
        return 0

    #Validate JSON
    if (args.action == "add") or (args.action == "replace") or (args.action == "edit"):
        with open(args.rule_json_file) as file:
            ruleJson = json.load(file)
        #ruleJson = json.loads(args.rule_json)
        if (not isinstance (ruleJson,list)):
            #We have received just one rule, but the validation and createFunction considers we should receive an array. So, convert it.
            #Also, the editRule can only edit 1 rule, so we need to preserve the received JSON and pass it to the editrule function.
            editRuleJson = ruleJson #preserves received json
            ruleJson = []
            ruleJson.append(editRuleJson)
        #print ("RULEJSON")
        #print (ruleJson)
        for one_rule in ruleJson:
            if ((one_rule.get('ruleType') is not None)   and  (one_rule['ruleType']  != 'MAC')): #Just validate this if its IP rule type
                if ((not 'sourceAddress' in one_rule) or (not re.match(r"(^(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\/([1-9]|[1-2][0-9]|3[0-2])$|any)", one_rule['sourceAddress'] ))):
                    print ("source Address Not specified or in wrong format.")
                    return
                if ((not 'destinationAddress' in one_rule) or (not re.match(r"(^(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\/([1-9]|[1-2][0-9]|3[0-2])$|any)", one_rule['destinationAddress'] ))):
                    print ("destination Address Not specified or in wrong format.")
                    return
                if (('sourcePort' in one_rule) and (not re.match(r"^[0-9]{1,5}-[0-9]{1,5}$|^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$", one_rule['sourcePort'] ))):
                    print ("source port in wrong format.")
                    return
                if (('destinationPort' in one_rule) and (not re.match(r"^[0-9]{1,5}-[0-9]{1,5}$|^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$", one_rule['destinationPort'] ))):
                    print ("destination port in wrong format.")
                    return
            if ((not 'protocol' in one_rule) and (not str(one_rule['protocol']).isdigit()) ):
                print ("protocol must be an integer. (eg.: TCP = 6, UDP = 17, etc.).")
                return        
            if ((not 'action' in one_rule) or (not re.match(r"^(accept|drop)$",one_rule['action']))):
                print ("action must be 'accept' or 'drop'.")
                return
            if ((not 'direction' in one_rule) or (not re.match(r"^(ingress|egress|both)$",one_rule['direction']))):
                print ("direction must be 'ingress', 'egress', or 'both'.")
                return
            if (not 'description' in one_rule):
                print ("must set a description.")
                return
    if (args.action == "add"):
        #Only Add Rules
        createRule (pgObject, ruleJson)
    
    if (args.action == "replace"):
        #Replace Old Rules with new ones
        createRule (pgObject, ruleJson, True)

    if (args.action == "edit"):
        #Edit rule
        editRule (pgObject, editRuleJson, args.ruleid)

    if (args.action == "delete"):
        #Remove rule
        removeRule (pgObject, args.ruleid)







def createQualifierSpec (rule):
    if ((rule.get('ruleType') is not None)   and (rule['ruleType'])  == 'MAC'): #Default is "IP". "MAC" also possible
        #MAC (L2) Type Rule!
        qualifierSpec = vim.DvsMacNetworkRuleQualifier()

        #qualifierSpec.vlanId = vim.IntExpression() 
        #qualifierSpec.vlanId .value = int(rule['l2Rule_vlanId']) #VLAN ID

        if (rule['sourceAddress'] == 'any'): #Any IP. Set null.
            qualifierSpec.sourceAddress = None
        else:
            exploded_source = rule['sourceAddress'].split('/')
            if (exploded_source[1] is not None):
                #Has a "/". Its a RANGE MAC!!!
                qualifierSpec.sourceAddress = vim.SingleMac()
                qualifierSpec.sourceAddress.address = exploded_source[0]
                qualifierSpec.sourceAddress.mask = exploded_source[1]
            else:
                #Its a single MAC!
                qualifierSpec.sourceAddress = vim.SingleMac()
                qualifierSpec.sourceAddress.address = rule['sourceAddress']


        if (rule['destinationAddress'] == 'any'): #Any IP. Set null.
            qualifierSpec.destinationAddress = None
        else:    
            exploded_source = rule['destinationAddress'].split('/')
            if (exploded_source[1] is not None):
                #Has a "/". Its a RANGE MAC!!!
                qualifierSpec.destinationAddress = vim.SingleMac()
                qualifierSpec.destinationAddress.address = exploded_source[0]
                qualifierSpec.destinationAddress.mask = exploded_source[1]
            else:
                #Its a single MAC!
                qualifierSpec.destinationAddress = vim.SingleMac()
                qualifierSpec.destinationAddress.address = rule['destinationAddress']
    else:
        #IP (L3 - L4) Type Rule!
        qualifierSpec = vim.DvsIpNetworkRuleQualifier()
        if (rule['sourceAddress'] == 'any'): #Any IP. Set null.
            qualifierSpec.sourceAddress = None
        else:
            exploded_source = rule['sourceAddress'].split('/')
            if (exploded_source[1] == 32):
                #Has a "/32". Its a single IP!
                qualifierSpec.sourceAddress = vim.SingleIp()
                qualifierSpec.sourceAddress.address = exploded_source[0]
            else:
                qualifierSpec.sourceAddress = vim.IpRange()
                qualifierSpec.sourceAddress.addressPrefix  = exploded_source[0]
                qualifierSpec.sourceAddress.prefixLength  = int(exploded_source[1])


        if (rule['destinationAddress'] == 'any'): #Any IP. Set null.
            qualifierSpec.destinationAddress = None
        else:    
            exploded_destination = rule['destinationAddress'].split('/')
            if (exploded_destination[1] == 32):
                #Has a "/32". Its a single IP!
                qualifierSpec.destinationAddress = vim.SingleIp()
                qualifierSpec.destinationAddress.address = exploded_destination[0]
            else:
                qualifierSpec.destinationAddress = vim.IpRange()
                qualifierSpec.destinationAddress.addressPrefix  = exploded_destination[0]
                qualifierSpec.destinationAddress.prefixLength  = int(exploded_destination[1])


        if (rule['sourcePort'] == ''): #Any port. Set null.
            qualifierSpec.sourceIpPort = None
        else:
            if (rule['sourcePort'].find('-') != -1): #Found "-". Its a range of ports
                exploded_source_port = rule['sourcePort'].split('-')
                qualifierSpec.sourceIpPort = vim.dvs.TrafficRule.IpPortRange()
                qualifierSpec.sourceIpPort.startPortNumber = int(exploded_source_port[0])
                qualifierSpec.sourceIpPort.endPortNumber = int(exploded_source_port[1])
            else:
                qualifierSpec.sourceIpPort = vim.dvs.TrafficRule.SingleIpPort()
                qualifierSpec.sourceIpPort.portNumber = int(rule['sourcePort'])


        if (rule['destinationPort'] == ''): #Any port. Set null.
            qualifierSpec.destinationIpPort = None
        else:  
            if (rule['destinationPort'].find('-') != -1): #Found "-". Its a range of ports
                exploded_destination_port = rule['destinationPort'].split('-')
                qualifierSpec.destinationIpPort = vim.dvs.TrafficRule.IpPortRange()
                qualifierSpec.destinationIpPort.startPortNumber = int(exploded_destination_port[0])
                qualifierSpec.destinationIpPort.endPortNumber = int(exploded_destination_port[1])
            else:
                qualifierSpec.destinationIpPort = vim.dvs.TrafficRule.SingleIpPort()
                qualifierSpec.destinationIpPort.portNumber = int(rule['destinationPort'])
        #print ("if tcp flags")
        if (rule.get('tcpFlags') is not None): #FLAG.
            #print ("TCP FLAGS")
            qualifierSpec.tcpFlags = vim.IntExpression()
            qualifierSpec.tcpFlags.value = int(rule['tcpFlags']) #Recebendo em DECIMAL.

    
    #print (rule)
    


    #Protocol
    if (rule['protocol'] == ''): #Any protocol. Set null.
        qualifierSpec.protocol = None
    else:
        qualifierSpec.protocol = vim.IntExpression()
        qualifierSpec.protocol.value = int(rule['protocol'])

    return qualifierSpec




def createRule (pgObject, ruleJson, replace = False):
    #sys.exit()
    #spec
    spec = vim.DVPortgroupConfigSpec()
    #print (pgObject.config)
    spec.configVersion = pgObject.config.configVersion 
    spec.defaultPortConfig = vim.VMwareDVSPortSetting()
    spec.defaultPortConfig.filterPolicy = vim.DvsFilterPolicy()


    filterOperation = vim.DvsTrafficFilterConfigSpec()
    filterOperation.agentName = 'dvfilter-generic-vmware'
    filterOperation.operation = vim.ConfigSpecOperation.add
    

    #rule
    rule = vim.DvsTrafficRule()
    #ruleset
    ruleSet = vim.DvsTrafficRuleset()
    ruleSet.enabled = True
    #check if filter already exists, to append rules at the end or if we are creating the first filter
    if (pgObject.config.defaultPortConfig.filterPolicy.filterConfig):
        #Filter exists!
        #get current rules and set it to be 're-added', in case we are "adding"
        if (replace == False):
            ruleSet.rules = pgObject.config.defaultPortConfig.filterPolicy.filterConfig[0].trafficRuleset.rules
        #Change operation to edit and set the key to be edited
        filterOperation.operation = vim.ConfigSpecOperation.edit
        filterOperation.key = pgObject.config.defaultPortConfig.filterPolicy.filterConfig[0].key



    if (isinstance(ruleJson,list)): #Multiple rules...
        for one_rule in ruleJson:
            #rule
            rule = vim.DvsTrafficRule()
            rule.qualifier = []
            rule.description = one_rule['description']
            rule.direction = one_rule['direction']
            if (one_rule['action'] == 'accept'):
                rule.action = vim.DvsAcceptNetworkRuleAction()
            else:
                rule.action = vim.DvsDropNetworkRuleAction()
            #Generate qualifier object on vmware format from JSON
            qualifierSpec = createQualifierSpec (one_rule)
            rule.qualifier.append(qualifierSpec)
            #Add new Rule
            #ruleSet.rules.insert(0, rule)
            ruleSet.rules.append(rule)

            

    else: #Just one rule
        rule.description = ruleJson['description']
        rule.direction = ruleJson['direction']
        if (ruleJson['action'] == 'accept'):
            rule.action = vim.DvsAcceptNetworkRuleAction()
        else:
            rule.action = vim.DvsDropNetworkRuleAction()
        qualifierSpec = createQualifierSpec (ruleJson)
        rule.qualifier.append(qualifierSpec)
        #Add new Rule
        #ruleSet.rules.insert(0, rule)
        ruleSet.rules.append(rule)
    
    filterOperation.trafficRuleset = ruleSet
    
    spec.defaultPortConfig.filterPolicy.filterConfig.append(filterOperation)
    #Change Portgroups conf with the new one.
    #print("REPLACE")
    #print(replace)
    #print(spec)
    #sys.exit()
    pgObject.Reconfigure(spec)
    return True


def editRule (pgObject, ruleJson, ruleId):
    #spec
    spec = vim.DVPortgroupConfigSpec()
    #print (pgObject.config)
    spec.configVersion = pgObject.config.configVersion 
    spec.defaultPortConfig = vim.VMwareDVSPortSetting()
    spec.defaultPortConfig.filterPolicy = vim.DvsFilterPolicy()


    filterOperation = vim.DvsTrafficFilterConfigSpec()
    filterOperation.agentName = 'dvfilter-generic-vmware'
    filterOperation.operation = vim.ConfigSpecOperation.edit
    filterOperation.key = pgObject.config.defaultPortConfig.filterPolicy.filterConfig[0].key #Edit only the first filterconfig
    

    #rule
    rule = vim.DvsTrafficRule()
    #ruleset
    ruleSet = vim.DvsTrafficRuleset()
    ruleSet.enabled = True


    #create qualifier
    qualifierSpec = createQualifierSpec (ruleJson)
    #print(qualifierSpec)
    
    #rule
    rule.description = ruleJson['description']
    rule.direction = ruleJson['direction']
    if (ruleJson['action'] == 'accept'):
        rule.action = vim.DvsAcceptNetworkRuleAction()
    else:
        rule.action = vim.DvsDropNetworkRuleAction()

    rule.qualifier.append(qualifierSpec)

    ruleSet.rules = pgObject.config.defaultPortConfig.filterPolicy.filterConfig[0].trafficRuleset.rules
    
    
    counter = 0
    foundRule = False
    for currentRule in ruleSet.rules: #catch each rule
        #print ("RULE KEY:"+currentRule.key + " DESCRIPTION:" + currentRule.description)
        if (currentRule.key == ruleId): #Found the rule!
            foundRule = True
            break
        counter = counter + 1

    if foundRule == False:
        print ("Rule to be edited not found")
        return False; #Rule not found!

    #overwrite current rule with the new created.
    ruleSet.rules[counter] = rule
    filterOperation.trafficRuleset = ruleSet
    spec.defaultPortConfig.filterPolicy.filterConfig.append(filterOperation)
    #Edit portgroup conf
    #print(spec)
    #sys.exit()
    pgObject.Reconfigure(spec)
    return True



def removeRule (pgObject, ruleId):    
    
    #spec
    spec = vim.DVPortgroupConfigSpec()
    #print (pgObject.config)
    spec.configVersion = pgObject.config.configVersion 
    spec.defaultPortConfig = vim.VMwareDVSPortSetting()
    spec.defaultPortConfig.filterPolicy = vim.DvsFilterPolicy()


    filterOperation = vim.DvsTrafficFilterConfigSpec()
    filterOperation.agentName = 'dvfilter-generic-vmware'
    filterOperation.operation = vim.ConfigSpecOperation.edit
    filterOperation.key = pgObject.config.defaultPortConfig.filterPolicy.filterConfig[0].key #Edit only the first filterconfig
    

    #rule
    rule = vim.DvsTrafficRule()
    #ruleset
    ruleSet = vim.DvsTrafficRuleset()
    ruleSet.enabled = True
    


    #ruleset
    ruleSet = vim.DvsTrafficRuleset()
    ruleSet.enabled = True
    #get current rules ans set it to be 're-added'
    ruleSet.rules = pgObject.config.defaultPortConfig.filterPolicy.filterConfig[0].trafficRuleset.rules
    
    
    counter = 0
    foundRule = False
    for currentRule in ruleSet.rules: #catch each rule
        #print ("RULE KEY:"+currentRule.key + " DESCRIPTION:" + currentRule.description)
        if (currentRule.key == ruleId): #Found the rule!
            foundRule = True
            break
        counter = counter + 1

    if foundRule == False:
        print ("Rule to be deleted not found")
        return False; #Rule not found!


    #Remove the found rule
    ruleSet.rules.pop(counter)
    filterOperation.trafficRuleset = ruleSet
    spec.defaultPortConfig.filterPolicy.filterConfig.append(filterOperation)

    #print(spec)
    #Push to portgroup
    #sys.exit()
    pgObject.Reconfigure(spec)
    return True






if __name__ == "__main__":
    main()
