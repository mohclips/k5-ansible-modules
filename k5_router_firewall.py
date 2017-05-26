#!/usr/bin/python



ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = '''
---
module: k5_router_firewall
short_description:  Add, update or remove a firewall from a K5 router
version_added: "1.0"
description:
    - returns # TODO
options:
    None
requirements:
    - "python >= 2.6"
'''

EXAMPLES = '''
- k5_router_firewall:
    router_name:  "k5_test_router"
    rules: "{{ my_rules_list }}"
    reset_connections: True
    state: present
    k5_auth: "{{ k5_auth_facts }}"

- k5_router_firewall:
    router_name:  "k5_test_router"
    state: absent
    k5_auth: "{{ k5_auth_facts }}"
'''

RETURN = '''

'''


import requests
import os
import json
import sys  # for function callee
import datetime # for debug timestamps
import time # for sleep / timimng issues
from ansible.module_utils.basic import *

# TODO  - maybe these should be a singleton
# global list of rule ids
rule_ids = []
# policy id of polciy in question
policy_id = None
# firewall id of firewall in question
firewall_id = None
# route details of router in question
router_details = None

# details of out K5 API connection
k5_facts = None

MAX_WAIT_TIME=10 # loop counter, 1 sec delay

############## Common debug ###############
k5_debug = False
k5_debug_out = []

def k5_debug_get():
    """Return our debug list"""
    return k5_debug_out

def k5_debug_clear():
    """Clear our debug list"""
    k5_debug_out = []

def k5_debug_add(s):
    """Add string to debug list if env K5_DEBUG is defined"""
    if k5_debug:
        timestamp = '{:%Y-%m-%d %H:%M:%S.%f} '.format(datetime.datetime.now())
        if isinstance(s, dict):
            k5_debug_out.append(timestamp)
            k5_debug_out.append(s)
        else:
            k5_debug_out.append(timestamp + str(s))


############## functions #############

def k5_get_endpoint(e,name):
    """Pull particular endpoint name from dict"""
    return e['endpoints'][name]


def k5_api(module,action,url,query_json):
    """call k5 api"""
    
    k5_debug_clear()

    k5_debug_add("def: " + sys._getframe().f_code.co_name)

    auth_token = module.params['k5_auth']['auth_token']
    k5_debug_add('auth_token: {0}'.format(auth_token))

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    k5_debug_add('REQ: {0} {1}'.format(action,url))
    #k5_debug_add('headers: {0}'.format(headers)) # not needed in debug

    if query_json is not None: 
        k5_debug_add('json:')
        k5_debug_add(query_json)    

    session = requests.Session()
    try:
        response = session.request(action, url, headers=headers, json=query_json)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e, k5_debug=k5_debug_out)

    k5_debug_add("RESP CODE: " + str(response.status_code))

    return response

def k5_get_router_details_from_name(module):
    """Get an id from a router_name"""

    global router_details

    k5_debug_add("def: " + sys._getframe().f_code.co_name)

    router_name = module.params['router_name']

    endpoint = k5_facts['endpoints']['networking']
    url = endpoint + '/v2.0/routers'

    response = k5_api(module, 'GET', url, None)

    k5_debug_add(response.json())

    # we failed to get data
    if response.status_code not in (200,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), k5_debug=k5_debug_out)

    # we got a response - find a match
    for n in response.json()['routers']:
        if str(n['name']) == router_name:
            router_details = n
            return True

    # No match
    return False

def k5_get_router_firewall_id(module):
    """Get an id of firewall on a router"""

    global policy_id
    global firewall_id

    k5_debug_add("def: " + sys._getframe().f_code.co_name)

    endpoint = k5_facts['endpoints']['networking']
    url = endpoint + '/v2.0/fw/firewalls'

    response = k5_api(module, 'GET', url, None)

    # we failed to get data
    if response.status_code not in (200,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), k5_debug=k5_debug_out)

    # we got a response - find a match on the router_id - thus one firewall per router
    for n in response.json()['firewalls']:
        if str(n['router_id']) == router_details['id']:
            firewall_id = n['id']
            policy_id = n['firewall_policy_id']
            return True

    # No match
    return False

def k5_get_firewall_policy_rules(module):
    """Get ids of rules in a policy"""

    global rule_ids

    k5_debug_add("def: " + sys._getframe().f_code.co_name)

    endpoint = k5_facts['endpoints']['networking']
    url = endpoint + '/v2.0/fw/firewall_policies/' + policy_id

    response = k5_api(module, 'GET', url, None)

    # we failed to get data
    if response.status_code not in (200,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), k5_debug=k5_debug_out)

    # update the global var with the rule ids
    rule_ids = response.json()['firewall_policy']['firewall_rules']

    k5_debug_add(rule_ids)


def k5_remove_firewall_rule(module,rule_id):
    """add each rule into K5"""

    k5_debug_add("def: " + sys._getframe().f_code.co_name)

    endpoint = k5_facts['endpoints']['networking']
    url = endpoint + '/v2.0/fw/firewall_rules/' + rule_id

    response = k5_api(module, 'DELETE', url, None)

    # we failed to get data
    if response.status_code not in (204,):
        k5_debug_add("Failed to delete rule_id: " + rule_id) # TODO this could cause issues later on
    else:
        k5_debug_add("Successfully deleted rule_id: " + rule_id)
        
        #module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), k5_debug=k5_debug_out)



def k5_remove_firewall_rules(module):
    """add each rule into K5"""

    global rule_ids

    k5_debug_add("def: " + sys._getframe().f_code.co_name)
   
    for rule_id in rule_ids:

        k5_remove_firewall_rule(module, rule_id) 

    rule_ids = [] # clean up
    


def k5_create_firewall_rule(module,rule):
    """add each rule into K5"""

    global rule_ids

    k5_debug_add("def: " + sys._getframe().f_code.co_name)
    k5_debug_add(rule)

    endpoint = k5_facts['endpoints']['networking']
    url = endpoint + '/v2.0/fw/firewall_rules'

    json = {
        "firewall_rule": 
                rule
        }

    response = k5_api(module, 'POST', url, json)

    # we failed to get data
    if response.status_code not in (201,):

        # adding a rule failed (bad parsing probably), back out all previous rules
        k5_remove_firewall_rules(module)

        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), k5_debug=k5_debug_out, failed_rule=rule) # we add in the failed rule here to enable better debugging

    # update the global var with the rule ids
    rule_id = response.json()['firewall_rule']['id']

    rule_ids.append(rule_id) 

    k5_debug_add("rule_id: " + rule_id)



def k5_create_firewall_rules(module):
    """add each rule into K5"""

    for rule in module.params['rules']:

        k5_create_firewall_rule(module, rule)


def k5_create_firewall_policy(module):
    """ create a firewall policy """

    global rule_ids
    global policy_id

    k5_debug_add("def: " + sys._getframe().f_code.co_name)

    router_name = module.params['router_name']

    endpoint = k5_facts['endpoints']['networking']
    url = endpoint + '/v2.0/fw/firewall_policies'

    timestamp = '{:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now())
    uni_ts = '{:%Y%m%d%H%M%S}'.format(datetime.datetime.now())

    json = {
            "firewall_policy": {
                "firewall_rules": rule_ids,
                "name": router_name + "_" + uni_ts, # make a unique name
                "description": "Created by Ansible on " + timestamp,
                "availability_zone": router_details['availability_zone']
            }
        }

    response = k5_api(module, 'POST', url, json)

    # we failed to get data
    if response.status_code not in (201,):

        # adding the policy failed, back out all previous rules
        k5_remove_firewall_rules(module)

        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), k5_debug=k5_debug_out)

 
    policy_id = response.json()['firewall_policy']['id']

    
def k5_remove_firewall_policy(module):
    """ remove a firewall policy """

    k5_debug_add("def: " + sys._getframe().f_code.co_name)

    endpoint = k5_facts['endpoints']['networking']
    url = endpoint + '/v2.0/fw/firewall_policies/' + str(policy_id)

    response = k5_api(module, 'DELETE', url, None)

    # we failed to get data
    if response.status_code not in (204,):

        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), k5_debug=k5_debug_out)



def k5_create_router_firewall(module):
    """ add the firewall to the router """

    k5_debug_add("def: " + sys._getframe().f_code.co_name)

    endpoint = k5_facts['endpoints']['networking']
    url = endpoint + '/v2.0/fw/firewalls'

    router_name = module.params['router_name']

    timestamp = '{:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now())
    uni_ts = '{:%Y%m%d%H%M%S}'.format(datetime.datetime.now())

    json = {
        "firewall": {
            "admin_state_up": "true",
            "firewall_policy_id": str(policy_id),
            "router_id": router_details['id'],
            "availability_zone": router_details['availability_zone'],
            "name": router_name + "_" + uni_ts, # make a unique name
            "description": "Created by Ansible on " + timestamp
             }
        }

    response = k5_api(module, 'POST', url, json)

    # we failed to get data
    if response.status_code not in (201,):

        # clean up
        k5_get_firewall_policy_rules(module)
        k5_remove_firewall_policy(module)
        k5_remove_firewall_rules(module)

        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), k5_debug=k5_debug_out)


def k5_remove_router_firewall(module):
    """ remove the firewall from the router """

    k5_debug_add("def: " + sys._getframe().f_code.co_name)

    endpoint = k5_facts['endpoints']['networking']
    url = endpoint + '/v2.0/fw/firewalls/' + str(firewall_id)

    response = k5_api(module, 'DELETE', url, None)

    # we failed to get data
    if response.status_code not in (204,):

        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), k5_debug=k5_debug_out)


def k5_remove_firewall_rule(module,rule_id):
    """remove a rule"""

    k5_debug_add("def: " + sys._getframe().f_code.co_name)

    endpoint = k5_facts['endpoints']['networking']
    url = endpoint + '/v2.0/fw/firewall_rules/' + rule_id

    response = k5_api(module, 'DELETE', url, None)

    # we failed to get data
    if response.status_code not in (204,):
        k5_debug_add("Failed to delete rule_id: " + rule_id) # TODO this could cause issues later on
    else:
        k5_debug_add("Successfully deleted rule_id: " + rule_id)


def k5_reset_firewall_connections(module,rule_id):
    """isend the reset all connections command"""

    k5_debug_add("def: " + sys._getframe().f_code.co_name)

    endpoint = k5_facts['endpoints']['networking']
    url = endpoint + '/v2.0/fw/firewalls/' + firewall_id + '/reset_connections'

    response = k5_api(module, 'PUT', url, None)

    # we failed to get data
    if response.status_code not in (200,):
        k5_debug_add("Failed to reset firewall connections") # TODO carry on regardless - or should we error and back out?
    else:
        k5_debug_add("Successfully reset firewall connections")


######################################################################################
def k5_router_firewall_present(module):
    """ main action """

    k5_debug_add("def: " + sys._getframe().f_code.co_name)

    reset_connections = module.params['reset_connections']

    # does router exist - get id
    if not k5_get_router_details_from_name(module):
         module.fail_json(msg="Router not found")

    # does fireall already exist - get id
    # does policy already exist - get id - policy_id part fo firewall details

    if k5_get_router_firewall_id(module):   #also gets the policy_id
        # firewall present - get rid of it

        k5_debug_add("**** START Removing old firewall before replacing with new")

        k5_get_firewall_policy_rules(module)
        k5_remove_router_firewall(module)

        counter = 0
        while ( (k5_get_router_firewall_id(module)) and (counter < MAX_WAIT_TIME) ):
            counter = counter + 1
            k5_debug_add(str(counter) + " Waiting for the removal of the firewall to complete")
            time.sleep(1)

        if counter >= MAX_WAIT_TIME:
            module.fail_json(msg="Timeout waiting to remove the firewall from the router")

        k5_remove_firewall_policy(module)
        k5_remove_firewall_rules(module)

        k5_debug_add("**** END Removing old firewall before replacing with new")

    # create rules - up date rules list - if any rule fails, back out all previously created rule - this passes the parsing onto K5 :)
    k5_create_firewall_rules(module)
    
    # create new policy - update description with date and Ansible - include unixtime in policy name
    k5_create_firewall_policy(module)

    # create firewall - update description with date and Ansible
    k5_create_router_firewall(module) 

    # reset connections?
    # TODO - do we need to do this, surely a re-create of the fireall does this anyway? - needs testing
    # k5_reset_firewall_connections(module)

    # exit cleanly
    if k5_debug:
        module.exit_json(changed=True, msg="Create Firewall Successful", k5_debug=k5_debug_out )
    else:
        module.exit_json(changed=True, msg="Create Firewall Successful")


def k5_router_firewall_absent(module):
    """ main action """

    k5_debug_add("def: " + sys._getframe().f_code.co_name)

    # does router exist - get id
    if not k5_get_router_details_from_name(module):
        module.fail_json(msg="Router not found")

    # does firewall exist - get id
    if k5_get_router_firewall_id(module):   #also gets the policy_id

        # get policy details - get id
        # get rule details from policy - save rule ids
        # delete firewall
        # delete policy
        # delete rules

        k5_get_firewall_policy_rules(module)
        k5_remove_router_firewall(module)

        # TODO do we need to sleep here?   test
        # eg. k5_get_router_firewall_id(module) - loop until false
        # We had a failure from K5 API if we delete the policy too early
        counter = 0
        while ( (k5_get_router_firewall_id(module)) and (counter < MAX_WAIT_TIME) ):
            counter = counter + 1
            k5_debug_add(str(counter) + " Waiting for the removal of the firewall to complete")
            time.sleep(1)

        if counter >= MAX_WAIT_TIME:
            module.fail_json(msg="Timeout waiting to remove the firewall from the router")

        k5_remove_firewall_policy(module)
        k5_remove_firewall_rules(module)

    # exit cleanly
    if k5_debug:
        module.exit_json(changed=True, msg="Create Firewall Successful", k5_debug=k5_debug_out )
    else:
        module.exit_json(changed=True, msg="Create Firewall Successful")



######################################################################################

def main():

    global k5_facts # setup our global var on the API connection
    global k5_debug # do we save loads of debug data?

    module = AnsibleModule( argument_spec=dict(
        k5_auth = dict(required=True, default=None, type='dict'),
        router_name = dict(required=True, default=None, type='str'),
        rules = dict(required=False, default=None, type='list'),
        reset_connections = dict(default='True', choices=['True', 'False']),
        state = dict(default='present', choices=['present', 'absent', 'update'])
    ) )

    # check for auth first
    if 'auth_spec' in module.params['k5_auth']:
        k5_facts = module.params['k5_auth']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")

    if 'K5_DEBUG' in os.environ:
        k5_debug = True

    # do stuff
    if 'present' in module.params['state']:
        k5_router_firewall_present(module)
    elif 'update' in module.params['state']:
        module.fail_json(msg="update function not written yet")
        # TODO 
        # create new rules
        # create new policy
        # update firewall with new policy - change description/name?
        # reset connections
        # k5_reset_firewall_connections(module)
        # delete old policy
        # delete old rules
    else:
        k5_router_firewall_absent(module)



######################################################################################

if __name__ == '__main__':  
    main()



