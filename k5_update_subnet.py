#!/usr/bin/python



ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = '''
---
module: k5_update_subnet
short_description:  update a subnet on K5
version_added: "1.0"
description:
    - returns # TODO
options:
    None
requirements:
    - "python >= 2.6"
'''

EXAMPLES = '''
- k5_update_subnet:
    name:  "k5_test_subnet"
    gateway_ip: "62.60.1.1"
    enable_dhcp: True
    dns_nameservers: 
        - 8.8.8.8
        - 8.8.4.4
    host_routes:
        - { "destination":"0.0.0.0/0", "nexthop":"172.16.1.254" }
        - { "destination":"192.168.0.1/32", "nexthop":"172.16.1.1" }
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

subnet_details = None

# details of out K5 API connection
k5_facts = None

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

##########################################################################################

def k5_get_subnet_details_from_name(module):
    """Get an id from a subnet name"""

    global subnet_details

    k5_debug_add("def: " + sys._getframe().f_code.co_name)

    name = module.params['name']

    endpoint = k5_facts['endpoints']['networking']
    url = endpoint + '/v2.0/subnets'

    response = k5_api(module, 'GET', url, None)

    k5_debug_add(response.json())

    # we failed to get data
    if response.status_code not in (200,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), k5_debug=k5_debug_out)

    # we got a response - find a match
    for n in response.json()['subnets']:
        if str(n['name']) == name:
            subnet_details = n
            return True

    # No match
    return False

def k5_update_subnet(module):
    """update a subnet"""

    k5_debug_add("def: " + sys._getframe().f_code.co_name)

    if not k5_get_subnet_details_from_name(module):
         module.fail_json(msg="Subnet not found")

    subnet_id = subnet_details['id']

    endpoint = k5_facts['endpoints']['networking']
    url = endpoint + '/v2.0/subnets/' + subnet_id

    json = {}

    # build json on available parameters
    if module.params['gateway_ip'] is not None:
        json['gateway_ip'] = module.params['gateway_ip'] 

    if module.params['enable_dhcp'] is not None:
        json['enable_dhcp'] = module.params['enable_dhcp'] 

    if module.params['dns_nameservers'] is not None:
        json['dns_nameservers'] = module.params['dns_nameservers'] 

    if module.params['host_routes'] is not None:
        json['host_routes'] = module.params['host_routes'] 

    response = k5_api(module, 'PUT', url, { "subnet": json } )

    # we failed to get data
    if response.status_code not in (200,):

        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), k5_debug=k5_debug_out )

    # exit cleanly
    if k5_debug:
        module.exit_json(changed=True, msg="Update Subnet Successful", k5_debug=k5_debug_out, subnet=response.json() )
    else:
        module.exit_json(changed=True, msg="Update Subnet Successful", subnet=response.json())



######################################################################################

def main():

    global k5_facts # setup our global var on the API connection
    global k5_debug # do we save loads of debug data?

    module = AnsibleModule( argument_spec=dict(
        k5_auth = dict(required=True, default=None, type='dict'),
        name = dict(required=True, default=None, type='str'),
        gateway_ip = dict(required=False, default=None, type='str'),
        enable_dhcp = dict(required=False, default=None, type='str'), # boolean?
        dns_nameservers = dict(required=False, default=None, type='list'),
        host_routes = dict(required=False, default=None, type='list')
    ) )

    # check for auth first
    if 'auth_spec' in module.params['k5_auth']:
        k5_facts = module.params['k5_auth']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")

    if 'K5_DEBUG' in os.environ:
        k5_debug = True

    k5_update_subnet(module)


######################################################################################

if __name__ == '__main__':  
    main()



