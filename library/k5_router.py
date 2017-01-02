#!/usr/bin/python

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = '''
---
module: k5_router
short_description: Create router on K5 in particular AZ
version_added: "1.0"
description:
    - Explicit K5 call to create a router in an AZ - replaces os_router from Openstack module, but is more limited. Use os_router to update the router. 
options:
   name:
     description:
        - Name of the router.
     required: true
     default: None
   state:
     description:
        - State of the router. Can only be 'present'.
     required: true
     default: None
   availability_zone:
     description:
        - AZ to create the router in.
     required: true
     default: None
   k5_auth:
     description:
       - dict of k5_auth module output.
     required: true
     default: None
requirements:
    - "python >= 2.6"
'''

EXAMPLES = '''
# Create a k5 router
- k5_router:
     name: admin
     state: present
     availability_zone: uk-1a
     k5_auth: "{{ k5_auth_facts }}"
'''

RETURN = '''
k5_router_facts:
    description: Dictionary describing the router details.
    returned: On success when router is created
    type: dictionary
    contains:
        id:
            description: Router ID.
            type: string
            sample: "474acfe5-be34-494c-b339-50f06aa143e4"
        name:
            description: Router name.
            type: string
            sample: "router1"
        admin_state_up:
            description: Administrative state of the router.
            type: boolean
            sample: true
        status:
            description: The router status.
            type: string
            sample: "ACTIVE"
        tenant_id:
            description: The tenant ID.
            type: string
            sample: "861174b82b43463c9edc5202aadc60ef"
        external_gateway_info:
            description: The external gateway parameters. Will always be null.
            type: dictionary
            sample: null
        availability_zone:
            description: The AZ the router was created in.
            type: string
            sample: uk-1a
'''


import requests
import os
import json
from ansible.module_utils.basic import *


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
        k5_debug_out.append(s)


############## router functions #############

def k5_get_endpoint(e,name):
    """Pull particular endpoint name from dict"""

    return e['endpoints'][name]

def k5_check_router_exists(module, k5_facts):
    """Chekc if a router_name already exists"""

    endpoint = k5_facts['endpoints']['networking']
    auth_token = k5_facts['auth_token']
    router_name = module.params['name']

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/v2.0/routers'

    k5_debug_add('endpoint: {0}'.format(endpoint))
    k5_debug_add('REQ: {0}'.format(url))
    k5_debug_add('headers: {0}'.format(headers))

    try:
        response = session.request('GET', url, headers=headers)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e)

    # we failed to get data
    if response.status_code not in (200,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    #k5_debug_add("RESP: " + str(response.json()))

    for n in response.json()['routers']:
        #k5_debug_add("Found router name: " + str(n['name']))
        if str(n['name']) == router_name:
            #k5_debug_add("Found it!")
            return True

    return False

def k5_create_router(module):
    """Create a router in an AZ on K5"""
    
    global k5_debug

    k5_debug_clear()

    if 'K5_DEBUG' in os.environ:
        k5_debug = True

    if 'auth_spec' in module.params['k5_auth']: 
        k5_facts = module.params['k5_auth']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")        

    endpoint = k5_facts['endpoints']['networking']
    auth_token = k5_facts['auth_token']

    router_name = module.params['name']

    if k5_check_router_exists(module, k5_facts):
        if k5_debug:
            module.exit_json(changed=False, msg="Router " + router_name + " already exists", debug=k5_debug_out)
        else:
            module.exit_json(changed=False, msg="Router " + router_name + " already exists")

    az = module.params['availability_zone']
    
    # actually the project_id, but stated as tenant_id in the API
    tenant_id = k5_facts['auth_spec']['os_project_id']
    
    k5_debug_add('auth_token: {0}'.format(auth_token))
    k5_debug_add('router_name: {0}'.format(router_name))
    k5_debug_add('tenant_id: {0}'.format(tenant_id))
    k5_debug_add('az: {0}'.format(az))

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/v2.0/routers'

    query_json = {"router": {"name": router_name,"tenant_id": tenant_id, "availability_zone": az}}

    k5_debug_add('endpoint: {0}'.format(endpoint))
    k5_debug_add('REQ: {0}'.format(url))
    k5_debug_add('headers: {0}'.format(headers))
    k5_debug_add('json: {0}'.format(query_json))

    try:
        response = session.request('POST', url, headers=headers, json=query_json)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e)

    # we failed to make a change
    if response.status_code not in (201,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    if k5_debug:
        module.exit_json(changed=True, msg="Router Creation Successful", k5_router_facts=response.json()['router'], debug=k5_debug_out )

    module.exit_json(changed=True, msg="Router Creation Successful", k5_router_facts=response.json()['router'] )


######################################################################################

def main():

    module = AnsibleModule( argument_spec=dict(
        name = dict(required=True, default=None, type='str'),
        state = dict(required=True, type='str'), # should be a choice
        availability_zone = dict(required=True, default=None, type='str'),
        k5_auth = dict(required=True, default=None, type='dict')
    ) )

    if module.params['state'] == 'present':
        k5_create_router(module)
    else:
       module.fail_json(msg="No 'absent' function in this module, use os_router module instead") 


######################################################################################

if __name__ == '__main__':  
    main()



