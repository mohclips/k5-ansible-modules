#!/usr/bin/python

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = '''
---
module: k5_inter_project_link
short_description: Create inter-project link on K5 in particular AZ
version_added: "1.0"
description:
    - K5 call to inter-project network link in an AZ - the inter-project link is custom to K5 therefore there is no Openstack module. 
options:
   router_name:
     description:
        - Name of the router network.
     required: true
     default: None
   state:
     description:
        - State of the network. Can be 'present' or 'absent'.
     required: true
     default: None
   k5_port:
     description:
       - dict of k5_port module output.
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
# Create an inter-project link in an AZ
- k5_create_inter_project_link:
        state: present
        k5_port: "{{ k5_port_reg.k5_port_facts }}"
        router_name: "nx-test-net-1a"
        k5_auth: "{{ k5_auth_reg.k5_auth_facts }}"
'''

RETURN = '''
- 
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


############## inter-project link functions #############

def k5_get_endpoint(e,name):
    """Pull particular endpoint name from dict"""

    return e['endpoints'][name]


def k5_get_router_id_from_name(module, k5_facts):
    """Get an id from a router_name"""

    endpoint = k5_facts['endpoints']['networking']
    auth_token = k5_facts['auth_token']
    
    router_name = module.params['router_name']

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
            return n['id']

    return ''

def k5_create_inter_project_link(module):
    """Create an inter-project link in an AZ on K5"""

    global k5_debug

    k5_debug_clear()

    if 'K5_DEBUG' in os.environ:
        k5_debug = True

    if 'auth_spec' in module.params['k5_auth']: 
        k5_facts = module.params['k5_auth']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?") 
        
    if 'id' in module.params['k5_port']: 
        k5_port = module.params['k5_port']
    else:
        module.fail_json(msg="k5_port_id not found, have you run k5_create_port?")         

    endpoint = k5_facts['endpoints']['networking-ex']
    auth_token = k5_facts['auth_token']
    port_id = k5_port['id']
    router_name = module.params['router_name']

   
    # we need the router_id not router_name, so grab it
    router_id = k5_get_router_id_from_name(module, k5_facts)
    if router_id == '':
        if k5_debug:
            module.exit_json(changed=False, msg="Router " + router_name + " not found", debug=k5_debug_out)
        else:
            module.exit_json(changed=False, msg="Router " + router_name + " not found")


    if router_id == k5_port['device_id']:
        module.exit_json(changed=False, msg="Port already connected to the correct router")
    elif k5_port['device_id'] != '':
        if k5_debug:
            module.fail_json(changed=False, msg="Port already attached to " + k5_port['device_id'], debug=k5_debug_out)
        else:
            module.fail_json(changed=False, msg="Port already attached to " + k5_port['device_id'])

    # actually the project_id, but stated as tenant_id in the API
    tenant_id = k5_facts['auth_spec']['os_project_id']
    
    k5_debug_add('router_name: {0}'.format(router_name))
    k5_debug_add('port_id: {0}'.format(port_id))

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/v2.0/routers/' + router_id + '/add_cross_project_router_interface'

    query_json = { "port_id": port_id }

    k5_debug_add('REQ: {0}'.format(url))
    k5_debug_add('headers: {0}'.format(headers))
    k5_debug_add('json: {0}'.format(query_json))

    try:
        response = session.request('PUT', url, headers=headers, json=query_json)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e)

    # we failed to make a change
    if response.status_code not in (200,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    if k5_debug:
        module.exit_json(changed=True, msg="Inter-porject Link Creation Successful", debug=k5_debug_out )

    module.exit_json(changed=True, msg="Inter-porject Link Creation Successful")

def k5_delete_inter_project_link(module):
    """Delete an inter-project link in an AZ on K5"""

    global k5_debug

    k5_debug_clear()

    if 'K5_DEBUG' in os.environ:
        k5_debug = True

    if 'auth_spec' in module.params['k5_auth']: 
        k5_facts = module.params['k5_auth']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?") 

    if 'id' in module.params['k5_port']: 
        k5_port = module.params['k5_port']
        port_id = k5_port['id']
    elif 'id' in module.params:
        port_id = module.params['port_id']
    else:
        module.fail_json(msg="port_id or k5_port not supplied")

    endpoint = k5_facts['endpoints']['networking-ex']
    auth_token = k5_facts['auth_token']
    router_name = module.params['router_name']
   
    # we need the router_id not router_name, so grab it
    router_id = k5_get_router_id_from_name(module, k5_facts)
    if router_id == '':
        if k5_debug:
            module.exit_json(changed=False, msg="Router " + router_name + " not found", debug=k5_debug_out)
        else:
            module.exit_json(changed=False, msg="Router " + router_name + " not found")

    # actually the project_id, but stated as tenant_id in the API
    tenant_id = k5_facts['auth_spec']['os_project_id']
    
    k5_debug_add('router_name: {0}'.format(router_name))
    k5_debug_add('port_id: {0}'.format(port_id))

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/v2.0/routers/' + router_id + '/remove_cross_project_router_interface'

    query_json = { "port_id": port_id }

    k5_debug_add('REQ: {0}'.format(url))
    k5_debug_add('headers: {0}'.format(headers))
    k5_debug_add('json: {0}'.format(query_json))

    try:
        response = session.request('PUT', url, headers=headers, json=query_json)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e)

    # we failed to make a change
    if response.status_code not in (200,):
        if "does not have an interface with id" in response.content:
            if k5_debug:
                module.exit_json(changed=False, msg="Inter-project Link did not exist", debug=k5_debug_out)

            module.exit_json(changed=False, msg="Inter-project Link did not exist")

        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    if k5_debug:
        module.exit_json(changed=True, msg="Inter-porject Link Deleted Successful", debug=k5_debug_out )

    module.exit_json(changed=True, msg="Inter-porject Link Deleted Successful" )


######################################################################################

def main():

    module = AnsibleModule( argument_spec=dict(
        router_name = dict(required=True, default=None, type='str'),
        state = dict(required=True, type='str'), # should be a choice
        k5_port = dict(required=True, default=None, type='dict'),
        k5_auth = dict(required=True, default=None, type='dict')
    ) )

    if module.params['state'] == 'present':
        k5_create_inter_project_link(module)
    elif module.params['state'] == 'absent':
        k5_delete_inter_project_link(module)
    else:
       module.fail_json(msg="Unknown state") 


######################################################################################

if __name__ == '__main__':  
    main()



