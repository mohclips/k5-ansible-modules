#!/usr/bin/python

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = '''
---
module: k5_srv_shelve
short_description: Shelve and un-shelve a virtual server in K5
version_added: "1.0"
description:
    - Explicit K5 call to shelve and un-shelve a server in K5  - no module for this action exists. 
options:
   server_name:
     description:
        - name of the server.
     required: true
     default: None
   state:
     description:
        - State of the network. Can be 'shelve' or 'unshelve'.
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
# Create a port in an AZ
- k5_srv_shelve:
        server_name: "nx-test-server"
        state: present
        k5_auth: "{{ k5_auth_reg.k5_auth_facts }}"
'''

RETURN = '''

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


############## server functions #############

def k5_get_endpoint(e,name):
    """Pull particular endpoint name from dict"""

    return e['endpoints'][name]


def k5_get_server_id_from_name(module, k5_facts):
    """Get an id from a server_name"""

    endpoint = k5_facts['endpoints']['compute']
    auth_token = k5_facts['auth_token']
    server_name = module.params['server_name']

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/servers'

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

    for n in response.json()['servers']:
        #k5_debug_add("Found server name: " + str(n['name']))
        if str(n['name']) == server_name:
            #k5_debug_add("Found it!")
            return n['id']

    return ''

def k5_get_server_status(module, k5_facts):
    """Get status from a server_name"""

    endpoint = k5_facts['endpoints']['compute']
    auth_token = k5_facts['auth_token']
    server_name = module.params['server_name']

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/servers/detail'

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

    for n in response.json()['servers']:
        #k5_debug_add("Found server name: " + str(n['name']))
        if str(n['name']) == server_name:
            #k5_debug_add("Found it!")
            return n['status']

    return ''

def k5_srv_shelve(module):
    """shelve the server"""
    
    global k5_debug

    k5_debug_clear()

    if 'K5_DEBUG' in os.environ:
        k5_debug = True

    if 'auth_spec' in module.params['k5_auth']: 
        k5_facts = module.params['k5_auth']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")        

    endpoint = k5_facts['endpoints']['compute']
    auth_token = k5_facts['auth_token']

    server_name = module.params['server_name']

    # we need the server_id not server_name, so grab it
    server_id = k5_get_server_id_from_name(module, k5_facts)
    if server_id == '':
        if k5_debug:
            module.exit_json(changed=False, msg="Server " + server_name + " not found", debug=k5_debug_out)
        else:
            module.exit_json(changed=False, msg="Server " + server_name + " not found")

    
    # actually the project_id, but stated as tenant_id in the API
    #tenant_id = k5_facts['auth_spec']['os_project_id']

    # Get the current server state
    server_status = k5_get_server_status(module, k5_facts)
    
    if server_status == '':
        if k5_debug:
            module.exit_json(changed=False, msg="Server " + server_name + " status not found", debug=k5_debug_out)
        else:
            module.exit_json(changed=False, msg="Server " + server_name + " status not found")

    
    k5_debug_add('auth_token: {0}'.format(auth_token))
    k5_debug_add('server_name: {0} {1}'.format(server_name, server_id))

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/servers/' + server_id + '/action'

    query_json = {"shelve": 'null'}

    k5_debug_add('endpoint: {0}'.format(endpoint))
    k5_debug_add('REQ: {0}'.format(url))
    k5_debug_add('headers: {0}'.format(headers))
    k5_debug_add('json: {0}'.format(query_json))

    if server_status == 'SHUTOFF':
        try:
            response = session.request('POST', url, headers=headers, json=query_json)
        except requests.exceptions.RequestException as e:
            module.fail_json(msg=e)
    elif server_status == 'SHELVED_OFFLOADED':
        module.exit_json(changed=False, msg="Server " + server_name + " already shelved")
    else:
        module.exit_json(changed=False, msg="Server " + server_name + " status " + server_status)
        
    # we failed to make a change
    if response.status_code not in (202,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    if k5_debug:
      module.exit_json(changed=True, msg="Server shelved successfully", debug=k5_debug_out )

    module.exit_json(changed=True, msg="Server shelved successfully", )

def k5_srv_unshelve(module):
    """unshelve the server"""
    
    global k5_debug

    k5_debug_clear()

    if 'K5_DEBUG' in os.environ:
        k5_debug = True

    if 'auth_spec' in module.params['k5_auth']: 
        k5_facts = module.params['k5_auth']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")        

    endpoint = k5_facts['endpoints']['compute']
    auth_token = k5_facts['auth_token']

    server_name = module.params['server_name']

    # we need the server_id not server_name, so grab it
    server_id = k5_get_server_id_from_name(module, k5_facts)
    if server_id == '':
        if k5_debug:
            module.exit_json(changed=False, msg="Server " + server_name + " not found", debug=k5_debug_out)
        else:
            module.exit_json(changed=False, msg="Server " + server_name + " not found")

    
    # actually the project_id, but stated as tenant_id in the API
    #tenant_id = k5_facts['auth_spec']['os_project_id']

    # Get the current server state
    server_status = k5_get_server_status(module, k5_facts)
    if server_status == '':
        if k5_debug:
            module.exit_json(changed=False, msg="Server " + server_name + " status not found", debug=k5_debug_out)
        else:
            module.exit_json(changed=False, msg="Server " + server_name + " status not found")
    
    k5_debug_add('auth_token: {0}'.format(auth_token))
    k5_debug_add('server_name: {0} {1}'.format(server_name, server_id))

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/servers/' + server_id + '/action'

    query_json = {"unshelve": 'null' }

    k5_debug_add('endpoint: {0}'.format(endpoint))
    k5_debug_add('REQ: {0}'.format(url))
    k5_debug_add('headers: {0}'.format(headers))
    k5_debug_add('json: {0}'.format(query_json))

    if server_status == 'SHELVED_OFFLOADED':
        try:
            response = session.request('POST', url, headers=headers, json=query_json)
        except requests.exceptions.RequestException as e:
            module.fail_json(msg=e)
    else:
        module.exit_json(changed=False, msg="Server " + server_name + " already un-shelved")

    # we failed to make a change
    if response.status_code not in (202,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)
    
    if k5_debug:
      module.exit_json(changed=True, msg="Server un-shelved successfully", debug=k5_debug_out )

    module.exit_json(changed=True, msg="Server un-shelved successfully", )
    
    
######################################################################################

def main():

    module = AnsibleModule( argument_spec=dict(
        server_name = dict(required=True, default=None, type='str'),
        state = dict(required=True, type='str'), # should be a choice
        k5_auth = dict(required=True, default=None, type='dict')
    ) )

    if module.params['state'] == 'shelve':
        k5_srv_shelve(module)
    elif module.params['state'] == 'unshelve':
        k5_srv_unshelve(module)
    else:
       module.fail_json(msg="k5_srv_shelve module only support states of shelve and unshelve") 


######################################################################################

if __name__ == '__main__':  
    main()

