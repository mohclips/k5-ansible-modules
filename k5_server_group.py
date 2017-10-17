#!/usr/bin/python

import datetime

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = '''
---
module: k5_servergroup
short_description: create / delete / list server groups
version_added: "1.0"
description:
    - returns server groups
options:
   _name:
     description:
        - Name to create / delete
     required: true
     default: None
   status:
     description:
        - present / absent / list
     required: true
     default: None
   policies:
     description:
        - one of either affinity or anti-affinity 
     required: true
     default: None
   availability_zone:
     description:
        - az to save the server group in / or to find the server group within
     required: true
     default: None

requirements:
    - "python >= 2.6"
'''

EXAMPLES = '''
- k5_servergroup:
    name: MyServerGroup
    status: present
    policies: affinity
    availability_zone: uk-1a
    k5_auth: "{{ k5_auth_facts }}"
'''

RETURN = '''
k5_group:
    description: group details.
    returned: On success when the group is created
    type: dict
    sample:
#TODO
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
    global k5_debug_out
    if k5_debug:
        k5_debug_out.append(s)


############## k5 functions #############

def k5_list_servergroups(module):
    """list servergroup"""
   
    k5_debug_add("k5_list_servergroups")
 
    if 'auth_spec' in module.params['k5_auth']: 
        k5_facts = module.params['k5_auth']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")        

    endpoint = k5_facts['endpoints']['compute']
    
    auth_token = k5_facts['auth_token']

    k5_debug_add('auth_token: {0}'.format(auth_token))
        
    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }
    
    url = endpoint + '/os-server-groups'

    k5_debug_add('REQ: {0}'.format(url))

    try:
        response = session.request('GET', url, headers=headers)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e)

    # we failed to make a change
    if response.status_code not in (200,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    #server_groups response doesn't include AZ, we need to iterate over the server groups to return all detail
    server_group_list = []
    
    for n in response.json()['server_groups']:
        servergroup_id = n['id']

        url = endpoint + '/os-server-groups/' + servergroup_id
        k5_debug_add('REQ: {0}'.format(url))

        try:
            response = session.request('GET', url, headers=headers)
        except requests.exceptions.RequestException as e:
            module.fail_json(msg=e)

        server_group_list.append(response.json()['server_group'])

    return server_group_list

def k5_create_servergroup(module):
    """Create a servergroup"""

    if 'auth_spec' in module.params['k5_auth']: 
        k5_facts = module.params['k5_auth']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")        

    endpoint = k5_facts['endpoints']['compute']
    
    auth_token = k5_facts['auth_token']

    k5_debug_add('auth_token: {0}'.format(auth_token))
        
    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }
    
    url = endpoint + '/os-server-groups'
    k5_debug_add('REQ: {0}'.format(url))

    servergroup_name = module.params['name']
    servergroup_policy = module.params['policies']
    az = module.params['availability_zone']

    query_json = {
        'server_group': {
            'name': servergroup_name, 
            'policies': servergroup_policy,
            'availability_zone': az
        }
    }

    k5_debug_add(query_json)

    for n in k5_list_servergroups(module):

        if (str(n['name']) == servergroup_name) and (str(n['availability_zone']) == az):
            module.exit_json(changed=False, msg="Server Group Exists", server_group=n)

    try:
        response = session.request('POST', url, headers=headers, json=query_json)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e)

    # we failed to make a change
    if response.status_code not in (200,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    module.exit_json(changed=True, msg="Create Server Group Successful", server_group=response.json()['server_group'] )

def k5_delete_servergroup(module):
    """Delete a server group"""
    
    if 'auth_spec' in module.params['k5_auth']: 
        k5_facts = module.params['k5_auth']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")        

    endpoint = k5_facts['endpoints']['compute']
    auth_token = k5_facts['auth_token']

    k5_debug_add('auth_token: {0}'.format(auth_token))
        
    session = requests.Session()

    servergroup_name = module.params['name']
    az = module.params['availability_zone']

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }
    

    for n in k5_list_servergroups(module):

        if (str(n['name']) == servergroup_name) and (str(n['availability_zone']) == az):

            url = endpoint + '/os-server-groups/' + str(n['id']) 
            k5_debug_add('REQ: {0}'.format(url))
            try:
                response = session.request('DELETE', url, headers=headers)
            except requests.exceptions.RequestException as e:
                module.fail_json(msg=e)
            # we failed to make a change
            if response.status_code not in (202,204):
                module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

            module.exit_json(changed=True, msg="Delete Server Group Successful")

    module.exit_json(changed=False, msg="Server Group Not Found")


######################################################################################

def main():

    global k5_debug

    module = AnsibleModule( argument_spec=dict(
        state = dict(choices=['list', 'present', 'absent' ], default='list'),
        name = dict(default=None, type='str'), 
        policies = dict(choices=[['affinity'], ['anti-affinity']], default=None, type='list'), 
        availability_zone = dict(default=None, type='str'), 
        k5_auth = dict(required=True,default=None, type='dict')
    ),
        # constraints
        required_if=[
            ('state', 'present', ['name', 'availability_zone']),
            ('state', 'absent', ['name', 'availability_zone'])
        ]
    )

    if 'K5_DEBUG' in os.environ:
        k5_debug = True
    
    #k5_debug_clear()

    mp = module.params
    if mp['state'] == 'present':
        k5_create_servergroup(module)
    if mp['state'] == 'absent':
        k5_delete_servergroup(module)
    if mp['state'] == 'list':
        groups = k5_list_servergroups(module)
        module.exit_json(changed=False, msg="List Server Groups Successful", server_groups=groups )



######################################################################################

if __name__ == '__main__':  
    main()

