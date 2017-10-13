#!/usr/bin/python

import datetime

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = '''
---
module: k5_keypair
short_description: create / delete / list ssh keys
version_added: "1.0"
description:
    - returns ssh public keys
options:
   keypair_name:
     description:
        - Name to create / delete
     required: true
     default: None
   project_name:
     description:
        - Name of the project
     required: true
     default: None
   status:
     description:
        - present / absent / list
     required: true
     default: None
   ssh_public_key:
     description:
        - string containing the ssh public key
     required: false
     default: None
   availability_zone:
     description:
        - az to save the key in / or to find the key within
     required: true
     default: None

requirements:
    - "python >= 2.6"
'''

EXAMPLES = '''
- k5_keypair:
    keypair_name: MyKey
    project_name: myproject
    status: present
    ssh_public_key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDx8nkQv/
zgGgB4rMYmIf+6A4l6Rr+o/6lHBQdW5aYd44bd8JttDCE/F/pNRr0lRE
+PiqSPO8nDPHw0010JeMH9gYgnnFlyY3/OcJ02RhIPyyxYpv9FhY
+2YiUkpwFOcLImyrxEsYXpD/0d3ac30bNH6Sw9JD9UZHYcpSxsIbECHw=="
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

def k5_get_endpoint(e,name):
    """Pull particular endpoint name from dict"""

    return e['endpoints'][name]

def k5_get_keystoneobject_list(module, k5_facts, objecttype):
    """Get list of objects"""
# Great find by Graham Land :)

    global k5_debug

    k5_debug_add('token_type: {0}'.format(k5_facts['token_type']))

    if k5_facts['token_type'] == 'global':
        endpoint = k5_facts['endpoints']['global-identity']
    elif k5_facts['token_type'] == 'regional':
        endpoint = k5_facts['endpoints']['identityv3']
    else:
        endpoint = k5_facts['endpoints']['identity']


    auth_token = k5_facts['auth_token']

    contract_id = k5_facts['user']['domain']['id']

    k5_debug_add('auth_token: {0}'.format(auth_token))
    k5_debug_add('objecttype: {0}'.format(objecttype))

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/' + objecttype + '?domain_id=' + contract_id 

    k5_debug_add('REQ: {0}'.format(url))

    try:
        response = session.request('GET', url, headers=headers)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e, debug=k5_debug_out)

    if response.status_code not in (200,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    return response.json()



def k5_list_keypairs(module):
    """list keypair"""
   
    k5_debug_add("k5_list_keypairs")
 
    if 'auth_spec' in module.params['k5_auth']: 
        k5_facts = module.params['k5_auth']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")        

    project_id = k5_facts['auth_spec']['os_project_id']

    if 'project_name' in module.params and module.params['project_name'] != None:
        # find project_id
        project_name = module.params['project_name']
        keystone_project_list = k5_get_keystoneobject_list(module, k5_facts, 'projects')
        matched_projects = [x for x in keystone_project_list['projects'] if x['name'] == project_name]
        if len(matched_projects) == 0:
            module.exit_json(changed=False, msg="Project does not exist", k5_debug=k5_debug_out)
        project_id = matched_projects[0]['id']

    #endpoint = k5_facts['endpoints']['compute']
    endpoint = "https://compute." + k5_facts['auth_spec']['os_region_name'] + ".cloud.global.fujitsu.com/"
    auth_token = k5_facts['auth_token']

    k5_debug_add('auth_token: {0}'.format(auth_token))
        
    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }
    
    url = endpoint + '/v2/' + project_id + '/os-keypairs'

    k5_debug_add('REQ: {0}'.format(url))

    try:
        response = session.request('GET', url, headers=headers)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e)

    # we failed to make a change
    if response.status_code not in (200,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    return response.json()['keypairs']

def k5_create_keypair(module):
    """Create a keypair"""

    if 'auth_spec' in module.params['k5_auth']: 
        k5_facts = module.params['k5_auth']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")        

    #endpoint = k5_facts['endpoints']['compute']
    endpoint = "https://compute." + k5_facts['auth_spec']['os_region_name'] + ".cloud.global.fujitsu.com/"
    auth_token = k5_facts['auth_token']

    project_id = k5_facts['auth_spec']['os_project_id']

    if 'project_name' in module.params and module.params['project_name'] != None:
        # find project_id
        project_name = module.params['project_name']
        keystone_project_list = k5_get_keystoneobject_list(module, k5_facts, 'projects')
        matched_projects = [x for x in keystone_project_list['projects'] if x['name'] == project_name]
        if len(matched_projects) == 0:
            module.exit_json(changed=False, msg="Project does not exist", k5_debug=k5_debug_out)
        project_id = matched_projects[0]['id']

    k5_debug_add('auth_token: {0}'.format(auth_token))
        
    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }
    
    url = endpoint + '/v2/' + project_id + '/os-keypairs'
    k5_debug_add('REQ: {0}'.format(url))

    ssh_key_name = module.params['keypair_name']
    public_key = module.params['ssh_public_key']
    az = module.params['availability_zone']

    query_json = {
        'keypair': {
            'name': ssh_key_name, 
            'public_key': public_key,
            'availability_zone': az
        }
    }

    if public_key == None:
        del query_json['keypair']['public_key'] # generate ssh_key on K5 side via Nova

    k5_debug_add(query_json)

    try:
        response = session.request('POST', url, headers=headers, json=query_json)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e)

    # we failed to make a change
    if response.status_code in (409,):
        module.exit_json(changed=False,msg="Keypair already exists", debug=k5_debug_out)
    elif response.status_code not in (200,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    module.exit_json(changed=True, msg="Create Key Pair Successful", keypair=response.json()['keypair'] )

def k5_delete_keypair(module):
    """Delete a keypair"""
    
    if 'auth_spec' in module.params['k5_auth']: 
        k5_facts = module.params['k5_auth']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")        

    #endpoint = k5_facts['endpoints']['compute']
    endpoint = "https://compute." + k5_facts['auth_spec']['os_region_name'] + ".cloud.global.fujitsu.com/"
    auth_token = k5_facts['auth_token']

    project_id = k5_facts['auth_spec']['os_project_id']

    if 'project_name' in module.params and module.params['project_name'] != None:
        # find project_id
        project_name = module.params['project_name']
        keystone_project_list = k5_get_keystoneobject_list(module, k5_facts, 'projects')
        matched_projects = [x for x in keystone_project_list['projects'] if x['name'] == project_name]
        if len(matched_projects) == 0:
            module.exit_json(changed=False, msg="Project does not exist", k5_debug=k5_debug_out)
        project_id = matched_projects[0]['id']

    k5_debug_add('auth_token: {0}'.format(auth_token))
        
    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }
    
    ssh_key_name = module.params['keypair_name']
    public_key = module.params['ssh_public_key']
    az = module.params['availability_zone']

    url = endpoint + '/v2/' + project_id + '/os-keypairs/' + ssh_key_name + '?' + az
    k5_debug_add('REQ: {0}'.format(url))

    try:
        response = session.request('DELETE', url, headers=headers)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e)

    # we failed to make a change
    if response.status_code not in (202,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    module.exit_json(changed=True, msg="Delete Key Pair Successful")



######################################################################################

def main():

    global k5_debug

    module = AnsibleModule( argument_spec=dict(
        project_name = dict(default=None, type='str'),
        state = dict(choices=['list', 'present', 'absent' ], default='list'),
        ssh_public_key = dict(default=None, type='str'), 
        keypair_name = dict(default=None, type='str'), 
        availability_zone = dict(default=None, type='str'), 
        k5_auth = dict(required=True,default=None, type='dict')
    ),
        # constraints
        required_if=[
            ('state', 'present', ['keypair_name', 'availability_zone']),
            ('state', 'absent', ['keypair_name', 'availability_zone'])
        ]
    )

    if 'K5_DEBUG' in os.environ:
        k5_debug = True
    
    #k5_debug_clear()

    mp = module.params
    if mp['state'] == 'present':
        k5_create_keypair(module)
    if mp['state'] == 'absent':
        k5_delete_keypair(module)
    if mp['state'] == 'list':
        keys = k5_list_keypairs(module)
        module.exit_json(changed=False, msg="List Key Pairs Successful", keypairs=keys )



######################################################################################

if __name__ == '__main__':  
    main()



