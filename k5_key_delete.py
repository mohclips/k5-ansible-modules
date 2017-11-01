#!/usr/bin/python

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = '''
---
# TODO
module: k5_key_delete
short_description: List key metadata containers
version_added: "1.0"
description:
    - returns a dict of containers
options:
   key_id:
     description:
       - ID of the key to delete.
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
- k5_key_delete:
     key_id: "decafbad-1234-5678-90ab-decafbad1234"
     k5_auth: "{{ k5_auth_facts }}"
'''

RETURN = '''
# TODO
k5_key_container_list
    description: Dictionary describing the novnc details.
    returned: On success when the server is found
    type: dictionary
    contains:
        list:
            name: container_ref
            description:
            type:
            sample:  https://keymanagement.uk-1.cloud.global.fujitsu.com/v1/dbbd47230bfd4e699099462cd8f51b53/containers/0a561620-3e4d-47e7-9b2d-77fc59b7395f
#TODO
created: '2017-04-13T08:55:13.241314'
name: Rail_VPN_1_container
secret_refs:
- name: ca
  secret_id: 8c1b3826-b653-4f07-9543-3db7f0be6b6a
- name: server_certificate
  secret_id: e05a9e43-d07d-4835-a635-9a976e2f88b0
- name: server_key
  secret_id: eb17318f-bd3d-41a2-a0fc-d0a75a4c522a
- name: dh
  secret_id: ad556fcd-a506-4ceb-8d81-42da2589be45
status: ACTIVE
type: generic
updated: '2017-04-13T08:55:13.241325'
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


############## functions #############

def k5_get_endpoint(e,name):
    """Pull particular endpoint name from dict"""

    return e['endpoints'][name]

def k5_key_delete(module):
    """delete vpn container"""
    
    global k5_debug

    k5_debug_clear()

    if 'K5_DEBUG' in os.environ:
        k5_debug = True

    if 'auth_spec' in module.params['k5_auth']: 
        k5_facts = module.params['k5_auth']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")        

    endpoint = k5_facts['endpoints']['keymanagement']
    auth_token = k5_facts['auth_token']

    #k5_debug_add('auth_token: {0}'.format(auth_token))

    # actually the project_id, but stated as tenant_id in the API
    tenant_id = k5_facts['auth_spec']['os_project_id']
    
    res_id = module.params['key_id']

    session = requests.Session()

    #headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }
    headers = {'X-Auth-Token': auth_token }

    url = endpoint + '/' + tenant_id + '/secrets/' + res_id 

    #k5_debug_add('endpoint: {0}'.format(endpoint))
    k5_debug_add('REQ: {0}'.format(url))
    #k5_debug_add('headers: {0}'.format(headers))
    #k5_debug_add('json: {0}'.format(query_json))

    try:
        response = session.request('DELETE', url, headers=headers)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e)

    # we failed to make a change
    if response.status_code not in (204,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    if k5_debug:
        module.exit_json(changed=True, msg="Delete Successful", debug=k5_debug_out )
    else:
        module.exit_json(changed=True, msg="Delete Successful" )


######################################################################################

def main():

    module = AnsibleModule( argument_spec=dict(
        k5_auth = dict(required=True, default=None, type='dict'),
        key_id = dict(required=True, default=None, type='str')
    ) )

    k5_key_delete(module)


######################################################################################

if __name__ == '__main__':  
    main()



