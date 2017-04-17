#!/usr/bin/python

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = '''
---
module: k5_ssl_vpn_delete
short_description: delete SSL VPN service
version_added: "1.0"
description:
    - return none
options:
    ssl_vpn_id:
        description:
            - UUID of the VPN 
        required: False
        default: None
    ssl_vpn_name:
        description:
            - Name of the VPN 
        required: False
        default: None
requirements:
    - "python >= 2.6"
'''

EXAMPLES = '''
- k5_ssl_vpn_delete:
     ssl_vpn_name: test01
     k5_auth: "{{ k5_auth_facts }}"
'''

RETURN = '''
none
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

def k5_ssl_vpn_delete_by_id(module):
    """list vpn servies"""
    
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
    
    ssl_vpn_id = module.params['ssl_vpn_id']

    k5_debug_add('auth_token: {0}'.format(auth_token))

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    #url = endpoint + '/v2.0/vpn/ssl-vpn-connections/' + ssl_vpn_id
    url = endpoint + '/v2.0/vpn/vpnservices/' + ssl_vpn_id

    k5_debug_add('endpoint: {0}'.format(endpoint))
    k5_debug_add('REQ: {0}'.format(url))
    k5_debug_add('headers: {0}'.format(headers))
    #k5_debug_add('json: {0}'.format(query_json))

    try:
        response = session.request('DELETE', url, headers=headers)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e)

    # we failed to make a change
    if response.status_code not in (204,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    if k5_debug:
        module.exit_json(changed=True, msg="Delete SSL VPN Connection Successful", debug=k5_debug_out )
    else:
        module.exit_json(changed=True, msg="Delete SSL VPN Connection Successful" )


######################################################################################

def main():

    module = AnsibleModule( argument_spec=dict(
        ssl_vpn_id = dict(required=False, default=None, type='str'),
        ssl_vpn_name = dict(required=False, default=None, type='str'),
        k5_auth = dict(required=True, default=None, type='dict')
    ),
        # constraints
        mutually_exclusive=[
         [ 'ssl_vpn_id', 'ssl_vpn_name' ]
        ],
        required_one_of=[
         [ 'ssl_vpn_id', 'ssl_vpn_name' ]
        ]
 )

    if module.params['ssl_vpn_id'] is not None:
        k5_ssl_vpn_delete_by_id(module)
    else:
        #k5_ssl_vpn_delete_by_name(module)
        module.fail_json(changed=False, msg="Delete via ssl_vpn_name not yet implemented and names are not Unique")


######################################################################################

if __name__ == '__main__':  
    main()



