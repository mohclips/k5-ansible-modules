#!/usr/bin/python

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = '''
---
module: k5_ssl_vpn_list
short_description:  List SSL VPNs on K5
version_added: "1.0"
options:
description:
    - returns dict of vpns
requirements:
    - "python >= 2.6"
'''

EXAMPLES = '''
- k5_ssl_vpn_list:
     k5_auth: "{{ k5_auth_facts }}"
'''

RETURN = '''
        "k5_ssl_vpn_facts": {
            "vpnservices": [
                {
                    "admin_state_up": true, 
                    "availability_zone": "uk-1a", 
                    "description": "", 
                    "id": "0be63045-6078-4c2f-96f8-c1da65d1e1aa", 
                    "name": "Rail_VPN_1", 
                    "router_id": "a4e21ce7-5204-4562-b003-372557ac9844", 
                    "status": "ACTIVE", 
                    "subnet_id": "80157e9b-4e7b-48ea-aa12-4997e16538ff", 
                    "tenant_id": "dbbd47230bfd4e699099462cd8f51b53"
                }
            ]
        }
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

def k5_ssl_vpn_list(module):
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

    k5_debug_add('auth_token: {0}'.format(auth_token))

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/v2.0/vpn/vpnservices'

    k5_debug_add('endpoint: {0}'.format(endpoint))
    k5_debug_add('REQ: {0}'.format(url))
    k5_debug_add('headers: {0}'.format(headers))
    #k5_debug_add('json: {0}'.format(query_json))

    try:
        response = session.request('GET', url, headers=headers)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e)

    # we failed to make a change
    if response.status_code not in (200,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    if k5_debug:
        module.exit_json(changed=True, msg="List VPN Credentials Successful", k5_ssl_vpn_facts=response.json(), debug=k5_debug_out )
    else:
        module.exit_json(changed=True, msg="List VPN Credentials Successful", k5_ssl_vpn_facts=response.json() )


######################################################################################

def main():

    module = AnsibleModule( argument_spec=dict(
        k5_auth = dict(required=True, default=None, type='dict')
    ) )

    k5_ssl_vpn_list(module)


######################################################################################

if __name__ == '__main__':  
    main()



