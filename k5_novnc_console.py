#!/usr/bin/python

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = '''
---
module: k5_novnc_console
short_description: Display the URL to the NoVNC Console
version_added: "1.0"
description:
    - returns a URL to the noVNC console.
options:
   server_name:
     description:
        - Name of the server.
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
# Get novnc url
- k5_novnc_console:
     server_name: test01
     k5_auth: "{{ k5_auth_facts }}"
'''

RETURN = '''
k5_novnc_console_facts
    description: Dictionary describing the novnc details.
    returned: On success when the server is found
    type: dictionary
    contains:
        id:
            description: Router ID.
            type: string
            sample: "474acfe5-be34-494c-b339-50f06aa143e4"
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

def k5_get_server_facts(module, k5_facts):
    """Get server facts"""

    endpoint = k5_facts['endpoints']['compute']
    auth_token = k5_facts['auth_token']

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

    if 'servers' in response.json():
      return response.json()
    else:
      module.fail_json(msg="Missing servers in response to server details request")


def k5_get_novnc_console(module):
    """Get novnc url"""
    
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
    server_facts = k5_get_server_facts(module, k5_facts)

    server_id = ''
    for s in server_facts['servers']:
        if s['name'] == server_name:
            server_id = s['id']
            break

    if server_id == '':
      if k5_debug:
          module.exit_json(changed=False, msg="Server " + server_name + " not found", debug=k5_debug_out)
      else:
          module.exit_json(changed=False, msg="Server " + server_name + " not found")

    k5_debug_add('auth_token: {0}'.format(auth_token))
    k5_debug_add('server_name: {0}'.format(server_name))

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/servers/' + server_id + '/action'

    query_json = { 'os-getVNCConsole': {'type': 'novnc' }}

    k5_debug_add('endpoint: {0}'.format(endpoint))
    k5_debug_add('REQ: {0}'.format(url))
    k5_debug_add('headers: {0}'.format(headers))
    k5_debug_add('json: {0}'.format(query_json))

    try:
        response = session.request('POST', url, headers=headers, json=query_json)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e)

    # we failed to make a change
    if response.status_code not in (200,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    if k5_debug:
        module.exit_json(changed=True, msg="Get URL Successful", k5_novnc_console_facts=response.json(), debug=k5_debug_out )

    module.exit_json(changed=True, msg="Get URL Successful", k5_novnc_console_facts=response.json() )


######################################################################################

def main():

    module = AnsibleModule( argument_spec=dict(
        server_name = dict(required=True, default=None, type='str'),
        k5_auth = dict(required=True, default=None, type='dict')
    ) )

    k5_get_novnc_console(module)


######################################################################################

if __name__ == '__main__':  
    main()



