#!/usr/bin/python

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = '''
---
module: k5_network
short_description: Create network on K5 in particular AZ
version_added: "1.0"
description:
    - Explicit K5 call to create a network in an AZ - replaces os_network from Openstack module, but is more limited. Use os_network to update the network. 
options:
   name:
     description:
        - Name of the network.
     required: true
     default: None
   state:
     description:
        - State of the network. Can only be 'present'.
     required: true
     default: None
   availability_zone:
     description:
        - AZ to create the network in.
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
# Create a network in an AZ
- k5_network:
     name: network-01
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


def k5_get_port_facts(module, k5_facts, server_id):
    """Get port facts for a server"""
   
    endpoint = k5_facts['endpoints']['compute']
    auth_token = k5_facts['auth_token']
 
    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/servers/' + server_id + '/os-interface'

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

    if 'interfaceAttachments' in response.json():
      return response.json()
    else:
      module.fail_json(msg="Missing interfaceAttachments in response to server port request")

def k5_create_floating_ip(module):
    """Attach a floating IP to a server on K5"""
    
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

    server_name = module.params['server']
    fixed_ip = module.params['fixed_ip']

    # we need the server_id not server_name, so grab it
    server_facts = k5_get_server_facts(module, k5_facts)

    az = ''
    server_id = ''
    for s in server_facts['servers']:
        if s['name'] == server_name:
            server_id = s['id']
            az = s['OS-EXT-AZ:availability_zone']
            # check if that server has a floating IP already assigned - maybe people want two floaing IPs, but we arent allowing that here
            for subnets in s['addresses']:
                for subnet in s['addresses'][subnets]:
                    if subnet['OS-EXT-IPS:type'] == 'floating':
                        module.exit_json(changed=False, msg="Floating IP " + subnet['addr'] + " already assigned")

            break

    if server_id == '':
      if k5_debug:
          module.exit_json(changed=False, msg="Server " + server_name + " not found", debug=k5_debug_out)
      else:
          module.exit_json(changed=False, msg="Server " + server_name + " not found")

    port_facts = k5_get_port_facts(module, k5_facts, server_id)

    k5_debug_add(port_facts)

    try:
      # attach to first port
      port = port_facts['interfaceAttachments'][0]
      port_id = port['port_id']
      network_id = port['net_id']
    except:
      # is there any need for this?  surely a port always exists?    
      if k5_debug:
          module.exit_json(changed=False, msg="Port on " + server_name + " not found", debug=k5_debug_out)
      else:
          module.exit_json(changed=False, msg="Port on " + server_name + " not found")

    k5_debug_add('port_id: '+str(port_id))
    k5_debug_add('net_id: '+str(network_id))
    k5_debug_add('auth_token: ' + str(auth_token))
    k5_debug_add('server_name: '+ str(server_name))
    k5_debug_add('fixed_ip: '+str(fixed_ip))
    k5_debug_add('az: '+str(az))

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/v2.0/floatingips'

    query_json = {"floatingip": {
            "floating_network_id": network_id, 
            "port_id": port_id, 
            "availability_zone": az
            }
        }

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
    
    k5_debug_add('response json: {0}'.format(response.json()))

    if k5_debug:
      module.exit_json(changed=True, msg="Floating IP Allocation Successful", k5_floatingip_facts=response.json()['floatingip'], debug=k5_debug_out )

    module.exit_json(changed=True, msg="Floating IP Allocation Successful", k5_floatingip_facts=response.json()['floatingip'] )


######################################################################################

def main():

    module = AnsibleModule( argument_spec=dict(
        server = dict(required=True, default=None, type='str'),
        fixed_ip = dict(required=True, default=None, type='str'),
        k5_auth = dict(required=True, default=None, type='dict')
    ) )

    k5_create_floating_ip(module)


######################################################################################

if __name__ == '__main__':  
    main()



