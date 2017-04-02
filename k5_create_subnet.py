#!/usr/bin/python

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = '''
---
module: k5_create_subnet
short_description: Create subnet on K5 in particular AZ
version_added: "1.0"
description:
    - Explicit K5 call to create a subnet in an AZ - replaces os_subnet from Openstack module, but is more limited. Use os_subnet to update the network. 
options:
   name:
     description:
        - Name of the subnet.
     required: true
     default: None
   state:
     description:
        - State of the subnet. Can only be 'present'.
     required: true
     default: None
   network_name:
     description:
        - Name of the Network the Subnet is created on.
     required: true
     default: None
   cidr:
     description:
        - CIDR for the subnet.
     required: true
     default: None
   gateway_ip:
     description:
        - Gateway ip of the subnet. Can only be 'present'.
     required: true
     default: None
   availability_zone:
     description:
        - AZ to create the subnet in.
     required: true
     default: None
   enable_dhcp:
     description:
        - Enable DHCP on the subnet.
     required: true
     default: None
   dhcp_pool_start:
     description:
        - DHCP scope start.
     required: false
     default: None
   dhcp_pool_end:
     description:
        - DHCP scope end.
     required: false
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
# Create a subnet in an AZ
    - k5_create_subnet:
        state: present
        network_name: "nx-test-net-1a"
        name: "nx-test-subnet-1a"
        cidr: "192.168.1.0/24"
        gateway_ip: 192.168.1.1
        availability_zone: "uk-1a"
        enable_dhcp: True
        dhcp_pool_start: "192.168.1.10"
        dhcp_pool_end: "192.168.1.240"
        k5_auth: "{{ k5_auth_reg.k5_auth_facts }}"
'''

RETURN = '''
k5_subnet_facts:
    description: Dictionary describing the subnet details.
    returned: On success when subnet is created
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

        "k5_subnet_facts": {
            "allocation_pools": [
                {
                    "end": "10.0.0.254", 
                    "start": "10.0.0.2"
                }
            ], 
            "availability_zone": "uk-1a", 
            "cidr": "10.0.0.0/24", 
            "dns_nameservers": [], 
            "enable_dhcp": true, 
            "gateway_ip": "10.0.0.1", 
            "host_routes": [], 
            "id": "71544057-9dda-454a-83f6-c55f31ce1c94", 
            "ip_version": 4, 
            "name": "nx-test-subnet-1a", 
            "network_id": "acd63e36-41f7-489d-be93-a1b40a4ef76b", 
            "tenant_id": "9505d1dab17946ea97745d5de30cc8be"
        }, 

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

def k5_get_network_id_from_name(module, k5_facts):
    """Get an id from a network_name"""

    endpoint = k5_facts['endpoints']['networking']
    auth_token = k5_facts['auth_token']
    network_name = module.params['network_name']

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/v2.0/networks'

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

    for n in response.json()['networks']:
        #k5_debug_add("Found network name: " + str(n['name']))
        if str(n['name']) == network_name:
            #k5_debug_add("Found it!")
            return n['id']

    return ''



def k5_check_subnet_exists(module, k5_facts):
    """Check if a network_name already exists"""
   
    endpoint = k5_facts['endpoints']['networking']
    auth_token = k5_facts['auth_token']
    subnet_name = module.params['name']
    network_name = module.params['network_name']
 
    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/v2.0/subnets'

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

    for n in response.json()['subnets']:
        #k5_debug_add("Found subnet name: " + str(n['name']))
        if str(n['name']) == subnet_name:
            #k5_debug_add("Found it!")
            return True

    return False

def k5_create_subnet(module):
    """Create a subnet in an AZ on K5"""
    
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

    subnet_name = module.params['name']
    network_name = module.params['network_name']
    cidr = module.params['cidr']
    dns = module.params['dns']
    gateway_ip = module.params['gateway_ip'] # optional
    enable_dhcp = module.params['enable_dhcp']
    dhcp_pool_start = module.params['dhcp_pool_start']
    dhcp_pool_end = module.params['dhcp_pool_end']

    if k5_check_subnet_exists(module, k5_facts):
        if k5_debug:
            module.exit_json(changed=False, msg="Subnet " + subnet_name + " already exists", debug=k5_debug_out)
        else:
            module.exit_json(changed=False, msg="Subnet " + subnet_name + " already exists")

    # we need the network_id not network_name, so grab it
    network_id = k5_get_network_id_from_name(module, k5_facts)
    if network_id == '':
        if k5_debug:
            module.exit_json(changed=False, msg="Network " + network_name + " not found", debug=k5_debug_out)
        else:
            module.exit_json(changed=False, msg="Network " + network_name + " not found")
    
    az = module.params['availability_zone']
    
    # actually the project_id, but stated as tenant_id in the API
    tenant_id = k5_facts['auth_spec']['os_project_id']
    
    k5_debug_add('auth_token: {0}'.format(auth_token))
    k5_debug_add('subnet_name: {0}'.format(subnet_name))
    k5_debug_add('network_name: {0} {1}'.format(network_name, network_id))
    k5_debug_add('cidr: {0}'.format(cidr))
    k5_debug_add('dns: {0}'.format(dns))
    k5_debug_add('gateway_ip: {0}'.format(gateway_ip))
    k5_debug_add('az: {0}'.format(az))
    k5_debug_add('enable_dhcp: {0}'.format(enable_dhcp))
    k5_debug_add('dhcp_pool_start: {0}'.format(dhcp_pool_start))
    k5_debug_add('dhcp_pool_end: {0}'.format(dhcp_pool_end))

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/v2.0/subnets'

    if dhcp_pool_start is None or dhcp_pool_end is None:
        query_json = {"subnet": {
            "name": subnet_name, 
            "network_id": network_id, 
            "cidr": cidr, 
            "dns_nameservers": dns, 
            "ip_version": 4, 
#            "gateway_ip": gateway_ip, 
            "availability_zone": az,
            "enable_dhcp": enable_dhcp
            }}
    else:
        query_json = {"subnet": {
            "name": subnet_name, 
            "network_id": network_id, 
            "cidr": cidr, 
            "dns_nameservers": dns, 
            "ip_version": 4, 
#            "gateway_ip": gateway_ip, 
            "availability_zone": az, 
            "enable_dhcp": enable_dhcp,
            "allocation_pools": [
                {
                    "start":dhcp_pool_start,
                    "end":dhcp_pool_end
                }
            ]
            }}

    # add gateway if defined - issue #5
    if gateway_ip is not None:
        k5_debug_add('adding gateway_ip: {0}'.format(gateway_ip))
        query_json.update({"gateway_ip": gateway_ip})


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
      module.exit_json(changed=True, msg="Subnet Creation Successful", k5_subnet_facts=response.json()['subnet'], debug=k5_debug_out )

    module.exit_json(changed=True, msg="Subnet Creation Successful", k5_subnet_facts=response.json()['subnet'] )


######################################################################################

def main():

    module = AnsibleModule( argument_spec=dict(
        name = dict(required=True, default=None, type='str'),
        state = dict(required=True, type='str'), # should be a choice
        cidr = dict(required=True, default=None, type='str'),
        network_name = dict(required=True, default=None, type='str'),
        dns = dict(required=False, default=None, type='list'),
        gateway_ip = dict(required=False, default=None, type='str'),
        availability_zone = dict(required=True, default=None, type='str'),
        enable_dhcp = dict(required=False, default=True, type='str'),
        dhcp_pool_start = dict(required=False, default=None, type='str'),
        dhcp_pool_end = dict(required=False, default=None, type='str'),
        k5_auth = dict(required=True, default=None, type='dict')
    ) )

    if module.params['state'] == 'present':
        k5_create_subnet(module)
    else:
       module.fail_json(msg="No 'absent' function in this module, use os_network module instead") 


######################################################################################

if __name__ == '__main__':  
    main()



