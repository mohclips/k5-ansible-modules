#!/usr/bin/python

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = '''
---
module: k5_create_port
short_description: Creates a network port to attach to a compute module in an AZ in K5.
version_added: "1.0"
description:
    - Explicit K5 call to create a network port in an AZ - replaces os_port from Openstack module, but is more limited. Use os_network to update the network.
options:
   name:
     description:
        - Name of the port.
     required: true
     default: None
   state:
     description:
        - State of the port. Can only be 'present'.
     required: true
     default: None
   subnet_name:
     description:
        - Name of the Subnet to attach the port to.
     required: true
     default: None
   network_name:
     description:
        - Name of the Network to attach the port to.
     required: true
     default: None
   availability_zone:
     description:
        - AZ to create the port in.
     required: true
     default: None
   security_groups:
     description:
        - The Security Group(s) to apply to the port.
     required: true
     default: None
   fixed_ip:
     description:
        - A list of IP addresses to define as 'fixed' (for DHCP purposes or static allocation on the host). If not provided, the DHCP server will offer an IP address instead.
     required: false
     default: None
   allowed_address_pairs:
     description:
        - Defined addresses or subnets which are allowed to bypass the OpenStack Anti-spoofing for this one interface. Usually defined as an individual host, a subnet. 0.0.0.0/0 is not permitted (use 0.0.0.0/1 and 128.0.0.1/1 instead)
     required: false
     default: None
   mac_address:
     description:
        - The MAC addres to assign to the port
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
- k5_create_port:
        name: "nx-test-port-1a"
        state: present
        availability_zone: "uk-1a"
        network_name: "nx-test-net-1a"
        subnet_name: "nx-test-subnet-1a"
        fixed_ip:
          - "10.0.0.250"
        security_groups:
          - 'default'
        k5_auth: "{{ k5_auth_reg.k5_auth_facts }}"

- k5_create_port:
        name: "devicename-port-1a"
        state: present
        subnet_name: "subnet-1a"
        network_name: "network-1a"
        security_groups:
          - "any any allow"
        availability_zone: "uk-1a"
        allowed_address_pairs:
          - "0.0.0.0/1"
          - "128.0.0.1/1"
        mac_address: "de:ca:fb:ad:00:11"
        k5_auth: "{{ k5_auth_reg.k5_auth_facts }}"
'''

RETURN = '''
k5_port_facts:
    description: Dictionary describing the port details.
    returned: On success when port is created
    type: dictionary
    contains:
        admin_state_up:
            description:
            type: string
            sample: true
        allowed_address_pairs:
            description:
            type: string
            sample: []
        availability_zone:
            description:
            type: string
            sample: uk-1a
        binding:vnic_type:
            description:
            type: string
            sample: normal
        device_id:
            description:
            type: string
            sample: ""
        device_owner:
            description:
            type: string
            sample: ""
        fixed_ips:
            description:
            type: list of dict
            sample: [
            {
                ip_address:
                    description:
                    type: string
                    sample: 10.0.0.253
                subnet_id:
                    description:
                    type: string
                    sample: 909b6f95-8591-4887-8932-1798c5cd1eec
            }
        ]
        id:
            description:
            type: string
            sample: 024078fb-6d95-4405-a466-c5c6e38d143f
        mac_address:
            description:
            type: string
            sample: fa:16:3e:fd:98:10
        name:
            description:
            type: string
            sample: nx-test-port-1a
        network_id:
            description:
            type: string
            sample: 817d6306-c2b6-44be-b70b-ca6f4b35fd05
        security_groups:
            description:
            type: list
            sample: [f214d25f-1352-42ee-a797-fa6bf163d6d6 ]
        status:
            description:
            type: string
            sample: DOWN
        tenant_id:
            description:
            type: string
            sample: 9505d1dab17946ea97745d5de30cc8be
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

def k5_get_security_group_ids_from_names(module, k5_facts):
    """Get a list of ids from a list of names"""

    endpoint = k5_facts['endpoints']['networking']
    auth_token = k5_facts['auth_token']
    security_groups = module.params['security_groups']

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/v2.0/security-groups'

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


    # check if the security group names provided actually exist
    sgs={}
    sg_ids=[]
    for n in response.json()['security_groups']:
        sgs[n['name']] = n['id']


    for sg in security_groups:
        if sg in sgs.keys():
            sg_ids.append( sgs[sg] )
        else:
            module.fail_json(msg="Security Group " + sg +  " not found")

    k5_debug_add(sg_ids)

    return sg_ids


def k5_get_subnet_id_from_name(module, k5_facts):
    """Get an id from a subnet_name"""

    endpoint = k5_facts['endpoints']['networking']
    auth_token = k5_facts['auth_token']
    subnet_name = module.params['subnet_name']

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
            return n['id']

    return ''


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



def k5_check_port_exists(module, k5_facts):
    """Check if a port_name already exists"""

    endpoint = k5_facts['endpoints']['networking']
    auth_token = k5_facts['auth_token']
    port_name = module.params['name']

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/v2.0/ports'

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

    for n in response.json()['ports']:
        #k5_debug_add("Found port name: " + str(n['name']))
        if str(n['name']) == port_name:
            #k5_debug_add("Found it!")
            return n

    return False

def k5_create_port(module):
    """Create a port in an AZ on K5"""

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

    port_name = module.params['name']
    subnet_name = module.params['subnet_name']
    network_name = module.params['network_name']
    fixed_ip = module.params['fixed_ip']
    security_groups = module.params['security_groups']
    allowed_address_pairs = module.params['allowed_address_pairs']
    mac_address = module.params['mac_address']

    check_port = k5_check_port_exists(module, k5_facts)
    if check_port and 'id' in check_port:
        if k5_debug:
            module.exit_json(changed=False, msg="Port " + port_name + " already exists", k5_port_facts=check_port, debug=k5_debug_out)
        else:
            module.exit_json(changed=False, msg="Port " + port_name + " already exists", k5_port_facts=check_port)

    # we need the network_id not network_name, so grab it
    network_id = k5_get_network_id_from_name(module, k5_facts)
    if network_id == '':
        if k5_debug:
            module.fail_json(changed=False, msg="Network " + network_name + " not found", debug=k5_debug_out)
        else:
            module.fail_json(changed=False, msg="Network " + network_name + " not found")

    # we need the subnet_id not subnet_name, so grab it
    subnet_id = k5_get_subnet_id_from_name(module, k5_facts)
    if subnet_id == '':
        if k5_debug:
            module.fail_json(changed=False, msg="Subnet " + subnet_name + " not found", debug=k5_debug_out)
        else:
            module.fail_json(changed=False, msg="Subnet " + subnet_name + " not found")

    # check the security groups exist
    sec_grp_list = k5_get_security_group_ids_from_names(module, k5_facts)

    az = module.params['availability_zone']

    # actually the project_id, but stated as tenant_id in the API
    #tenant_id = k5_facts['auth_spec']['os_project_id']

    k5_debug_add('auth_token: {0}'.format(auth_token))
    k5_debug_add('port_name: {0}'.format(port_name))
    k5_debug_add('subnet_name: {0} {1}'.format(subnet_name, subnet_id))
    k5_debug_add('network_name: {0} {1}'.format(network_name, network_id))
    k5_debug_add('fixed_ip: {0}'.format(fixed_ip))
    k5_debug_add('security_groups: {0}'.format(security_groups))
    k5_debug_add('az: {0}'.format(az))
    k5_debug_add('allowed_address_pairs: {0}'.format(allowed_address_pairs))

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/v2.0/ports'

    port_config = {
        "network_id": network_id,
        "name": port_name,
        "availability_zone":az,
        "security_groups": sec_grp_list,
    }

    if allowed_address_pairs != '' and allowed_address_pairs != None:
        port_config["allowed_address_pairs"] = allowed_address_pairs

    if mac_address != '' and mac_address != None:
        port_config["mac_address"] = mac_address

    if fixed_ip != None and fixed_ip != '':
        port_config["fixed_ips"] = []
        for ip_address in fixed_ip:
            port_config["fixed_ips"].append({"subnet_id": subnet_id, "ip_address": ip_address})
    else:
        port_config["fixed_ips"] = [{"subnet_id": subnet_id}]

    query_json = {"port":port_config}

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
      module.exit_json(changed=True, msg="Port Creation Successful", k5_port_facts=response.json()['port'], debug=k5_debug_out )

    module.exit_json(changed=True, msg="Port Creation Successful", k5_port_facts=response.json()['port'] )


######################################################################################

def main():

    module = AnsibleModule( argument_spec=dict(
        name = dict(required=True, default=None, type='str'),
        state = dict(required=True, type='str'), # should be a choice
        subnet_name = dict(required=True, default=None, type='str'),
        network_name = dict(required=True, default=None, type='str'),
        fixed_ip = dict(required=False, default=None, type='list'),
        security_groups = dict(required=True, default=None, type='list'),
        availability_zone = dict(required=True, default=None, type='str'),
        allowed_address_pairs = dict(required=False, default=None, type='list'),
        mac_address = dict(required=False, default=None, type='str'),
        k5_auth = dict(required=True, default=None, type='dict')
    ) )

    if module.params['state'] == 'present':
        k5_create_port(module)
    else:
       module.fail_json(msg="No 'absent' function in this module, use os_port module instead")


######################################################################################

if __name__ == '__main__':
    main()



