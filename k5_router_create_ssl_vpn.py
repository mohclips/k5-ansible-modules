#!/usr/bin/python

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = '''
---
module: k5_router_create_ssl_vpn
short_description: Create an OpenVPN Server
version_added: "1.0"
description:
    - Create an OpenVPN Server
options:
   name:
     description:
        - Name of the VPN
     required: true
     default: None
   router_name:
     description:
        - Name of the router to attach the SSL VPN to
     required: true
     default: None
   subnet_name:
     description:
        - Name of the subnet that the VON connects to inside K5
     required: true
     default: None
   client_cidr:
     description:
        - IP subnet of the remote clients. A NAT subnet inside K5. (not the clients actual subnet)
     required: true
     default: None
   availablity_zone:
     description:
        - Name of the availability zone
     required: true
     default: None
   ca:
     description:
        - CA key in pem format
     required: true
     default: None
   server_certificate:
     description:
        - server cert in pem format
     required: true
     default: None
   server_key:
     description:
        - server key in pem format
     required: true
     default: None
   dh:
     description:
        - dh in pem format
     required: true
     default: None

requirements:
    - "python >= 2.6"
'''

#TODO
EXAMPLES = '''
'''

#TODO
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


############## functions #############

def k5_get_endpoint(e,name):
    """Pull particular endpoint name from dict"""

    return e['endpoints'][name]

def k5_upload_payload(module, payload, payload_name):
    """Upload payload vpn secrets"""
    
    k5_debug_add("def: " + sys._getframe().f_code.co_name)

    k5_facts = module.params['k5_auth']

    endpoint = k5_facts['endpoints']['keymanagement']
    auth_token = k5_facts['auth_token']
    vpn_name = module.params['name']

    k5_debug_add('auth_token: {0}'.format(auth_token))

    session = requests.Session()

    project_id = k5_facts['auth_spec']['os_project_id']

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }
    
    url = endpoint + "/" + project_id + '/secrets'

    query_json =  {
        "name": vpn_name + "_" + payload_name,
        #"name": payload_name,
        "payload": payload,
        "payload_content_type": "text/plain"
    }

    k5_debug_add('endpoint: {0}'.format(endpoint))
    k5_debug_add('REQ: {0}'.format(url))
    k5_debug_add('headers: {0}'.format(headers))
#    k5_debug_add('json: {0}'.format(query_json))

    try:
        response = session.request('POST', url, headers=headers, json=query_json)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e)

    # we failed to make a change
    if response.status_code not in (201,):
        module.fail_json(msg="k5_upload_payload " + payload_name + " RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    return response.json()['secret_ref']


def k5_create_credentials_container(module, ca_ref, server_certificate_ref, server_key, dh_ref):
    """create the container"""
    
    k5_debug_add("def: " + sys._getframe().f_code.co_name)

    k5_facts = module.params['k5_auth']

    endpoint = k5_facts['endpoints']['keymanagement']
    auth_token = k5_facts['auth_token']
    vpn_name = module.params['name']

    k5_debug_add('secret_refs:'+ str( [  ca_ref, server_certificate_ref, server_key, dh_ref ]))

    session = requests.Session()

    project_id = k5_facts['auth_spec']['os_project_id']

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }
    
    url = endpoint + '/' + project_id + '/containers'

    #Provided object does not match schema 'Container': only 'private_key', 'certificate', or 'intermediates' reference names are allowed for Certificate type

    query_json =  {
        "name": vpn_name + "_container",
        "type":"generic",   # TODO why this?  and not certificate
        "secret_refs":[
            {
                "name": "ca",
                "secret_ref": ca_ref
            },
            {
                "name": "server_certificate",
                "secret_ref": server_certificate_ref
            },
            {
                "name": "server_key",
                "secret_ref": server_key
            },
            {
                "name": "dh",
                "secret_ref": dh_ref
            }
          ]
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
        module.fail_json(msg="k5_create_credentials_container RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    return response.json()['container_ref']

def k5_get_subnet_id_from_name(module, k5_facts):
    """Get an id from a subnet_name"""

    k5_debug_add("def: " + sys._getframe().f_code.co_name)

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
        module.fail_json(msg="k5_get_subnet_id_from_name RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    #k5_debug_add("RESP: " + str(response.json()))

    for n in response.json()['subnets']:
        #k5_debug_add("Found subnet name: " + str(n['name']))
        if str(n['name']) == subnet_name:
            #k5_debug_add("Found it!")
            return n['id']

    return ''

def k5_get_router_id_from_name(module, k5_facts):
    """Get an id from a router_name"""

    k5_debug_add("def: " + sys._getframe().f_code.co_name)

    endpoint = k5_facts['endpoints']['networking']
    auth_token = k5_facts['auth_token']

    router_name = module.params['router_name']

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/v2.0/routers'

    k5_debug_add('endpoint: {0}'.format(endpoint))
    k5_debug_add('REQ: {0}'.format(url))
    k5_debug_add('headers: {0}'.format(headers))

    try:
        response = session.request('GET', url, headers=headers)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e)

    # we failed to get data
    if response.status_code not in (200,):
        module.fail_json(msg="k5_get_router_id_from_name RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    #k5_debug_add("RESP: " + str(response.json()))

    for n in response.json()['routers']:
        #k5_debug_add("Found router name: " + str(n['name']))
        if str(n['name']) == router_name:
            #k5_debug_add("Found it!")
            return n['id']

    return ''


def k5_router_attach_ssl_vpn_service(module):
    """create the service"""
    
    k5_debug_add("def: " + sys._getframe().f_code.co_name)

    k5_facts = module.params['k5_auth']

    endpoint = k5_facts['endpoints']['networking']
    auth_token = k5_facts['auth_token']
    vpn_name = module.params['name']
    az = module.params['availability_zone']

    session = requests.Session()

    subnet_id = k5_get_subnet_id_from_name(module,k5_facts) 
    router_id = k5_get_router_id_from_name(module,k5_facts)

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }
    
    url = endpoint + '/v2.0/vpn/vpnservices'

    query_json =  {
        "vpnservice": {
            "subnet_id": subnet_id,
            "router_id": router_id,
            "name": vpn_name,
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
        module.fail_json(msg="k5_router_attach_ssl_vpn_service RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    return response.json()['vpnservice']['id']

def k5_create_ssl_vpn_connection(module, container_id, vpn_id):
    """create the connection"""
    
    k5_debug_add("def: " + sys._getframe().f_code.co_name)

    k5_facts = module.params['k5_auth']

    endpoint = k5_facts['endpoints']['networking']
    auth_token = k5_facts['auth_token']
    vpn_name = module.params['name']
    az = module.params['availability_zone']

    client_cidr = module.params['client_cidr']

    session = requests.Session()

    project_id = k5_facts['auth_spec']['os_project_id']

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }
    
    url = endpoint + '/v2.0/vpn/ssl-vpn-connections'

    query_json =  {
        "ssl_vpn_connection": {
            "name": vpn_name,
            "client_address_pool_cidr": client_cidr,
            "credential_id": container_id,
            "vpnservice_id": vpn_id,
            "availability_zone": az,
            "protocol": "tcp"
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
        module.fail_json(msg="k5_create_ssl_vpn_connection RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)


    # all okay
    if k5_debug:
        module.exit_json(msg="k5_create_ssl_vpn_connection successful", k5_ssl_vpn=response.json(),  debug=k5_debug_out)
    else:
        module.exit_json(msg="k5_create_ssl_vpn_connection successful", k5_ssl_vpn=response.json() )
    


def k5_router_create_ssl_vpn(module):
    """Create ssl vpn on a router"""
    
    global k5_debug

    k5_debug_clear()

    k5_debug_add("def: " + sys._getframe().f_code.co_name)

    if 'K5_DEBUG' in os.environ:
        k5_debug = True

    if 'auth_spec' in module.params['k5_auth']: 
        k5_facts = module.params['k5_auth']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")        

    endpoint = k5_facts['endpoints']['networking']
    auth_token = k5_facts['auth_token']

    vpn_name = module.params['name']
    ca = module.params['ca']
    server_certificate = module.params['server_certificate']
    server_key = module.params['server_key']
    dh = module.params['dh']

    k5_debug_add('auth_token: {0}'.format(auth_token))
    k5_debug_add('vpn_name: {0}'.format(vpn_name))

    #
    # upload the payloads
    #
    ca_ref = k5_upload_payload(module, ca, "ca")
    server_certificate_ref = k5_upload_payload(module, server_certificate, "server_certificate")
    server_key = k5_upload_payload(module, server_key, "server_key")
    dh_ref = k5_upload_payload(module, dh, "dh")

    #
    # create the credentials container
    #
    container_ref = k5_create_credentials_container(module, ca_ref, server_certificate_ref, server_key, dh_ref)
    container_id = container_ref.split('/')[-1]

    #
    # create vpn service on the router
    #
    vpn_id = k5_router_attach_ssl_vpn_service(module)
#    vpn_id = vpn_ref.split('/')[-1]

    #
    # create ssl vpn connection
    #
    k5_create_ssl_vpn_connection(module, container_id, vpn_id) 
    


######################################################################################

def main():

    module = AnsibleModule( argument_spec=dict(
        name = dict(required=True, default=None, type='str'),
        router_name = dict(required=True, default=None, type='str'),
        subnet_name = dict(required=True, default=None, type='str'),
        client_cidr = dict(required=True, default=None, type='str'),
        availability_zone = dict(required=True, default=None, type='str'),
        ca = dict(required=True, default=None, type='str'),
        server_certificate = dict(required=True, default=None, type='str'),
        server_key = dict(required=True, default=None, type='str'),
        dh = dict(required=True, default=None, type='str'),
        k5_auth = dict(required=True, default=None, type='dict')
    ) )

    # TODO more checks on the data here - are the certs provided
    if k5_get_router_id_from_name(module,module.params['k5_auth']) is '':
        module.fail_json(msg="Router does not exist")
        

    k5_router_create_ssl_vpn(module)


######################################################################################

if __name__ == '__main__':  
    main()



