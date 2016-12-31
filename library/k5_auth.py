#!/usr/bin/python

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = '''
---
module: k5_auth
short_description: Retrieve an authentication token from K5
version_added: "1.0"
description:
    - Login and Retrieve an authentication token from K5, plus the endpoints
options:
   username:
     description:
        - Login username.
     required: false
     default: None
   password:
     description:
        - Password of user.
     required: false
     default: None
   user_domain:
     description:
        - Domain the user belongs to.
     required: false
     default: None
   project_id:
     description:
       - Project id.
     required: false
     default: None
   region_name:
     description:
       - Region the user belongs to.
     required: false
     default: None     
requirements:
    - "python >= 2.6"
'''

EXAMPLES = '''
# Get auth token using module paramters
- k5_auth:
     username: admin
     password: secret
     user_domain: demo
     project_id: 9500d1d6b17936ea97745d5de30cc112
     region_name: uk-1
# Get auth token using Openstack OS_* environment variables
- k5_auth:
'''

RETURN = '''
k5_auth_facts:
    description: Dictionary describing the authentication details.
    returned: On success when token is returned
    type: dictionary
    contains:
        K5-DEBUG:
            description: Is K5_DEBUG environment variable set.
            type: boolean
            sample: True
        auth_token:
            description: The K5 authentication token.
            type: string
            sample: "010101928282726528495fe"
        endpoints:
            description: The endpoints applicable to this authentication token.
            type: dictionary
            contains:
                endpoint-name:
                    description: The url to the endpoint
                    type: string
                    sample: "https://compute.uk-1.cloud.global.fujitsu.com/v2/9500d1d6b17936ea97745d5de30cc112"
        expiry:
            description: Expiry date of the token.
            type: string
            sample: "2017-01-01T01:44:28.081619Z"
        issed:
            description: Issue date of the token.
            type: string
            sample: "2016-12-31T22:44:28.081655Z"
'''


import requests
import os
import json
from ansible.module_utils.basic import *

k5_auth_spec = dict(
    os_username=None, 
    os_password=None, 
    os_region_name=None, 
    os_project_name=None, 
    os_project_id=None, 
    os_user_domain=None, 
    k5_token=None
)

k5_endpoints = dict(
    global_contract='https://contract.gls.cloud.global.fujitsu.com', 
    global_identity='https://identity.gls.cloud.global.fujitsu.com', 
    global_billing='https://billing.gls.cloud.global.fujitsu.com', 
    global_dns='https://dns.gls.cloud.global.fujitsu.com', 
    global_catalog='https://catalog.gls.cloud.global.fujitsu.com', 

    identity='https://identity.REGION_ID.cloud.global.fujitsu.com', 

#   these are returned by the auth token request
#    keymanagement='https://keymanagement.REGION_ID.cloud.global.fujitsu.com', 
#    software='https://software.REGION_ID.cloud.global.fujitsu.com', 
#    compute='https://compute.REGION_ID.cloud.global.fujitsu.com', 
#    image='https://image.REGION_ID.cloud.global.fujitsu.com', 
#    vmimport='https://vmimport.REGION_ID.cloud.global.fujitsu.com', 
#    computew='https://compute-w.REGION_ID.cloud.global.fujitsu.com', 
#    autoscale='https://autoscale.REGION_ID.cloud.global.fujitsu.com', 
#    blockstorage='https://blockstorage.REGION_ID.cloud.global.fujitsu.com', 
#    objectstorage='https://objectstorage.REGION_ID.cloud.global.fujitsu.com', 
#    networking='https://networking.REGION_ID.cloud.global.fujitsu.com', 
#    networkingex='https://networking-ex.REGION_ID.cloud.global.fujitsu.com', 
#    loadbalancing='https://loadbalancing.REGION_ID.cloud.global.fujitsu.com', 
#    database='https://database.REGION_ID.cloud.global.fujitsu.com', 
#    mail='https://mail.REGION_ID.cloud.global.fujitsu.com', 
#    orchestration='https://orchestration.REGION_ID.cloud.global.fujitsu.com', 
#    telemetry='https://telemetry.REGION_ID.cloud.global.fujitsu.com'

)

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


############## auth functions #############
def k5_build_endpoints():
    """Update Endpoint dict with region"""
    for key, value in k5_endpoints.iteritems():
        if 'REGION_ID' in value:
            k5_endpoints[key] = value.replace('REGION_ID', k5_auth_spec['os_region_name'])
            #k5_debug_add('k5 endpoint: {0}'.format(k5_endpoints[key]))


def k5_get_endpoints(e):
    """Pull endpoints from json response"""

#token
#    project
#    catalog
#       endpoints
#           0
#               name, url
#    extras
#    methods
#    roles
#    issued_at
#    expires_at
#    user

    for i in e['token']['catalog']:
        if i['endpoints']:
            j = i['endpoints'][0]
            k5_endpoints[ j['name'] ] = j['url']


def k5_get_auth_spec(module):
    """Get the K5 authentication details from the shell environment or module params"""

    global k5_debug

    if 'K5_DEBUG' in os.environ:
        k5_debug = True

    OS_USERNAME = os.environ.get('OS_USERNAME', None)
    OS_PASSWORD = os.environ.get('OS_PASSWORD', None)
    OS_REGION_NAME = os.environ.get('OS_REGION_NAME', None)
    OS_PROJECT_ID = os.environ.get('OS_PROJECT_ID', None)
    OS_USER_DOMAIN_NAME = os.environ.get('OS_USER_DOMAIN_NAME', None)

    # now overwrite the vars if provided within the playbook module

    mp = module.params

    if 'username' in mp and mp['username']:
        k5_auth_spec['os_username'] = mp['username']
    elif OS_USERNAME is None:
        module.fail_json(msg='param username or OS_USERNAME environment variable is missing', k5_auth_facts=k5_debug)
    else:
        k5_auth_spec['os_username'] = OS_USERNAME

    if 'password' in mp and mp['password']:
        k5_auth_spec['os_password'] = mp['password']
    elif OS_PASSWORD is None:
        module.fail_json(msg='param password or OS_PASSWORD environment variable is missing', k5_auth_facts=k5_debug)
    else:
        k5_auth_spec['os_password'] = OS_PASSWORD

    if 'region_name' in mp and mp['region_name']:
        k5_auth_spec['os_region_name'] = mp['region_name']
    elif OS_REGION_NAME is None:
        module.fail_json(msg='param region_name or OS_REGION_NAME environment variable is missing', k5_auth_facts=k5_debug)
    else:
        k5_auth_spec['os_region_name'] = OS_REGION_NAME

    if 'project_id' in mp and mp['project_id']:
        k5_auth_spec['os_project_id'] = mp['project_id']
    elif OS_PROJECT_ID is None:
        module.fail_json(msg= 'param project_id or OS_PROJECT_ID environment variable is missing', k5_auth_facts=k5_debug)
    else:
        k5_auth_spec['os_project_id'] = OS_PROJECT_ID

    if 'user_domain' in mp and mp['user_domain']:
        k5_auth_spec['os_user_domain'] = mp['user_domain']
    elif OS_USER_DOMAIN_NAME is None:
        module.fail_json(msg= 'param user_domain or OS_USER_DOMAIN_NAME environment variable is missing', k5_auth_facts=k5_debug)
    else:
        k5_auth_spec['os_user_domain'] = OS_USER_DOMAIN_NAME
    
    k5_debug_add('os_username: {0}'.format(k5_auth_spec['os_username']))
#    k5_debug_add('os_password: {0}'.format(k5_auth_spec['os_password']))
    k5_debug_add('os_region_name: {0}'.format(k5_auth_spec['os_region_name']))
    k5_debug_add('os_project_id: {0}'.format(k5_auth_spec['os_project_id']))
    k5_debug_add('os_user_domain: {0}'.format(k5_auth_spec['os_user_domain']))

    k5_build_endpoints()

def k5_get_auth_token(module):
    """Request an authentication token from K5 - you are going to want to do this before calling any module"""

    k5_debug_clear()

    k5_get_auth_spec(module)

    session = requests.Session()
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    url = k5_endpoints['identity'] + '/v3/auth/tokens'
    k5_debug_add('endpoint: {0}'.format(url))

    query_json = {'auth': {'identity': {'methods': ['password'],
                           'password': {'user': {'domain': {'name': k5_auth_spec['os_user_domain']},
                                                 'name': k5_auth_spec['os_username'],
                                                 'password': k5_auth_spec['os_password']}}},
              'scope': {'project': {'id': k5_auth_spec['os_project_id']}}}}


    #k5_debug_add('json: {0}'.format(query_json))
    k5_debug_add('REQ: {0}'.format(url))

    try:
        response = session.request('POST', url, headers=headers, json=query_json)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e)

    # we failed to authenticate
    if response.status_code not in (201,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    # we authenticated, now check the token is present
    if 'X-Subject-Token' in response.headers.keys():
        auth_token = response.headers['X-Subject-Token']
    else:
        module.fail_json(msg="Token not found", k5_auth_facts=k5_debug)

    #
    # If we get here we the server responded with our token
    #
    k5_get_endpoints(response.json())

    # our json to return as succesful
    k5_auth = {
        "auth_token": auth_token,
        "endpoints": k5_endpoints,
        "issued": response.json()['token']['issued_at'], 
        "expiry": response.json()['token']['expires_at'],
        "K5_DEBUG": k5_debug
    }

    if k5_debug:
        k5_auth['server_response']=response.json()

    module.exit_json(changed=True, msg="Authentication Successful", k5_auth_facts=k5_auth)

######################################################################################

def main():

    module = AnsibleModule( argument_spec=dict(
        username = dict(required=False, default=None, type='str'),
        password = dict(required=False, default=None, type='str'),
        user_domain = dict(required=False, default=None, type='str'), 
        project_id = dict(required=False, default=None, type='str'),
        region_name = dict(required=False, default=None, type='str') 
    ) )

    k5_get_auth_token(module)

######################################################################################

if __name__ == '__main__':  
    main()



