#!/usr/bin/python
import requests
import os

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

k5_debug = False

k5_debug_out = []

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

def k5_get_auth_spec():
    """Get the K5 authentication details from the shell environment"""

    OS_USERNAME = os.environ.get('OS_USERNAME', None)
    OS_PASSWORD = os.environ.get('OS_PASSWORD', None)
    OS_REGION_NAME = os.environ.get('OS_REGION_NAME', None)
    OS_PROJECT_ID = os.environ.get('OS_PROJECT_ID', None)
    OS_USER_DOMAIN_NAME = os.environ.get('OS_USER_DOMAIN_NAME', None)

    DEBUG = os.environ.get('K5_DEBUG', 0) 
    if DEBUG != 0:
        k5_debug = True

    if OS_USERNAME is None:
        return (False, 'OS_USERNAME environment variable is missing', '')
    else:
        k5_auth_spec['os_username'] = OS_USERNAME

    if OS_PASSWORD is None:
        return (False, 'OS_PASSWORD environment variable is missing', '')
    else:
        k5_auth_spec['os_password'] = OS_PASSWORD

    if OS_REGION_NAME is None:
        return (False, 'OS_REGION_NAME environment variable is missing', '')
    else:
        k5_auth_spec['os_region_name'] = OS_REGION_NAME

    if OS_PROJECT_ID is None:
        return (False, 'OS_PROJECT_ID environment variable is missing', '')
    else:
        k5_auth_spec['os_project_id'] = OS_PROJECT_ID

    if OS_USER_DOMAIN_NAME is None:
        return (False, 'OS_USER_DOMAIN_NAME environment variable is missing', '')
    else:
        k5_auth_spec['os_user_domain'] = OS_USER_DOMAIN_NAME

    k5_build_endpoints()

def k5_get_auth_token():
    """Request an authentication token from K5 - you are going to want to do this before calling any module"""

    k5_debug_clear()

    k5_get_auth_spec()

    session = requests.Session()
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

    url = k5_endpoints['identity'] + '/v3/auth/tokens'
    k5_debug_add('endpoint: {0}'.format(url))

    json = {'auth': {'identity': {'methods': ['password'],
                           'password': {'user': {'domain': {'name': k5_auth_spec['os_user_domain']},
                                                 'name': k5_auth_spec['os_username'],
                                                 'password': k5_auth_spec['os_password']}}},
              'scope': {'project': {'id': k5_auth_spec['os_project_id']}}}}


    #k5_debug_add('json: {0}'.format(json))
    k5_debug_add('REQ: {0}'.format(url))

    try:
        response = session.request('POST', url, headers=headers, json=json)
    except requests.exceptions.RequestException as e:
        return (False, e, k5_debug_get())

    if response.status_code not in (201,):
        return (False, "RESP: " + response.status_code + " " + response.content, k5_debug_get())

    if 'X-Subject-Token' in response.headers.keys():
        auth_token = response.headers['X-Subject-Token']
    else:
        return (False, "Token not found!", k5_debug_get())

    #
    # If we get here we the server responded with our token
    #
    k5_get_endpoints(response.json())

    if k5_debug:
        response_json = response.json()
    else:
        response_json = ''

    k5_auth = {
        "auth_token": auth_token,
        "endpoints": k5_endpoints,
        "server_response": response_json
    }

    return (True, k5_auth, k5_debug_get())


