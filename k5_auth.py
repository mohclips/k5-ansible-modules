#!/usr/bin/python

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = '''
---
module: k5_auth
short_description: Create and retrieve an authentication token from K5
version_added: "1.0"
description:
    - Login and Retrieve an authentication token from K5, plus the endpoints
options:
   username:
     description:
        - Login username. LEGACY will be removed in future versions.
     required: false
     default: None
   password:
     description:
        - Password of user. LEGACY will be removed in future versions.
     required: false
     default: None
   token_type:
     description:
        - Regional or Global token type creation.
     required: false
     default: Regional
   scoped:
     description:
        - Set scope of token
     required: false
     default: True
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
# Requires access to OS_* environment variables or os_client_config cloud.yaml
 
- name: "Regional default scoped"
  k5_auth:
    token_type: regional
  register: regional_auth


- name: "Regional un-scoped"
  k5_auth:
    token_type: regional
    scoped: False
  register: regional_auth


- name: "Regional set as scoped"
  k5_auth:
    token_type: regional
    scoped: True
  register: regional_auth


- name: "Global un-scoped"
  k5_auth:
    token_type: global
    scoped: False
  register: global_auth


- name: "Global set scoped - and override some external vars"
  k5_auth:
    token_type: global
    scoped: True
    user_domain: "YssmW1yI"
    project_id: eadb882573ac40b1b101eac93009a313 # default project id for YssmW1yI-prj
  register: global_auth


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
        k5_auth_spec:
            description: Authentication details used
            type: dictionary
            contains:
                os_username:
                    description: Username.
                    type: string
                    sample: "crossnicholas"
                os_region_name: 
                    description: Region name.
                    type: string
                    sample: "uk-1"
                os_project_id: 
                    description: project id, sometimes called tenant id.
                    type: string
                    sample: "9500d1d6b17936ea97745d5de30cc112"
                os_user_domain: 
                    description: user domain, actually the contract id on K5
                    type: string
                    sample: "Ylahen"
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
import os_client_config

import sys
import keystoneauth1.exceptions

import re

#useful items to use later in other modules
k5_auth_spec = dict(
    os_username=None,
    os_password=None,
    os_region_name=None,
    os_project_id=None,
    os_project_name=None,
    os_user_domain=None
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

    OS_REGION_NAME = None
    OS_USERNAME = None
    OS_PASSWORD = None
    OS_PROJECT_NAME = None
    OS_PROJECT_ID = None
    OS_USER_DOMAIN_NAME = None

    if 'K5_DEBUG' in os.environ:
        k5_debug = True

    mp = module.params

    cloud_configured = False
   
    # not so nice fix for #24
    # not happy about this, but os_client_config.OpenStackConfig().get_all_clouds() seems to 
    # wipe the OS_ envvars if OS_AUTH_TOKEN is set
    # TBH why set OS_AUTH_TOKEN if you are using these modules
    if 'OS_AUTH_TOKEN' in os.environ:
        module.warn('OS_AUTH_TOKEN is set, this breaks this module and has been unset')
        del os.environ['OS_AUTH_TOKEN']
 
    if 'cloud' in mp and mp['cloud'] and 'region_name' in mp and mp['region_name']:
        cloud_config = os_client_config.OpenStackConfig().get_one_cloud(mp['cloud'], region_name=mp['region_name'])
        cloud_configured = True
    elif 'cloud' in mp and mp['cloud']:
        cloud_config = os_client_config.OpenStackConfig().get_one_cloud(mp['cloud'])
        cloud_configured = True
    else:
        all_cloud_config = {}
        try:
            # this fails if OS_AUTH_TOKEN is set #24 = but does not raise
            all_cloud_config = os_client_config.OpenStackConfig().get_all_clouds()
        except keystoneauth1.exceptions.auth_plugins.MissingRequiredOptions as e:
            # no envvars AND no cloud.yaml found!
            # keystoneauth1.exceptions.auth_plugins.MissingRequiredOptions: Auth plugin requires parameters which were not given: auth_url
            warn_msg="Old style LEGACY auth found, consider using openstack OS_ ENVVARS or cloud.yaml in the future. " + str(e)
            k5_debug_add(warn_msg)
            k5_debug_add(str(e))
            module.warn(warn_msg)
            # no fail here, just pass though for now!
        except:
            print "Unexpected error: {0}".format( sys.exc_info()[0] )

        #------------------------------------------------------------

        cloud_names = ""
        cloud_counter = 0
        for cloud in all_cloud_config:
            if cloud.name == "envvars":
                cloud_config = os_client_config.OpenStackConfig().get_one_cloud('envvars')
                cloud_configured = True

            cloud_counter = cloud_counter + 1

            if cloud_names != "":
                cloud_names = cloud_names + ", "

            cloud_names = cloud_names + "'cloud=" + cloud.name + " region=" + cloud.region +"'"

        if cloud_configured == False:
            if k5_debug:
                module.fail_json(msg='Found a clouds.yaml file. Please select a cloud/region pair from ' + cloud_names, k5_debug=k5_debug_out)
            else:
                module.fail_json(msg='Found a clouds.yaml file. Please select a cloud/region pair from ' + cloud_names)


    # ----------------------------------
    if cloud_configured == True:
        k5_debug_add(cloud_config.config)

        # finish here! Debug begins!
        OS_REGION_NAME = cloud_config.region
        if 'username' in cloud_config.auth and cloud_config.auth['username']:
            OS_USERNAME = cloud_config.auth['username']
        if 'password' in cloud_config.auth and cloud_config.auth['password']:
            OS_PASSWORD = cloud_config.auth['password']
        if 'project_name' in cloud_config.auth and cloud_config.auth['project_name']:
            OS_PROJECT_NAME = cloud_config.auth['project_name']
        if 'project_id' in cloud_config.auth and cloud_config.auth['project_id']:
            OS_PROJECT_ID = cloud_config.auth['project_id']
        if 'domain_name' in cloud_config.auth and cloud_config.auth['domain_name']:
            OS_USER_DOMAIN_NAME = cloud_config.auth['domain_name']
        if 'user_domain_name' in cloud_config.auth and cloud_config.auth['user_domain_name']:
            OS_USER_DOMAIN_NAME = cloud_config.auth['user_domain_name']

    # now overwrite the vars if provided within the playbook module

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
    elif OS_REGION_NAME == "" and 'auth_url' in cloud_config.auth and cloud_config.auth['auth_url']:
        match = re.search('https://identity\.([^\.]*)\.cloud.global.fujitsu.com', cloud_config.auth['auth_url'])
        k5_auth_spec['os_region_name'] = match.group(1)
    elif OS_REGION_NAME == "":
        module.fail_json(msg='param region_name or OS_REGION_NAME environment variable is missing', k5_auth_facts=k5_debug)
    else:
        k5_auth_spec['os_region_name'] = OS_REGION_NAME

    if 'user_domain' in mp and mp['user_domain']:
        k5_auth_spec['os_user_domain'] = mp['user_domain']
    elif OS_USER_DOMAIN_NAME is None:
        module.fail_json(msg= 'param user_domain or OS_USER_DOMAIN_NAME environment variable is missing', k5_auth_facts=k5_debug)
    else:
        k5_auth_spec['os_user_domain'] = OS_USER_DOMAIN_NAME

    # Note that these two fields won't error here, but do below after the scope is build
    if 'project_name' in mp and mp['project_name']:
        k5_auth_spec['os_project_name'] = mp['project_name']
    elif OS_PROJECT_NAME is not None:
        k5_auth_spec['os_project_name'] = OS_PROJECT_NAME

    if 'project_id' in mp and mp['project_id']:
        k5_auth_spec['os_project_id'] = mp['project_id']
    elif OS_PROJECT_ID is not None:
        k5_auth_spec['os_project_id'] = OS_PROJECT_ID
    
    k5_debug_add('os_username: {0}'.format(k5_auth_spec['os_username']))
#    k5_debug_add('os_password: {0}'.format(k5_auth_spec['os_password']))
    k5_debug_add('os_region_name: {0}'.format(k5_auth_spec['os_region_name']))
    k5_debug_add('os_project_name: {0}'.format(k5_auth_spec['os_project_name']))
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

    # note 'scope' is missing
    if 'os_project_id' in k5_auth_spec and k5_auth_spec['os_project_id'] is not None:
        query_json = {'auth': {
                                'identity': {
                                    'methods': ['password'],
                                    'password': {
                                        'user': {
                                            'domain': {
                                                'name': k5_auth_spec['os_user_domain']
                                            },
                                            'name': k5_auth_spec['os_username'],
                                            'password': k5_auth_spec['os_password']
                                        }
                                    }
                                },
                                "scope": {
                                    "project": {
                                        "id": k5_auth_spec['os_project_id']
                                    }
                                }
                           }
                        }
    elif 'os_project_name' in k5_auth_spec and k5_auth_spec['os_project_name'] is not None:
        query_json = {'auth': {
                                'identity': {
                                    'methods': ['password'],
                                    'password': {
                                        'user': {
                                            'domain': {
                                                'name': k5_auth_spec['os_user_domain']
                                            },
                                            'name': k5_auth_spec['os_username'],
                                            'password': k5_auth_spec['os_password']
                                        }
                                    }
                                },
                                "scope": {
                                    "project": {
                                        "name": k5_auth_spec['os_project_name'],
                                        "domain": {
                                            'name': k5_auth_spec['os_user_domain']
                                        }
                                    }
                                }
                           }
                        }
    else:
        module.fail_json(msg= 'param project_id, project_name or one of environment variables OS_PROJECT_ID or OS_PROJECT_NAME is missing', k5_auth_facts=k5_debug)

    if module.params['token_type'].lower() == 'global':
        # K5 global token required - change URL
        url = 'https://identity.gls.cloud.global.fujitsu.com/v3/auth/tokens'
#    else:
#        # scope regional token to a project
#        query_json['auth']['scope'] = { 'project': { 'id': k5_auth_spec['os_project_id'] } }

    if module.params['scoped'] == False:
        k5_debug_add('removing token scope')
        if 'scope' in query_json['auth']:
            del query_json['auth']['scope']

    k5_debug_add('endpoint: {0}'.format(url))
    k5_debug_add('query_json:')
    k5_debug_add(query_json)
    k5_debug_add('REQ: {0}'.format(url))

    try:
        response = session.request('POST', url, headers=headers, json=query_json)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e)

    # we failed to authenticate
    if response.status_code not in (201,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), k5_debug=k5_debug_out)

    # we authenticated, now check the token is present
    if 'X-Subject-Token' in response.headers.keys():
        auth_token = response.headers['X-Subject-Token']
    elif 'x-subject-token' in response.headers.keys():      # fix for issue #1
        auth_token = response.headers['x-subject-token']
    else:
        module.fail_json(msg="Token not found", k5_auth_facts=k5_debug)

    #
    # If we get here we the server responded with our token
    #
    k5_get_endpoints(response.json())

    # clear os_password from spec before we send it back to the user
    k5_auth_spec['os_password'] = 'xxxxxxxxxxxxxxxxx'

    resp = response.json()['token']

    # our json to return as succesful
    k5_auth = {
        "auth_token": auth_token,
        "token_type": module.params['token_type'].lower(),
        "auth_spec": k5_auth_spec,
        "endpoints": k5_endpoints,
        "issued": resp['issued_at'],
        "expiry": resp['expires_at'],
        "roles": resp['roles'],
        "user": resp['user'],
        "catalog": resp['catalog'],
        "scoped": module.params['scoped'],
        "K5_DEBUG": k5_debug
    }

#    if k5_debug:
#        k5_auth['server_response']=response.json()

    module.exit_json(changed=True, msg="Authentication Successful", k5_auth_facts=k5_auth, k5_debug=k5_debug_out)

######################################################################################

def main():

    module = AnsibleModule( argument_spec=dict(
        username = dict(required=False, default=None, type='str'),
        password = dict(required=False, default=None, type='str', no_log=True),
        user_domain = dict(required=False, default=None, type='str'),
        project_id = dict(required=False, default=None, type='str'),
        project_name = dict(required=False, default=None, type='str'),
        region_name = dict(required=False, default=None, type='str'),
        token_type = dict(default='regional', choices=['regional', 'global']),
        cloud = dict(required=False, default=None, type='str'),
        scoped = dict(required=False, default=True, type='bool')
    ) )

    k5_get_auth_token(module)

######################################################################################

if __name__ == '__main__':
    main()



