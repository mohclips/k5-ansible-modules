#!/usr/bin/python

import datetime

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = '''
---
module: k5_group
short_description: create / delete groups
version_added: "1.0"
description:
    - returns groups
options:
   group_name:
     description:
        - Name group to create / delete
     required: true
     default: None
   status:
     description:
        - present / absent
     required: true
     default: None
requirements:
    - "python >= 2.6"
'''

EXAMPLES = '''
- k5_group:
    group_name: zzCrossNgrp
    status: present
    k5_auth: "{{ k5_auth_facts }}"
'''

RETURN = '''
k5_group:
    description: group details.
    returned: On success when the group is created
    type: dict
    sample:
#TODO
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
    global k5_debug_out
    if k5_debug:
        k5_debug_out.append(s)


############## k5 functions #############

def k5_get_endpoint(e,name):
    """Pull particular endpoint name from dict"""

    return e['endpoints'][name]


def k5_get_keystoneobject_list(module, k5_facts, objecttype):
    """Get list of objects"""
# Great find by Graham Land :)

    global k5_debug

    k5_debug_add('token_type: {0}'.format(k5_facts['token_type']))

    if k5_facts['token_type'] == 'global':
        endpoint = k5_facts['endpoints']['global-identity']
    elif k5_facts['token_type'] == 'regional':
        endpoint = k5_facts['endpoints']['identityv3']
    else:
        endpoint = k5_facts['endpoints']['identity']


    auth_token = k5_facts['auth_token']

    contract_id = k5_facts['user']['domain']['id']

    k5_debug_add('auth_token: {0}'.format(auth_token))
    k5_debug_add('objecttype: {0}'.format(objecttype))

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/' + objecttype + '?domain_id=' + contract_id 

    k5_debug_add('REQ: {0}'.format(url))

    try:
        response = session.request('GET', url, headers=headers)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e, debug=k5_debug_out)

    if response.status_code not in (200,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    return response.json()


def k5_list_users(module):
    """Get users list"""
    
    global k5_debug

    if 'auth_spec' in module.params['k5_auth_global']: 
        k5_facts = module.params['k5_auth_global']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")        

    endpoint = k5_facts['endpoints']['global-identity']
    auth_token = k5_facts['auth_token']

    group_name = module.params['group_name']

    groups_list = k5_list_groups(module) # get projects available to the user the token was created by

    matched_groups = [x for x in groups_list if x['name'] == group_name]

    if len(matched_groups) == 0:
        module.exit_json(changed=False, msg="Group does not exist")

    group_id = matched_groups[0]['id']

    k5_debug_add('auth_token: {0}'.format(auth_token))
    k5_debug_add('group_id: {0}'.format(group_id))

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/groups/' + group_id + '/users'

    k5_debug_add('REQ: {0}'.format(url))

    try:
        response = session.request('GET', url, headers=headers)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e, debug=k5_debug_out)

    if response.status_code not in (200,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    return response.json()['users']

def k5_list_groups(module):
    """Get project list"""
    
    global k5_debug

    if 'auth_spec' in module.params['k5_auth_global']: 
        k5_facts = module.params['k5_auth_global']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")        

    endpoint = k5_facts['endpoints']['global-identity']
    auth_token = k5_facts['auth_token']

    contract_id = k5_facts['user']['domain']['id']

    k5_debug_add('auth_token: {0}'.format(auth_token))
    k5_debug_add('contract_id: {0}'.format(contract_id))

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/groups/?domain_id=' + contract_id

    k5_debug_add('REQ: {0}'.format(url))

    try:
        response = session.request('GET', url, headers=headers)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e, debug=k5_debug_out)

    if response.status_code not in (200,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    return response.json()['groups']

def k5_create_group(module):
    """Create a group"""
    
    if 'auth_spec' in module.params['k5_auth_global']: 
        k5_facts = module.params['k5_auth_global']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")        

    endpoint = k5_facts['endpoints']['global-identity']
    auth_token = k5_facts['auth_token']
    contract_id = k5_facts['user']['domain']['id']

    group_name = module.params['group_name']

    groups_list = k5_list_groups(module) # get projects available to the user the token was created by

    matched_groups = [x for x in groups_list if x['name'] == group_name]

    if len(matched_groups) > 0:
        module.exit_json(changed=False, msg="Group already exists")

    k5_debug_add('auth_token: {0}'.format(auth_token))
    k5_debug_add('group_name: {0}'.format(group_name))
    k5_debug_add('contract_id: {0}'.format(contract_id))
        
    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/groups'

    query_json = { "group":
                       { "description": "Ansible created group - " + str(datetime.datetime.now()),
                        "domain_id": contract_id,
                        "name": group_name
                        }
                }

    k5_debug_add('REQ: {0}'.format(url))

    try:
        response = session.request('POST', url, headers=headers, json=query_json)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e)

    # we failed to make a change
    if response.status_code not in (201,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    if k5_debug:
        module.exit_json(changed=True, msg="Create Project Successful", debug=k5_debug_out, group=response.json()['group'] )

    module.exit_json(changed=True, msg="Create Project Successful", group=response.json()['group'] )

def k5_delete_group(module):
    """delete a group"""
    
    if 'auth_spec' in module.params['k5_auth_global']: 
        k5_facts = module.params['k5_auth_global']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")        

    endpoint = k5_facts['endpoints']['global-identity']
    auth_token = k5_facts['auth_token']
    contract_id = k5_facts['user']['domain']['id']

    group_name = module.params['group_name']

    groups_list = k5_list_groups(module) # get projects available to the user the token was created by

    matched_groups = [x for x in groups_list if x['name'] == group_name]

    if len(matched_groups) == 0:
        module.exit_json(changed=False, msg="Group does not exist")

    group_id = matched_groups[0]['id']

    k5_debug_add('auth_token: {0}'.format(auth_token))
    k5_debug_add('group_name: {0}'.format(group_name))
    k5_debug_add('contract_id: {0}'.format(contract_id))
        
    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/groups/' + group_id

    k5_debug_add('REQ: {0}'.format(url))

    try:
        response = session.request('DELETE', url, headers=headers)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e, debug=k5_debug_out)

    # we failed to make a change
    if response.status_code not in (204,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    if k5_debug:
        module.exit_json(changed=True, msg="Delete Group Successful", debug=k5_debug_out )

    module.exit_json(changed=True, msg="Delete Group Successful" )

def k5_add_user_to_group(module):
    """add users to group"""
    
    if 'auth_spec' in module.params['k5_auth_global']: 
        k5_facts = module.params['k5_auth_global']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")        

    endpoint = k5_facts['endpoints']['global-identity']
    auth_token = k5_facts['auth_token']
    contract_id = k5_facts['user']['domain']['id']

    # find group_id
    group_name = module.params['group_name']
    groups_list = k5_list_groups(module) 
    matched_groups = [x for x in groups_list if x['name'] == group_name]
    if len(matched_groups) == 0:
        module.exit_json(changed=False, msg="Group does not exist")
    group_id = matched_groups[0]['id']

    # find user_id
    user_name = module.params['user_name']
    keystone_user_list = k5_get_keystoneobject_list(module, k5_facts, 'users')
    matched_users = [x for x in keystone_user_list['users'] if x['name'] == user_name]
    if len(matched_users) == 0:
        module.exit_json(changed=False, msg="User does not exist")
    user_id = matched_users[0]['id']
 
    k5_debug_add('auth_token: {0}'.format(auth_token))
    k5_debug_add('group_name: {0}'.format(group_name))
    k5_debug_add('group_id: {0}'.format(group_id))
    k5_debug_add('contract_id: {0}'.format(contract_id))
    k5_debug_add('user_name: {0}'.format(user_name))
    k5_debug_add('user_id: {0}'.format(user_id))
         
    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/groups/' + group_id + '/users/' + user_id

    k5_debug_add('REQ: {0}'.format(url))

    try:
        response = session.request('PUT', url, headers=headers )
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e, debug=k5_debug_out)

    # we failed to make a change
    if response.status_code not in (204,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    if k5_debug:
        module.exit_json(changed=True, msg="Add user to group Successful", debug=k5_debug_out )

    module.exit_json(changed=True, msg="Add user to group Successful" )

def k5_add_role_to_project_group(module):
    """add role to group in a project"""
    
    if 'auth_spec' in module.params['k5_auth_regional']: 
        regional_k5_facts = module.params['k5_auth_regional']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")        
    
    regional_auth_token = regional_k5_facts['auth_token']

    if 'auth_spec' in module.params['k5_auth_global']: 
        global_k5_facts = module.params['k5_auth_global']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")        
    
    global_auth_token = global_k5_facts['auth_token']

    # find group_id
    group_name = module.params['group_name']
    groups_list = k5_list_groups(module) 
    matched_groups = [x for x in groups_list if x['name'] == group_name]
    if len(matched_groups) == 0:
        module.exit_json(changed=False, msg="Group does not exist")
    group_id = matched_groups[0]['id']

    # find project_id
    project_name = module.params['project_name']
    keystone_project_list = k5_get_keystoneobject_list(module, regional_k5_facts, 'projects')

    k5_debug_add(keystone_project_list)

    matched_projects = [x for x in keystone_project_list['projects'] if x['name'] == project_name]
    if len(matched_projects) == 0:
        module.exit_json(changed=False, msg="Project does not exist", k5_debug=k5_debug_out)
    project_id = matched_projects[0]['id']
 
    # find role_id
    role_name = module.params['role_name']
    keystone_roles_list = k5_get_keystoneobject_list(module, global_k5_facts, 'roles')
    matched_roles = [x for x in keystone_roles_list['roles'] if x['name'] == role_name]
    if len(matched_roles) == 0:
        module.exit_json(changed=False, msg="Role does not exist")
    role_id = matched_roles[0]['id']

    endpoint = regional_k5_facts['endpoints']['identityv3']

    k5_debug_clear()

    k5_debug_add('group_name: {0}'.format(group_name))
    k5_debug_add('group_id: {0}'.format(group_id))
    k5_debug_add('project_id: {0}'.format(project_id))
    k5_debug_add('role_id: {0}'.format(role_id))
         
    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': regional_auth_token }

    url = endpoint + '/projects/' + project_id + '/groups/' + group_id + '/roles/' + role_id

    k5_debug_add('REQ: {0}'.format(url))

    try:
        response = session.request('PUT', url, headers=headers )
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e, debug=k5_debug_out)

    # we failed to make a change
    if response.status_code not in (204,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    if k5_debug:
        module.exit_json(changed=True, msg="Assign role to project group  Successful", debug=k5_debug_out )

    module.exit_json(changed=True, msg="Assign role to project group Successful" )



######################################################################################

def main():

    global k5_debug

    module = AnsibleModule( argument_spec=dict(
        group_name = dict(default=None, type='str'),
        state = dict(choices=['list', 'present', 'absent', 'list_users', 'add_user','add_role_to_project_group' ], default='list'),
        user_name = dict(default=None, type='str'), 
        project_name = dict(default=None, type='str'), 
        role_name = dict(default=None, type='str'), 
        k5_auth_regional = dict(default=None, type='dict'),
        k5_auth_global = dict(required=True, default=None, type='dict')
    ),
        # constraints
        required_if=[
            ('state', 'present', ['group_name']),
            ('state', 'absent', ['group_name']),
            ('state', 'list_users', ['group_name']),
            ('state', 'add_user', ['group_name', 'user_name']),
            ('state', 'add_role_to_project_group', ['group_name', 'project_name', 'role_name', 'k5_auth_regional']),
        ]
    )

    if 'K5_DEBUG' in os.environ:
        k5_debug = True
    
    #k5_debug_clear()

    mp = module.params
    if mp['state'] == 'present':
        k5_create_group(module)
    if mp['state'] == 'absent':
        k5_delete_group(module)
    if mp['state'] == 'add_user':
        k5_add_user_to_group(module)
    if mp['state'] == 'add_role_to_project_group':
        k5_add_role_to_project_group(module)
    if mp['state'] == 'list_users':
        u=k5_list_users(module)
        module.exit_json(changed=False, msg="List Group Users Successful", k5_group_users=u )
    if mp['state'] == 'list':
        gs = k5_list_groups(module)
        module.exit_json(changed=False, msg="List Projects Successful", k5_groups=gs )



######################################################################################

if __name__ == '__main__':  
    main()



