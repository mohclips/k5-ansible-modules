#!/usr/bin/python

import datetime

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = '''
---
module: k5_project
short_description: create / delete projects
version_added: "1.0"
description:
    - returns project id
options:
   project_name:
     description:
        - Name project to create / delete
     required: true
     default: None
   status:
     description:
        - present / absent
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
- k5_project:
    project_name: zzCrossNproj
    status: present
    k5_auth: "{{ k5_auth_facts }}"
'''

RETURN = '''
k5_project:
    description: project details.
    returned: On success when the project is created
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

def k5_list_projects(module):
    """Get project list"""
    
    global k5_debug

    if 'auth_spec' in module.params['k5_auth']: 
        k5_facts = module.params['k5_auth']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")        

    endpoint = k5_facts['endpoints']['identityv3']
    auth_token = k5_facts['auth_token']

    user_id = k5_facts['user']['id']

    project_name = module.params['project_name']

    k5_debug_add('auth_token: {0}'.format(auth_token))
    k5_debug_add('project_name: {0}'.format(project_name))
    k5_debug_add('user_id: {0}'.format(user_id))

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/users/' + user_id + '/projects'

    k5_debug_add('REQ: {0}'.format(url))

    try:
        response = session.request('GET', url, headers=headers)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e)

    if response.status_code not in (200,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    #k5_debug_add('RESP: {0}'.format(response.json()))

    return response.json()['projects']

def k5_create_project(module):
    """Create a project"""
    
    if 'auth_spec' in module.params['k5_auth']: 
        k5_facts = module.params['k5_auth']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")        

    endpoint = k5_facts['endpoints']['identityv3']
    auth_token = k5_facts['auth_token']
    contract_id = k5_facts['user']['domain']['id']

    project_name = module.params['project_name']

    projects_list = k5_list_projects(module) # get projects available to the user the token was created by
    matched_projects = [x for x in projects_list if x['name'] == project_name]

    if len(matched_projects) > 0:
        module.exit_json(changed=False, msg="Project already exists", project=matched_projects[0])

    k5_debug_add('auth_token: {0}'.format(auth_token))
    k5_debug_add('project_name: {0}'.format(project_name))
    k5_debug_add('contract_id: {0}'.format(contract_id))
    k5_debug_add('projects: {0}'.format(projects_list))
        
#    module.fail_json(msg="fail",zzK5_DEBUG=k5_debug_out)        

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/projects?domain_id=' + contract_id

    query_json = { "project":
                       { "description": "Ansible created project - " + str(datetime.datetime.now()),
                        "domain_id": contract_id,
                        "enabled": True,
                        "is_domain": False,
                        "name": project_name
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

    #k5_debug_add('RESP: {0}'.format(response.json()))

    if k5_debug:
        module.exit_json(changed=True, msg="Create Project Successful", debug=k5_debug_out, project=response.json()['project'] )

    module.exit_json(changed=True, msg="Create Project Successful", project=response.json()['project'] )


def k5_delete_project(module):
    """delete a project"""
    
    module.exit_json(changed=False, msg="There is no delete function for projects on K5!!!" )

def k5_patch_project(module):
    """Change state of a  project"""
    
    if 'auth_spec' in module.params['k5_auth']: 
        k5_facts = module.params['k5_auth']
    else:
        module.fail_json(msg="k5_auth_facts not found, have you run k5_auth?")        

    endpoint = k5_facts['endpoints']['identityv3']
    auth_token = k5_facts['auth_token']
    contract_id = k5_facts['user']['domain']['id']

    project_name = module.params['project_name']

    projects_list = k5_list_projects(module) # get projects available to the user the token was created by

    #k5_debug_add('projects: {0}'.format(projects_list))

    matched_projects = [x for x in projects_list if x['name'] == project_name]

    if len(matched_projects) == 0:
        module.exit_json(changed=False, msg="Project does not exist")

    project_id = matched_projects[0]['id']

    state = module.params['state']
    if state == 'enabled':
        set_state = True
    else:
        set_state = False

    k5_debug_add('auth_token: {0}'.format(auth_token))
    k5_debug_add('project_name: {0}'.format(project_name))
    k5_debug_add('project_id: {0}'.format(project_id))
    k5_debug_add('contract_id: {0}'.format(contract_id))
    k5_debug_add('projects: {0}'.format(projects_list))
        
#    module.fail_json(msg="fail",zzK5_DEBUG=k5_debug_out)        

    session = requests.Session()

    headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Auth-Token': auth_token }

    url = endpoint + '/projects/' + project_id

    query_json = { "project":
                       { "description": "Ansible updated project - " + str(datetime.datetime.now()),
                        "enabled": set_state,
                        "name": project_name
                        }
                }

    k5_debug_add('REQ: {0}'.format(url))

    try:
        response = session.request('PATCH', url, headers=headers, json=query_json)
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=e)

    # we failed to make a change
    if response.status_code not in (200,):
        module.fail_json(msg="RESP: HTTP Code:" + str(response.status_code) + " " + str(response.content), debug=k5_debug_out)

    if k5_debug:
        module.exit_json(changed=True, msg="Create Project Successful", project=response.json()['project'], debug=k5_debug_out )

    module.exit_json(changed=True, msg="Create Project Successful", project=response.json()['project'] )


######################################################################################

def main():

    global k5_debug

    module = AnsibleModule( argument_spec=dict(
        project_name = dict(default=None, type='str'),
        state = dict(choices=['list', 'present', 'absent', 'enable', 'disable'], default='list'),
        k5_auth = dict(required=True, default=None, type='dict')
    ),
        # constraints
        required_if=[
            ('state', 'present', ['project_name']),
            ('state', 'absent', ['project_name']),
            ('state', 'enable', ['project_name']),
            ('state', 'disable', ['project_name']),
        ]
    )

    if 'K5_DEBUG' in os.environ:
        k5_debug = True
    
    #k5_debug_clear()

    mp = module.params
    if mp['state'] == 'present':
        k5_create_project(module)
    if mp['state'] == 'absent':
        k5_delete_project(module)
    if mp['state'] == 'disable':
        k5_patch_project(module)
    if mp['state'] == 'enable':
        k5_patch_project(module)
    if mp['state'] == 'list':
        ps = k5_list_projects(module)
        module.exit_json(changed=False, msg="List Projects Successful", k5_projects=ps )



######################################################################################

if __name__ == '__main__':  
    main()



