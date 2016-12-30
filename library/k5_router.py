#!/usr/bin/python



#
# Q. Why do this when we already have os_router from Openstack?
# A. K5 requires Availablilty Zones and these are not supported by the underlying shade API.
#



ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'committer',
                    'version': '0.1'}

#TODO
DOCUMENTATION = '''
'''

#TODO
EXAMPLES = '''
'''

try:
    # our common functions
    import k5
    HAS_K5=True
except:
    HAS_K5=False


import json


def main():
    module = AnsibleModule(
        argument_spec=dict(
            ssh_cert_path=dict(),
            name=dict(),
            hostname=dict()
        )
    )


    if not HAS_K5:
        module.fail_json(msg='k5 python module required for this module')



# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()

