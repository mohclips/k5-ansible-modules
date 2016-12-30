#!/usr/bin/python

from k5_utils import k5_get_auth_token

#import k5_utils


from ansible.module_utils.basic import *

module=None

def main():

    module = AnsibleModule( argument_spec=dict() )

    (ok, message, debug) = k5_get_auth_token()

    if ok:
        #module.exit_json(changed=ok, msg="Authentication Successful")

        k5_auth_dict = {
            "changed" : ok,
            "k5": message,
            "debug": debug
        }

        module.exit_json(changed=ok, msg="Authentication Successful", auth=k5_auth_dict)
    else:
        module.fail_json(msg=message)


if __name__ == '__main__':  
    main()



