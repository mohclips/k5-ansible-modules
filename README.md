# Intro

This git repository contains examples of how to create infrastructure as code on the Fujitsu K5 Cloud.

Where necessary new modules are created to communicate with K5 which bypass limitations in the Ansible Openstack os modules.
Primarily, k5_auth, k5_router, k5_network as these require working Availability Zone paramaters.  The K5 API uses different parameters in the network module.

Guides: http://www.fujitsu.com/global/solutions/cloud/k5/guides/ 



TODO more

uploaded for safekeeping - none of this works fully as yet


# Usage

## openrc

Set the following if you wish:
```bash
 export OS_USERNAME=obvs
 export OS_PASSWORD=obvs
 export OS_PROJECT_ID=from api url hex
 export OS_REGION_NAME=uk-1
 export OS_USER_DOMAIN_NAME=contract id
```

Then use the k5_auth module to retrieve an authentication token

TODO more

