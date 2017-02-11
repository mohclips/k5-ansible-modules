# Intro

This git repository contains examples of how to create infrastructure as code on the Fujitsu K5 Cloud.

Basically, in my day job I help people with Intrafructure as Code, automation and other such things.  I wrote these modules to help people access K5 more readily.  Plus it's a bit of fun. ;)

As K5 is Availability Zone centric new modules were created to communicate with K5 which then bypass limitations in the Ansible Openstack os module

Primarily as K5 requires those working Availability Zone parameters. It seems from what i can tell that the underlying API 'shade' does not honour or process the availability zone parameters passed to it from Ansible.  I could have hacked about at the shade API i guess, which is probably a better idea for some of the modules, but it's easier to create new modules and more of a learning experience with Ansible module creation and K5 APIs.

Hopefully the modules are simple enough for others to understand and offer addtional updates. (Pull requests).

# Usage

This is a split from k5-ansible-infra, into a git sub-module, to allow others to pull just the ```library/``` code down into their own repositories, without the example infrastrucure code.

# Note

These are unoffical Ansible modules for Fujitsu K5 Cloud.  I hope in the end Fujitsu Japan take up the task of creating formal modules for K5 and push them into Ansible core.

No warranty is expressed or Implied, by myself the other developers or Fujitsu.  Use at your own risk.


## Modules

### k5_auth

Authenticate to K5, use the returned facts to authenticate on each of the below modules.

### k5_create_router

Create a router in a specified Availability Zone

### k5_create_network

Create a Network in a specified Availability Zone

Also note the K5 API uses different parameters in the network module to regular OpenStack API calls.  

### k5_create_subnet

Create a Subnet in a specified Availability Zone

### k5_create_port

Create a port in a specified Availability Zone

### k5_assign_floating_ip

Assign a floating ip from a specified Availability Zone

### k5_server_console_output

Return the openstack console logs for a defined server, the builds logs or sometimes called Compute Instance Logs.

### k5_novnc_console

Return the URL to a noVNC console for a defined server.  These URLs are time limited (for security purposes?).  

Also only works in Japan East-1 at present while the update is rolled out across the various regions. (Jan2017) 

### k5_inter_project_link

Link two projects (virtual routers) together.  Developed by Kenny Brown.

### k5_update_router_routes

Update routes on a virtual router.  Developed by Kenny Brown.



## Online API Guides

http://www.fujitsu.com/global/solutions/cloud/k5/guides/ 

## Ansible

Initially see the test cases for really simple invocation.

Use my other repo to see a working example:  https://github.com/mohclips/k5-ansible-infra

### openrc

Set the following if you wish, this is the easiest way and compatible with the env vars of the OpenStack CLI comand.

Or use the parameters in ```k5_auth```.

```bash
 export OS_USERNAME=obvs
 export OS_PASSWORD=obvs
 export OS_PROJECT_ID=from api url hex
 export OS_REGION_NAME=uk-1
 export OS_USER_DOMAIN_NAME=contract id
```

# Contributors

*Nicholas Cross
*Jon Spriggs
*Kenny Brown


