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


## Module Documentation

see [DOCUMENTATION.md](DOCUMENTATION.md) which is generated from the inline module documentation metadata.

## Online API Guides

http://www.fujitsu.com/global/solutions/cloud/k5/guides/ 

## Ansible

Initially see the test cases for really simple invocation.

Use my other repo to see a working example:  https://github.com/mohclips/k5-ansible-infra

### openrc

Set the following if you wish, this is the easiest way and compatible with the env vars of the OpenStack CLI comand.

Or use the parameters in `k5_auth`.

```bash
 export OS_USERNAME=obvs
 export OS_PASSWORD=obvs
 export OS_PROJECT_ID=from api url hex
 export OS_REGION_NAME=uk-1
 export OS_USER_DOMAIN_NAME=contract id
```

### clouds.y(a)ml / secure.y(a)ml
See the example files in Examples/clouds.yml and Examples/secure.yml.example

### shade - IMPORTANT

The python shade library needs to be at or below 1.13.2

This is because K5 API does not support the GET / request to the image endpoint as per https://developer.openstack.org/api-ref/image/versions/index.html

Therefore you should downgrade shade to 1.13.2 Eg. `sudo pip install shade==1.13.2`


# Contributors

Many thanks to the following people:

* Nicholas Cross
* Jon Spriggs
* Kenny Brown
* Peter Beverley


# Windows Version

## Is there a Windows PowerShell version of this?

Well of course there is...

See Steve Atherton's code here:  https://github.com/athertonsp/k5-powershell-functions and https://github.com/athertonsp/PowerShell-Scripts-for-K5




