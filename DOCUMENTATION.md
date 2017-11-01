# Ansible K5 modules
### *Auto-generated documentation for the K5 modules*

---
### Requirements
* See official Ansible docs
* shade == 1.13.2

---
### Modules


Number of modules: 26

  * [k5_auth - create and retrieve an authentication token from k5](#k5_auth)
  * [k5_create_port - creates a network port to attach to a compute module in an az in k5.](#k5_create_port)
  * [k5_create_subnet - create subnet on k5 in particular az](#k5_create_subnet)
  * [k5_group - create / delete groups](#k5_group)
  * [k5_inter_project_link - create inter-project link on k5 in particular az](#k5_inter_project_link)
  * [k5_key_container_delete - delete a key metadata container](#k5_key_container_delete)
  * [k5_key_container_list - list key metadata containers](#k5_key_container_list)
  * [k5_key_delete - list key metadata containers](#k5_key_delete)
  * [k5_key_list - display](#k5_key_list)
  * [k5_keypair - create / delete / list ssh keys](#k5_keypair)
  * [k5_network - create network on k5 in particular az](#k5_network)
  * [k5_novnc_console - display the url to the novnc console](#k5_novnc_console)
  * [k5_project - create / delete projects](#k5_project)
  * [k5_router - create router on k5 in particular az](#k5_router)
  * [k5_router_create_ssl_vpn - create an openvpn server](#k5_router_create_ssl_vpn)
  * [k5_router_create_ssl_vpn - display the url to the novnc console](#k5_router_create_ssl_vpn)
  * [k5_router_firewall - add, update or remove a firewall from a k5 router](#k5_router_firewall)
  * [k5_server_console_output - display the url to the novnc console](#k5_server_console_output)
  * [k5_servergroup - create / delete / list server groups](#k5_servergroup)
  * [k5_srv_shelve - shelve and un-shelve a virtual server in k5](#k5_srv_shelve)
  * [k5_ssl_vpn_delete - delete ssl vpn service](#k5_ssl_vpn_delete)
  * [k5_ssl_vpn_list - list ssl vpns on k5](#k5_ssl_vpn_list)
  * [k5_ssl_vpn_list - list ssl vpns on k5](#k5_ssl_vpn_list)
  * [k5_update_router_add_port - add ports to a k5 router](#k5_update_router_add_port)
  * [k5_update_router_routes - replaces the existing routes on a k5 router](#k5_update_router_routes)
  * [k5_update_subnet - update a subnet on k5](#k5_update_subnet)

---

## k5_auth
Create and retrieve an authentication token from K5

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Login and Retrieve an authentication token from K5, plus the endpoints

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   no  |    | |  Login username. LEGACY will be removed in future versions.  |
| user_domain  |   no  |    | |  Domain the user belongs to.  |
| region_name  |   no  |    | |  Region the user belongs to.  |
| token_type  |   no  |  Regional  | |  Regional or Global token type creation.  |
| project_id  |   no  |    | |  Project id.  |
| scoped  |   no  |  True  | |  Set scope of token  |
| password  |   no  |    | |  Password of user. LEGACY will be removed in future versions.  |


 
#### Examples

```
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



```



---


## k5_create_port
Creates a network port to attach to a compute module in an AZ in K5.

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Explicit K5 call to create a network port in an AZ - replaces os_port from Openstack module, but is more limited. Use os_network to update the network.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| name  |   yes  |    | |  Name of the port.  |
| allowed_address_pairs  |   no  |    | |  Defined addresses or subnets which are allowed to bypass the OpenStack Anti-spoofing for this one interface. Usually defined as an individual host, a subnet. 0.0.0.0/0 is not permitted (use 0.0.0.0/1 and 128.0.0.1/1 instead)  |
| availability_zone  |   yes  |    | |  AZ to create the port in.  |
| fixed_ip  |   no  |    | |  A list of IP addresses to define as 'fixed' (for DHCP purposes or static allocation on the host). If not provided, the DHCP server will offer an IP address instead.  |
| state  |   yes  |    | |  State of the port. Can only be 'present'.  |
| subnet_name  |   yes  |    | |  Name of the Subnet to attach the port to.  |
| k5_auth  |   yes  |    | |  dict of k5_auth module output.  |
| network_name  |   yes  |    | |  Name of the Network to attach the port to.  |
| security_groups  |   yes  |    | |  The Security Group(s) to apply to the port.  |


 
#### Examples

```
# Create a port in an AZ
- k5_create_port:
        name: "nx-test-port-1a"
        state: present
        availability_zone: "uk-1a"
        network_name: "nx-test-net-1a"
        subnet_name: "nx-test-subnet-1a"
        fixed_ip:
          - "10.0.0.250"
        security_groups:
          - 'default'
        k5_auth: "{{ k5_auth_reg.k5_auth_facts }}"

- k5_create_port:
        name: "devicename-port-1a"
        state: present
        subnet_name: "subnet-1a"
        network_name: "network-1a"
        security_groups:
          - "any any allow"
        availability_zone: "uk-1a"
        allowed_address_pairs:
          - "0.0.0.0/1"
          - "128.0.0.1/1"
        k5_auth: "{{ k5_auth_reg.k5_auth_facts }}"

```



---


## k5_create_subnet
Create subnet on K5 in particular AZ

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Explicit K5 call to create a subnet in an AZ - replaces os_subnet from Openstack module, but is more limited. Use os_subnet to update the network.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| name  |   yes  |    | |  Name of the subnet.  |
| enable_dhcp  |   yes  |    | |  Enable DHCP on the subnet.  |
| availability_zone  |   yes  |    | |  AZ to create the subnet in.  |
| dhcp_pool_start  |   no  |    | |  DHCP scope start.  |
| state  |   yes  |    | |  State of the subnet. Can only be 'present'.  |
| gateway_ip  |   yes  |    | |  Gateway ip of the subnet. Can only be 'present'.  |
| dhcp_pool_end  |   no  |    | |  DHCP scope end.  |
| k5_auth  |   yes  |    | |  dict of k5_auth module output.  |
| cidr  |   yes  |    | |  CIDR for the subnet.  |
| network_name  |   yes  |    | |  Name of the Network the Subnet is created on.  |


 
#### Examples

```
# Create a subnet in an AZ
    - k5_create_subnet:
        state: present
        network_name: "nx-test-net-1a"
        name: "nx-test-subnet-1a"
        cidr: "192.168.1.0/24"
        gateway_ip: 192.168.1.1
        availability_zone: "uk-1a"
        enable_dhcp: True
        dhcp_pool_start: "192.168.1.10"
        dhcp_pool_end: "192.168.1.240"
        k5_auth: "{{ k5_auth_reg.k5_auth_facts }}"

```



---


## k5_group
create / delete groups

  * Synopsis
  * Options
  * Examples

#### Synopsis
 returns groups

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| status  |   yes  |    | |  present / absent  |
| group_name  |   yes  |    | |  Name group to create / delete  |


 
#### Examples

```
- k5_group:
    group_name: zzCrossNgrp
    status: present
    k5_auth: "{{ k5_auth_facts }}"

```



---


## k5_inter_project_link
Create inter-project link on K5 in particular AZ

  * Synopsis
  * Options
  * Examples

#### Synopsis
 K5 call to inter-project network link in an AZ - the inter-project link is custom to K5 therefore there is no Openstack module.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| k5_port  |   yes  |    | |  dict of k5_port module output.  |
| state  |   yes  |    | |  State of the network. Can be 'present' or 'absent'.  |
| router_name  |   yes  |    | |  Name of the router network.  |
| k5_auth  |   yes  |    | |  dict of k5_auth module output.  |


 
#### Examples

```
# Create an inter-project link in an AZ
- k5_create_inter_project_link:
        state: present
        k5_port: "{{ k5_port_reg.k5_port_facts }}"
        router_name: "nx-test-net-1a"
        k5_auth: "{{ k5_auth_reg.k5_auth_facts }}"

```



---


## k5_key_container_delete
Delete a key metadata container

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Delete a metadata container

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| container_id  |   yes  |    | |  The ID of the container to remove.  |
| k5_auth  |   yes  |    | |  dict of k5_auth module output.  |


 
#### Examples

```
k5_key_container_delete:
     container_id: "decafbad-1234-5678-90ab-decafbad1234"
     k5_auth: "{{ k5_auth_facts }}"

```



---


## k5_key_container_list
List key metadata containers

  * Synopsis
  * Options
  * Examples

#### Synopsis
 returns a dict of containers

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| k5_auth  |   yes  |    | |  dict of k5_auth module output.  |


 
#### Examples

```
- k5_key_container_list:
     k5_auth: "{{ k5_auth_facts }}"

```



---


## k5_key_delete
List key metadata containers

  * Synopsis
  * Options
  * Examples

#### Synopsis
 returns a dict of containers

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| key_id  |   yes  |    | |  ID of the key to delete.  |
| k5_auth  |   yes  |    | |  dict of k5_auth module output.  |


 
#### Examples

```
- k5_key_delete:
     key_id: "decafbad-1234-5678-90ab-decafbad1234"
     k5_auth: "{{ k5_auth_facts }}"

```



---


## k5_key_list
Display

  * Synopsis
  * Options
  * Examples

#### Synopsis
 returns list of keys

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| k5_auth  |   yes  |    | |  dict of k5_auth module output.  |


 
#### Examples

```
- k5_key_list:
     k5_auth: "{{ k5_auth_facts }}"

```



---


## k5_keypair
create / delete / list ssh keys

  * Synopsis
  * Options
  * Examples

#### Synopsis
 returns ssh public keys

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| status  |   yes  |    | |  present / absent / list  |
| project_name  |   yes  |    | |  Name of the project  |
| ssh_public_key  |   no  |    | |  string containing the ssh public key  |
| keypair_name  |   yes  |    | |  Name to create / delete  |
| availability_zone  |   yes  |    | |  az to save the key in / or to find the key within  |


 
#### Examples

```
- k5_keypair:
    keypair_name: MyKey
    project_name: myproject
    status: present
    ssh_public_key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDx8nkQv/
zgGgB4rMYmIf+6A4l6Rr+o/6lHBQdW5aYd44bd8JttDCE/F/pNRr0lRE
+PiqSPO8nDPHw0010JeMH9gYgnnFlyY3/OcJ02RhIPyyxYpv9FhY
+2YiUkpwFOcLImyrxEsYXpD/0d3ac30bNH6Sw9JD9UZHYcpSxsIbECHw=="
    availability_zone: uk-1a
    k5_auth: "{{ k5_auth_facts }}"

```



---


## k5_network
Create network on K5 in particular AZ

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Explicit K5 call to create a network in an AZ - replaces os_network from Openstack module, but is more limited. Use os_network to update the network.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| state  |   yes  |    | |  State of the network. Can only be 'present'.  |
| name  |   yes  |    | |  Name of the network.  |
| k5_auth  |   yes  |    | |  dict of k5_auth module output.  |
| availability_zone  |   yes  |    | |  AZ to create the network in.  |


 
#### Examples

```
# Create a network in an AZ
- k5_network:
     name: network-01
     state: present
     availability_zone: uk-1a
     k5_auth: "{{ k5_auth_facts }}"

```



---


## k5_novnc_console
Display the URL to the NoVNC Console

  * Synopsis
  * Options
  * Examples

#### Synopsis
 returns a URL to the noVNC console.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| server_name  |   yes  |    | |  Name of the server.  |
| k5_auth  |   yes  |    | |  dict of k5_auth module output.  |


 
#### Examples

```
# Get novnc url
- k5_novnc_console:
     server_name: test01
     k5_auth: "{{ k5_auth_facts }}"

```



---


## k5_project
create / delete projects

  * Synopsis
  * Options
  * Examples

#### Synopsis
 returns project id

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| status  |   yes  |    | |  present / absent  |
| project_name  |   yes  |    | |  Name project to create / delete  |
| k5_auth  |   yes  |    | |  dict of k5_auth module output.  |


 
#### Examples

```
- k5_project:
    project_name: zzCrossNproj
    status: present
    k5_auth: "{{ k5_auth_facts }}"

```



---


## k5_router
Create router on K5 in particular AZ

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Explicit K5 call to create a router in an AZ - replaces os_router from Openstack module, but is more limited. Use os_router to update the router.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| state  |   yes  |    | |  State of the router. Can only be 'present'.  |
| name  |   yes  |    | |  Name of the router.  |
| k5_auth  |   yes  |    | |  dict of k5_auth module output.  |
| availability_zone  |   yes  |    | |  AZ to create the router in.  |


 
#### Examples

```
# Create a k5 router
- k5_router:
     name: admin
     state: present
     availability_zone: uk-1a
     k5_auth: "{{ k5_auth_facts }}"

```



---


## k5_router_create_ssl_vpn
Create an OpenVPN Server

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Create an OpenVPN Server

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| server_key  |   yes  |    | |  server key in pem format  |
| name  |   yes  |    | |  Name of the VPN  |
| dh  |   yes  |    | |  dh in pem format  |
| ca  |   yes  |    | |  CA key in pem format  |
| availablity_zone  |   yes  |    | |  Name of the availability zone  |
| server_certificate  |   yes  |    | |  server cert in pem format  |
| subnet_name  |   yes  |    | |  Name of the subnet that the VON connects to inside K5  |
| client_cidr  |   yes  |    | |  IP subnet of the remote clients. A NAT subnet inside K5. (not the clients actual subnet)  |
| router_name  |   yes  |    | |  Name of the router to attach the SSL VPN to  |


 
#### Examples

```

```



---


## k5_router_create_ssl_vpn
Display the URL to the NoVNC Console

  * Synopsis
  * Options
  * Examples

#### Synopsis
 returns a URL to the noVNC console.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| server_key  |   yes  |    | |  server key in pem format  |
| name  |   yes  |    | |  Name of the VPN  |
| dh  |   yes  |    | |  dh in pem format  |
| ca  |   yes  |    | |  CA key in pem format  |
| availablity_zone  |   yes  |    | |  Name of the availability zone  |
| server_certificate  |   yes  |    | |  server cert in pem format  |
| subnet_name  |   yes  |    | |  Name of the subnet that the VON connects to inside K5  |
| client_cidr  |   yes  |    | |  IP subnet of the remote clients. A NAT subnet inside K5. (not the clients actual subnet)  |
| router_name  |   yes  |    | |  Name of the router to attach the SSL VPN to  |


 
#### Examples

```
# Get novnc url
- k5_router_create_ssl_vpn:
     server_name: test01
     k5_auth: "{{ k5_auth_facts }}"

```



---


## k5_router_firewall
Add, update or remove a firewall from a K5 router

  * Synopsis
  * Options
  * Examples

#### Synopsis
 returns

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |


 
#### Examples

```
- k5_router_firewall:
    router_name:  "k5_test_router"
    rules: "{{ my_rules_list }}"
    reset_connections: True
    state: present
    k5_auth: "{{ k5_auth_facts }}"

- k5_router_firewall:
    router_name:  "k5_test_router"
    state: absent
    k5_auth: "{{ k5_auth_facts }}"

```



---


## k5_server_console_output
Display the URL to the NoVNC Console

  * Synopsis
  * Options
  * Examples

#### Synopsis
 returns the openstack console output.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| console_length  |   yes  |    | |  Number of lines to tail from the console output  |
| server_name  |   yes  |    | |  Name of the server.  |


 
#### Examples

```
# Get server console output
- k5_server_console_output:
    server_name: test01
    length: 50 
    k5_auth: "{{ k5_auth_facts }}"

```



---


## k5_servergroup
create / delete / list server groups

  * Synopsis
  * Options
  * Examples

#### Synopsis
 returns server groups

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| status  |   yes  |    | |  present / absent / list  |
| _name  |   yes  |    | |  Name to create / delete  |
| policies  |   yes  |    | |  one of either affinity or anti-affinity  |
| availability_zone  |   yes  |    | |  az to save the server group in / or to find the server group within  |


 
#### Examples

```
- k5_servergroup:
    name: MyServerGroup
    status: present
    policies: affinity
    availability_zone: uk-1a
    k5_auth: "{{ k5_auth_facts }}"

```



---


## k5_srv_shelve
Shelve and un-shelve a virtual server in K5

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Explicit K5 call to shelve and un-shelve a server in K5  - no module for this action exists.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| state  |   yes  |    | |  State of the network. Can be 'shelve' or 'unshelve'.  |
| server_name  |   yes  |    | |  name of the server.  |
| k5_auth  |   yes  |    | |  dict of k5_auth module output.  |


 
#### Examples

```
# Create a port in an AZ
- k5_srv_shelve:
        server_name: "nx-test-server"
        state: present
        k5_auth: "{{ k5_auth_reg.k5_auth_facts }}"

```



---


## k5_ssl_vpn_delete
delete SSL VPN service

  * Synopsis
  * Options
  * Examples

#### Synopsis
 return none

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| ssl_vpn_id  |   no  |    | |  UUID of the VPN  |
| ssl_vpn_name  |   no  |    | |  Name of the VPN  |


 
#### Examples

```
- k5_ssl_vpn_delete:
     ssl_vpn_name: test01
     k5_auth: "{{ k5_auth_facts }}"

```



---


## k5_ssl_vpn_list
List SSL VPNs on K5

  * Synopsis
  * Options
  * Examples

#### Synopsis
 returns dict of vpns

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |


 
#### Examples

```
- k5_ssl_vpn_list:
     k5_auth: "{{ k5_auth_facts }}"

```



---


## k5_ssl_vpn_list
List SSL VPNs on K5

  * Synopsis
  * Options
  * Examples

#### Synopsis
 returns

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |


 
#### Examples

```

- k5_ssl_vpn_list:
     k5_auth: "{{ k5_auth_facts }}"

```



---


## k5_update_router_add_port
Add ports to a K5 router

  * Synopsis
  * Options
  * Examples

#### Synopsis
 K5 call to add ports to a router

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| state  |   yes  |    | |  State of the network. Can only be 'present'.  |
| router_name  |   yes  |    | |  Name of the router network.  |
| ports  |   yes  |    | |  list of ports to be added to the router.  |
| k5_auth  |   yes  |    | |  dict of k5_auth module output.  |


 
#### Examples

```
# Add ports to a K5 router
- k5_update_router_add_port:
        state: present
        ports: 
          - "myport_a"
          - "myport_b"
        router_name: "nx-test-net-1a"
        k5_auth: "{{ k5_auth_reg.k5_auth_facts }}"

```



---


## k5_update_router_routes
Replaces the existing routes on a K5 router

  * Synopsis
  * Options
  * Examples

#### Synopsis
 K5 call to update the route on a router - option is not available in the Openstack module.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| routes  |   yes  |    | |  routes to be applied to the router.  |
| state  |   yes  |    | |  State of the network. Can only be 'present'.  |
| router_name  |   yes  |    | |  Name of the router network.  |
| k5_auth  |   yes  |    | |  dict of k5_auth module output.  |


 
#### Examples

```
# Set routes on K5 router
- k5_update_router_routes:
        state: present
        routes: 
          - nexthop: "10.10.10.0/24"
            destination: "172.16.1.1"
          - nexthop: "10.10.20.0/24"
            destination: "172.16.1.1"
        router_name: "nx-test-net-1a"
        k5_auth: "{{ k5_auth_reg.k5_auth_facts }}"

```



---


## k5_update_subnet
update a subnet on K5

  * Synopsis
  * Options
  * Examples

#### Synopsis
 returns

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |


 
#### Examples

```
- k5_update_subnet:
    name:  "k5_test_subnet"
    gateway_ip: "62.60.1.1"
    enable_dhcp: True
    dns_nameservers: 
        - 8.8.8.8
        - 8.8.4.4
    host_routes:
        - { "destination":"0.0.0.0/0", "nexthop":"172.16.1.254" }
        - { "destination":"192.168.0.1/32", "nexthop":"172.16.1.1" }
    k5_auth: "{{ k5_auth_facts }}"

```



---


---
