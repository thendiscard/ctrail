### ctrail

ctrail is a collection of scripts which can retrieve control and forwarding
plane information from the various nodes of a Contrail system.

The scripts are not complete and are meant more like an example of how the APIs
can be used. However the information provided can be useful as is.

### Installation

```sh
user@jump0:~$ python3 -m venv ctrail

user@jump0:~$ source ctrail/bin/activate

(ctrail) user@jump0:~$ pip3 install git+https://github.com/thendiscard/ctrail.git
Downloading/unpacking git+https://github.com/thendiscard/ctrail.git
  Cloning https://github.com/thendiscard/ctrail.git to /tmp/pip-c4sj1mtf-build
  Running setup.py (path:/tmp/pip-c4sj1mtf-build/setup.py) egg_info for package from git+https://github.com/thendiscard/ctrail.git

Downloading/unpacking Click>=6.7 (from ctrail==0.1.0)
  Downloading click-6.7-py2.py3-none-any.whl (71kB): 71kB downloaded
Downloading/unpacking requests (from ctrail==0.1.0)
  Downloading requests-2.18.4-py2.py3-none-any.whl (88kB): 88kB downloaded
Downloading/unpacking xmltodict (from ctrail==0.1.0)
  Downloading xmltodict-0.11.0-py2.py3-none-any.whl
Downloading/unpacking idna<2.7,>=2.5 (from requests->ctrail==0.1.0)
  Downloading idna-2.6-py2.py3-none-any.whl (56kB): 56kB downloaded
Downloading/unpacking chardet<3.1.0,>=3.0.2 (from requests->ctrail==0.1.0)
  Downloading chardet-3.0.4-py2.py3-none-any.whl (133kB): 133kB downloaded
Downloading/unpacking urllib3<1.23,>=1.21.1 (from requests->ctrail==0.1.0)
  Downloading urllib3-1.22-py2.py3-none-any.whl (132kB): 132kB downloaded
Downloading/unpacking certifi>=2017.4.17 (from requests->ctrail==0.1.0)
  Downloading certifi-2018.4.16-py2.py3-none-any.whl (150kB): 150kB downloaded
Installing collected packages: Click, requests, xmltodict, ctrail, idna, chardet, urllib3, certifi
  Running setup.py install for ctrail

    Installing ctrail script to /home/user/ctrail/bin
Successfully installed Click requests xmltodict ctrail idna chardet urllib3 certifi
Cleaning up...

(ctrail) user@jump0:~$ ctrail --help
Usage: ctrail [OPTIONS] COMMAND [ARGS]...

  ctrail is a collection of scripts which can retrieve control and
  forwarding plane information from the various nodes of a Contrail system.

  The scripts are not complete and are meant more like an example of how the
  APIs can be used. However the information provided can be useful as is.

Options:
  -l, --log-level [error|NORMAL|DEBUG|WARN|normal|info|warn|ERROR|debug|INFO]
                                  Set the logging level (the default is to
                                  only log normal and error messages).
  -v, --verbose                   Set the verbosity level. This controls how
                                  much of the original API response is
                                  printed. The default is 0 which means to
                                  only print the post-processing information.
  --help                          Show this message and exit.

Commands:
  config    Get configuration information from the...
  control   Get VRF and route information from the...
  opserver  Get UVE, flow information from the analytics...
  vrouter   Get vrouter control and forwarding plane...
```

### Usage

#### config
```sh
(ctrail) user@jump0:~$ ctrail config
2018-04-20 14:51:53,405 ERROR: request for http://localhost:35357/v3/auth/tokens?nocatalog failed: HTTPConnectionPool(host='localhost', port=35357): Max retries exceeded with url: /v3/auth/tokens?nocatalog (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x7f2655a29518>: Failed to establish a new connection: [Errno 111] Connection refused',))

(ctrail) user@jump0:~$ ctrail conf --help
Usage: ctrail conf [OPTIONS] [URLS]...

  Get configuration information from the Contrail config node.

  The config API requires authentication, you can either provide an
  OpenStack token via an environment variable or via the --os-token option
  or full OpenStack credentials, see:

  https://developer.openstack.org/api-guide/quick-start/api-quick-start.html
  https://docs.openstack.org/mitaka/install-guide-ubuntu/keystone-
  verify.html

  If no URLs are specified on the command line the default is to get
  `virtual-networks`. In order to see all the information the API provides
  pass `/` as the URL and then any of those options can be specified as an
  argument to the script, for example `service-instances`.

Options:
  -a, --address TEXT        The hostname or address of the config node (the
                            default is contrail0.
  -p, --port INTEGER
  --os-token TEXT           OpenStack AUTH token (will default to the OS_TOKEN
                            environment variable).
  --os-auth-url TEXT        Will default to the OS_AUTH_URL environment
                            variable.
  --os-user TEXT            Will default to the OS_USERNAME environment
                            variable.
  --os-pass TEXT            Will default to the OS_PASSWORD environment
                            variable.
  --os-user-domain TEXT     Will default to the OS_USER_DOMAIN_NAME
                            environment variable.
  --os-project TEXT         Will default to the OS_PROJECT_NAME environment
                            variable.
  --os-project-domain TEXT  Will default to the OS_PROJECT_DOMAIN_NAME
                            environment variable.
  --help                    Show this message and exit.

(ctrail) user@jump0:~$ source ~/.config/openstack/admin.vars

(ctrail) user@jump0:~$ ctrail conf
virtual-network: default-domain:acmecorp:net-acmevpn    uuid: bdbf634c-778c-446a-932c-5462601efb2b
    routing_instance: default-domain:acmecorp:net-acmevpn:net-acmevpn    uuid: f1e8ea0c-6df8-4d4a-b768-99a3c64733cd

virtual-network: default-domain:default-project:__link_local__    uuid: 80bb2162-b306-43ba-8d4a-ce6ae6d8df6c
    routing_instance: default-domain:default-project:__link_local__:__link_local__    uuid: 30654205-8e86-42d1-840f-5176abbffae8

virtual-network: default-domain:default-project:default-virtual-network    uuid: ef571173-eb56-450f-99c4-2888a1e9c2a4
    routing_instance: default-domain:default-project:default-virtual-network:default-virtual-network    uuid: 49047275-d8d4-42d0-bbd3-d5caa9f89a53

virtual-network: default-domain:default-project:ip-fabric    uuid: 1e562439-8552-43cd-a441-4031a603a647
    routing_instance: default-domain:default-project:ip-fabric:__default__    uuid: 68895ecb-5f41-42fb-be9a-f332320a8425
```

#### control
```sh
(ctrail) user@jump0:~$ ctrail control
control node routes:
    routing_instance: default-domain:acmecorp:net-acmevpn:net-acmevpn routing_table_name: default-domain:acmecorp:net-acmevpn:net-acmevpn.ermvpn.0
        0-10.23.0.26:1-0.0.0.0,255.255.255.255,0.0.0.0 paths:
            next_hop: 10.23.0.26 label: 0 protocol: XMPP source: compute0 origin_vn: default-domain:acmecorp:net-acmevpn
                communities: encapsulation:gre, encapsulation:udp
                tunnel_encap: gre, udp secondary_tables: n/a
        0-10.23.0.28:1-0.0.0.0,255.255.255.255,0.0.0.0 paths:
            next_hop: 10.23.0.28 label: 0 protocol: XMPP source: compute2 origin_vn: default-domain:acmecorp:net-acmevpn
                communities: encapsulation:gre, encapsulation:udp
                tunnel_encap: gre, udp secondary_tables: n/a
        1-0:0-10.23.0.23,255.255.255.255,0.0.0.0 paths:
            next_hop: 10.23.0.23 label: 0 protocol: Local source: None origin_vn: default-domain:acmecorp:net-acmevpn
                communities: n/a
                tunnel_encap: n/a secondary_tables: bgp.ermvpn.0

    routing_instance: default-domain:acmecorp:net-acmevpn:net-acmevpn routing_table_name: default-domain:acmecorp:net-acmevpn:net-acmevpn.inet.0
        10.0.90.3/32 paths:
            next_hop: 10.23.0.26 label: 18 protocol: XMPP source: compute0 origin_vn: default-domain:acmecorp:net-acmevpn
                communities: encapsulation:gre, encapsulation:udp, mobility:1, secgroup:64512:8000002
                tunnel_encap: gre, udp secondary_tables: bgp.l3vpn.0
        10.0.90.4/32 paths:
            next_hop: 10.23.0.28 label: 17 protocol: XMPP source: compute2 origin_vn: default-domain:acmecorp:net-acmevpn
                communities: encapsulation:gre, encapsulation:udp, mobility:1, secgroup:64512:8000002
                tunnel_encap: gre, udp secondary_tables: bgp.l3vpn.0

    routing_instance: default-domain:default-project:ip-fabric:__default__ routing_table_name: bgp.ermvpn.0
        1-10.23.0.28:1-10.23.0.23,255.255.255.255,0.0.0.0 paths:
            next_hop: 10.23.0.23 label: 0 protocol: Local source: None origin_vn: default-domain:acmecorp:net-acmevpn
                communities: target:64512:9090, target:64512:8000001, originvn:64512:4
                tunnel_encap: n/a secondary_tables: n/a

    routing_instance: default-domain:default-project:ip-fabric:__default__ routing_table_name: bgp.l3vpn.0
        10.23.0.26:1:10.0.90.3/32 paths:
            next_hop: 10.23.0.26 label: 18 protocol: XMPP source: compute0 origin_vn: default-domain:acmecorp:net-acmevpn
                communities: target:64512:9090, target:64512:8000001, encapsulation:gre, encapsulation:udp, mobility:1, secgroup:64512:8000002, originvn:64512:4
                tunnel_encap: gre, udp secondary_tables: n/a
        10.23.0.28:1:10.0.90.4/32 paths:
            next_hop: 10.23.0.28 label: 17 protocol: XMPP source: compute2 origin_vn: default-domain:acmecorp:net-acmevpn
                communities: target:64512:9090, target:64512:8000001, encapsulation:gre, encapsulation:udp, mobility:1, secgroup:64512:8000002, originvn:64512:4
                tunnel_encap: gre, udp secondary_tables: n/a

    routing_instance: default-domain:default-project:ip-fabric:__default__ routing_table_name: bgp.rtarget.0
        64512:target:64512:9030 paths:
            next_hop: 10.23.0.23 label: 0 protocol: XMPP source: compute0 origin_vn: default-domain:default-project:ip-fabric
                communities: n/a
                tunnel_encap: n/a secondary_tables: n/a
            next_hop: 10.23.0.23 label: 0 protocol: XMPP source: compute2 origin_vn: default-domain:default-project:ip-fabric
                communities: n/a
                tunnel_encap: n/a secondary_tables: n/a
        64512:target:64512:9040 paths:
            next_hop: 10.23.0.23 label: 0 protocol: XMPP source: compute0 origin_vn: default-domain:default-project:ip-fabric
                communities: n/a
                tunnel_encap: n/a secondary_tables: n/a
            next_hop: 10.23.0.23 label: 0 protocol: XMPP source: compute2 origin_vn: default-domain:default-project:ip-fabric
                communities: n/a
                tunnel_encap: n/a secondary_tables: n/a
        64512:target:64512:8000001 paths:
            next_hop: 10.23.0.23 label: 0 protocol: XMPP source: compute0 origin_vn: default-domain:default-project:ip-fabric
                communities: n/a
                tunnel_encap: n/a secondary_tables: n/a
            next_hop: 10.23.0.23 label: 0 protocol: XMPP source: compute2 origin_vn: default-domain:default-project:ip-fabric
                communities: n/a
                tunnel_encap: n/a secondary_tables: n/a

(ctrail) user@jump0:~$ ctrail control --rt acmevpn.inet.0
control node routes:
    routing_instance: default-domain:acmecorp:net-acmevpn:net-acmevpn routing_table_name: default-domain:acmecorp:net-acmevpn:net-acmevpn.inet.0
        10.0.90.3/32 paths:
            next_hop: 10.23.0.26 label: 18 protocol: XMPP source: compute0 origin_vn: default-domain:acmecorp:net-acmevpn
                communities: encapsulation:gre, encapsulation:udp, mobility:1, secgroup:64512:8000002
                tunnel_encap: gre, udp secondary_tables: bgp.l3vpn.0
        10.0.90.4/32 paths:
            next_hop: 10.23.0.28 label: 17 protocol: XMPP source: compute2 origin_vn: default-domain:acmecorp:net-acmevpn
                communities: encapsulation:gre, encapsulation:udp, mobility:1, secgroup:64512:8000002
                tunnel_encap: gre, udp secondary_tables: bgp.l3vpn.0
```

#### vrouter agent
```sh
(ctrail) user@jump0:~$ ctrail vrouter --help
Usage: ctrail vrouter [OPTIONS] COMMAND [ARGS]...

  Get vrouter control and forwarding plane information.

Options:
  --help  Show this message and exit.

Commands:
  agent   Get vrouter agent control plane information.
  kernel  Get vrouter kernel forwarding plane...

(ctrail) user@jump0:~$ ctrail vrouter agent --help
Usage: ctrail vrouter agent [OPTIONS]

  Get vrouter agent control plane information.

Options:
  -a, --address TEXT  The hostname or address of the compute node (the default
                      is compute0).
  -p, --port INTEGER
  --vrfs TEXT         The id of a specific VRF routing-table to show it's
                      routes (can be specified multiple times).
  --acls              Show only access-lists.
  --help              Show this message and exit.

(ctrail) user@jump0:~$ ctrail vrouter agent
vrouter agent interfaces:
    name: eth-flat index: 0 vrf_name: default-domain:default-project:ip-fabric:__default__ vn_name: None vm_name: None vm_uuid: None
        admin_state: Enabled active: Active ipv4_active: Active ip6_active: Inactive l2_active: L2 Active
        type: eth label: -1 l2_label: -1 mac_addr: None ip_addr: None ip6_addr: --NA--

    name: tap840e81f6-8f index: 3 vrf_name: default-domain:acmecorp:net-acmevpn:net-acmevpn vn_name: default-domain:acmecorp:net-acmevpn vm_name: acmevpn-a-2 vm_uuid: 761eca57-ac5a-4923-83bf-ed4c440247eb
        admin_state: Enabled active: Active ipv4_active: Active ip6_active: Ipv6 Inactive < no-ipv6-addr  > l2_active: L2 Inactive < l2-disabled  >
        type: vport label: 18 l2_label: -1 mac_addr: 02:84:0e:81:f6:8f ip_addr: 10.0.90.3 ip6_addr: ::

    name: vhost0 index: 1 vrf_name: default-domain:default-project:ip-fabric:__default__ vn_name: None vm_name: None vm_uuid: None
        admin_state: Enabled active: Active ipv4_active: Active ip6_active: Inactive l2_active: L2 Inactive
        type: vhost label: -1 l2_label: -1 mac_addr: None ip_addr: None ip6_addr: --NA--

    name: pkt0 index: 2 vrf_name: --ERROR-- vn_name: None vm_name: None vm_uuid: None
        admin_state: Enabled active: Active ipv4_active: Active ip6_active: Inactive l2_active: L2 Active
        type: pkt label: -1 l2_label: -1 mac_addr: None ip_addr: None ip6_addr: --NA--

# ... output omitted ...

vrouter agent vrfs:
    name: default-domain:acmecorp:net-acmevpn:net-acmevpn RD: 10.23.0.26:1 vn: default-domain:acmecorp:net-acmevpn

    name: default-domain:default-project:ip-fabric:__default__ RD: 10.23.0.26:0 vn: N/A

vrouter agent next-hops:
    nh_index: 1 type: discard ref_count: 2 itf: n/a vrf: n/a
        mac: n/a sip: n/a valid: true policy: disabled

    nh_index: 3 type: l2-receive ref_count: 4 itf: n/a vrf: n/a
        mac: n/a sip: n/a valid: true policy: disabled

    nh_index: 5 type: receive ref_count: 5 itf: vhost0 vrf: n/a
        mac: n/a sip: n/a valid: true policy: disabled

    nh_index: 6 type: receive ref_count: 1 itf: vhost0 vrf: n/a
        mac: n/a sip: n/a valid: true policy: enabled

    nh_index: 9 type: resolve ref_count: 1 itf: n/a vrf: n/a
        mac: n/a sip: n/a valid: true policy: disabled

    nh_index: 12 type: arp ref_count: 1 itf: eth-flat vrf: default-domain:default-project:ip-fabric:__default__
        mac: 2:0:0:fc:14:3 sip: 10.23.0.20 valid: true policy: disabled

    nh_index: 11 type: arp ref_count: 1 itf: eth-flat vrf: default-domain:default-project:ip-fabric:__default__
        mac: 2:0:0:fc:17:3 sip: 10.23.0.23 valid: true policy: disabled

    nh_index: 27 type: arp ref_count: 1 itf: eth-flat vrf: default-domain:default-project:ip-fabric:__default__
        mac: 2:0:0:fc:1b:3 sip: 10.23.0.27 valid: true policy: disabled

    nh_index: 28 type: arp ref_count: 1 itf: eth-flat vrf: default-domain:default-project:ip-fabric:__default__
        mac: 2:0:0:fc:1c:3 sip: 10.23.0.28 valid: true policy: disabled

    nh_index: 18 type: arp ref_count: 1 itf: eth-flat vrf: default-domain:default-project:ip-fabric:__default__
        mac: 2:0:0:fc:1d:3 sip: 10.23.0.29 valid: true policy: disabled

    nh_index: 10 type: arp ref_count: 1 itf: eth-flat vrf: default-domain:default-project:ip-fabric:__default__
        mac: 2:6:a:e:ff:f1 sip: 10.23.0.254 valid: true policy: disabled

    nh_index: 13 type: vrf ref_count: 1 itf: n/a vrf: default-domain:acmecorp:net-acmevpn:net-acmevpn
        mac: n/a sip: n/a valid: true policy: disabled

# ... output omitted ...

(ctrail) user@jump0:~$ ctrail v a --vrfs 1
vrouter agent IPv6 routes (vrf id 1):
    fe80::5e00:100/128 src_vrf: default-domain:acmecorp:net-acmevpn:net-acmevpn paths:
        nh_index: 7 label: -1 gw_ip: n/a peer: Local active_tunnel_type: MPLSoGRE vrf: n/a info: n/a
            dest_vn_list: default-domain:acmecorp:net-acmevpn
            communities: n/a

    ff02::1/128 src_vrf: default-domain:acmecorp:net-acmevpn:net-acmevpn paths:
        nh_index: 7 label: -1 gw_ip: n/a peer: Local active_tunnel_type: MPLSoGRE vrf: n/a info: n/a
            dest_vn_list: default-domain:acmecorp:net-acmevpn
            communities: n/a

    ff02::2/128 src_vrf: default-domain:acmecorp:net-acmevpn:net-acmevpn paths:
        nh_index: 7 label: -1 gw_ip: n/a peer: Local active_tunnel_type: MPLSoGRE vrf: n/a info: n/a
            dest_vn_list: default-domain:acmecorp:net-acmevpn
            communities: n/a

vrouter agent L2 routes (vrf id 1):
    mac: 00:00:5e:00:01:00 src_vrf: None paths:
        nh_index: 3 label: 0 gw_ip: n/a peer: Local_Vm active_tunnel_type: MPLSoGRE vrf: n/a info: n/a
            dest_vn_list: None
            communities: n/a

    mac: 02:00:00:fc:1a:03 src_vrf: None paths:
        nh_index: 3 label: 0 gw_ip: n/a peer: Local_Vm active_tunnel_type: MPLSoGRE vrf: n/a info: n/a
            dest_vn_list: None
            communities: n/a

    mac: 02:84:0e:81:f6:8f src_vrf: None paths:
        nh_index: 1 label: -1 gw_ip: n/a peer: MacVmBindingPeer active_tunnel_type: MPLSoGRE vrf: n/a info: n/a
            dest_vn_list: n/a
            communities: n/a

    mac: ff:ff:ff:ff:ff:ff src_vrf: None paths:
        nh_index: 25 label: 4610 gw_ip: n/a peer: Multicast active_tunnel_type: MPLSoGRE vrf: n/a info: n/a
            dest_vn_list: default-domain:acmecorp:net-acmevpn
            communities: n/a
        nh_index: 21 label: 17 gw_ip: n/a peer: Local_Vm active_tunnel_type: MPLSoGRE vrf: n/a info: n/a
            dest_vn_list: default-domain:acmecorp:net-acmevpn
            communities: n/a
        nh_index: 14 label: 17 gw_ip: n/a peer: Local active_tunnel_type: VXLAN vrf: n/a info: n/a
            dest_vn_list: default-domain:acmecorp:net-acmevpn
            communities: n/a
        nh_index: 24 label: 4610 gw_ip: n/a peer: MulticastTreeBuilder active_tunnel_type: MPLSoGRE vrf: n/a info: n/a
            dest_vn_list: default-domain:acmecorp:net-acmevpn
            communities: n/a

vrouter agent IPv4 routes (vrf id 1):
    10.0.90.0/24 src_vrf: default-domain:acmecorp:net-acmevpn:net-acmevpn paths:
        nh_index: 1 label: -1 gw_ip: n/a peer: Local active_tunnel_type: MPLSoGRE vrf: n/a info: n/a
            dest_vn_list: default-domain:acmecorp:net-acmevpn
            communities: n/a

    10.0.90.1/32 src_vrf: default-domain:acmecorp:net-acmevpn:net-acmevpn paths:
        nh_index: 8 label: -1 gw_ip: n/a peer: Local active_tunnel_type: MPLSoGRE vrf: n/a info: n/a
            dest_vn_list: default-domain:acmecorp:net-acmevpn
            communities: n/a

    10.0.90.2/32 src_vrf: default-domain:acmecorp:net-acmevpn:net-acmevpn paths:
        nh_index: 8 label: -1 gw_ip: n/a peer: Local active_tunnel_type: MPLSoGRE vrf: n/a info: n/a
            dest_vn_list: default-domain:acmecorp:net-acmevpn
            communities: n/a

    10.0.90.3/32 src_vrf: default-domain:acmecorp:net-acmevpn:net-acmevpn paths:
        nh_index: 19 label: 18 gw_ip: n/a peer: 10.23.0.23 active_tunnel_type: MPLSoGRE vrf: n/a info: n/a
            dest_vn_list: default-domain:acmecorp:net-acmevpn
            communities: n/a
        nh_index: 19 label: 18 gw_ip: n/a peer: LocalVmPort active_tunnel_type: MPLSoGRE vrf: n/a info: n/a
            dest_vn_list: default-domain:acmecorp:net-acmevpn
            communities: n/a

    10.0.90.4/32 src_vrf: default-domain:acmecorp:net-acmevpn:net-acmevpn paths:
        nh_index: 23 label: 17 gw_ip: n/a peer: 10.23.0.23 active_tunnel_type: MPLSoGRE vrf: n/a info: n/a
            dest_vn_list: default-domain:acmecorp:net-acmevpn
            communities: n/a

    169.254.169.254/32 src_vrf: default-domain:acmecorp:net-acmevpn:net-acmevpn paths:
        nh_index: 6 label: -1 gw_ip: n/a peer: LinkLocal active_tunnel_type: MPLSoGRE vrf: n/a info: n/a
            dest_vn_list: default-domain:acmecorp:net-acmevpn
            communities: n/a

(ctrail) user@jump0:~$ ctrail v a --acls
access-lists:
    name: default-domain:acmecorp:default:egress-access-control-list uuid: 79fecb91-7f63-4308-8671-d8fa440e1577 dynamic_acl: False
        ace_id: 1 rule_type: Terminal src_type: None src: None dst_type: ip dst: 0.0.0.0 0.0.0.0 uuid: 104b3a8a-4aad-4659-b0ec-946dd3316f59
            proto_l: min=0, max=255 src_port_l: min=0, max=65535 dst_port_l: min=0, max=65535
            action_l: pass
        ace_id: 2 rule_type: Terminal src_type: None src: None dst_type: ip dst: :: :: uuid: b3c16270-f02c-4aa5-b4c8-1c5f45d9e816
            proto_l: min=0, max=255 src_port_l: min=0, max=65535 dst_port_l: min=0, max=65535
            action_l: pass

    name: default-domain:acmecorp:default:ingress-access-control-list uuid: fe7527db-e4b3-4f6e-b8ea-4bb2dd08a05c dynamic_acl: False
        ace_id: 1 rule_type: Terminal src_type: sg src: 8000002 dst_type: None dst: None uuid: fd66cb29-52e4-4c7b-b963-0c90cc44df42
            proto_l: min=0, max=255 src_port_l: min=0, max=65535 dst_port_l: min=0, max=65535
            action_l: pass
        ace_id: 2 rule_type: Terminal src_type: sg src: 8000002 dst_type: None dst: None uuid: 866f6546-cf49-4625-a856-ea94219723cc
            proto_l: min=0, max=255 src_port_l: min=0, max=65535 dst_port_l: min=0, max=65535
            action_l: pass
```

#### vrouter kernel
```sh
(ctrail) user@jump0:~$ ctrail v k --help
Usage: ctrail v k [OPTIONS]

  Get vrouter kernel forwarding plane information.

Options:
  -a, --address TEXT  The hostname or address of the compute node (the default
                      is compute0).
  -p, --port INTEGER
  --vrfs TEXT         The id of a specific VRF routing-table to show it's
                      routes (can be specified multiple times).
  --flows             Show only flows active on the vrouter.
  --help              Show this message and exit.

(ctrail) user@jump0:~$ ctrail v k
mirror:
flows (active):
mpls:
    label: 17 nhid: 25 rid: 0

    label: 18 nhid: 19 rid: 0

    label: 4610 nhid: 25 rid: 0

vrf-stats:
next-hops (2):

# ... output omitted ...

    id: 16 type: ENCAP family: INVALID rid: 0 vrf: 1 flags: VALID ref_cnt: 2
        encap_family: ETH_P_ARP encap_oif_id: 3 encap_len: 14 encap: 02840e81f68f00005e0001000800

    id: 17 type: ENCAP family: INVALID rid: 0 vrf: 1 flags: VALID | POLICY ref_cnt: 1
        encap_family: ETH_P_ARP encap_oif_id: 3 encap_len: 14 encap: 02840e81f68f00005e0001000800

    id: 18 type: ENCAP family: AF_INET rid: 0 vrf: 0 flags: VALID ref_cnt: 2
        encap_family: ETH_P_ARP encap_oif_id: 0 encap_len: 14 encap: 020000fc1d03020000fc1a030800

    id: 19 type: ENCAP family: AF_INET rid: 0 vrf: 1 flags: VALID | POLICY ref_cnt: 4
        encap_family: ETH_P_ARP encap_oif_id: 3 encap_len: 14 encap: 02840e81f68f00005e0001000800

    id: 20 type: ENCAP family: AF_INET rid: 0 vrf: 1 flags: VALID ref_cnt: 1
        encap_family: ETH_P_ARP encap_oif_id: 3 encap_len: 14 encap: 02840e81f68f00005e0001000800

    id: 21 type: COMPOSITE family: AF_INET rid: 0 vrf: 1 flags: VALID ref_cnt: 2
        encap_family: n/a encap_oif_id: n/a encap_len: n/a encap: n/a

    id: 23 type: TUNNEL family: AF_INET rid: 0 vrf: 0 flags: VALID | TUNNEL_GRE ref_cnt: 3
        encap_family: INVALID encap_oif_id: 0 encap_len: 14 encap: 020000fc1c03020000fc1a030800
        tun_sip: 10.23.0.26 tun_dip: 10.23.0.28

    id: 24 type: COMPOSITE family: AF_INET rid: 0 vrf: 1 flags: VALID | FABRIC_MULTICAST ref_cnt: 2
        encap_family: n/a encap_oif_id: n/a encap_len: n/a encap: n/a

    id: 25 type: COMPOSITE family: INVALID rid: 0 vrf: 1 flags: VALID | L2_MULTICAST ref_cnt: 4
        encap_family: n/a encap_oif_id: n/a encap_len: n/a encap: n/a

    id: 27 type: ENCAP family: AF_INET rid: 0 vrf: 0 flags: VALID ref_cnt: 2
        encap_family: ETH_P_ARP encap_oif_id: 0 encap_len: 14 encap: 020000fc1b03020000fc1a030800

    id: 28 type: ENCAP family: AF_INET rid: 0 vrf: 0 flags: VALID ref_cnt: 2
        encap_family: ETH_P_ARP encap_oif_id: 0 encap_len: 14 encap: 020000fc1c03020000fc1a030800

drop stats:
    rid: 0 discard: 3327 nowhere_to_go: 0 ttl_exceeded: 6 misc: 0
        invalid_packet: 0 invalid_protocol: 0 invalid_label: 0 invalid_nh: 8 invalid_if: 0 invalid_vnid: 0 invalid_source: 0
        arp_not_me: 0 cksum_err: 0 cloned_original: 862 drop_new_flow: 0 duplicated: 0 flow_action_drop: 88046 flow_action_invalid: 0 flow_evict: 23 flow_invalid_protocol: 0
        flow_nat_no_rflow: 0 flow_no_memory: 0 flow_queue_limit_exceeded: 0 flow_table_full: 0 flow_unusable: 0 frag_err: 0 head_alloc_fail: 0 interface_drop: 78 interface_rx_discard: 0
        interface_tx_discard: 0 invalid_arp: 0 invalid_mcast_source: 0 l2_no_route: 56 mcast_clone_fail: 0 mcast_df_bit: 0 no_fmd: 0 no_memory: 0 pcow_fail: 0
        pull: 0 push: 0 rewrite_fail: 0 trap_no_if: 0 vlan_fwd_enq: 0 vlan_fwd_tx: 0 more: False

interfaces (2):
next-hops (1):
interfaces (1):
    name: eth-flat idx: 0 type: PHYSICAL vrf: 0 flags: None mtu: 1514
        ip: 0.0.0.0 mac: 02:00:00:fc:1a:03 src_mac: 00:00:00:00:00:00 nh_id: 0 vlan_id: 0
        ipackets: 98812754 ibytes: 114445314126 ierrors: 78 opackets: 231572439 obytes: 334187678989 oerrors: 0

    name: vhost0 idx: 1 type: HOST vrf: 0 flags: None mtu: 1514
        ip: 26.0.23.10 mac: 02:00:00:fc:1a:03 src_mac: 00:00:00:00:00:00 nh_id: 0 vlan_id: 0
        ipackets: 30735277 ibytes: 41328110988 ierrors: 0 opackets: 27164505 obytes: 10013020865 oerrors: 0

    name: pkt0 idx: 2 type: AGENT vrf: 65535 flags: None mtu: 1514
        ip: 0.0.0.0 mac: 00:00:5e:00:01:00 src_mac: 00:00:00:00:00:00 nh_id: 0 vlan_id: 0
        ipackets: 2032594 ibytes: 176763438 ierrors: 0 opackets: 1345488 obytes: 115861385 oerrors: 0

    name: tap840e81f6-8f idx: 3 type: VIRTUAL vrf: 1 flags: POLICY mtu: 9160
        ip: 3.90.0.10 mac: 00:00:5e:00:01:00 src_mac: 00:00:00:00:00:00 nh_id: 0 vlan_id: 0
        ipackets: 27679 ibytes: 1215062 ierrors: 0 opackets: 27688 obytes: 1218056 oerrors: 0

    name: NULL idx: 4350 type: INVALID vrf: 65535 flags: None mtu: 9136
        ip: 0.0.0.0 mac: 00:00:00:00:00:00 src_mac: 00:00:00:00:00:00 nh_id: 0 vlan_id: 0
        ipackets: 70253869 ibytes: 101305872122 ierrors: 0 opackets: 70253869 obytes: 100322317956 oerrors: 0

    name: NULL idx: 4351 type: INVALID vrf: 65535 flags: None mtu: 9136
        ip: 0.0.0.0 mac: 00:00:00:00:00:00 src_mac: 00:00:00:00:00:00 nh_id: 0 vlan_id: 0
        ipackets: 1309571 ibytes: 109980048 ierrors: 0 opackets: 1309574 obytes: 109980204 oerrors: 0

(ctrail) user@jump0:~$ ctrail v k --vrfs 1
routes (vrf id 1):
    0.0.0.0/8    vrf_id: 1 rid: 0 family: AF_INET nh_id: 0 label: 0 label_flags: --NONE-- index: 0

    1.0.0.0/8    vrf_id: 1 rid: 0 family: AF_INET nh_id: 0 label: 0 label_flags: --NONE-- index: 0

# ... output omitted ...

    10.0.89.0/24    vrf_id: 1 rid: 0 family: AF_INET nh_id: 0 label: 0 label_flags: --NONE-- index: 0

    10.0.90.0/32    vrf_id: 1 rid: 0 family: AF_INET nh_id: 1 label: 0 label_flags: PROXY-ARP index: 0

    10.0.90.1/32    vrf_id: 1 rid: 0 family: AF_INET nh_id: 8 label: 0 label_flags: PROXY-ARP index: 0

    10.0.90.2/32    vrf_id: 1 rid: 0 family: AF_INET nh_id: 8 label: 0 label_flags: PROXY-ARP index: 0

    10.0.90.3/32    vrf_id: 1 rid: 0 family: AF_INET nh_id: 19 label: 0 label_flags: PROXY-ARP index: 0

    10.0.90.4/32    vrf_id: 1 rid: 0 family: AF_INET nh_id: 23 label: 17 label_flags: MPLS PROXY-ARP index: 0

# ... output omitted ...

(ctrail) user@jump0:~$ ctrail v k -a compute0 --flows
flows (active):
    index: 39176 rflow: 448548 nhid: 19 underlay_udp_sport: 60257 insight: 0 ecmp_index: n/a
        action: FORWARD flags: ACTIVE | RFLOW_VALID vrf_id: 1 d_vrf_id: 0 qos_id: -1 gen_id: 1 ttl: 0
        sip: 10.0.90.4 sport: 9508 dip: 10.0.90.3 dport: 0 proto: 1 tcp_seq: 0 bytes: 1176 pkts: 14

    index: 448548 rflow: 39176 nhid: 19 underlay_udp_sport: 52878 insight: 0 ecmp_index: n/a
        action: FORWARD flags: ACTIVE | RFLOW_VALID vrf_id: 1 d_vrf_id: 0 qos_id: -1 gen_id: 1 ttl: 0
        sip: 10.0.90.3 sport: 9508 dip: 10.0.90.4 dport: 0 proto: 1 tcp_seq: 0 bytes: 1372 pkts: 14

(ctrail) user@jump0:~$ ctrail v k -a compute1 --flows
flows (active):

(ctrail) user@jump0:~$ ctrail v k -a compute2 --flows
flows (active):
    index: 161028 rflow: 516176 nhid: 24 underlay_udp_sport: 64178 insight: 0 ecmp_index: n/a
        action: FORWARD flags: ACTIVE | RFLOW_VALID vrf_id: 1 d_vrf_id: 0 qos_id: -1 gen_id: 1 ttl: 0
        sip: 10.0.90.4 sport: 9508 dip: 10.0.90.3 dport: 0 proto: 1 tcp_seq: 0 bytes: 2156 pkts: 22

    index: 516176 rflow: 161028 nhid: 24 underlay_udp_sport: 61079 insight: 0 ecmp_index: n/a
        action: FORWARD flags: ACTIVE | RFLOW_VALID vrf_id: 1 d_vrf_id: 0 qos_id: -1 gen_id: 1 ttl: 0
        sip: 10.0.90.3 sport: 9508 dip: 10.0.90.4 dport: 0 proto: 1 tcp_seq: 0 bytes: 1848 pkts: 22

(ctrail) user@jump0:~$ ctrail v k -a compute3 --flows
flows (active):
```

#### analytics (opserver)

```sh
(ctrail) user@jump0:~$ ctrail ops /
/:
    links:
        [0]:
            link:
                name = documentation
                href = http://contrail0:8081/documentation/index.html
        [1]:
            link:
                name = Message documentation
                href = http://contrail0:8081/documentation/messages/index.html
        [2]:
            link:
                name = analytics
                href = http://contrail0:8081/analytics
    href = http://contrail0:8081

(ctrail) user@jump0:~$ ctrail ops uves | egrep 'name ='
        name = storage-pools
        name = service-instances
        name = servers
        name = storage-disks
        name = service-chains
        name = generators
        name = bgp-peers
        name = physical-interfaces
        name = xmpp-peers
        name = storage-clusters
        name = analytics-nodes
        name = config-nodes
        name = virtual-machines
        name = control-nodes
        name = prouters
        name = database-nodes
        name = virtual-machine-interfaces
        name = virtual-networks
        name = logical-interfaces
        name = loadbalancers
        name = vrouters
        name = storage-osds
        name = routing-instances
        name = user-defined-log-statistics
        name = dns-nodes

(ctrail) user@jump0:~$ ctrail ops uves/virtual-machine-interfaces
uves/virtual-machine-interfaces:
    [0]:
        href = http://contrail0:8081/analytics/uves/virtual-machine-interface/default-domain:acmecorp:840e81f6-8fb2-4acf-aebb-4c9995273684?flat
        name = default-domain:acmecorp:840e81f6-8fb2-4acf-aebb-4c9995273684
    [1]:
        href = http://contrail0:8081/analytics/uves/virtual-machine-interface/default-domain:acmecorp:0cadb459-6c08-438f-838b-dcb9c161e382?flat
        name = default-domain:acmecorp:0cadb459-6c08-438f-838b-dcb9c161e382

(ctrail) user@jump0:~$ ctrail ops uves/virtual-machine-interface/default-domain:acmecorp:840e81f6-8fb2-4acf-aebb-4c9995273684 | egrep ' if_stats:' -A 11
        if_stats:
            [0]:
                [0]:
                    @stats = raw_if_stats:DSNon0:
                    @type = struct
                    @tags = vm_name,vm_uuid
                    VmInterfaceStats:
                        in_pkts = 32
                        out_pkts = 32
                        in_bytes = 2968
                        out_bytes = 2968
                [1] = compute0:Compute:contrail-vrouter-agent:0
```
