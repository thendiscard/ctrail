import logging

from copy import deepcopy

from ctrail.introspect import *


def print_agent_vrfs(x, filters=None, indent_level=0, indent='    ', verb=0):
    print_keys = (
        ['name', 'RD', 'vn'],
        [],
        []
    )

    if (filters is not None) and (not filter_generic(x, filters)):
        return 0

    return print_generic(x, print_keys=print_keys, indent_level=indent_level,
                         indent=indent)


def print_agent_intfs(x, filters=None, indent_level=0, indent='    ', verb=0):
    print_keys = (
        ['name', 'index', 'vrf_name', 'vn_name', 'vm_name', 'vm_uuid'],
        ['admin_state', 'active', 'ipv4_active', 'ip6_active', 'l2_active'],
        ['type', 'label', 'l2_label', 'mac_addr', 'ip_addr', 'ip6_addr']
    )

    if (filters is not None) and (not filter_generic(x, filters)):
        return 0

    return print_generic(x, print_keys=print_keys, indent_level=indent_level,
                         indent=indent)


def print_agent_nhs(x, filters=None, indent_level=0, indent='    ', verb=0):
    print_keys = (
        ['nh_index', 'type', 'ref_count', 'itf', 'vrf'],
        ['mac', 'sip', 'valid', 'policy'],
        []
    )

    if (filters is not None) and (not filter_generic(x, filters)):
        return 0

    return print_generic(x, print_keys=print_keys, indent_level=indent_level,
                         indent=indent)


def print_agent_acl(x, filters=None, indent_level=0, indent='    ', verb=0):
    print_keys = (
        ['name', 'uuid', 'dynamic_acl'],
        [],
        []
    )

    if (filters is not None) and (not filter_generic(x, filters)):
        return 0

    print("{}".format(indent_level * indent), end='')
    for k in print_keys[0]:
        print("{}: {} ".format(k, x.get(k, 'n/a')), end='')
    print()

    for ace in x['entries']['AclEntrySandeshData']:
        print_agent_ace(ace, indent_level=(indent_level + 1), indent=indent)

    return (1 + len(x['entries']['AclEntrySandeshData']))


def print_agent_ace(x, filters=None, indent_level=0, indent='    ', verb=0):
    print_keys = (
        ['ace_id', 'rule_type', 'src_type', 'src', 'dst_type', 'dst', 'uuid'],
        ['proto_l', 'src_port_l', 'dst_port_l'],
        ['action_l']
    )

    if (filters is not None) and (not filter_generic(x, filters)):
        return 0

    print("{}".format(indent_level * indent), end='')
    for k in print_keys[0]:
        print("{}: {} ".format(k, x.get(k, 'n/a')), end='')
    print()

    for key_line in print_keys[1:]:
        print("{}".format((indent_level + 1) * indent), end='')
        for k in key_line:
            key_text = 'n/a'
            if ('SandeshRange' in x[k]) and isinstance(x[k]['SandeshRange'], list):
                key_list = x[k]['SandeshRange']
                key_text = ', '.join([ord_dict_prettify(le, hide_key_names=('action')) for le in key_list])
            elif ('ActionStr' in x[k]) and isinstance(x[k]['ActionStr'], list):
                key_list = x[k]['ActionStr']
                key_text = ', '.join([ord_dict_prettify(le, hide_key_names=('action')) for le in key_list])

            print("{}: {} ".format(k, key_text), end='')
        print()

    return 3


def print_agent_route(x, filters=None, indent_level=0, indent='    ', verb=0):

    if (filters is not None) and (not filter_generic(x, filters)):
        return 0

    if 'src_ip' in x:
        print("{}{}/{} src_vrf: {} paths:".format(indent_level * indent, x['src_ip'],
                                                  x['src_plen'], x['src_vrf']))
    elif ('mac' in x):
        print("{}mac: {} src_vrf: {} paths:".format(indent_level * indent, x['mac'],
                                                    x['src_vrf']))
    else:
        print("{}???? src_vrf: {} paths:".format(indent_level * indent, x['src_vrf']))

    for p in x['path_list']['PathSandeshData']:
        print_agent_path(p, indent_level=(indent_level + 1), indent=indent)

    return (1 + len(x['path_list']['PathSandeshData']))


def print_agent_path(x, filters=None, indent_level=0, indent='    ', verb=0):
    print_keys = (
        ['label', 'gw_ip', 'peer', 'active_tunnel_type', 'vrf', 'info'],
        [],
        []
    )

    if (filters is not None) and (not filter_generic(x, filters)):
        return 0

    print("{}nh_index: {} ".format(indent_level * indent,
                                   x['nh']['NhSandeshData']['nh_index']),
          end='')
    for k in print_keys[0]:
        print("{}: {} ".format(k, x.get(k, 'n/a')), end='')
    print()
    if 'element' in x['dest_vn_list']:
        dest_vn_list_text = ', '.join([str(y) for y in x['dest_vn_list']['element']])
    else:
        dest_vn_list_text = 'n/a'
    if 'element' in x['communities']:
        communities_text = ', '.join([str(y) for y in x['communities']['element']])
    else:
        communities_text = 'n/a'
    print("{}dest_vn_list: {}".format((indent_level + 1) * indent, dest_vn_list_text))
    print("{}communities: {}".format((indent_level + 1) * indent, communities_text))
          
    return 3


def get_state(address, port, vrf_ids=(), acls=False, verb=0):
    dump = False
    introspect_requests = {
        'vrouter agent vrfs': {
            'url': 'Snh_VrfListReq', 'print_func': print_agent_vrfs,
            'snh_keys': ['__VrfListResp_list', 'VrfListResp', 'vrf_list', 'VrfSandeshData'],
            'filters': None
        },
        'vrouter agent interfaces': {
            'url': 'Snh_ItfReq', 'print_func': print_agent_intfs,
            'snh_keys': ['__ItfResp_list', 'ItfResp', 'itf_list', 'ItfSandeshData'],
            'filters': None
        },
        'vrouter agent next-hops': {
            'url': 'Snh_NhListReq', 'print_func': print_agent_nhs,
            'snh_keys': ['__NhListResp_list', 'NhListResp', 'nh_list', 'NhSandeshData'],
            'filters': None
        },
        'access-lists' : {
            'url': 'Snh_AclReq', 'print_func': print_agent_acl,
            'snh_keys': ['__AclResp_list', 'AclResp', 'acl_list', 'AclSandeshData'],
            'filters': None
        }
    }
    per_vrf_requests = {
        'vrouter agent IPv4 routes': {
            'url_template': 'Snh_Inet4UcRouteReq?vrf_index={}',
            'url': 'Snh_Inet4UcRouteReq', 'print_func': print_agent_route,
            'snh_keys': ['__Inet4UcRouteResp_list', 'Inet4UcRouteResp', 'route_list', 'RouteUcSandeshData'],
            'filters': None
        },
        'vrouter agent IPv6 routes': {
            'url_template': 'Snh_Inet6UcRouteReq?vrf_index={}',
            'url': 'Snh_Inet6UcRouteReq', 'print_func': print_agent_route,
            'snh_keys': ['__Inet6UcRouteResp_list', 'Inet6UcRouteResp', 'route_list', 'RouteUcSandeshData'],
            'filters': None
        },
        'vrouter agent L2 routes': {
            'url_template': 'Snh_Layer2RouteReq?vrf_index={}',
            'url': 'Snh_Layer2RouteReq', 'print_func': print_agent_route,
            'snh_keys': ['__Layer2RouteResp_list', 'Layer2RouteResp', 'route_list', 'RouteL2SandeshData'],
            'filters': None
        },
    }

    current_requests = introspect_requests

    if len(vrf_ids):
        generic_keys = list(per_vrf_requests.keys())
        for k in generic_keys:
            for vrf_id in vrf_ids:
                req_name = "{} (vrf id {})".format(k, vrf_id)
                req_url = per_vrf_requests[k]['url_template'].format(vrf_id)
                per_vrf_requests[req_name] = deepcopy(per_vrf_requests[k])
                per_vrf_requests[req_name]['url'] = req_url
            per_vrf_requests.pop(k) 
        current_requests = per_vrf_requests
    elif acls:
        current_requests = {'access-lists': introspect_requests['access-lists']}

    if verb > 2:
        dump = True

    sandesh_generic_requests(address, port, current_requests, dump, verb)
