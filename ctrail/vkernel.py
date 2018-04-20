import logging

from copy import deepcopy

from ctrail.introspect import *


def print_kintf(x, filters=None, indent_level=0, indent='    ', verb=0):
    print_keys = (
        ['name', 'idx', 'type', 'vrf', 'flags', 'mtu'],
        ['ip', 'mac', 'src_mac', 'nh_id', 'vlan_id'],
        ['ipackets', 'ibytes', 'ierrors', 'opackets', 'obytes', 'oerrors']
    )

    if (filters is not None) and (not filter_generic(x, filters)):
        return 0

    return print_generic(x, print_keys=print_keys, indent_level=indent_level,
                         indent=indent)


def print_kvrf_stats(x, filters=None, indent_level=0, indent='    ', verb=0):
    print_keys = (
        ['vrf_id', 'vrf_family', 'vrf_rid'],
        ['vrf_udp_tunnels', 'vrf_udp_mpls_tunnels', 'vrf_gre_mpls_tunnels', 'vrf_vxlan_tunnels'],
        ['vrf_discards', 'vrf_resolves', 'vrf_receives', 'vrf_encaps', 'vrf_l2_encaps', 'vrf_l2_receives'],
    )

    if (filters is not None) and (not filter_generic(x, filters)):
        return 0

    return print_generic(x, print_keys=print_keys, indent_level=indent_level,
                         indent=indent)

def print_mpls(x, filters=None, indent_level=0, indent='    ', verb=0):
    print_keys = (
        ['label', 'nhid', 'rid'],
        [],
        []
    )

    if (filters is not None) and (not filter_generic(x, filters)):
        return 0

    return print_generic(x, print_keys=print_keys, indent_level=indent_level,
                         indent=indent, print_extra_keys=True)

def print_mirror(x, filters=None, indent_level=0, indent='    ', verb=0):
    print_keys = (
        ['mirr_index', 'mirr_rid', 'mirr_flags', 'mirr_users', 'mirr_nhid', 'mirr_vni'],
        [],
        []
    )

    if (filters is not None) and (not filter_generic(x, filters)):
        return 0

    return print_generic(x, print_keys=print_keys, indent_level=indent_level,
                         indent=indent, print_extra_keys=True)


def print_knh(x, filters=None, indent_level=0, indent='    ', verb=0):
    print_keys = (
        ['id', 'type', 'family', 'rid', 'vrf', 'flags', 'ref_cnt'],
        ['encap_family', 'encap_oif_id', 'encap_len', 'encap'],
        []
    )

    if (filters is not None) and (not filter_generic(x, filters)):
        return 0

    return print_generic(x, print_keys=print_keys, indent_level=indent_level,
                         indent=indent, print_extra_keys=True)


def print_flow(x, filters=None, indent_level=0, indent='    ', verb=0):
    print_keys = (
        ['index', 'rflow', 'nhid', 'underlay_udp_sport', 'insight', 'ecmp_index'],
        ['action', 'flags', 'vrf_id', 'd_vrf_id', 'qos_id', 'gen_id', 'ttl'],
        ['sip', 'sport', 'dip', 'dport', 'proto', 'tcp_seq', 'bytes', 'pkts']
    )

    if (filters is not None) and (not filter_generic(x, filters)):
        return 0

    return print_generic(x, print_keys=print_keys, indent_level=indent_level,
                         indent=indent, print_extra_keys=True)


def print_drops(x, filters=None, indent_level=0, indent='    ', verb=0):
    print_keys = (
        ['ds_rid', 'ds_discard','ds_nowhere_to_go', 'ds_ttl_exceeded', 'ds_misc'],
        ['ds_invalid_packet', 'ds_invalid_protocol', 'ds_invalid_label', 'ds_invalid_nh', 'ds_invalid_if', 'ds_invalid_vnid', 'ds_invalid_source'],
        []
    )
    ignore_keys = ['@type']
    max_keys_per_line = 8
    lines_printed = 0
    keys_printed = []

    if (filters is not None) and (not filter_generic(x, filters)):
        return 0

    for i, keys in enumerate(print_keys):
        if len(keys) > 0:
            print((indent_level + min(i, 1)) * indent, end='')
            for k in keys:
                print("{}: {} ".format(k.replace('ds_', ''), x.get(k, 'n/a')), end='')
                keys_printed.append(k)
            print()
            lines_printed += 1

    if len(x.keys()) > len(keys_printed):
        curr_line_keys = 0
        print((indent_level + 1) * indent, end='')
        for k in sorted([k for k in x.keys() if k not in keys_printed]):
            if curr_line_keys > max_keys_per_line:
                lines_printed += 1
                print()
                print((indent_level + 1) * indent, end='')
                curr_line_keys = 0
            if (k not in keys_printed) and (k not in ignore_keys):
                print("{}: {} ".format(k.replace('ds_', ''), x.get(k, 'n/a')), end='')
                curr_line_keys += 1
        print()
        lines_printed += 1

    return lines_printed


def print_kroute(x, filters=None, indent_level=0, indent='    ', verb=0):
    print_keys = (
        ['vrf_id', 'rid', 'family', 'nh_id', 'label', 'label_flags', 'index'],
        [],
        []
    )

    if (filters is not None) and (not filter_generic(x, filters)):
        return 0

    print("{}{}/{}".format(indent_level * indent, x['prefix'], x['prefix_len']),
          end='')
    return print_generic(x, print_keys=print_keys, indent_level=indent_level,
                         indent=indent)


def get_state(address, port, vrfs=(), flows=False, verb=0):
    dump = False
    introspect_requests = {
        'vrf-assign': {
            'url': 'Snh_KVrfAssignReq', 'print_func': None,
            'snh_keys': ['KVrfAssignResp', 'vrf_assign_list', '????'],
            'filters': None
        },
        'vrf-stats': {
            'url': 'Snh_KVrfStatsReq', 'print_func': print_kvrf_stats,
            'snh_keys': ['KVrfStatsResp', 'vrf_stats_list', 'KVrfStatsInfo'],
            'filters': None
        },
        'interfaces (1)': {
            'url': 'Snh_KInterfaceReq', 'print_func': print_kintf,
            'snh_keys': ['KInterfaceResp', 'if_list', 'KInterfaceInfo'],
            'filters': None
        },
        'interfaces (2)': {
            'url': 'Snh_KInterfaceReq', 'print_func': print_kintf,
            'snh_keys': ['__KInterfaceResp_list', 'KInterfaceResp', 'if_list', 'KInterfaceInfo'],
            'filters': None
        },
        'mpls': {
            'url': 'Snh_KMplsReq', 'print_func': print_mpls,
            'snh_keys': ['KMplsResp', 'mpls_list', 'KMplsInfo'],
            'filters': None
        },
        'mirror': {
            'url': 'Snh_KMirrorReq', 'print_func': print_mirror,
            'snh_keys': ['KMirrorResp', 'mirror_list', 'KMirrorInfo'],
            'filters': None
        },
        'next-hops (1)': {
            'url': 'Snh_KNHReq', 'print_func': print_knh,
            'snh_keys': ['KNHResp', 'nh_list', 'KNHInfo'],
            'filters': None
        },
        'next-hops (2)': {
            'url': 'Snh_KNHReq', 'print_func': print_knh,
            'snh_keys': ['__KNHResp_list', 'KNHResp', 'nh_list', 'KNHInfo'],
            'filters': None
        },
        'drop stats': {
            'url': 'Snh_KDropStatsReq', 'print_func': print_drops,
            'snh_keys': ['KDropStatsResp'],
            'filters': None
        },
        'flows (active)': {
            'url': 'Snh_KFlowReq', 'print_func': print_flow,
            'snh_keys': ['KFlowResp', 'flow_list', 'KFlowInfo'],
            'filters': None
        }
    }
    per_vrf_requests = {
        'routes': {
            'url_template': 'Snh_KRouteReq?vrf_id={}',
            'url': 'Snh_KRouteReq', 'print_func': print_kroute,
            'snh_keys': ['__KRouteResp_list', 'KRouteResp', 'rt_list', 'KRouteInfo'],
            'filters': None
        }
    }

    current_requests = introspect_requests

    if len(vrfs) > 0:
        generic_keys = list(per_vrf_requests.keys())
        for k in generic_keys:
            for vrf_id in vrfs:
                req_name = "{} (vrf id {})".format(k, vrf_id)
                req_url = per_vrf_requests[k]['url_template'].format(vrf_id)
                per_vrf_requests[req_name] = deepcopy(per_vrf_requests[k])
                per_vrf_requests[req_name]['url'] = req_url
            per_vrf_requests.pop(k) 
        current_requests = per_vrf_requests
    elif flows:
        current_requests = {'flows (active)': introspect_requests['flows (active)']}

    if verb > 2:
        dump = True

    sandesh_generic_requests(address, port, current_requests, dump, verb)
