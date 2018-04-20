import logging
import re

from ctrail.introspect import *


def print_path(x, filters=None, indent_level=0, indent='    ', verb=0):
    print_keys = (
        ['next_hop', 'label', 'protocol', 'source', 'origin_vn'],
        [],
        []
    )

    if (filters is not None) and (not filter_generic(x, filters)):
        return 0

    print(indent_level * indent, end='')
    for k in print_keys[0]:
        print("{}: {} ".format(k, x.get(k, 'n/a')), end='')
    print()
    if 'element' in x['communities']:
        communities_text = ', '.join([y for y in x['communities']['element']])
    else:
        communities_text = 'n/a'
    if 'element' in x['tunnel_encap']:
        tunnel_encap_text = ', '.join([y for y in x['tunnel_encap']['element']])
    else:
        tunnel_encap_text = 'n/a'
    if 'element' in x['secondary_tables']:
        secondary_tables_text = ', '.join([y for y in x['secondary_tables']['element']])
    else:
        secondary_tables_text = 'n/a'
    print("{}communities: {}".format((indent_level + 1) * indent, communities_text))
    print("{}tunnel_encap: {} secondary_tables: {}"
          "".format((indent_level + 1) * indent, tunnel_encap_text,
                    secondary_tables_text))
          
    return 3


def print_route(x, filters=None, indent_level=0, indent='    ', verb=0):

    if (filters is not None) and (not filter_generic(x, filters)):
        return 0

    print("{}{} paths:".format(indent_level * indent, x['prefix']))

    for p in x['paths']['ShowRoutePath']:
        print_path(p, filters=filters, indent_level=(indent_level + 1), indent=indent)

    return (1 + len(x['paths']['ShowRoutePath']))


def print_rtable(x, filters=None, indent_level=0, indent='    ', verb=0):
    print_keys = (
        ['routing_instance', 'routing_table_name'],
        [],
        []
    )

    if (filters is not None) and (not filter_generic(x, filters)):
        return 0
    
    print_generic(x, print_keys=print_keys, indent_level=indent_level,
                  indent=indent)

    for r in x['routes']['ShowRoute']:
        print_route(r, filters=None, indent_level=(indent_level + 1), indent=indent)

    return (1 + len(x['routes']['ShowRoute']))


def get_state(address, port, ri=(), rt=(), verb=0):
    dump = False
    introspect_requests = {
        'control node routes': {
            'url': 'Snh_ShowRouteReq', 'print_func': print_rtable,
            'snh_keys': ['ShowRouteResp', 'tables', 'ShowRouteTable'],
            'filters': None
        }
    }

    if len(ri) > 0:
        if introspect_requests['control node routes']['filters'] is None: 
            introspect_requests['control node routes']['filters'] = {} 
        introspect_requests['control node routes']['filters']['routing_instance'] = \
                [re.compile(x) for x in ri]

    if len(rt) > 0:
        if introspect_requests['control node routes']['filters'] is None: 
            introspect_requests['control node routes']['filters'] = {} 
        introspect_requests['control node routes']['filters']['routing_table_name'] = \
                [re.compile(x) for x in rt]

    if verb > 2:
        dump = True

    sandesh_generic_requests(address, port, introspect_requests, dump, verb)
