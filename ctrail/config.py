import logging
import pprint
import re

import requests
import ctrail.introspect as introspect


def print_routing_instance(ri, indent_level=0, indent='    ', verb=0):

    print(indent_level * indent, end='')
    print("routing_instance: {}{}uuid: {}".format(':'.join(ri['to']),
                                                max(indent_level, 1) * indent,
                                                ri['uuid']))


def print_virtual_network(vn, indent_level=0, indent='    ', verb=0):

    print(indent_level * indent, end='')
    print("virtual-network: {}{}uuid: {}".format(':'.join(vn['fq_name']),
                                                 max(indent_level, 1) * indent,
                                                 vn['uuid']))
    if 'vn_details' in vn:
        for ri in vn['vn_details']['virtual-network']['routing_instances']:
            print_routing_instance(ri, indent_level + 1, indent)
    
    print()


def process_virtual_networks(session, vns_data):

    for vn in vns_data['virtual-networks']:
        if 'href' in vn:
            resp = session.get(vn['href'])
            if resp.status_code != requests.codes.ok:
                logging.error("request for {} failed: {}".format(vn['href'], resp.text))
                continue
            vn['vn_details'] = resp.json()
            print_virtual_network(vn)


def get(address, port, token, urls, verb=0):
    headers = {
        'X-Auth-Token': token, 
        'Content-Type': 'application/json; charset=UTF-8'
    }
    url_template = "http://{}:{}/{}"

    s = requests.Session()
    s.headers.update(headers)
    for url in urls:
        if url == '/':
            url_full = url_template.format(address, port, '')
        else:
            url_full = url_template.format(address, port, url)
        try:
            r = s.get(url_full)
        except Exception as err:
            logging.error("request for {} failed: {}".format(url, err))
            continue
        if r.status_code != requests.codes.ok:
            logging.error("request for {} failed: {}".format(url, r.text))
            continue

        if verb > 2:
            data = r.json()
            pprint.pprint(data)
        elif verb == 2:
            data = introspect.sandesh_pythonize(r.json())
            pprint.pprint(data)
        elif verb == 1:
            data = introspect.sandesh_pythonize(r.json())
            introspect.dump_tree(url, data, verb=verb)
        else:
            data = r.json()
            if url == 'virtual-networks':
                process_virtual_networks(s, data)
            else:
                introspect.dump_tree(url, data, verb=verb)
