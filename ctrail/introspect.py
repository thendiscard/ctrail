import logging

import requests
import xmltodict


def dump_tree(node_name, node, indent_level=0, indent='    ', verb=1):

    if isinstance(node, dict):
        if verb > 0:
            print("{}{} (dict):".format(indent_level * indent, node_name))
        else:
            print("{}{}:".format(indent_level * indent, node_name))
        for k, v in node.items():
            dump_tree(k, v, indent_level=(indent_level + 1), indent=indent,
                      verb=verb)
    elif isinstance(node, list):
        if verb > 0:
            print("{}{} (list):".format(indent_level * indent, node_name))
        else:
            print("{}{}:".format(indent_level * indent, node_name))
        for i, v in enumerate(node):
            dump_tree("[{}]".format(i), v, indent_level=(indent_level + 1),
                      indent=indent, verb=verb)
    else:
        print("{}{} = {}".format(indent_level * indent, node_name, node))


def sandesh_pythonize(node):
    int_types = ['i16', 'i32', 'i64', 'i128', 'u16', 'u32', 'u64', 'u128',
                 'byte']

    if isinstance(node, dict):
        if '@type' in node:
            if node['@type'] in int_types:
                if '#text' in node:
                    try:
                        node_val = int(node['#text'])
                        return node_val
                    except ValueError as err:
                        return None
                else:
                    return None

            elif node['@type'] == 'string':
                if '#text' in node:
                    return str(node['#text'])
                else:
                    return None

            elif node['@type'] == 'bool':
                if ('#text' in node) and (node['#text'].lower() == 'true'):
                    return True
                elif ('#text' in node) and (node['#text'].lower() == 'false'):
                    return False
                else:
                    return None

            elif node['@type'] == 'list':
                if ('list' in node) and isinstance(node['list'], dict):
                    list_keys = [k for k in node['list'].keys()
                                    if not k.startswith('@')]
                    if len(list_keys) == 1:
                        actual_list = node['list'][list_keys[0]]
                        if isinstance(actual_list, list):
                            node[list_keys[0]] = actual_list
                        else:
                            node[list_keys[0]] = [actual_list]
                        node['list'] = '__moved_up__'

        for k, v in node.items():
            node[k] = sandesh_pythonize(v)

    elif isinstance(node, list):
        for i, v in enumerate(node):
            node[i] = sandesh_pythonize(v)

    return node


def sandesh_generic_requests(host, port, introspect_requests, dump=False, verb=0):
    all_data = {}
    s = requests.Session()
    headers = {
        # Although we would have preferred to work with JSON encoded data,
        # currently the API only returns XML
        # 'Content-Type': 'application/json; charset=UTF-8'
        'Content-Type': 'text/xml; charset=UTF-8'
    }

    s.headers.update(headers)

    for rname, rinfo in introspect_requests.items():
        url_full = "http://{}:{}/{}".format(host, port, rinfo['url'])
        try:
            resp = s.get(url_full)
        except Exception as err:
            logging.error("request for {} failed: {}".format(rinfo['url'], err))
            continue
        if resp.status_code != requests.codes.ok:
            logging.error("request for {} failed: {}".format(rinfo['url'], r.text))
            continue

        resp_data = xmltodict.parse(resp.text)
        snh_data = sandesh_pythonize(resp_data)
        all_data[rname] = snh_data

        if dump:
            if verb > 0:
                dump_tree(rname, resp_data, verb=(verb - 1))
            else:
                dump_tree(rname, snh_data, verb=0)
            continue

        if rinfo['print_func'] is not None:
            snh_keys = rinfo['snh_keys']
            print("{}:".format(rname))

            if len(snh_keys) == 1:
                if snh_keys[0] in snh_data:
                    x = snh_data[snh_keys[0]]
                    if rinfo['print_func'](x, filters=rinfo['filters'],
                                               indent_level=1, verb=verb) > 0:
                        print()

            elif len(snh_keys) == 3:
                if ((snh_keys[0] in snh_data)
                        and (snh_keys[1] in snh_data[snh_keys[0]])
                        and (snh_keys[2] in snh_data[snh_keys[0]][snh_keys[1]])):

                    for x in snh_data[snh_keys[0]][snh_keys[1]][snh_keys[2]]:
                        if rinfo['print_func'](x, filters=rinfo['filters'],
                                               indent_level=1, verb=verb) > 0:
                            print()

            elif len(snh_keys) == 4:
                if ((snh_keys[0] in snh_data)
                        and (snh_keys[1] in snh_data[snh_keys[0]])):

                    z = snh_data[snh_keys[0]][snh_keys[1]]
                    if isinstance(z, list):
                        for y in z:
                            for x in y[snh_keys[2]][snh_keys[3]]:
                                if rinfo['print_func'](x, filters=rinfo['filters'],
                                                       indent_level=1, verb=verb) > 0:
                                    print()
                    else:
                        for x in z[snh_keys[2]][snh_keys[3]]:
                            if rinfo['print_func'](x, filters=rinfo['filters'],
                                                   indent_level=1, verb=verb) > 0:
                                print()

    return all_data


def filter_generic(x, filters):

    for k, regexpen in filters.items():
        if k in x:
            curr_matches = 0
            for regex in regexpen:
                if regex.search(x[k]) is not None:
                    curr_matches += 1
            if curr_matches == 0:
                return False
            else:
                return True


def print_generic(x, print_keys=(), indent_level=0, indent='    ', print_extra_keys=False):
    lines_printed = 0
    keys_printed = []

    for i, keys in enumerate(print_keys):
        if len(keys) > 0:
            print((indent_level + min(i, 1)) * indent, end='')
            for k in keys:
                print("{}: {} ".format(k, x.get(k, 'n/a')), end='')
                keys_printed.append(k)
            print()
            lines_printed += 1

    if print_extra_keys and (len(x.keys()) > len(keys_printed)):
        print((indent_level + 1) * indent, end='')
        for k in x.keys():
            if k not in keys_printed:
                print("{}: {} ".format(k, x.get(k, 'n/a')), end='')
        print()
        lines_printed += 1

    return lines_printed


def ord_dict_prettify(x, hide_key_names = ()):
    pairs = []

    for k, v in x.items():
        if k in hide_key_names:
            pairs.append("{}".format(v))
        else:
            pairs.append("{}={}".format(k, v))

    return ", ".join(pairs)
