import logging
import pprint

import requests
import ctrail.introspect as introspect


def get(address, port, token, urls, verb=0):
    headers = {
        'X-Auth-Token': token, 
        'Content-Type': 'application/json; charset=UTF-8'
    }
    url_template = "http://{}:{}/analytics/{}"

    s = requests.Session()
    s.headers.update(headers)
    for url in urls:
        if url == '/':
            url_full = "http://{}:{}/".format(address, port)
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
        else:
            data = introspect.sandesh_pythonize(r.json())
            introspect.dump_tree(url, data, verb=verb)


def query(address, port, token, query, verb=0):
    headers = {
        'X-Auth-Token': token, 
        'Content-Type': 'application/json; charset=UTF-8'
    }
    url_template = "http://{}:{}/analytics/query"

    s = requests.Session()
    s.headers.update(headers)
    url_full = url_template.format(address, port)
    if verb >=2:
        pprint.pprint(query)
    r = s.post(url_full, json=query)
    if r.status_code != requests.codes.ok:
        logging.error("query POST request failed")
        logging.debug(str(r.text))
        return

    if verb > 2:
        data = r.json()
        pprint.pprint(data)
    elif verb == 2:
        data = introspect.sandesh_pythonize(r.json())
        pprint.pprint(data)
    else:
        data = introspect.sandesh_pythonize(r.json())
        introspect.dump_tree('query', data, verb=verb)
