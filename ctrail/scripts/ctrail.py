import json

import click
import requests

import ctrail.config
import ctrail.control
import ctrail.vagent
import ctrail.vkernel
import ctrail.opserver

from ctrail.colorlogging import *


GLOBAL_OPTS = {
    'verbose': 0,
    'log_level': 'normal'
}


class AliasedGroup(click.Group):

    def get_command(self, ctx, cmd_name):
        rv = click.Group.get_command(self, ctx, cmd_name)
        if rv is not None:
            return rv
        matches = [x for x in self.list_commands(ctx)
                    if x.startswith(cmd_name)]
        if not matches:
            return None
        elif len(matches) == 1:
            return click.Group.get_command(self, ctx, matches[0])
        ctx.fail("{} is ambiguous, it maches multiple commands: {}"
                 "".format(cmd_name, ', '.join(sorted(matches))))


def os_get_token(os_auth_url, os_user, os_pass, os_user_domain, os_project,
                 os_project_domain):
    auth_data = {
        'auth': {
            'identity': {
                'methods': ['password'],
                'password': {
                    'user': {
                        'domain': { 'name': os_user_domain },
                        'name': os_user,
                        'password': os_pass
                    }
                }
            },
            'scope': {
                'project': {
                    'domain': { 'name': os_project_domain },
                    'name':  os_project
                }
            }
        }
    }
    auth_url_full = "{}/auth/tokens?nocatalog".format(os_auth_url)
    headers = { 'Content-Type': 'application/json; charset=UTF-8' }

    s = requests.Session()
    s.headers.update(headers)
    try:
        r = s.post(auth_url_full, json=auth_data)
    except Exception as err:
        error("request for {} failed: {}".format(auth_url_full, err))
        return None

    if r.status_code != requests.codes.created:
        error("request for {} failed: {}".format(auth_url_full, r.text))
        return None

    if ('X-Subject-Token' not in r.headers) or (len(r.headers['X-Subject-Token']) == 0):
        error("token is empty: {}".format(auth_url_full, r.text))
        return None

    return r.headers['X-Subject-Token']


@click.command()
@click.option('-a', '--address', default='contrail0',
              help='The hostname or address of the config node (the default '
                   'is contrail0.')
@click.option('-p', '--port', default=8082)
@click.option('--os-token', default='', envvar='OS_TOKEN',
              help='OpenStack AUTH token (will default to the OS_TOKEN '
                   'environment variable).')
@click.option('--os-auth-url', default='http://localhost:35357/v3', envvar='OS_AUTH_URL',
              help='Will default to the OS_AUTH_URL environment variable.')
@click.option('--os-user', envvar='OS_USERNAME',
              help='Will default to the OS_USERNAME environment variable.')
@click.option('--os-pass', envvar='OS_PASSWORD',
              help='Will default to the OS_PASSWORD environment variable.')
@click.option('--os-user-domain', envvar='OS_USER_DOMAIN_NAME',
              help='Will default to the OS_USER_DOMAIN_NAME environment variable.')
@click.option('--os-project', envvar='OS_PROJECT_NAME',
              help='Will default to the OS_PROJECT_NAME environment variable.')
@click.option('--os-project-domain', envvar='OS_PROJECT_DOMAIN_NAME',
              help='Will default to the OS_PROJECT_DOMAIN_NAME environment variable.')
@click.argument('urls', nargs=-1)
def config(address, port, os_token, os_auth_url, os_user, os_pass,
           os_user_domain, os_project, os_project_domain, urls):
    """Get configuration information from the Contrail config node.

    The config API requires authentication, you can either provide an OpenStack
    token via an environment variable or via the --os-token option or full
    OpenStack credentials, see:

    https://developer.openstack.org/api-guide/quick-start/api-quick-start.html
    https://docs.openstack.org/mitaka/install-guide-ubuntu/keystone-verify.html

    If no URLs are specified on the command line the default is to get `virtual-networks`.
    In order to see all the information the API provides pass `/` as the URL and
    then any of those options can be specified as an argument to the script, for
    example `service-instances`.
    """

    if len(urls) == 0:
        urls = ('virtual-networks',)

    if len(os_token) == 0:
        os_token = os_get_token(os_auth_url, os_user, os_pass, os_user_domain,
                                os_project, os_project_domain)
        if os_token is None:
            info('missing os auth information')
            return

    ctrail.config.get(address, port, os_token, urls, verb=GLOBAL_OPTS['verbose'])


@click.command()
@click.option('-a', '--address', default='contrail0',
              help='The hostname or address of the control node (the default is '
                   'contrail0).')
@click.option('-p', '--port', default=8083)
@click.option('--ri',
              help='Show only routing-instances with names matching a REGEX '
                   '(can be specified multiple times).')
@click.option('--rt',
              help='Show only routing table with names matching a REGEX '
                   'can be specified multiple times).')
def control(address, port, ri, rt):
    """Get VRF and route information from the control node."""

    if ri is None:
        ri = ()
    elif isinstance(ri, str):
        ri = (ri, )

    if rt is None:
        rt = ()
    elif isinstance(rt, str):
        rt = (rt, )

    ctrail.control.get_state(address, port, ri=ri, rt=rt,
                             verb=GLOBAL_OPTS['verbose'])


@click.command()
@click.option('-a', '--address', default='compute0',
              help='The hostname or address of the compute node (the default is '
                   'compute0).')
@click.option('-p', '--port', default=8085)
@click.option('--vrfs',
              help='The id of a specific VRF routing-table to show it\'s routes '
                   '(can be specified multiple times).')
@click.option('--acls', is_flag=True, help='Show only access-lists.')
def agent(address, port, vrfs, acls):
    """Get vrouter agent control plane information."""

    if vrfs is None:
        vrfs = ()
    elif isinstance(vrfs, str):
        vrfs = (vrfs, )

    ctrail.vagent.get_state(address, port, vrfs, acls, verb=GLOBAL_OPTS['verbose'])
    

@click.command()
@click.option('-a', '--address', default='compute0',
              help='The hostname or address of the compute node (the default is '
                   'compute0).')
@click.option('-p', '--port', default=8085)
@click.option('--vrfs',
              help='The id of a specific VRF routing-table to show it\'s routes '
                   '(can be specified multiple times).')
@click.option('--flows', is_flag=True, help='Show only flows active on the vrouter.')
def kernel(address, port, vrfs, flows):
    """Get vrouter kernel forwarding plane information."""

    if vrfs is None:
        vrfs = ()
    elif isinstance(vrfs, str):
        vrfs = (vrfs, )

    ctrail.vkernel.get_state(address, port, vrfs, flows, verb=GLOBAL_OPTS['verbose'])


@click.group(cls=AliasedGroup)
def vrouter():
    """Get vrouter control and forwarding plane information.""" 

    pass


vrouter.add_command(agent)
vrouter.add_command(kernel)


@click.command()
@click.option('-a', '--address', default='contrail0',
              help='The hostname or address of the analytics node (the default '
                   'is contrail0.')
@click.option('-p', '--port', default=8081)
@click.option('--os-token', default='', envvar='OS_TOKEN',
              help='OpenStack AUTH token (will default to the OS_TOKEN '
                   'environment variable).')
@click.option('--os-auth-url', default='http://localhost:35357/v3', envvar='OS_AUTH_URL',
              help='Will default to the OS_AUTH_URL environment variable.')
@click.option('--os-user', envvar='OS_USERNAME',
              help='Will default to the OS_USERNAME environment variable.')
@click.option('--os-pass', envvar='OS_PASSWORD',
              help='Will default to the OS_PASSWORD environment variable.')
@click.option('--os-user-domain', envvar='OS_USER_DOMAIN_NAME',
              help='Will default to the OS_USER_DOMAIN_NAME environment variable.')
@click.option('--os-project', envvar='OS_PROJECT_NAME',
              help='Will default to the OS_PROJECT_NAME environment variable.')
@click.option('--os-project-domain', envvar='OS_PROJECT_DOMAIN_NAME',
              help='Will default to the OS_PROJECT_DOMAIN_NAME environment variable.')
@click.option('-q', '--query', default='', nargs=1, help='File containing the JSON query.')
@click.argument('urls', nargs=-1)
def opserver(address, port, os_token, os_auth_url, os_user, os_pass,
           os_user_domain, os_project, os_project_domain, query, urls):
    """Get UVE, flow information from the analytics node.
    
    The analytics API requires authentication, see the help for the config
    command for more details.

    If no URLs are specified on the command line the default is to get `/`,
    `uves` and `tables`.
    """

    if len(os_token) == 0:
        os_token = os_get_token(os_auth_url, os_user, os_pass, os_user_domain,
                                os_project, os_project_domain)
        if os_token is None:
            info('missing os auth information')
            return

    if len(urls) == 0:
        urls = ('/', 'uves', 'tables')

    if len(query) > 0:
        json_text = None
        query_dict = None
        try:
            with open(query) as fin:
                json_text = fin.read()
        except OSError as err:
            error("Can't open file {}: {}".format(query, err))

        if json_text is not None:
            try:
                query_dict = json.loads(json_text)
            except JSONDecodeError as err:
                error("Invalid JSON document: {}".format(err))

        if query_dict is not None:
            ctrail.opserver.query(address, port, os_token, query_dict, verb=GLOBAL_OPTS['verbose'])
    else:
        ctrail.opserver.get(address, port, os_token, urls, verb=GLOBAL_OPTS['verbose'])


@click.group(cls=AliasedGroup)
@click.option('-l', '--log-level', default=GLOBAL_OPTS['log_level'],
              type=click.Choice(LOGGING_LEVELS_MAP.keys()),
              help='Set the logging level (the default is to only log normal '
                   'and error messages).')
@click.option('-v', '--verbose', count=True,
              help='Set the verbosity level. This controls how much of the '
                  'original API response is printed. The default is 0 which '
                  'means to only print the post-processing information.')
def cli(log_level, verbose):
    """ctrail is a collection of scripts which can retrieve control and
    forwarding plane information from the various nodes of a Contrail system.

    The scripts are not complete and are meant more like an example of how the
    APIs can be used. However the information provided can be useful as is.
    """

    GLOBAL_OPTS['verbose'] = verbose
    GLOBAL_OPTS['log_level'] = log_level

    logger = color_logging_setup()
    logger.setLevel(LOGGING_LEVELS_MAP[log_level])


cli.add_command(config)
cli.add_command(control)
cli.add_command(vrouter)
cli.add_command(opserver)
