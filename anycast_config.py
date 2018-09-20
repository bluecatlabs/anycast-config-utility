#!/usr/bin/env python3

# Copyright 2018 BlueCat Networks. All rights reserved.

import base64
import functools
import getpass
import json
import os.path
import sys
from argparse import ArgumentParser
from http import HTTPStatus
from requests.auth import HTTPBasicAuth
import requests
import urllib3

urllib3.disable_warnings()

PROG = sys.argv[0]

DAEMONS = ('zebra', 'ospfd', 'bgpd')

DEBUG_INFOS = (
    'zebraSummary', 'bgpSummary', 'bgpNeighbors',
    'ospfNeighbors', 'ospfRoutes', 'routes',
    'interfaces', 'ospfRouterInfo', 'runningConfig',
    'ospfDatabase'
)

DAEMONS_STRING = '{ ' + functools.reduce(lambda x, y: x + ' | ' + y, DAEMONS) + ' }'

DEBUG_INFOS_STRING = '{ ' + functools.reduce(lambda x, y: x + ' | ' + y, DEBUG_INFOS) + ' }'

# Argument setup

PARSER = ArgumentParser(
    description='Configure Anycast daemons and related networking configurations.',
    usage='%(prog)s <action> [options]')

ACTION = PARSER.add_subparsers(
    dest='action',
    description='The available Anycast configuration actions.')

PAUSE_DAEMON = ACTION.add_parser(
    name='pause',
    usage='%(prog)s {}'.format(DAEMONS_STRING),
    description='Pause the specified daemon.')
PAUSE_DAEMON.add_argument(
    dest='daemon',
    metavar='daemon',
    help='The daemon that will be paused.')

START_DAEMON = ACTION.add_parser(
    name='start',
    usage='%(prog)s {}'.format(DAEMONS_STRING),
    description='Start the specified daemon.')
START_DAEMON.add_argument(
    dest='daemon',
    metavar='daemon',
    help='The daemon that will be started.')

SHOW_DAEMONS = ACTION.add_parser(
    name='show_daemons',
    description='Show which daemons are currently running.')

SET_STAGED_CONF = ACTION.add_parser(
    name='set_staged_conf',
    usage='%(prog)s {} <file>'.format(DAEMONS_STRING),
    description='Set the staged configuration of the specified daemon.')
SET_STAGED_CONF.add_argument(
    dest='daemon',
    metavar='daemon',
    help='The daemon that will receive the staged configuration file contents.',
    choices=DAEMONS)
SET_STAGED_CONF.add_argument(
    dest='file',
    help='The file that contains the contents to pass to the daemon.')

SHOW_STAGED_CONF = ACTION.add_parser(
    name='show_staged_conf',
    usage='%(prog)s {}'.format(DAEMONS_STRING),
    description='Show the staged configuration of the specified daemon.')
SHOW_STAGED_CONF.add_argument(
    dest='daemon',
    metavar='daemon',
    help='The daemon to get the staged configuration for.',
    choices=DAEMONS)

NO_STAGED_CONF = ACTION.add_parser(
    name='no_staged_conf',
    usage='%(prog)s {}'.format(DAEMONS_STRING),
    description='Delete the staged configuration of the specified daemon.')
NO_STAGED_CONF.add_argument(
    dest='daemon',
    metavar='daemon',
    help='The daemon to have its staged configuration deleted.',
    choices=DAEMONS)

SET_RUN_CONF = ACTION.add_parser(
    name='set_run_conf',
    usage='%(prog)s {} <file>'.format(DAEMONS_STRING),
    description='Set the configuration of the specified daemon and apply the change by restarting the daemon.')
SET_RUN_CONF.add_argument(
    dest='daemon',
    metavar='daemon',
    help='The daemon that will receive the running configuration file contents.',
    choices=DAEMONS)
SET_RUN_CONF.add_argument(
    dest='file',
    help='The file that contains the contents to pass to the daemon.')

SHOW_RUN_CONF = ACTION.add_parser(
    name='show_run_conf',
    usage='%(prog)s {}'.format(DAEMONS_STRING),
    description='Show the running configuration of the specified daemon.')
SHOW_RUN_CONF.add_argument(
    dest='daemon',
    metavar='daemon',
    help='The daemon to get the running configuration for.',
    choices=DAEMONS)

NO_RUN_CONF = ACTION.add_parser(
    name='no_run_conf',
    usage='%(prog)s {}'.format(DAEMONS_STRING),
    description='Delete the configuration of the specified daemon and apply the change by restarting the daemon.')
NO_RUN_CONF.add_argument(
    dest='daemon',
    metavar='daemon',
    help='The daemon to have its running configuration deleted.',
    choices=DAEMONS)

APPLY = ACTION.add_parser(
    name='apply',
    description='Converts staged configuration files to running configurations and restarts daemons to apply changes.')

SHOW_DEBUG = ACTION.add_parser(
    name='show_debug',
    usage='%(prog)s {}'.format(DEBUG_INFOS_STRING),
    description='Show debug information for the specified daemon.')
SHOW_DEBUG.add_argument(
    dest='option',
    metavar='option',
    help='The debug command.',
    choices=DEBUG_INFOS)

SHOW_LOGS = ACTION.add_parser(
    name='show_logs',
    usage='%(prog)s {}'.format(DAEMONS_STRING),
    description='Show the raw logs of the specified daemon.')
SHOW_LOGS.add_argument(
    dest='daemon',
    metavar='daemon',
    help='The daemon to get the logs for',
    choices=DAEMONS)

SET_LOOPBACKS = ACTION.add_parser(
    name='set_loopbacks',
    usage='%(prog)s {}'.format('[loopbacks ...]'),
    description='Set the Anycast loopback interfaces.')
SET_LOOPBACKS.add_argument(
    dest='loopbacks',
    nargs='+',
    help='The Anycast loopback interfaces to be set.')

SHOW_LOOPBACKS = ACTION.add_parser(
    name='show_loopbacks',
    description='Show the Anycast loopback interfaces.')

NO_LOOPBACKS = ACTION.add_parser(
    name='no_loopbacks',
    description='Delete all of the Anycast loopback interfaces.')

# Globals

DEFAULT_HTTPS_PORT = 443

# Endpoints

DAEMONS_RUNNING_ENDPOINT = 'https://{}:{}/v1/routing/anycast/configuration/daemons/running'

DAEMONS_STAGED_ENDPOINT = 'https://{}:{}/v1/routing/anycast/configuration/daemons/staged'

CONF_STAGED_ENDPOINT = 'https://{}:{}/v1/routing/anycast/configuration/{}/staged'

CONF_RUNNING_ENDPOINT = 'https://{}:{}/v1/routing/anycast/configuration/{}/running'

APPLY_ENDPOINT = 'https://{}:{}/v1/routing/anycast/configuration/apply'

DEBUG_ENDPOINT = 'https://{}:{}/v1/routing/anycast/debug?{}'

LOGS_ENDPOINT = 'https://{}:{}/v1/routing/anycast/logs/{}'

NETWORKING_ENDPOINT = 'https://{}:{}/v1/routing/networking/configuration/'

# Helpers to handle the minor logic

def get_input(input_name):
    return input(input_name + ':')

def get_password():
    return getpass.getpass('Password:')

def write_script_config(content):
    try:
        with open('.script_config', 'w') as file:
            file.write(base64.b64encode(bytes(content, 'utf-8')).decode('ascii'))
    except IOError as e:
        raise e

def extract_credentials():
    contents = None
    try:
        with open('.script_config', 'r') as file:
            base64_contents = file.read()
            contents = base64.standard_b64decode(bytes(base64_contents, 'ascii')).decode('ascii').split('\n')
            assert len(contents) == 4
    except (IOError, AssertionError) as e:
        raise e

    contents[-1] = int(contents[-1])
    return contents

def get_file_contents(filename):
    try:
        with open(filename, 'r') as file:
            return file.read()
    except IOError as e:
        raise e

def get_existing_daemons_file(user, password, service_point_ip, port):
    """Retrieves the appropriate daemons file contents.
    Returns an existing daemons file if there is one, checking for staged first.
    If neither exist, it returns a file with all daemons disabled.
    """

    try:
        staged_daemons_file_response = requests.get(
            DAEMONS_STAGED_ENDPOINT.format(service_point_ip, port),
            auth=HTTPBasicAuth(user, password),
            verify=False)

        if staged_daemons_file_response.status_code == HTTPStatus.OK:
            return staged_daemons_file_response.text

        running_daemons_file_response = requests.get(
            DAEMONS_RUNNING_ENDPOINT.format(service_point_ip, port),
            auth=HTTPBasicAuth(user, password),
            verify=False)

        if running_daemons_file_response.status_code == HTTPStatus.OK:
            return running_daemons_file_response.text
    except (ConnectionError, TimeoutError) as e:
        raise e

    return 'zebra=no\nospfd=no\nbgpd=no'

def generate_daemons_file(user, password, service_point_ip, port, daemon, disable):
    """Generate the contents of a daemons file.
    This behaviour depends on the existing one and the given daemon to activate/deactivate as per the disable flag.
    This will check the staged file before the running one and then a default (all daemons set to no).
    """
    try:
        daemons_file_content = get_existing_daemons_file(user, password, service_point_ip, port)
        if not daemons_file_content.strip():
            daemons_file_content = 'zebra=no\nospfd=no\nbgpd=no'
        return daemons_file_content.replace(daemon+'=yes', daemon+'=no') if disable \
        else daemons_file_content.replace(daemon+'=no', daemon+'=yes')
    except (ConnectionError, TimeoutError) as e:
        raise e

def send_get(url, user, password):
    return requests.get(url, auth=HTTPBasicAuth(user, password), verify=False)

def send_put(url, user, password, content):
    return requests.put(url, auth=HTTPBasicAuth(user, password), verify=False, data=content)

def send_post(url, user, password, content):
    return requests.post(url, auth=HTTPBasicAuth(user, password), verify=False, data=content)

def send_delete(url, user, password):
    return requests.delete(url, auth=HTTPBasicAuth(user, password), verify=False)

def send_apply_call(user, password, service_point_ip, port):
    return send_post(APPLY_ENDPOINT.format(service_point_ip, port), user, password, '')

def stage_daemons_file(daemon, disable, user, password, service_point_ip, port):
    daemons_file_content = generate_daemons_file(user, password, service_point_ip, port, daemon, disable)
    return send_put(DAEMONS_STAGED_ENDPOINT.format(service_point_ip, port), user, password, daemons_file_content)

def handle_api_response(response, suppress, text_handling_func=None):
    """Handles the output from API calls.  If a text_handling_func is given, it uses that to parse the response text,
    otherwise prints the response text."""
    if response.status_code == HTTPStatus.NO_CONTENT or response.status_code == HTTPStatus.OK:
        if not suppress:
            print('Success.')
            if response.text != None:
                if text_handling_func is None:
                    print(response.text)
                else:
                    text_handling_func(response.text)
    elif response.status_code == HTTPStatus.UNAUTHORIZED:
        raise requests.HTTPError('Unauthorized.')
    elif response.status_code == HTTPStatus.BAD_REQUEST:
        raise requests.HTTPError('Invalid parameters.')
    else:
        raise requests.HTTPError(response.text)

def handle_show_debug_output(output):
    output_dict = json.loads(output)
    print('Event type: ' + output_dict['events'][0]['metadata']['eventType'])
    print(output_dict['events'][0]['event'])

# Authentication handling

def authenticate(func):
    def wrapper(*args, **kwargs):
        if not os.path.exists('.script_config') or not os.path.isfile('.script_config'):
            save_creds = get_input('Save credentials and service point hostname/IP to .script_config? [y/n]')
            user = get_input('Username')
            password = get_password()
            service_point_ip = get_input('Service Point Hostname/IP')
            port = get_input('Port (default 443)')
            if not port.strip():
                port = DEFAULT_HTTPS_PORT
            if save_creds == 'y':
                write_script_config(user + '\n' + password + '\n' + service_point_ip + '\n' + str(port))
            return func(*args, **kwargs, user=user, password=password, service_point_ip=service_point_ip, port=port)
        else:
            user, password, service_point_ip, port = extract_credentials()
            return func(*args, **kwargs, user=user, password=password, service_point_ip=service_point_ip, port=port)
    return wrapper

# Command logic

@authenticate
def do_pause_start_daemon(daemon, disable, user=None, password=None, service_point_ip=None, port=443):
    handle_api_response(
        stage_daemons_file(daemon, disable, user, password, service_point_ip, port), True)
    handle_api_response(
        send_apply_call(user, password, service_point_ip, port), False)

@authenticate
def do_show_daemons(user=None, password=None, service_point_ip=None, port=443):
    handle_api_response(
        send_get(DAEMONS_RUNNING_ENDPOINT.format(service_point_ip, port), user, password), False)

@authenticate
def do_set_staged_conf(daemon, file, user=None, password=None, service_point_ip=None, port=443):
    """Stage the given daemon's conf file while also adjusting and staging the daemons file accordingly."""
    contents = get_file_contents(file)

    handle_api_response(
        stage_daemons_file(daemon, False, user, password, service_point_ip, port), True)
    handle_api_response(
        send_put(CONF_STAGED_ENDPOINT.format(service_point_ip, port, daemon), user, password, contents), False)

@authenticate
def do_show_staged_conf(daemon, user=None, password=None, service_point_ip=None, port=443):
    handle_api_response(
        send_get(CONF_STAGED_ENDPOINT.format(service_point_ip, port, daemon), user, password), False)

@authenticate
def do_no_staged_conf(daemon, user=None, password=None, service_point_ip=None, port=443):
    """Unstage the given daemon's conf file while also adjusting and staging the daemons file accordingly."""
    handle_api_response(
        stage_daemons_file(daemon, False, user, password, service_point_ip, port), True)
    handle_api_response(
        send_delete(CONF_STAGED_ENDPOINT.format(service_point_ip, port, daemon), user, password), False)

@authenticate
def do_apply(user=None, password=None, service_point_ip=None, port=443):
    handle_api_response(
        send_post(APPLY_ENDPOINT.format(service_point_ip, port), user, password, ''), False)

@authenticate
def do_set_run_conf(daemon, file, user=None, password=None, service_point_ip=None, port=443):
    contents = get_file_contents(file)

    handle_api_response(
        stage_daemons_file(daemon, False, user, password, service_point_ip, port), True)
    handle_api_response(
        send_put(CONF_STAGED_ENDPOINT.format(service_point_ip, port, daemon), user, password, contents), True)
    handle_api_response(
        send_apply_call(user, password, service_point_ip, port), False)

@authenticate
def do_show_run_conf(daemon, user=None, password=None, service_point_ip=None, port=443):
    handle_api_response(
        send_get(CONF_RUNNING_ENDPOINT.format(service_point_ip, port, daemon), user, password), False)

@authenticate
def do_no_run_conf(daemon, user=None, password=None, service_point_ip=None, port=443):
    handle_api_response(
        stage_daemons_file(daemon, True, user, password, service_point_ip, port), True)
    handle_api_response(
        send_put(CONF_STAGED_ENDPOINT.format(service_point_ip, port, daemon), user, password, ''), True)
    handle_api_response(
        send_apply_call(user, password, service_point_ip, port), False)

@authenticate
def do_show_debug(option, user=None, password=None, service_point_ip=None, port=443):
    handle_api_response(
        send_get(DEBUG_ENDPOINT.format(service_point_ip, port, 'option={}'.format(option)), user, password),
        False,
        text_handling_func=handle_show_debug_output)

@authenticate
def do_show_logs(daemon, user=None, password=None, service_point_ip=None, port=443):
    handle_api_response(
        send_get(LOGS_ENDPOINT.format(service_point_ip, port, daemon), user, password), False)

@authenticate
def do_set_loopbacks(loopbacks, user=None, password=None, service_point_ip=None, port=443):
    additional_loopbacks = {}
    additional_loopbacks['additionalLoopbacks'] = loopbacks
    handle_api_response(
        send_put(NETWORKING_ENDPOINT.format(service_point_ip, port), user, password, json.dumps(additional_loopbacks)),
        False)

@authenticate
def do_show_loopbacks(user=None, password=None, service_point_ip=None, port=443):
    handle_api_response(
        send_get(NETWORKING_ENDPOINT.format(service_point_ip, port), user, password),
        False)

@authenticate
def do_no_loopbacks(user=None, password=None, service_point_ip=None, port=443):
    handle_api_response(
        send_delete(NETWORKING_ENDPOINT.format(service_point_ip, port), user, password), False)

def main(args):
    try:
        if args.action is None:
            print('Must supply a command.  Run <python> anycast_config.py -h for help.')
        elif args.action == 'pause':
            do_pause_start_daemon(args.daemon, True)
        elif args.action == 'start':
            do_pause_start_daemon(args.daemon, False)
        elif args.action == 'show_daemons':
            do_show_daemons()
        elif args.action == 'set_staged_conf':
            do_set_staged_conf(args.daemon, args.file)
        elif args.action == 'show_staged_conf':
            do_show_staged_conf(args.daemon)
        elif args.action == 'no_staged_conf':
            do_no_staged_conf(args.daemon)
        elif args.action == 'apply':
            do_apply()
        elif args.action == 'set_run_conf':
            do_set_run_conf(args.daemon, args.file)
        elif args.action == 'show_run_conf':
            do_show_run_conf(args.daemon)
        elif args.action == 'no_run_conf':
            do_no_run_conf(args.daemon)
        elif args.action == 'show_debug':
            do_show_debug(args.option)
        elif args.action == 'show_logs':
            do_show_logs(args.daemon)
        elif args.action == 'set_loopbacks':
            do_set_loopbacks(args.loopbacks)
        elif args.action == 'show_loopbacks':
            do_show_loopbacks()
        elif args.action == 'no_loopbacks':
            do_no_loopbacks()
        else:
            raise ValueError('Unsupported action was given.')
    except (ConnectionError, TimeoutError) as e:
        print('Error while making request: ' + str(e))
    except requests.HTTPError as e:
        print('Unsuccessful status code: ' + str(e))
    except requests.exceptions.InvalidURL:
        print('Invalid service point IP.')
    except requests.exceptions.ConnectionError as e:
        print('Connection error.')
    except IOError as e:
        print('Error handling file.')
    except Exception as e:
        print('Unexpected error.')
        if os.environ.get('SCRIPT_DEBUG', False):
            print(e)

if __name__ == '__main__':
    main(PARSER.parse_args())
