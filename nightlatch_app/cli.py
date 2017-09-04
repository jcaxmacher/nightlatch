"""Nightlatch

Usage:
  nightlatch [--profile=<profile_name>] [--config=<config_file>] [--api=<api_url>]
  nightlatch createconfig
  nightlatch (-h | --help)
  nightlatch --version

Options:
  -h --help       Show this screen
  --profile=<profile_name>   Select a credentials profile from the
                             ~/.aws/credentials file. When not specified,
                             normal boto3 credential discovery is used.
  --config=<config_file>     Specify the desired Nightlatch config file.
                             When not specified, ./nightlatch.config is
                             attempted, then ~/nightlatch.config
  --api=<api_url>            Directly specify the Nightlatch API url.
                             This bypasses any value in the Nightlatch
                             config file.

"""
from configparser import ConfigParser

import requests
from requests_aws_sign import AWSV4Sign
from boto3.session import Session
from docopt import docopt


def create_configfile():
    print('Creating config file')


def get_configuration(arguments):
    profile_name = arguments['--profile']
    url = None
    if arguments['--config']:
        c = ConfigParser()
        c.read([arguments['--config']])
        values = dict(c.items('Options'))
        if 'profile_name' in values:
            profile_name = values['profile_name']
        if 'url' in values:
            url = values['url']
    if arguments['--api']:
        url = arguments['--api']
    session = Session(profile_name=profile_name)
    return session, url


def call_nightlatch(session, url):
    credentials = session.get_credentials()
    region = url.split('execute-api.')[1].split('.amazonaws.com')[0]
    service = 'execute-api'
    auth = AWSV4Sign(credentials, region, service)
    response = requests.get(url, auth=auth)
    print(response)


if __name__ == '__main__':
    arguments = docopt(__doc__, version='Nightlatch 0.1')
    if arguments['createconfig']:
        create_configfile()
    else:
        session, url = get_configuration(arguments)
        call_nightlatch(session, url)