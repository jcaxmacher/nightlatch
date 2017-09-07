import os
import sys
import time
import json
import logging
from collections import namedtuple

import boto3
from boto3.session import Session
from botocore import exceptions

GROUP_NAME = os.environ['GROUP_NAME']
FILTER = [{'Name': 'tag:Name', 'Values': [GROUP_NAME]}]

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
session = Session(profile_name='personal')
client = session.client('ec2')


SecurityGroup = namedtuple(
    'SecurityGroup',
    [
        'group_id',
        'valid_ports',
        'duration'
    ]
)
IngressRule = namedtuple(
    'IngressRule',
    [
        'group_id',
        'from_port',
        'to_port',
        'protocol',
        'cidr_ip',
        'expires',
        'valid_ports'
    ]
)


def boto_retry(exc_list, retries=5):
    """Retry the decorated function when one of the exceptions given occurs.

    Args:
        exc_list (List[ExceptionClass]|ExceptionClass): the exception(s)
            to retry.
        retries (Optional[int]): the number of times to retry.
    
    Returns:
        Function: a retrying decorator.
    """
    def wrapper(func):
        """Decorate the supplied function with retry capability.

        Args:
            func (Function): the function to decorate.

        Returns:
            Function: the decorated function.
        """
        def inner(*args, **kwargs):
            """The retry logic that wraps the function."""
            retry_count = retries
            while True:
                retry_count -= 1
                try:
                    result = func(*args, **kwargs)
                    return result
                except (exceptions.ClientError, exceptions.BotoCoreError) as exc:
                    # BotoCoreErrors are low level (often transport-level) errors
                    # ClientErrors are generic and we match against the code
                    # contained in the exception.
                    # Asterisk (*) is a special value that retries everything.
                    # (Not really a good idea)
                    if (isinstance(exc, exceptions.BotoCoreError)
                            or exc_list == '*'
                            or getattr(exc, 'response', {}).get('Error', {}).\
                            get('Code') in exc_list):
                        logger.debug(
                            'Failed calling function.  Attempt %s of %s.',
                            retries - retry_count,
                            retries,
                            exc_info=True
                        )
                        if retry_count:
                            # Increase wait each time to backoff
                            time.sleep(retries - retry_count)
                        else:
                            raise
                    else:
                        raise
        return inner
    return wrapper


@boto_retry('*')
def add_permission(group, ip_address):
    """Add ingress permission to the given I.P. address on the given group,
    using the groups configuration to determine TCP ports and duration.

    Args:
        group (SecurityGroup): the group to add permission to.
        ip_address (str): the I.P. address to add.
    """
    now = int(time.time())
    expires = group.duration + now
    description = 'expires={}'.format(expires)
    for port in group.valid_ports:
        try:
            client.authorize_security_group_ingress(
                GroupId=group.group_id,
                IpPermissions=[dict(
                    IpProtocol='tcp',
                    FromPort=port,
                    ToPort=port,
                    IpRanges=[dict(
                        CidrIp='{}/32'.format(ip_address),
                        Description=description
                    )]
                )]
            )
        except exceptions.ClientError as exc:
            code = exc.response['Error']['Code']
            if code == 'InvalidPermission.Duplicate':
                continue
            else:
                raise


@boto_retry('*')
def revoke_ingress_rules(rules):
    """Revoke ingress rules.

    Args:
        rules (List[IngressRule]): the rules to revoke.
    """
    for rule in rules:
        client.revoke_security_group_ingress(
            CidrIp=rule.cidr_ip,
            FromPort=rule.from_port,
            ToPort=rule.to_port,
            IpProtocol=rule.protocol,
            GroupId=rule.group_id
        )


@boto_retry('*')
def get_groups(filters=FILTER):
    """Query EC2 API for security groups matching the given filter.

    Also converting the group's tags into configuration attributes.

    Args:
        filters (List[Dict(str, str)]): the security group filters

    Returns:
        Generator(SecurityGroup): zero or more security groups.
    """
    groups = client.describe_security_groups(Filters=filters)
    for group in groups['SecurityGroups']:
        tags = process_tags(group['Tags'])
        yield SecurityGroup(
            group['GroupId'], tags['valid_ports'], tags['duration_in_seconds']
        )


def process_description(text):
    """Convert a security group rule description into rule attributes.

    Args:
        text (str): the rule description.

    Returns:
        Dict(str, str): the rule attributes.
    """
    result = {}
    for kv in text.split(';'):
        if '=' in kv:
            key, value = kv.split('=')
            if key and value:
                result[key] = value
    return result


def process_tags(tags):
    """Convert Security Group tags into configuration attributes.

    Args:
        tags (List[Dict(str, str)]): the security groups tags.

    Returns:
        Dict(str, Any): a dictionary of configuration values.
    """
    tags = {t['Key']: t['Value'] for t in tags}
    if tags.get('valid_ports'):
        valid_ports = tags['valid_ports'].split(',')
        tags['valid_ports'] = tuple(sorted([int(port) for port in valid_ports]))
    else:
        tags['valid_ports'] = tuple()
    tags['duration_in_seconds'] = int(tags.get('duration_in_seconds', 0))
    return tags


@boto_retry('*')
def get_ingress_rules(filters=FILTER):
    """Query EC2 API for ingress rules on security groups matching the filters

    Args:
        filters (List[Dict(str, str)]): the security group filters

    Returns:
        Set(IngressRule): the set of ingress rules.
    """
    groups = client.describe_security_groups(Filters=FILTER)
    rules = []
    for group in groups['SecurityGroups']:
        tags = process_tags(group['Tags'])
        for permission in group['IpPermissions']:
            for ip_range in permission['IpRanges']:
                rule_attrs = process_description(ip_range.get('Description',''))
                rules.append(IngressRule(
                    group['GroupId'],
                    permission['FromPort'],
                    permission['ToPort'],
                    permission['IpProtocol'],
                    ip_range['CidrIp'],
                    int(rule_attrs.get('expires', 0)),
                    tags['valid_ports']
                ))
    return set(rules)


def is_invalid(rule):
    """Determine if an ingress rule is invalid or expired.

    Args:
        rule (IngressRule): the rule to examine

    Returns:
        bool: True or False
    """
    now = int(time.time())
    _, bits = rule.cidr_ip.split('/')
    return (
        rule.from_port != rule.to_port
        or rule.from_port not in rule.valid_ports
        or rule.protocol != 'tcp'
        or bits != '32'
        or now >= rule.expires
    )


def revoke():
    """Revoke security group ingress rules that have expired."""
    rules = get_ingress_rules()
    logger.debug('Searching for expired or invalid ingress rules')
    invalid_rules = [
        rule
        for rule in rules
        if is_invalid(rule)
    ]
    logger.debug(
        'Determined invalid ingress rules - %s',
        invalid_rules
    )
    revoke_ingress_rules(invalid_rules)


def revoke_handler(*args, **kwargs):
    """Handle periodic Cloudwatch events to revoke expired access."""
    revoke()


def add(ip_address):
    """Add the given I.P. address to Nightlatch security groups in AWS.

    Args:
        ip_address (str): the I.P. address to add to security group
            ingress rules.

    Returns:
        dict[str, str]: the I.P. address and message
    """
    for group in get_groups():
        add_permission(group, ip_address)
    return {
        "source_ip": ip_address,
        "message": "Successfully added I.P. address"
    }


def add_handler(event, *args, **kwargs):
    """
    Handle requests to add the source I.P. address to bastion-host security
    group in AWS.

    Args:
        event (dict[str, Any]): the request event.
            http://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-set-up-simple-proxy.html#api-gateway-simple-proxy-for-lambda-input-format

    Returns:
        dict[str, Any]: the response
            http://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-set-up-simple-proxy.html#api-gateway-simple-proxy-for-lambda-output-format
    """
    ip_address = event['requestContext']['identity']['sourceIp']
    response = add(ip_address)
    return {"statusCode": 200, "body": json.dumps(response)}