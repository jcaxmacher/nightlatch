import os
import sys
import time
import json
import logging
from collections import namedtuple

import boto3
from boto3.session import Session
from boto3.dynamodb.conditions import Key
from botocore import exceptions

PORTS = [int(p) for p in os.environ.get('PORTS', '22').split(',')]
OPEN_ACCESS_DURATION = int(os.environ.get('DURATION', 60 * 5))
GROUP_TAG = os.environ.get('GROUP_TAG', 'nightlatch-group')

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
session = Session(profile_name='personal')
client = session.client('ec2')
db = session.resource('dynamodb')
table = db.Table('nightlatch')


class BaseError(Exception):
    pass


class DbQueryError(BaseError):
    pass


Permission = namedtuple('Permission', ['group_id', 'from_port', 'to_port', 'protocol', 'cidr_ip'])


def boto_retry(exc_list):
    def wrapper(func):
        def inner(*args, **kwargs):
            initial = retries = 5
            while True:
                retries -= 1
                try:
                    result = func(*args, **kwargs)
                    return result
                except (exceptions.ClientError, exceptions.BotoCoreError) as exc:
                    if (isinstance(exc, exceptions.BotoCoreError)
                            or exc_list == '*'
                            or getattr(exc, 'response', {}).get('Error', {}).\
                            get('Code') in exc_list):
                        logger.debug(
                            'Failed calling function.  Attempt %s of %s.',
                            5 - retries,
                            initial,
                            exc_info=True
                        )
                        if retries:
                            # Increase wait each time
                            time.sleep(initial - retries)
                        else:
                            raise
                    else:
                        raise
        return inner
    return wrapper


@boto_retry('*')
def get_latch_duration():
    response = table.get_item(Key={'k': 'latch_duration'})
    item = response.get('Item', {})
    if not item.get('v'):
        table.update_item(
            Key={
                'k': 'latch_duration'
            },
            UpdateExpression='SET v = :v',
            ExpressionAttributeValues={
                ':v': OPEN_ACCESS_DURATION
            },
        )
        duration = OPEN_ACCESS_DURATION

    else:
        duration = int(item.get('v'))
    return duration


@boto_retry('*')
def get_group_filter():
    response = table.get_item(Key={'k': 'group_tag'})
    item = response.get('Item', {})
    if not item.get('v'):
        table.update_item(
            Key={
                'k': 'group_tag'
            },
            UpdateExpression='SET v = :v',
            ExpressionAttributeValues={
                ':v': GROUP_TAG
            },
        )
        filter = [{'Name': 'tag:{}'.format(GROUP_TAG), 'Values': ['true']}]

    else:
        group_tag = item.get('v')
        filter = [{'Name': 'tag:{}'.format(group_tag), 'Values': ['true']}]
    return filter


@boto_retry('*')
def get_ports():
    response = table.get_item(Key={'k': 'ports'})
    item = response.get('Item', {})
    if not item.get('v'):
        table.update_item(
            Key={
                'k': 'ports'
            },
            UpdateExpression='SET v = :v',
            ExpressionAttributeValues={
                ':v': PORTS
            },
        )
        ports = PORTS
    else:
        ports = [int(p) for p in item.get('v')]
    return ports


@boto_retry('*')
def add_permission(group_id, ip_address):
    for port in get_ports():
        try:
            client.authorize_security_group_ingress(
                CidrIp='{}/32'.format(ip_address),
                FromPort=port,
                ToPort=port,
                IpProtocol='tcp',
                GroupId=group_id
            )
        except exceptions.ClientError as exc:
            code = exc.response['Error']['Code']
            if code == 'InvalidPermission.Duplicate':
                continue
            else:
                raise


@boto_retry('*')
def revoke_permissions(permissions):
    for permission in permissions:
        client.revoke_security_group_ingress(
            CidrIp=permission.cidr_ip,
            FromPort=permission.from_port,
            ToPort=permission.to_port,
            IpProtocol=permission.protocol,
            GroupId=permission.group_id
        )


@boto_retry('*')
def get_group_ids():
    group_filter = get_group_filter()
    groups = client.describe_security_groups(Filters=group_filter)
    for group in groups['SecurityGroups']:
        yield group['GroupId']


@boto_retry('*')
def get_effective_permissions():
    group_filter = get_group_filter()
    groups = client.describe_security_groups(Filters=group_filter)
    permissions = []
    for group in groups['SecurityGroups']:
        for permission in group['IpPermissions']:
            for range in permission['IpRanges']:
                permissions.append(Permission(
                    group['GroupId'],
                    permission['FromPort'],
                    permission['ToPort'],
                    permission['IpProtocol'],
                    range['CidrIp']
                ))
    return set(permissions)


@boto_retry('ConditionalCheckFailedException')
def add_authorization(ip_address):
    now = int(time.time())
    authorizations, seq = get_authorizations()
    authorizations[ip_address] = now
    table.update_item(
        Key={
            'k': 'ip_addresses'
        },
        UpdateExpression='SET v = :v, s = :s',
        ExpressionAttributeValues={
            ':v': authorizations,
            ':s': seq + 1,
            ':o': seq
        },
        ConditionExpression='NOT attribute_exists(k) OR s = :o'
    )


@boto_retry('ConditionalCheckFailedException')
def delete_authorizations(ip_addresses):
    authorizations, seq = get_authorizations()
    for ip_address in ip_addresses:
        if ip_address in authorizations:
            del authorizations[ip_address]
    table.update_item(
        Key={
            'k': 'ip_addresses'
        },
        UpdateExpression='SET v = :v, s = :s',
        ExpressionAttributeValues={
            ':v': authorizations,
            ':s': seq + 1,
            ':o': seq
        },
        ConditionExpression='NOT attribute_exists(k) OR s = :o'
    )


@boto_retry('*')
def get_authorizations():
    response = table.get_item(Key={'k': 'ip_addresses'})
    logger.debug('Getting authorizations table response - %s', response)
    item = response.get('Item', {})
    seq = item.get('s', 0)
    authorizations = {k: int(v) for k, v in item.get('v', {}).items()}
    return authorizations, seq


def is_invalid(permission, invalid_set):
    valid_ports = get_ports()
    ip_address, bits = permission.cidr_ip.split('/')
    return (
        permission.from_port != permission.to_port
        or permission.from_port not in valid_ports
        or permission.protocol != 'tcp'
        or bits != '32'
        or ip_address in invalid_set
    )


def revoke(*args, **kwargs):
    """
    Handle periodic Cloudwatch events to remove access to I.P. addresses
    after specified time.
    """
    cutoff_time = int(time.time()) - get_latch_duration()
    logger.debug('Searching for authorizations invalid after %s', cutoff_time)
    # Calculate authorization validations
    authorizations, _ = get_authorizations()
    logger.debug('Found authorizations - %s', authorizations)
    invalid_authorizations = [
        ip_address
        for ip_address, created_at in authorizations.items()
        if cutoff_time >= int(created_at)
    ]
    logger.debug(
        'Determined invalid authorizations - %s',
        invalid_authorizations
    )
    # Calculate invalid permissions
    effective_permissions = get_effective_permissions()
    invalid_permissions = [
        permission for permission in effective_permissions
        if is_invalid(permission, invalid_set=invalid_authorizations)
    ]
    # Enact permission revocations and authorization deletions
    revoke_permissions(invalid_permissions)
    delete_authorizations(invalid_authorizations)


def authorize(event, *args, **kwargs):
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
    add_authorization(ip_address)
    for group_id in get_group_ids():
        add_permission(group_id, ip_address)
    response = {
        "source_ip": ip_address,
        "message": "Successfully added I.P. address"
    }
    return {"statusCode": 200, "body": json.dumps(response)}