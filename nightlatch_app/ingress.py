import sys
import time
import json
import logging
from collections import namedtuple

import boto3
from boto3.session import Session
from boto3.dynamodb.conditions import Key
from botocore import exceptions

PORTS = [22]
OPEN_ACCESS_DURATION = 60 * 5 # five minutes
GROUP_FILTER = [{'Name': 'tag:crowbar-group', 'Values': ['true']}]

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


def get_effective_permissions(group_filter=GROUP_FILTER):
    groups = client.describe_security_groups(
        Filters=[{'Name': 'tag:crowbar-group', 'Values': ['true']}]
    )
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


def get_authorizations():
    response = table.scan()
    if response.get('Items'):
        return set(response['Items'])
    elif response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return set()
    else:
        raise DbQueryError('Error occurred scanning table')


def is_invalid(permission, valid_set, valid_port=PORT):
    ip_address, bits = permission.cidr_ip.split('/')
    return (
        permission.from_port != permission.to_port
        or permission.from_port not in valid_ports
        or permission.protocol != 'tcp'
        or bits != '32'
        or ip_address not in valid_set
    )


def revoke_permissions(permissions):
    for permission in permissions:
        client.revoke_security_group_ingress(
            CidrIp=permission.cidr_ip,
            FromPort=permission.from_port,
            ToPort=permission.to_port,
            IpProtocol=permission.protocol,
            GroupId=permission.group_id
        )


def delete_authorizations(authorizations):
    for ip_address in authorizations:
        table.delete_item(Key={'ip_address': ip_address})


def revoke(*args, **kwargs):
    """Handle periodic Cloudwatch events to remove access to I.P. addresses
    after specified time."""
    cutoff_time = int(time.time()) - OPEN_ACCESS_DURATION
    # Calculate authorization validations
    authorizations = get_authorizations()
    valid_authorizations = set(
        auth['ip_address'] for auth in authorizations
        if cutoff_time > auth['created_at']
    )
    invalid_authorizations = authorizations - valid_authorizations
    # Calculate invalid permissions
    effective_permissions = get_effective_permissions()
    invalid_permissions = set(
        permission for permission in effective_permissions
        if is_invalid(permission, valid_set=valid_authorizations)
    )
    # Enact permission revocations and authorization deletions
    revoke_permissions(invalid_permissions)
    delete_authorizations(invalid_authorizations)


def authorize(event, *args, **kwargs):
    """Handle requests to add the source I.P. address to bastion-host security
    group in AWS.

    Args:
        event (dict[str, Any]): the request event.

    Returns:
        dict[str, Any]: the response
    """
    ip_address = event['requestContext']['identity']['sourceIp']
    now = int(time.time())
    table.put_item(
        Item={
            'ip_address': ip_address,
            'created_at': now
        }
    )
    groups = client.describe_security_groups(
        Filters=[{'Name': 'tag:crowbar-group', 'Values': ['true']}]
    )
    for group in groups['SecurityGroups']:
        group_id = group['GroupId']
        try:
            for port in PORTS:
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
    response = {
        "source_ip": ip_address,
        "message": "Successfully added I.P. address"
    }
    return {"statusCode": 200, "body": json.dumps(response)}