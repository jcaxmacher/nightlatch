import sys
import time
import json
import logging

import boto3
from boto3.dynamodb.conditions import Key
from botocore import exceptions

PORT = 22
OPEN_ACCESS_DURATION = 60 * 5 # five minutes

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
client = boto3.client('ec2')
db = boto3.resource('dynamodb')
table = db.Table('nightlatch')


def revoke(event, *args, **kwargs):
    """Handle periodic Cloudwatch events to remove access to I.P. addresses
    after specified time."""
    cutoff_time = int(time.time()) - OPEN_ACCESS_DURATION
    groups = client.describe_security_groups(
        Filters=[{'Name': 'tag:crowbar-group', 'Values': ['true']}]
    )
    logger.debug('Security group response %s', groups)
    for group in groups['SecurityGroups']:
        group_id = group['GroupId']
        logger.debug('Examining group %s', group_id)
        for permission in group['IpPermissions']:
            if permission['FromPort'] == PORT and permission['ToPort'] == PORT:
                logger.debug('Examining permission %s', permission)
                for range in permission['IpRanges']:
                    ip = range['CidrIp'].split('/32')[0]
                    logger.debug('Querying db table for ip %s', ip)
                    response = table.get_item(Key={'ip_address': ip})
                    logger.debug('Response %s', response)
                    if response.get('Item'):
                        created_at = int(response['Item']['created_at'])
                        if cutoff_time > created_at:
                            logger.debug('Access expired for range %s', range['CidrIp'])
                            client.revoke_security_group_ingress(
                                CidrIp=range['CidrIp'],
                                FromPort=PORT,
                                ToPort=PORT,
                                IpProtocol='tcp',
                                GroupId=group_id
                            )
                            table.delete_item(Key={'ip_address': ip})
                        else:
                            logger.debug('Permission for ip %s has not expired', ip)
                    elif response['ResponseMetadata']['HTTPStatusCode'] != 200:
                        raise Exception('Could not query DynamoDB table for IP')
                    else:
                        logger.debug('IP address %s does not exist in table. Removing.', ip)
                        client.revoke_security_group_ingress(
                            CidrIp=range['CidrIp'],
                            FromPort=PORT,
                            ToPort=PORT,
                            IpProtocol='tcp',
                            GroupId=group_id
                        )
            else:
                logger.debug('Found an IP permission for an unknown port. Removing.')
                for range in permission['IpRanges']:
                    logger.debug('Revoking %s', range['CidrIp'])
                    client.revoke_security_group_ingress(
                        CidrIp=range['CidrIp'],
                        FromPort=permission['FromPort'],
                        ToPort=permission['ToPort'],
                        IpProtocol=permission['IpProtocol'],
                        GroupId=group_id
                    )
    return {"statusCode": 200, "body": json.dumps({'message': 'success'})}


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
            client.authorize_security_group_ingress(
                CidrIp='{}/32'.format(ip_address),
                FromPort=PORT,
                ToPort=PORT,
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