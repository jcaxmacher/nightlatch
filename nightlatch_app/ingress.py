import time
import json

import boto3
from botocore import exceptions


client = boto3.client('ec2')
db = boto3.resource('dynamodb')
table = db.Table('nightlatch')


def remove(event, *args, **kwargs):
    """Handle periodic Cloudwatch events to remove access to I.P. addresses
    after specified time."""
    pass


def add(event, *args, **kwargs):
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
                FromPort=22,
                ToPort=22,
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