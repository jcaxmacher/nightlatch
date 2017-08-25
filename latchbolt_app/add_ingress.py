import json

import boto3


client = boto3.client('ec2')


def handler(event, *args, **kwargs):
    """Handle requests to add the source I.P. address to bastion-host security
    group in AWS.

    Args:
        event (dict[str, Any]): the request event.

    Returns:
        dict[str, Any]: the response
    """
    ip_address = event['requestContext']['identity']['sourceIp']
    groups = client.describe_security_groups(
        Filters=[{'Name': 'tag:crowbar-group', 'Values': ['true']}]
    )
    for group in groups['SecurityGroups']:
        group_id = group['GroupId']
        client.authorize_security_group_ingress(
            CidrIp='{}/32'.format(ip_address),
            FromPort=22,
            ToPort=22,
            IpProtocol='tcp',
            GroupId=group_id
        )
    response = {
        "source_ip": ip_address,
        "message": "Successfully added I.P. address"
    }
    return {"statusCode": 200, "body": json.dumps(response)}