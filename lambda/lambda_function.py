import boto3
import json
import urllib.request
import urllib.error
import logging

# Set up logging so we can see output in CloudWatch
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_slack_webhook():
    """
    Fetches the Slack webhook URL from Secrets Manager.
    Never stored in code — always fetched at runtime.
    """
    client = boto3.client('secretsmanager', region_name='us-east-1')
    response = client.get_secret_value(
        SecretId='watchman/slack-webhook'
    )
    return response['SecretString']

def create_isolation_security_group(ec2_client, vpc_id, instance_id):
    """
    Creates a DENY-ALL security group and returns its ID.
    A security group with NO inbound or outbound rules
    blocks ALL traffic by default.
    """
    group_name = f'ISOLATED-{instance_id}'

    logger.info(f"Creating isolation security group: {group_name}")

    response = ec2_client.create_security_group(
        GroupName=group_name,
        Description=f'ISOLATION: Auto-created by Watchman for {instance_id}',
        VpcId=vpc_id
    )

    isolation_group_id = response['GroupId']
    logger.info(f"Created security group: {isolation_group_id}")

    # Remove the default outbound rule that AWS adds automatically.
    # By default AWS adds: allow all outbound traffic.
    # We remove this so NO traffic can leave either.
    ec2_client.revoke_security_group_egress(
        GroupId=isolation_group_id,
        IpPermissions=[{
            'IpProtocol': '-1',
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }]
    )
    logger.info("Removed default outbound rule — all traffic now blocked")

    return isolation_group_id

def isolate_ec2(ec2_client, instance_id, isolation_group_id):
    """
    Replaces ALL existing security groups on the EC2
    with ONLY the isolation group.
    Previous security groups are completely removed.
    """
    logger.info(f"Isolating instance {instance_id}")

    ec2_client.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[isolation_group_id]
    )

    logger.info(f"Instance {instance_id} is now isolated")

def send_slack_alert(webhook_url, instance_id, finding_type,
                     severity, isolation_group_id):
    """
    Sends a formatted alert to Slack with all incident details.
    """
    # Map severity number to human readable label.
    # GuardDuty uses numbers: 7-8.9 = HIGH, 9.0+ = CRITICAL
    if severity >= 9:
        severity_label = "🔴 CRITICAL"
    elif severity >= 7:
        severity_label = "🔴 HIGH"
    elif severity >= 4:
        severity_label = "🟡 MEDIUM"
    else:
        severity_label = "🟢 LOW"

    message = {
        "text": (
            f"*🚨 WATCHMAN ALERT — GuardDuty Threat Detected*\n"
            f"*Finding Type:* {finding_type}\n"
            f"*Severity:* {severity_label} ({severity})\n"
            f"*Affected Instance:* {instance_id}\n"
            f"*Action Taken:* Instance ISOLATED\n"
            f"*Isolation Group:* {isolation_group_id}\n"
            f"*Status:* All inbound and outbound traffic blocked\n"
            f"*Next Step:* Investigate via SSM Session Manager"
        )
    }

    # Convert message to bytes for the HTTP request
    data = json.dumps(message).encode('utf-8')

    request = urllib.request.Request(
        webhook_url,
        data=data,
        headers={'Content-Type': 'application/json'},
        method='POST'
    )

    try:
        with urllib.request.urlopen(request) as response:
            logger.info(f"Slack alert sent successfully: {response.status}")
    except urllib.error.URLError as e:
        logger.error(f"Failed to send Slack alert: {e}")

def lambda_handler(event, context):
    """
    Main function. AWS Lambda calls this automatically
    when EventBridge triggers it with a GuardDuty finding.

    'event' contains the full GuardDuty finding JSON.
    'context' contains Lambda runtime information (we don't use it).
    """
    logger.info("Watchman Lambda triggered")
    logger.info(f"Event received: {json.dumps(event)}")

    # Step 1: Extract finding details from the event.
    # GuardDuty findings arrive nested inside 'detail'.
    detail = event.get('detail', {})

    finding_type = detail.get('type', 'Unknown')
    severity = detail.get('severity', 0)

    # Navigate into the nested JSON to find the EC2 instance ID
    resource = detail.get('resource', {})
    instance_details = resource.get('instanceDetails', {})
    instance_id = instance_details.get('instanceId')

    # Get the VPC ID — needed to create security group in right VPC
    network_interfaces = instance_details.get('networkInterfaces', [{}])
    vpc_id = network_interfaces[0].get('vpcId') if network_interfaces else None

    # If this finding is not about an EC2 instance, log and exit
    if not instance_id or not vpc_id:
        logger.info(f"Finding type {finding_type} is not EC2-related. No action needed.")
        return {
            'statusCode': 200,
            'body': 'Finding not EC2-related, no action taken'
        }

    logger.info(f"Finding: {finding_type} | Severity: {severity} | Instance: {instance_id}")

    # Step 2: Fetch Slack webhook from Secrets Manager.
    # Done BEFORE isolation so we have everything ready.
    logger.info("Fetching Slack webhook from Secrets Manager")
    webhook_url = get_slack_webhook()

    # Step 3: Create isolation security group and isolate EC2
    ec2_client = boto3.client('ec2', region_name='us-east-1')

    isolation_group_id = create_isolation_security_group(
        ec2_client, vpc_id, instance_id
    )

    isolate_ec2(ec2_client, instance_id, isolation_group_id)

    # Step 4: Send Slack alert with all details
    logger.info("Sending Slack alert")
    send_slack_alert(
        webhook_url,
        instance_id,
        finding_type,
        severity,
        isolation_group_id
    )

    logger.info("Watchman complete — instance isolated, team notified")

    return {
        'statusCode': 200,
        'body': f'Instance {instance_id} isolated successfully'
    }