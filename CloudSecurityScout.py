import boto3
from botocore.exceptions import ClientError
import json
import uuid

DYNAMODB_TABLE = 'CloudSecurityScoutResults'
SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:ACCOUNT-ID:SecurityAlerts'

def get_regions():
    return ['ap-south-1', 'us-east-1']

def get_severity(resource_type, issue):
    # Lowercase for comparison
    r = (resource_type or "").lower()
    i = (issue or "").lower()

    # ------------------ CRITICAL --------------------
    if r == "account root" and "no mfa" in i:
        return "CRITICAL"
    if r == "iam user" and "no mfa" in i:
        return "CRITICAL"
    if r == "iam role" and "no mfa" in i:
        return "CRITICAL"
    if r == "s3 bucket" and "bucket is public" in i:
        return "CRITICAL"
    if r == "s3 bucket" and "block public access not fully enabled" in i:
        return "CRITICAL"
    if r == "vpc default sg" and "allows inbound" in i:
        return "CRITICAL"
    if r == "ec2 security group" and "open to internet" in i:
        return "CRITICAL"
    if r == "kms key" and "overly broad" in i:
        return "CRITICAL"
    if r == "rds instance" and "publicly accessible" in i:
        return "CRITICAL"
    if r == "rds instance" and "weak/default cred" in i:
        return "CRITICAL"
    if r == "iam role" and "overly permissive" in i:
        return "CRITICAL"
    if r == "iam" and "hardcoded access key" in i:
        return "CRITICAL"

    # ------------------- HIGH -----------------------
    if r == "iam role" and "unused" in i:
        return "HIGH"
    if r == "iam user" and "unused" in i:
        return "HIGH"
    if r == "s3 bucket" and "not encrypted" in i:
        return "HIGH"
    if r == "rds instance" and "not encrypted" in i:
        return "HIGH"
    if r == "ec2 ebs volume" and "not encrypted" in i:
        return "HIGH"
    if r == "ec2 security group" and "open to internet" in i:
        return "CRITICAL"
    if r == "kms key" and "too many grants" in i:
        return "HIGH"
    if r == "lambda function" and "over-privileged" in i:
        return "HIGH"
    if r == "lambda function" and "secrets in environment" in i:
        return "HIGH"
    if r == "vpc nacl" and "allows all traffic" in i:
        return "HIGH"
    if r == "kms key" and "grant" in i:
        return "HIGH"
    if r == "sns topic" and "public" in i:
        return "HIGH"

    # ------------------ MEDIUM ---------------------
    if r == "s3 bucket" and "access logging is not enabled" in i:
        return "MEDIUM"
    if r == "rds instance" and "backup retention" in i:
        return "MEDIUM"
    if r == "lambda function" and "not connected to a vpc" in i:
        return "MEDIUM"
    if r == "vpc endpoint" and "no vpc endpoint" in i:
        return "MEDIUM"
    if r == "kms key" and "rotation is not enabled" in i:
        return "MEDIUM"
    if r == "sns topic" and "encryption is not enabled" in i:
        return "MEDIUM"
    if r == "sns topic" and "sse encryption is not enabled" in i:
        return "MEDIUM"

    # All others:
    return "LOW"

def scan_iam():
    findings = []
    iam = boto3.client('iam')
    # Overly permissive policies
    try:
        roles = iam.list_roles()['Roles']
        for role in roles:
            try:
                attached_policies = iam.list_attached_role_policies(RoleName=role['RoleName'])['AttachedPolicies']
                for policy in attached_policies:
                    policy_ver = iam.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
                    pol_doc = iam.get_policy_version(
                        PolicyArn=policy['PolicyArn'],
                        VersionId=policy_ver)['PolicyVersion']['Document']
                    statement = pol_doc['Statement']
                    if not isinstance(statement, list):
                        statement = [statement]
                    for stmt in statement:
                        effect = stmt.get('Effect', '')
                        action = stmt.get('Action', [])
                        resource = stmt.get('Resource', [])
                        if (effect == 'Allow' and
                            ('*' in action or (isinstance(action, list) and '*' in action)) and
                            ('*' in resource or (isinstance(resource, list) and '*' in resource))):
                            findings.append({
                                'Region': 'global',
                                'ResourceType': 'IAM Role',
                                'ResourceName': role['RoleName'],
                                'Issue': 'Overly permissive IAM policy (Action/Resource: "*")',
                                'Severity': get_severity('IAM Role', 'Overly permissive IAM policy (Action/Resource: "*")')
                            })
            except Exception:
                continue
    except Exception as e:
        findings.append({
            'Region': 'global',
            'ResourceType': 'IAM Service',
            'ResourceName': 'N/A',
            'Issue': f'Error scanning IAM: {str(e)}',
            'Severity': get_severity('IAM Service', f'Error scanning IAM: {str(e)}')
        })
    # MFA enforcement (root + users)
    try:
        root_report = iam.get_account_summary()
        if root_report['SummaryMap']['AccountMFAEnabled'] == 0:
            findings.append({
                'Region': 'global',
                'ResourceType': 'Account Root',
                'ResourceName': 'Root',
                'Issue': 'Root account has no MFA enabled',
                'Severity': get_severity('Account Root', 'Root account has no MFA enabled')
            })
        users = iam.list_users()['Users']
        for user in users:
            mfa = iam.list_mfa_devices(UserName=user['UserName'])
            if not mfa['MFADevices']:
                findings.append({
                    'Region': 'global',
                    'ResourceType': 'IAM User',
                    'ResourceName': user['UserName'],
                    'Issue': 'No MFA device configured',
                    'Severity': get_severity('IAM User', 'No MFA device configured')
                })
    except Exception as e:
        findings.append({
            'Region': 'global',
            'ResourceType': 'IAM Service',
            'ResourceName': 'N/A',
            'Issue': f'Error scanning IAM for MFA: {str(e)}',
            'Severity': get_severity('IAM Service', f'Error scanning IAM for MFA: {str(e)}')
        })
    return findings

def scan_s3(region):
    findings = []
    s3 = boto3.client('s3', region_name=region)
    try:
        buckets = s3.list_buckets().get('Buckets', [])
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                loc = s3.get_bucket_location(Bucket=bucket_name).get('LocationConstraint')
                this_bucket_region = loc or 'us-east-1'
                if this_bucket_region != region:
                    continue
            except Exception:
                continue
            # Public access
            try:
                s3_policy_client = boto3.client('s3', region_name='us-east-1')
                status = s3_policy_client.get_bucket_policy_status(Bucket=bucket_name)
                if status.get('PolicyStatus', {}).get('IsPublic', False):
                    findings.append({
                        'Region': region,
                        'ResourceType': 'S3 Bucket',
                        'ResourceName': bucket_name,
                        'Issue': 'Bucket is public',
                        'Severity': get_severity('S3 Bucket', 'Bucket is public')
                    })
            except Exception:
                pass
            # Access Logging
            try:
                logging = s3.get_bucket_logging(Bucket=bucket_name)
                if 'LoggingEnabled' not in logging:
                    findings.append({
                        'Region': region,
                        'ResourceType': 'S3 Bucket',
                        'ResourceName': bucket_name,
                        'Issue': 'Access logging is not enabled',
                        'Severity': get_severity('S3 Bucket', 'Access logging is not enabled')
                    })
            except Exception:
                pass
            # Encryption
            try:
                s3.get_bucket_encryption(Bucket=bucket_name)
            except Exception:
                findings.append({
                    'Region': region,
                    'ResourceType': 'S3 Bucket',
                    'ResourceName': bucket_name,
                    'Issue': 'Default encryption is not enabled',
                    'Severity': get_severity('S3 Bucket', 'Default encryption is not enabled')
                })
            # Block public access
            try:
                bpa = s3.get_public_access_block(Bucket=bucket_name)
                cfg = bpa.get('PublicAccessBlockConfiguration', {})
                if not all(cfg.get(k, False) for k in [
                    'BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets']):
                    findings.append({
                        'Region': region,
                        'ResourceType': 'S3 Bucket',
                        'ResourceName': bucket_name,
                        'Issue': 'Block Public Access not fully enabled',
                        'Severity': get_severity('S3 Bucket', 'Block Public Access not fully enabled')
                    })
            except Exception:
                findings.append({
                    'Region': region,
                    'ResourceType': 'S3 Bucket',
                    'ResourceName': bucket_name,
                    'Issue': 'Block Public Access configuration missing',
                    'Severity': get_severity('S3 Bucket', 'Block Public Access configuration missing')
                })
    except Exception as e:
        findings.append({
            'Region': region,
            'ResourceType': 'S3 Service',
            'ResourceName': 'N/A',
            'Issue': f'Error listing buckets: {str(e)}',
            'Severity': get_severity('S3 Service', f'Error listing buckets: {str(e)}')
        })
    return findings

def scan_ec2(region):
    findings = []
    ec2 = boto3.client('ec2', region_name=region)
    # Security Groups
    try:
        security_groups = ec2.describe_security_groups()['SecurityGroups']
        for sg in security_groups:
            sg_id = sg['GroupId']
            for perm in sg.get('IpPermissions', []):
                for ip_range in perm.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        msg = f'Open to internet: {perm.get("IpProtocol")} ports {perm.get("FromPort")} - {perm.get("ToPort")}'
                        findings.append({
                            'Region': region,
                            'ResourceType': 'EC2 Security Group',
                            'ResourceName': sg_id,
                            'Issue': msg,
                            'Severity': get_severity('EC2 Security Group', msg)
                        })
    except Exception as e:
        findings.append({
            'Region': region,
            'ResourceType': 'EC2 Service',
            'ResourceName': 'N/A',
            'Issue': f'Error listing security groups: {str(e)}',
            'Severity': get_severity('EC2 Service', f'Error listing security groups: {str(e)}')
        })
    # EBS Encryption
    try:
        volumes = ec2.describe_volumes()['Volumes']
        for vol in volumes:
            if not vol.get('Encrypted', False):
                findings.append({
                    'Region': region,
                    'ResourceType': 'EC2 EBS Volume',
                    'ResourceName': vol['VolumeId'],
                    'Issue': 'EBS volume is not encrypted',
                    'Severity': get_severity('EC2 EBS Volume', 'EBS volume is not encrypted')
                })
    except Exception as e:
        findings.append({
            'Region': region,
            'ResourceType': 'EC2 Service',
            'ResourceName': 'N/A',
            'Issue': f'Error listing volumes: {str(e)}',
            'Severity': get_severity('EC2 Service', f'Error listing volumes: {str(e)}')
        })
    return findings

def scan_rds(region):
    findings = []
    rds = boto3.client('rds', region_name=region)
    try:
        dbs = rds.describe_db_instances()['DBInstances']
        for db in dbs:
            dbid = db['DBInstanceIdentifier']
            if db.get('PubliclyAccessible', False):
                findings.append({
                    'Region': region,
                    'ResourceType': 'RDS Instance',
                    'ResourceName': dbid,
                    'Issue': 'Database instance is publicly accessible',
                    'Severity': get_severity('RDS Instance', 'Database instance is publicly accessible')
                })
            if not db.get('StorageEncrypted', False):
                findings.append({
                    'Region': region,
                    'ResourceType': 'RDS Instance',
                    'ResourceName': dbid,
                    'Issue': 'Database instance is not encrypted',
                    'Severity': get_severity('RDS Instance', 'Database instance is not encrypted')
                })
            if db.get('BackupRetentionPeriod', 0) < 7:
                findings.append({
                    'Region': region,
                    'ResourceType': 'RDS Instance',
                    'ResourceName': dbid,
                    'Issue': 'Backup Retention period < 7 days',
                    'Severity': get_severity('RDS Instance', 'Backup Retention period < 7 days')
                })
    except Exception as e:
        findings.append({
            'Region': region,
            'ResourceType': 'RDS Service',
            'ResourceName': 'N/A',
            'Issue': f'Error listing RDS: {str(e)}',
            'Severity': get_severity('RDS Service', f'Error listing RDS: {str(e)}')
        })
    return findings

def scan_lambda(region):
    findings = []
    lam = boto3.client('lambda', region_name=region)
    iam = boto3.client('iam')
    try:
        funcs = lam.list_functions()['Functions']
        for fn in funcs:
            fn_name = fn['FunctionName']
            role_arn = fn.get('Role', '')
            if role_arn:
                role_name = role_arn.split('/')[-1]
                try:
                    att_pols = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
                    for policy in att_pols:
                        pol_ver = iam.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
                        pol_doc = iam.get_policy_version(
                            PolicyArn=policy['PolicyArn'],
                            VersionId=pol_ver)['PolicyVersion']['Document']
                        statement = pol_doc['Statement']
                        if not isinstance(statement, list):
                            statement=[statement]
                        for stmt in statement:
                            effect = stmt.get('Effect', '')
                            action = stmt.get('Action', [])
                            resource = stmt.get('Resource', [])
                            if (effect == 'Allow' and
                                ('*' in action or (isinstance(action, list) and '*' in action)) and
                                ('*' in resource or (isinstance(resource, list) and '*' in resource))):
                                findings.append({
                                    'Region': region,
                                    'ResourceType': 'Lambda Function',
                                    'ResourceName': fn_name,
                                    'Issue': 'Lambda function uses over-privileged IAM role',
                                    'Severity': get_severity('Lambda Function', 'Lambda function uses over-privileged IAM role')
                                })
                except Exception:
                    pass
            if not fn.get('VpcConfig', {}).get('VpcId'):
                findings.append({
                    'Region': region,
                    'ResourceType': 'Lambda Function',
                    'ResourceName': fn_name,
                    'Issue': 'Not connected to a VPC',
                    'Severity': get_severity('Lambda Function', 'Not connected to a VPC')
                })
    except Exception as e:
        findings.append({
            'Region': region,
            'ResourceType': 'Lambda Service',
            'ResourceName': 'N/A',
            'Issue': f'Error listing lambda functions: {str(e)}',
            'Severity': get_severity('Lambda Service', f'Error listing lambda functions: {str(e)}')
        })
    return findings

def scan_vpc(region):
    findings = []
    ec2 = boto3.client('ec2', region_name=region)
    try:
        nacls = ec2.describe_network_acls()['NetworkAcls']
        for nacl in nacls:
            for entry in nacl['Entries']:
                if entry['RuleAction'] == 'allow' and entry.get('CidrBlock', '') == '0.0.0.0/0':
                    msg = f"NACL allows all traffic. Rule #{entry['RuleNumber']}"
                    findings.append({
                        'Region': region,
                        'ResourceType': 'VPC NACL',
                        'ResourceName': nacl['NetworkAclId'],
                        'Issue': msg,
                        'Severity': get_severity('VPC NACL', msg)
                    })
    except Exception as e:
        findings.append({
            'Region': region,
            'ResourceType': 'VPC Service',
            'ResourceName': 'N/A',
            'Issue': f'Error listing NACLs: {str(e)}',
            'Severity': get_severity('VPC Service', f'Error listing NACLs: {str(e)}')
        })
    try:
        ec2_endpoints = ec2.describe_vpc_endpoints()['VpcEndpoints']
        s3_endpoint_exists = any(
            ep['ServiceName'].endswith('.s3') for ep in ec2_endpoints
        )
        if not s3_endpoint_exists:
            findings.append({
                'Region': region,
                'ResourceType': 'VPC Endpoint',
                'ResourceName': "N/A",
                'Issue': 'No VPC endpoint for S3',
                'Severity': get_severity('VPC Endpoint', 'No VPC endpoint for S3')
            })
    except Exception:
        pass
    try:
        sgroups = ec2.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': ['default']}])['SecurityGroups']
        for sg in sgroups:
            open_ingress = False
            for perm in sg.get('IpPermissions', []):
                for ip_range in perm.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        open_ingress = True
            if open_ingress:
                findings.append({
                    'Region': region,
                    'ResourceType': 'VPC Default SG',
                    'ResourceName': sg['GroupId'],
                    'Issue': 'Default security group allows inbound from 0.0.0.0/0',
                    'Severity': get_severity('VPC Default SG', 'Default security group allows inbound from 0.0.0.0/0')
                })
    except Exception:
        pass
    return findings

def scan_kms(region):
    findings = []
    kms = boto3.client('kms', region_name=region)
    try:
        keys = kms.list_keys()['Keys']
        for key_obj in keys:
            key_id = key_obj['KeyId']
            try:
                attrs = kms.describe_key(KeyId=key_id)['KeyMetadata']
                if not attrs.get('KeyRotationEnabled', False):
                    findings.append({
                        'Region': region,
                        'ResourceType': 'KMS Key',
                        'ResourceName': key_id,
                        'Issue': 'Key rotation is not enabled',
                        'Severity': get_severity('KMS Key', 'Key rotation is not enabled')
                    })
                policy_json = kms.get_key_policy(KeyId=key_id, PolicyName='default')['Policy']
                policy = json.loads(policy_json)
                stmts = policy['Statement'] if 'Statement' in policy else []
                if not isinstance(stmts, list):
                    stmts=[stmts]
                for stmt in stmts:
                    if stmt.get('Effect') == 'Allow':
                        action = stmt.get('Action', [])
                        resource = stmt.get('Resource', [])
                        principal = stmt.get('Principal', {})
                        if ('*' in action or (isinstance(action, list) and '*' in action)) \
                                and (stmt.get('Resource') == '*' or (isinstance(resource, list) and '*' in resource)) \
                                and (principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*')):
                            findings.append({
                                'Region': region,
                                'ResourceType': 'KMS Key',
                                'ResourceName': key_id,
                                'Issue': 'Overly broad KMS key policy',
                                'Severity': get_severity('KMS Key', 'Overly broad KMS key policy')
                            })
                grants = kms.list_grants(KeyId=key_id)['Grants']
                if len(grants) > 3:
                    findings.append({
                        'Region': region,
                        'ResourceType': 'KMS Key',
                        'ResourceName': key_id,
                        'Issue': 'Too many grants on KMS key',
                        'Severity': get_severity('KMS Key', 'Too many grants on KMS key')
                    })
            except Exception:
                pass
    except Exception as e:
        findings.append({
            'Region': region,
            'ResourceType': 'KMS Service',
            'ResourceName': 'N/A',
            'Issue': f'Error listing keys: {str(e)}',
            'Severity': get_severity('KMS Service', f'Error listing keys: {str(e)}')
        })
    return findings

def scan_sns(region):
    findings = []
    sns = boto3.client('sns', region_name=region)
    try:
        topics = sns.list_topics()['Topics']
        for t in topics:
            arn = t['TopicArn']
            try:
                attrs = sns.get_topic_attributes(TopicArn=arn)['Attributes']
                policy = json.loads(attrs.get('Policy', '{}'))
                stmts = policy['Statement'] if 'Statement' in policy else []
                if not isinstance(stmts, list):
                    stmts=[stmts]
                for stmt in stmts:
                    effect = stmt.get('Effect', '')
                    principal = stmt.get('Principal', {})
                    if effect == 'Allow' and (principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*')):
                        findings.append({
                            'Region': region,
                            'ResourceType': 'SNS Topic',
                            'ResourceName': arn,
                            'Issue': 'SNS topic is public',
                            'Severity': get_severity('SNS Topic', 'SNS topic is public')
                        })
            except Exception:
                pass
            try:
                attrs = sns.get_topic_attributes(TopicArn=arn)['Attributes']
                if 'KmsMasterKeyId' not in attrs:
                    findings.append({
                        'Region': region,
                        'ResourceType': 'SNS Topic',
                        'ResourceName': arn,
                        'Issue': 'SSE encryption is not enabled',
                        'Severity': get_severity('SNS Topic', 'SSE encryption is not enabled')
                    })
            except Exception:
                pass
    except Exception as e:
        findings.append({
            'Region': region,
            'ResourceType': 'SNS Service',
            'ResourceName': 'N/A',
            'Issue': f'Error listing topics: {str(e)}',
            'Severity': get_severity('SNS Service', f'Error listing topics: {str(e)}')
        })
    return findings

def store_findings(findings, scan_id):
    dynamodb = boto3.client('dynamodb')
    for finding in findings:
        item = {
            'ScanID': {'S': scan_id},
            'Region': {'S': finding['Region']},
            'ResourceType': {'S': finding['ResourceType']},
            'ResourceName': {'S': finding['ResourceName']},
            'Issue': {'S': finding['Issue']},
            'Severity': {'S': finding['Severity']}
        }
        try:
            dynamodb.put_item(
                TableName=DYNAMODB_TABLE,
                Item=item
            )
        except ClientError as e:
            print(f"Error storing item: {e}")

def publish_findings(findings):
    if not findings:
        return
    sns = boto3.client('sns')
    findings_by_region = {}
    for finding in findings:
        findings_by_region.setdefault(finding['Region'], []).append(finding)
    message_lines = []
    for region in sorted(findings_by_region):
        message_lines.append(f"Region: {region}")
        for finding in findings_by_region[region]:
            message_lines.append(
                f"- [{finding['ResourceType']}] {finding['ResourceName']}: {finding['Issue']} (Severity: {finding['Severity']})"
            )
        message_lines.append("")
    message = "\n".join(message_lines)
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="Cloud Security Scout Findings",
            Message=message
        )
    except ClientError as e:
        print(f"Error publishing to SNS: {e}")

def lambda_handler(event, context):
    scan_id = str(uuid.uuid4())
    regions = get_regions()
    all_findings = []
    all_findings.extend(scan_iam())
    for region in regions:
        all_findings.extend(scan_s3(region))
        all_findings.extend(scan_ec2(region))
        all_findings.extend(scan_rds(region))
        all_findings.extend(scan_lambda(region))
        all_findings.extend(scan_vpc(region))
        all_findings.extend(scan_kms(region))
        all_findings.extend(scan_sns(region))
    store_findings(all_findings, scan_id)
    publish_findings(all_findings)
    return {
        'statusCode': 200,
        'body': f'Scan completed, total findings: {len(all_findings)}, scan_id: {scan_id}'
    }
