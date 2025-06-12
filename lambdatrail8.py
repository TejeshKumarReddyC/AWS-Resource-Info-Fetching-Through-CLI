#Author- Tejesh Kumar Reddy .C
#Version-2.4
#Purpose-To check aws arn status in different accounts 
import boto3
import threading
import re
import csv
import time
import subprocess
from collections import defaultdict
from botocore.exceptions import ClientError

output_lock = threading.Lock()
log_file = 'results.csv'
arn_pattern = re.compile(r"^arn:aws:([^:]+):([^:]*):([^:]*):([^:/]*)([:/].+)?$")

stop_event = threading.Event()
#Auto Authentication For Every 4 Minutes to Get rid of Session Token Expiration of Base Account.
def run_auth_loop(region, profile_name, username, password):
    print("auth_started")
    while not stop_event.is_set():
        cloud_tool_auth(region, profile_name, username, password)
        stop_event.wait(timeout=240)

assumed_sessions = {}
last_context = {'account_id': None, 'region': None}
#CLOUD-TOOL AUTHENTICATION
def cloud_tool_auth(region, profile_name, username, password):
    input_data1 = f"{region}\n{profile_name}\n{username}\n\n\n\n"
    process1 = subprocess.run(
            [r'C:\Users\C292242\.venv\cloud-tool\Scripts\cloud-tool.cmd', 'configure'],
            input=input_data1.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
           )
    process2 = subprocess.run(
            [r'C:\Users\C292242\.venv\cloud-tool\Scripts\cloud-tool.cmd', 'login', '-f', profile_name, '--password', password],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
           )
    print("done")
    return None
def get_waf_tags(session, arn, region):
    try:
        arn_lower = arn.lower()

        # Detect WAFv2 (newer generation)
        if ":wafv2:" in arn:
            wafv2 = session.client('wafv2', region_name=region)
            try:
                response = wafv2.list_tags_for_resource(ResourceARN=arn)
                tags = response.get('TagInfoForResource', {}).get('TagList', [])
                return "; ".join(f"{tag['Key']}={tag['Value']}" for tag in tags)
            except Exception as e:
                print(f"[WARNING] Failed to fetch WAFv2 tags for {arn}: {e}")
        # Detect WAF Classic
        elif ":waf-regional:" in arn_lower:
            print("check")
            # Use waf-regional in the specified region
            client = session.client("waf-regional", region_name=region)
            response = client.list_tags_for_resource(ResourceARN=arn)
            print(response)
            tags = response.get('TagInfoForResource', {}).get('TagList', [])
            return "; ".join(f"{tag['Key']}={tag['Value']}" for tag in tags)

        elif ":waf:" in arn_lower:
            # Use us-east-1 for global WAF Classic (CloudFront)
            client = session.client("waf", region_name="us-east-1")
            response = client.list_tags_for_resource(ResourceARN=arn)
            print(response)
            tags = response.get('TagInfoForResource', {}).get('TagList', [])
            return "; ".join(f"{tag['Key']}={tag['Value']}" for tag in tags)

        else:
            print(f"[WARNING] Unknown WAF service type for ARN: {arn}")

    except Exception as e:
        print(f"[WARNING] Failed to fetch WAF tags for {arn}: {e}")
    return ""
def get_sagemaker_tags(session, arn, region):
    try:
        sm_client = session.client('sagemaker', region_name=region)

        # Try exact match first
        try:
            response = sm_client.list_tags(ResourceArn=arn)
            tags = response.get('Tags', [])
            return "; ".join(f"{tag['Key']}={tag['Value']}" for tag in tags)
        except sm_client.exceptions.ClientError as ce:
            if "ValidationException" not in str(ce):
                raise  # Reraise if it's not a validation issue (e.g., resource doesn't exist)

        # Try case-insensitive fallback
        paginator = session.client('resourcegroupstaggingapi', region_name=region).get_paginator('get_resources')
        for page in paginator.paginate(ResourceTypeFilters=["sagemaker"]):
            for resource in page.get('ResourceTagMappingList', []):
                if resource['ResourceARN'].lower() == arn.lower():
                    tags = resource.get('Tags', [])
                    return "; ".join(f"{tag['Key']}={tag['Value']}" for tag in tags)

    except Exception as e:
        print(f"[WARNING] Failed to fetch SageMaker tags for {arn}: {e}")
    return ""

def get_env_tag(session, arn, region):
    try:
        # Normalize ARN to lowercase for service detection
        match = re.match(r"arn:aws:([^:]+):", arn, re.IGNORECASE)
        service = match.group(1).lower() if match else None

        if service in ['waf', 'wafv2', 'waf-regional']:
            return get_waf_tags(session, arn, region)
        elif service == "sagemaker":
            return get_sagemaker_tags(session, arn, region)
        elif service == "ecs":
            return get_ecs_tags(session, arn, region)
        else:
            tag_client = session.client('resourcegroupstaggingapi', region_name=region)
            paginator = tag_client.get_paginator('get_resources')
            page_iterator = paginator.paginate(ResourceARNList=[arn])

            # First try exact match
            for page in page_iterator:
                for resource in page.get('ResourceTagMappingList', []):
                    if resource['ResourceARN'] == arn:
                        tags = resource.get('Tags', [])
                        return "; ".join(f"{tag['Key']}={tag['Value']}" for tag in tags)

            # Case-insensitive fallback
            page_iterator = paginator.paginate()
            for page in page_iterator:
                for resource in page.get('ResourceTagMappingList', []):
                    if resource['ResourceARN'].lower() == arn.lower():
                        tags = resource.get('Tags', [])
                        return "; ".join(f"{tag['Key']}={tag['Value']}" for tag in tags)

    except Exception as e:
        print(f"[WARNING] Failed to fetch tags for {arn}: {e}")
    return ""

def get_ecs_tags(session, arn, region):
    try:
        ecs_client = session.client('ecs', region_name=region)

        # Extract service name from short ARN
        match = re.match(r"arn:aws:ecs:[^:]+:[^:]+:service/(.+)", arn)
        if not match:
            raise ValueError("Invalid ECS ARN format")
        service_name = match.group(1).split('/')[-1]

        # List all clusters and search for the service
        clusters = ecs_client.list_clusters()['clusterArns']
        for cluster_arn in clusters:
            response = ecs_client.describe_services(
                cluster=cluster_arn,
                services=[service_name]
            )
            services = response.get('services', [])
            for service in services:
                if service['status'] == 'ACTIVE' and service['serviceName'] == service_name:
                    long_arn = service['serviceArn']
                    tag_response = ecs_client.list_tags_for_resource(resourceArn=long_arn)
                    tags = tag_response.get('tags', [])
                    return "; ".join(f"{tag['key']}={tag['value']}" for tag in tags)

    except Exception as e:
        print(f"[WARNING] Failed to fetch ECS tags for {arn}: {e}")
    return ""
#Function for reading arns from a text file(arns.txt)
def read_arns(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]
#Function for extracting SERVICE, REGION, ACCOUNT_ID from the arn
def parse_arn(arn):
    match = arn_pattern.match(arn)
    if not match:
       return None
    service, region, account = match.group(1), match.group(2), match.group(3)
    return {
          'service': service,
          'region': region,
          'account': account,
          'full_arn': arn
      }
def group_arns_by_key(arns):
    grouped = defaultdict(list)
    for arn in arns:
        #print(arn)
        parts = parse_arn(arn)
        if not parts:
            print("couldn't parse arn")
            continue
        if parts:
            key = (parts['service'], parts['account'], parts['region'])
            grouped[key].append(parts['full_arn'])
    return grouped
        
#Logs output to a file
def log_result(arn, service, account_id, region, status, message, env=""):
    with output_lock:
        with open(log_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([arn, service, account_id, region, status, message, env])
#Session Management
def get_session(account_id, region, BASE_PROFILE, ROLE_NAME, username, password):
    #print(account_id)
    global assumed_sessions, last_context
    if last_context['account_id'] == account_id and last_context['region'] == region:
        return assumed_sessions.get(account_id)
    if account_id == get_base_account_id(BASE_PROFILE):
        #cloud_tool_auth(region, BASE_PROFILE, username, password)
        session = boto3.session.Session(profile_name=BASE_PROFILE, region_name=region)
    else:
        role_arn =f"arn:aws:iam::{account_id}:role/{ROLE_NAME}"
        base_session = boto3.session.Session(profile_name=BASE_PROFILE)
        sts = base_session.client('sts')
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName='CheckSession')['Credentials']
            session = boto3.session.Session(aws_access_key_id=creds['AccessKeyId'], aws_secret_access_key=creds['SecretAccessKey'], aws_session_token=creds['SessionToken'], region_name=region)
        except Exception as e:
            print(f"[ERROR] Cannot assume role into {account_id}: {e}")
            assumed_sessions[account_id] = None
            return None
    assumed_sessions[account_id] = session
    last_context['account_id'] = account_id
    last_context['region'] = region
    return session
def get_base_account_id(BASE_PROFILE):
    session = boto3.session.Session(profile_name=BASE_PROFILE)
    sts = session.client('sts')
    return sts.get_caller_identity()['Account']
#____SERVICE CHECK FUNCTIONS______
def check_lambda_batch(account_id, region, arns, session):
    try:
        client = session.client('lambda', region_name=region)
        paginator = client.get_paginator('list_functions')
        existing = {}
        for page in paginator.paginate():
            for fn in page['Functions']:
                existing[fn['FunctionArn']] = fn.get('Runtime', 'Unknown')

        existing_lower = {k.lower(): (k, v) for k, v in existing.items()}

        for arn in arns:
            print(f"[INFO] Processing ARN: {arn}")

            if arn in existing:
                runtime = existing[arn]
                env_value = get_env_tag(session, arn, region)
                log_result(arn, 'lambda', account_id, region, 'FOUND', f"Exists (Runtime: {runtime})", env=env_value)

            elif arn.lower() in existing_lower:
                orig_arn, runtime = existing_lower[arn.lower()]
                env_value = get_env_tag(session, orig_arn, region)
                log_result(orig_arn, 'lambda', account_id, region, 'FOUND (Case-Insensitive)', f"Exists (Runtime: {runtime})", env=env_value)

            else:
                log_result(arn, 'lambda', account_id, region, 'MISSING', "Lambda Not Found", env="")

    except Exception as e:
        for arn in arns:
            log_result(arn, 'lambda', account_id, region, 'ERROR', str(e))
def check_eks_by_arn(account_id, region, arns, session):
    import re

    def extract_eks_name_from_arn(arn):
        match = re.match(r"^arn:aws:eks:[^:]+:[^:]+:cluster/(.+)$", arn)
        return match.group(1) if match else None

    try:
        client = session.client('eks', region_name=region)
        paginator = client.get_paginator('list_clusters')
        existing_clusters = set()

        for page in paginator.paginate():
            existing_clusters.update(page.get('clusters', []))

        for arn in arns:
            arn = arn.strip()
            cluster_name = extract_eks_name_from_arn(arn)
            if not cluster_name:
                log_result(arn, 'eks', account_id, region, 'INVALID', "Invalid EKS ARN format", env="")
                continue

            if cluster_name in existing_clusters:
                response = client.describe_cluster(name=cluster_name)
                version = response['cluster']['version']
                #env_value = get_env_tag(session, cluster_name, region, resource_type='eks')
                log_result(arn, 'eks', account_id, region, 'FOUND', f"Kubernetes Version: {version}")
            else:
                log_result(arn, 'eks', account_id, region, 'MISSING', "EKS Cluster Not Found", env="")

    except Exception as e:
        for arn in arns:
            log_result(arn, 'eks', account_id, region, 'ERROR', str(e))

def check_ec2_by_arn(account_id, region, arns, session):
   
    def extract_ec2_id_from_arn(arn):
        match = re.match(r"^arn:aws:ec2:[^:]+:[^:]+:instance/(.+)$", arn)
        return match.group(1) if match else None

    client = session.client('ec2', region_name=region)
    arn_map = {}
    instance_ids = []

    for arn in arns:
        arn = arn.strip()
        iid = extract_ec2_id_from_arn(arn)
        if iid:
            instance_ids.append(iid)
            arn_map[iid] = arn
        else:
            log_result(arn, 'ec2', account_id, region, 'INVALID', "Invalid EC2 ARN format", env="")

    found_ids = set()

    # Process in chunks of 100 (API limit)
    for i in range(0, len(instance_ids), 100):
        chunk = instance_ids[i:i + 100]
        try:
            response = client.describe_instances(InstanceIds=chunk)
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    iid = instance['InstanceId']
                    found_ids.add(iid)
                    state = instance['State']['Name']
                    itype = instance['InstanceType']
                    #env_value = get_env_tag(session, iid, region, resource_type='ec2')
                    log_result(arn_map[iid], 'ec2', account_id, region, 'FOUND', f"Type: {itype}, State: {state}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                # Extract invalid IDs from the error message
                missing_ids = [id.strip() for id in e.response['Error']['Message'].split("'")[1].split(',')]
                for mid in missing_ids:
                    log_result(arn_map.get(mid, mid), 'ec2', account_id, region, 'MISSING', "EC2 Instance Not Found", env="")
            else:
                for iid in chunk:
                    log_result(arn_map[iid], 'ec2', account_id, region, 'ERROR', str(e))

def check_rds_batch(account_id, region, arns, session):
    try:
        client = session.client('rds', region_name=region)
        paginator_db = client.get_paginator('describe_db_instances')
        paginator_cluster = client.get_paginator('describe_db_clusters')

        all_instances = []
        for page in paginator_db.paginate():
            all_instances.extend(page.get('DBInstances', []))

        all_clusters = []
        for page in paginator_cluster.paginate():
            all_clusters.extend(page.get('DBClusters', []))

        # Prepare case-insensitive lookup maps
        instance_arns = {inst['DBInstanceArn']: inst for inst in all_instances if 'DBInstanceArn' in inst}
        instance_arns_lower = {k.lower(): k for k in instance_arns}

        cluster_arns = {clus['DBClusterArn']: clus for clus in all_clusters if 'DBClusterArn' in clus}
        cluster_arns_lower = {k.lower(): k for k in cluster_arns}

        for arn in arns:
            print('yes')
            if arn in instance_arns:
                inst = instance_arns[arn]
                engine = inst.get('Engine', 'Unknown')
                engine_version = inst.get('EngineVersion', 'Unknown')
                instance_class = inst.get('DBInstanceClass', 'Unknown')
                ca_cert = inst.get('CACertificateIdentifier', 'Unknown')
                db_type = 'serverless' if inst.get('DBInstanceClass') == 'db.serverless' else 'provisioned'
                env_value = get_env_tag(session, arn, region)
                log_result(arn, 'rds', account_id, region, 'FOUND',
                           f"Engine: {engine} {engine_version}, Class: {instance_class}, CA: {ca_cert}, Type: {db_type}", env=env_value)

            elif arn.lower() in instance_arns_lower:
                matched_arn = instance_arns_lower[arn.lower()]
                inst = instance_arns[matched_arn]
                engine = inst.get('Engine', 'Unknown')
                engine_version = inst.get('EngineVersion', 'Unknown')
                instance_class = inst.get('DBInstanceClass', 'Unknown')
                ca_cert = inst.get('CACertificateIdentifier', 'Unknown')
                db_type = 'serverless' if inst.get('DBInstanceClass') == 'db.serverless' else 'provisioned'
                env_value = get_env_tag(session, matched_arn, region)
                log_result(matched_arn, 'rds', account_id, region, 'FOUND (Case-Insensitive)',
                           f"Engine: {engine} {engine_version}, Class: {instance_class}, CA: {ca_cert}, Type: {db_type}", env=env_value)

            elif arn in cluster_arns:
                clus = cluster_arns[arn]
                engine = clus.get('Engine', 'Unknown')
                engine_version = clus.get('EngineVersion', 'Unknown')
                ca_cert = clus.get('CACertificateIdentifier', 'Unknown')
                instance_ids = [m['DBInstanceIdentifier'] for m in clus.get('DBClusterMembers', [])]
                db_type = 'serverless' if clus.get('EngineMode') == 'serverless' else 'provisioned'
                env_value = get_env_tag(session, arn, region)
                log_result(arn, 'rds', account_id, region, 'FOUND',
                           f"Engine: {engine} {engine_version}, Instance_count: {len(instance_ids)}, "
                           f"Instances: {', '.join(instance_ids)}, CA: {ca_cert}, Type: {db_type}", env=env_value)

            elif arn.lower() in cluster_arns_lower:
                matched_arn = cluster_arns_lower[arn.lower()]
                clus = cluster_arns[matched_arn]
                engine = clus.get('Engine', 'Unknown')
                engine_version = clus.get('EngineVersion', 'Unknown')
                ca_cert = clus.get('CACertificateIdentifier', 'Unknown')
                instance_ids = [m['DBInstanceIdentifier'] for m in clus.get('DBClusterMembers', [])]
                db_type = 'serverless' if clus.get('EngineMode') == 'serverless' else 'provisioned'
                env_value = get_env_tag(session, matched_arn, region)
                log_result(matched_arn, 'rds', account_id, region, 'FOUND (Case-Insensitive)',
                           f"Engine: {engine} {engine_version}, Instance_count: {len(instance_ids)}, "
                           f"Instances: {', '.join(instance_ids)}, CA: {ca_cert}, Type: {db_type}", env=env_value)

            else:
                log_result(arn, 'rds', account_id, region, 'MISSING', 'RDS ARN Not found', env="")

    except Exception as e:
        for arn in arns:
            log_result(arn, 'rds', account_id, region, 'ERROR', str(e))
                
def check_dms_batch(account_id, region, arns, session):
    try:
        client = session.client('dms', region_name=region)
        dms_instances = []
        for page in client.get_paginator('describe_replication_instances').paginate():
            dms_instances.extend(page.get('ReplicationInstances', []))
        for arn in arns:
            found = False
            for dms in dms_instances:
                if dms.get('ReplicationInstanceArn') == arn:
                    instance_class = dms.get('ReplicationInstanceClass', 'Unknown')
                    engine_version = dms.get('EngineVersion', 'Unknown')
                    env_value = get_env_tag(session, arn, region)
                    log_result(arn, 'dms', account_id, region, 'FOUND', f"Class: {instance_class}, EngineVersion: {engine_version}", env=env_value)
                    found = True
                    break
            if not found:
                log_result(arn, 'dms', account_id, region, 'MISSING', "DMS Instance Not found", env="")
    except Exception as e:
        for arn in arns:
            log_result(arn, 'dms', account_id, region, 'ERROR', str(e))

def check_sagemaker_batch(account_id, region, arns, session):
    try:
        client = session.client('sagemaker', region_name=region)
        paginator = client.get_paginator('list_notebook_instances')
        actual_arns = []
        arn_to_name = {}
        for page in paginator.paginate():
            for notebook in page.get('NotebookInstances', []):
                arn = notebook['NotebookInstanceArn']
                name = notebook['NotebookInstanceName']
                actual_arns.append(arn)
                arn_to_name[arn.lower()] = name  # map lowercased ARN to name for describe

        existing_lower = {arn.lower(): arn for arn in actual_arns}

        for arn in arns:
            print("Processing the", arn)
            if arn in actual_arns:
                nb_desc = client.describe_notebook_instance(NotebookInstanceName=arn_to_name[arn.lower()])
                platform = nb_desc.get('PlatformIdentifier', 'Unknown')
                env_value = get_env_tag(session, arn, region)
                log_result(arn, 'sagemaker', account_id, region, 'FOUND', f"Platform: {platform}", env=env_value)
            elif arn.lower() in existing_lower:
                actual_arn = existing_lower[arn.lower()]
                nb_desc = client.describe_notebook_instance(NotebookInstanceName=arn_to_name[arn.lower()])
                platform = nb_desc.get('PlatformIdentifier', 'Unknown')
                env_value = get_env_tag(session, arn, region)
                log_result(actual_arn, 'sagemaker', account_id, region, 'FOUND (Case-Insensitive)', f"Platform: {platform}", env=env_value)
            else:
                log_result(arn, 'sagemaker', account_id, region, 'MISSING', 'Notebook ARN not found', env="")
    except Exception as e:
        for arn in arns:
            log_result(arn, 'sagemaker', account_id, region, 'ERROR', str(e))

def check_mq_batch(account_id, region, arns, session):
    try:
        client = session.client('mq', region_name=region)
        paginator = client.get_paginator('list_brokers')
        aws_brokers = {}

        # Build a dictionary of BrokerArn -> BrokerId
        for page in paginator.paginate():
            for broker in page.get('BrokerSummaries', []):
                aws_brokers[broker['BrokerArn']] = broker['BrokerId']

        # Also build a lowercase mapping for case-insensitive comparison
        lower_arn_map = {arn.lower(): (arn, broker_id) for arn, broker_id in aws_brokers.items()}

        for arn in arns:
            if arn in aws_brokers:
                broker_id = aws_brokers[arn]
                try:
                    response = client.describe_broker(BrokerId=broker_id)
                    engine_type = response.get('EngineType', 'Unknown')
                    engine_version = response.get('EngineVersion', 'Unknown')
                    env_value = get_env_tag(session, arn, region)
                    log_result(arn, 'mq', account_id, region, 'FOUND',
                               f"Engine: {engine_type}, Version: {engine_version}", env=env_value)
                except Exception as e:
                    log_result(arn, 'mq', account_id, region, 'ERROR', str(e))
            elif arn.lower() in lower_arn_map:
                actual_arn, broker_id = lower_arn_map[arn.lower()]
                try:
                    response = client.describe_broker(BrokerId=broker_id)
                    engine_type = response.get('EngineType', 'Unknown')
                    engine_version = response.get('EngineVersion', 'Unknown')
                    env_value = get_env_tag(session, arn, region)
                    log_result(actual_arn, 'mq', account_id, region, 'FOUND (Case-Insensitive)',
                               f"Engine: {engine_type}, Version: {engine_version}", env=env_value)
                except Exception as e:
                    log_result(actual_arn, 'mq', account_id, region, 'ERROR', str(e))
            else:
                log_result(arn, 'mq', account_id, region, 'MISSING', "MQ ARN Not found", env="")

    except Exception as e:
        for arn in arns:
            log_result(arn, 'mq', account_id, region, 'ERROR', str(e))

def check_waf_batch(account_id, region, arns, session):
    for arn in arns:
        try:
            service = arn.split(':')[2]

            if service == 'wafv2':
                client = session.client('wafv2', region_name=region)
                scope = 'REGIONAL' if ':regional/' in arn else 'CLOUDFRONT'
                parts = arn.split('/')
                acl_name = parts[-2]
                acl_id = parts[-1]

                response = client.list_web_acls(Scope=scope)
                found = any(acl['Name'] == acl_name and acl['Id'] == acl_id for acl in response['WebACLs'])

                if found:
                    env_value = get_env_tag(session, arn, region)
                    log_result(arn, 'waf', account_id, region, f'FOUND (AWS WAF v2 - {scope})', '', env=env_value)
                else:
                    log_result(arn, 'waf', account_id, region, 'MISSING', 'Not found in AWS WAF v2', env="")

            elif service in ['waf', 'waf-regional']:
                client = session.client(service, region_name=region)
                acl_id = arn.split('/')[-1]
                response = client.list_web_acls()

                found = any(acl['WebACLId'] == acl_id for acl in response['WebACLs'])
                waf_type = 'WAF Classic (CloudFront)' if service == 'waf' else 'WAF Classic (Regional)'

                if found:
                    env_value = get_env_tag(session, arn, region)
                    log_result(arn, 'waf', account_id, region, f'FOUND ({waf_type})', '', env=env_value)
                else:
                    log_result(arn, 'waf', account_id, region, 'MISSING', f'Not found in {waf_type}', env="")
            else:
                log_result(arn, 'waf', account_id, region, 'ERROR', 'Unknown WAF service in ARN')

        except Exception as e:
            log_result(arn, 'waf', account_id, region, 'ERROR', str(e))
def check_ecs_batch(account_id, region, arns, session):
    try:
        client = session.client('ecs', region_name=region)
        paginator = client.get_paginator('list_clusters')
        clusters = []
        for page in paginator.paginate():
            clusters.extend(page['clusterArns'])

        existing_services = {}
        for cluster_arn in clusters:
            service_paginator = client.get_paginator('list_services')
            service_arns = []
            for svc_page in service_paginator.paginate(cluster=cluster_arn):
                service_arns.extend(svc_page['serviceArns'])

            if service_arns:
                describe_batches = [service_arns[i:i + 10] for i in range(0, len(service_arns), 10)]
                for batch in describe_batches:
                    response = client.describe_services(cluster=cluster_arn, services=batch)
                    for service in response.get('services', []):
                        service_arn = service['serviceArn']
                        launch_type = service.get('launchType', 'Unknown')
                        existing_services[service_arn] = (cluster_arn, launch_type)

        existing_lower = {k.lower(): (k, v) for k, v in existing_services.items()}

        for arn in arns:
            print(f"[INFO] Processing ARN: {arn}")
            if arn in existing_services:
                cluster_arn, launch_type = existing_services[arn]
                env_value = get_env_tag(session, arn, region)
                log_result(arn, 'ecs', account_id, region, 'FOUND', f"Exists in cluster: {cluster_arn} (Launch Type: {launch_type})", env=env_value)

            elif arn.lower() in existing_lower:
                orig_arn, (cluster_arn, launch_type) = existing_lower[arn.lower()]
                env_value = get_env_tag(session, orig_arn, region)
                log_result(orig_arn, 'ecs', account_id, region, 'FOUND (Case-Insensitive)', f"Exists in cluster: {cluster_arn} (Launch Type: {launch_type})", env=env_value)

            else:
                log_result(arn, 'ecs', account_id, region, 'MISSING', "ECS Service Not Found", env="")

    except Exception as e:
        for arn in arns:
            log_result(arn, 'ecs', account_id, region, 'ERROR', str(e))

def check_beanstalk_batch(account_id, region, arns, session):
    try:
        client = session.client('elasticbeanstalk', region_name=region)
        platforms = client.list_platform_versions()['PlatformSummaryList']
        platform_arn_map = {p['PlatformArn']: p for p in platforms if 'PlatformArn' in p}
        platform_arn_map_lower = {k.lower(): k for k in platform_arn_map}

        for arn in arns:
            print(f"[INFO] Processing Beanstalk Platform ARN: {arn}")
            if arn in platform_arn_map:
                platform = platform_arn_map[arn]
                name = platform.get('PlatformOwner', 'Unknown') + "/" + platform.get('PlatformVersion', 'Unknown')
                env_value = get_env_tag(session, arn, region)
                log_result(arn, 'beanstalk-platform', account_id, region, 'FOUND',
                           f"Platform: {name}", env=env_value)

            elif arn.lower() in platform_arn_map_lower:
                matched_arn = platform_arn_map_lower[arn.lower()]
                platform = platform_arn_map[matched_arn]
                name = platform.get('PlatformOwner', 'Unknown') + "/" + platform.get('PlatformVersion', 'Unknown')
                env_value = get_env_tag(session, matched_arn, region)
                log_result(matched_arn, 'beanstalk-platform', account_id, region, 'FOUND (Case-Insensitive)',
                           f"Platform: {name}", env=env_value)

            else:
                log_result(arn, 'beanstalk-platform', account_id, region, 'MISSING', 'Platform ARN not found', env="")

    except Exception as e:
        for arn in arns:
            log_result(arn, 'beanstalk-platform', account_id, region, 'ERROR', str(e))

def check_docdb_batch(account_id, region, arns, session):
    try:
        client = session.client('docdb', region_name=region)

        instances = client.describe_db_instances().get('DBInstances', [])
        clusters = client.describe_db_clusters().get('DBClusters', [])

        docdb_resources = {}

        for inst in instances:
            if 'DBInstanceArn' in inst:
                docdb_resources[inst['DBInstanceArn']] = {
                    'type': 'instance',
                    'info': f"{inst.get('Engine', 'Unknown')} {inst.get('EngineVersion', 'Unknown')} | Class: {inst.get('DBInstanceClass', 'Unknown')}"
                }

        for clus in clusters:
            if 'DBClusterArn' in clus:
                members = [m['DBInstanceIdentifier'] for m in clus.get('DBClusterMembers', [])]
                docdb_resources[clus['DBClusterArn']] = {
                    'type': 'cluster',
                    'info': f"{clus.get('Engine', 'Unknown')} {clus.get('EngineVersion', 'Unknown')} | Instances: {', '.join(members)}"
                }

        docdb_resources_lower = {k.lower(): k for k in docdb_resources}

        for arn in arns:
            print(f"[INFO] Processing DocDB ARN: {arn}")

            if arn in docdb_resources:
                res = docdb_resources[arn]
                env_value = get_env_tag(session, arn, region)
                log_result(arn, f"docdb-{res['type']}", account_id, region, 'FOUND', res['info'], env=env_value)

            elif arn.lower() in docdb_resources_lower:
                matched_arn = docdb_resources_lower[arn.lower()]
                res = docdb_resources[matched_arn]
                env_value = get_env_tag(session, matched_arn, region)
                log_result(matched_arn, f"docdb-{res['type']}", account_id, region, 'FOUND (Case-Insensitive)', res['info'], env=env_value)

            else:
                log_result(arn, 'docdb', account_id, region, 'MISSING', 'Not found as instance or cluster', env="")

    except Exception as e:
        for arn in arns:
            log_result(arn, 'docdb', account_id, region, 'ERROR', str(e))
        
def check_kafka_batch(account_id, region, arns, session):
    try:
        client = session.client('kafka', region_name=region)

        paginator = client.get_paginator('list_clusters_v2')
        clusters = []
        for page in paginator.paginate():
            clusters.extend(page.get('ClusterInfoList', []))

        cluster_map = {
            cl['ClusterArn']: cl for cl in clusters if 'ClusterArn' in cl
        }
        cluster_map_lower = {k.lower(): k for k in cluster_map}

        for arn in arns:
            print(f"[INFO] Processing Kafka ARN: {arn}")
            matched_arn = None

            if arn in cluster_map:
                matched_arn = arn
            elif arn.lower() in cluster_map_lower:
                matched_arn = cluster_map_lower[arn.lower()]

            if matched_arn:
                try:
                    response = client.describe_cluster(ClusterArn=matched_arn)
                    cluster_info = response.get('ClusterInfo', {})
                    kafka_version = cluster_info.get('CurrentBrokerSoftwareInfo', {}).get('KafkaVersion', 'Unknown')
                    state = cluster_info.get('State', 'Unknown')
                    env_value = get_env_tag(session, matched_arn, region)

                    status_label = 'FOUND' if matched_arn == arn else 'FOUND (Case-Insensitive)'
                    log_result(matched_arn, 'kafka', account_id, region, status_label,
                               f"Kafka Version: {kafka_version}, Status: {state}", env=env_value)
                except Exception as e:
                    log_result(arn, 'kafka', account_id, region, 'ERROR', f"Failed to describe cluster: {str(e)}", env="")
            else:
                log_result(arn, 'kafka', account_id, region, 'MISSING', 'Kafka Cluster ARN not found', env="")

    except Exception as e:
        for arn in arns:
            log_result(arn, 'kafka', account_id, region, 'ERROR', str(e))

#___________SERVICE FUNCTION MAP______________
SERVICE_FUNCTION_MAP = {
    'lambda': check_lambda_batch,
    'rds' : check_rds_batch,
    'dms' : check_dms_batch,
    'sagemaker': check_sagemaker_batch,
    'mq': check_mq_batch,
    'waf-regional': check_waf_batch,
    'waf': check_waf_batch,
    'wafv2': check_waf_batch,
    'ecs': check_ecs_batch,
    'elasticbeanstalk': check_beanstalk_batch,
    'kafka': check_kafka_batch,
    'eks': check_eks_by_arn,
    'ec2': check_ec2_by_arn
}

#_______________MAIN EXECUTION_________________
def main():
    input_file = 'arns.txt'
    BASE_PROFILE = "tr-enterprise-cicd-prod"
    ROLE_NAME = "human-role/207950-SupportReadOnly"
    username = input("Enter the username like MGMT...: ")
    password = input("Enter the Cyberark Password: ")
    cloud_tool_auth('us-east-1', BASE_PROFILE, username, password)
    auth_thread = threading.Thread(target=run_auth_loop, args=('us-east-1', BASE_PROFILE, username, password), daemon=True)
    auth_thread.start()
    all_arns = read_arns(input_file)
    grouped_arns = group_arns_by_key(all_arns)
    for key, value in grouped_arns.items():
      with open(log_file, 'w', newline='') as f:
         writer = csv.writer(f)
         writer.writerow(['ARN', 'Service', 'AccountId', 'Region', 'Status', 'Message', 'Tags'])

    threads = []
    for (service, account_id, region), arns in grouped_arns.items():
            session = get_session(account_id, region, BASE_PROFILE, ROLE_NAME, username, password)
            if session is None:
                for arn in arns:
                    log_result(arn, service, account_id, region, 'ERROR', 'Session creation Failed')
                    continue
            check_func = SERVICE_FUNCTION_MAP.get(service)
            if check_func:
                t = threading.Thread(target=check_func, args=(account_id, region, arns, session))
                """ for key, arns in grouped_arns.items():
                    print(f" Group {key}: {len(arns)} ARNs")"""
                t.start()
                threads.append(t)
            else:
                for arn in arns:
                    log_result(arn, service, account_id, region, 'ERROR', 'Service is not supported currently')
    for t in threads:
        t.join()
    print("Resource Check Completed, See the results.csv for output")
    stop_event.set()
    auth_thread.join()
if __name__ == "__main__":
    main()
