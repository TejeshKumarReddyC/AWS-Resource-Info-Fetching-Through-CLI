#Author- Tejesh Kumar Reddy .C
#Version-2.4
#Purpose-To check aws arn status in different accounts 
import boto3
import threading
import re
import csv
import time
import subprocess
import getpass
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
                cluster_arn = response['cluster']['arn']

                # Fetch Nodegroup AMI Info + AL2 Detection
                ami_info = []
                al2_detected = False

                try:
                    ng_paginator = client.get_paginator('list_nodegroups')
                    nodegroups = []
                    for ng_page in ng_paginator.paginate(clusterName=cluster_name):
                        nodegroups.extend(ng_page.get('nodegroups', []))

                    for ng in nodegroups:
                        ng_detail = client.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng)
                        ami_type = ng_detail['nodegroup'].get('amiType', 'Unknown')
                        release_version = ng_detail['nodegroup'].get('releaseVersion', 'Unknown')

                        if 'AL2' in ami_type.upper():
                            al2_detected = True

                        ami_info.append(f"{ng}: {ami_type} ({release_version})")

                    ami_summary = "; ".join(ami_info) if ami_info else "No Managed Nodegroups found"

                except Exception as ng_err:
                    ami_summary = f"Error fetching nodegroups: {ng_err}"

                # Fetch All Tags
                try:
                    tags_response = client.list_tags_for_resource(resourceArn=cluster_arn)
                    tags = tags_response.get('tags', {})
                    if tags:
                        tags_str = "; ".join([f"{k}={v}" for k, v in tags.items()])
                    else:
                        tags_str = "NO_TAGS_FOUND"
                except Exception as tag_err:
                    tags_str = f"TagFetchError: {tag_err}"

                # Determine AL2 Risk Status
                if al2_detected:
                    status = 'RISK_AL2_AMI'
                else:
                    status = 'SAFE_AMI'

                # Final Output
                log_result(
                    arn, 'eks', account_id, region, "FOUND", 
                    f"{status}, Kubernetes Version: {version}; Node AMIs: {ami_summary}; Tags: {tags_str}",
                    env=tags_str
                )

            else:
                log_result(arn, 'eks', account_id, region, 'MISSING', "EKS Cluster Not Found", env="")

    except Exception as e:
        for arn in arns:
            log_result(arn, 'eks', account_id, region, 'ERROR', str(e))

"""def check_eks_by_arn(account_id, region, arns, session):
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
            log_result(arn, 'eks', account_id, region, 'ERROR', str(e))"""

def check_ec2_by_arn(account_id, region, arns, session):
   
    def extract_ec2_id_from_arn(arn):
        match = re.match(r"^arn:aws:ec2:[^:]+:[^:]+:instance/(.+)$", arn)
        return match.group(1) if match else None

    def extract_tags(tags_list):
        """Convert EC2 tag list to dictionary"""
        return {tag['Key']: tag['Value'] for tag in tags_list}

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

    # Try batch first
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

                    tags = extract_tags(instance.get('Tags', []))
                    name = tags.get('Name', '')
                    env_value = tags.get('Env', '')

                    tag_str = ', '.join([f"{k}:{v}" for k, v in tags.items()])

                    log_result(
                        arn_map[iid],
                        'ec2',
                        account_id,
                        region,
                        'FOUND',
                        f"Type: {itype}, State: {state}, Name: {name}, Tags: {tag_str}",
                        env=env_value
                    )
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                # Batch failed, process each ARN separately to prevent overwrite
                for iid in chunk:
                    try:
                        response = client.describe_instances(InstanceIds=[iid])
                        for reservation in response['Reservations']:
                            for instance in reservation['Instances']:
                                state = instance['State']['Name']
                                itype = instance['InstanceType']

                                tags = extract_tags(instance.get('Tags', []))
                                name = tags.get('Name', '')
                                env_value = tags.get('Env', '')

                                tag_str = ', '.join([f"{k}:{v}" for k, v in tags.items()])

                                log_result(
                                    arn_map[iid],
                                    'ec2',
                                    account_id,
                                    region,
                                    'FOUND',
                                    f"Type: {itype}, State: {state}, Name: {name}, Tags: {tag_str}",
                                    env=env_value
                                )
                    except ClientError as single_e:
                        if single_e.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                            log_result(arn_map[iid], 'ec2', account_id, region, 'MISSING', "EC2 Instance Not Found", env="")
                        else:
                            log_result(arn_map[iid], 'ec2', account_id, region, 'ERROR', str(single_e), env="")
            else:
                for iid in chunk:
                    log_result(arn_map[iid], 'ec2', account_id, region, 'ERROR', str(e), env="")
                    

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
                env_value = get_env_tag(session, arn, region)
                log_result(arn, 'rds', account_id, region, 'FOUND',
                           f"Engine: {engine} {engine_version}, Class: {instance_class}, CA: {ca_cert}", env=env_value)
            elif arn.lower() in instance_arns_lower:
                matched_arn = instance_arns_lower[arn.lower()]
                inst = instance_arns[matched_arn]
                engine = inst.get('Engine', 'Unknown')
                engine_version = inst.get('EngineVersion', 'Unknown')
                instance_class = inst.get('DBInstanceClass', 'Unknown')
                ca_cert = inst.get('CACertificateIdentifier', 'Unknown')
                env_value = get_env_tag(session, arn, region)
                log_result(matched_arn, 'rds', account_id, region, 'FOUND (Case-Insensitive)',
                           f"Engine: {engine} {engine_version}, Class: {instance_class}, CA: {ca_cert}", env=env_value)
            elif arn in cluster_arns:
                clus = cluster_arns[arn]
                engine = clus.get('Engine', 'Unknown')
                engine_version = clus.get('EngineVersion', 'Unknown')
                ca_cert = clus.get('CACertificateIdentifier', 'Unknown')
                instance_ids = [m['DBInstanceIdentifier'] for m in clus.get('DBClusterMembers', [])]
                env_value = get_env_tag(session, arn, region)
                log_result(arn, 'rds', account_id, region, 'FOUND',
                           f"Engine: {engine} {engine_version}, Instance_count: {len(instance_ids)}, "
                           f"Instances: {', '.join(instance_ids)}, CA: {ca_cert}",env=env_value)
            elif arn.lower() in cluster_arns_lower:
                matched_arn = cluster_arns_lower[arn.lower()]
                clus = cluster_arns[matched_arn]
                engine = clus.get('Engine', 'Unknown')
                engine_version = clus.get('EngineVersion', 'Unknown')
                ca_cert = clus.get('CACertificateIdentifier', 'Unknown')
                instance_ids = [m['DBInstanceIdentifier'] for m in clus.get('DBClusterMembers', [])]
                env_value = get_env_tag(session, arn, region)
                log_result(matched_arn, 'rds', account_id, region, 'FOUND (Case-Insensitive)',
                           f"Engine: {engine} {engine_version}, Instance_count: {len(instance_ids)}, "
                           f"Instances: {', '.join(instance_ids)}, CA: {ca_cert}",env=env_value)
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

        # Fetch clusters
        paginator = client.get_paginator('list_clusters')
        clusters = []
        for page in paginator.paginate():
            clusters.extend(page['clusterArns'])

        # Prepare service and task info maps
        existing_services = {}
        cluster_task_pv_map = {}

        for cluster_arn in clusters:
            # List services per cluster
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
                        service_platform_version = service.get('platformVersion', 'LATEST')

                        # Detect short or long ARN
                        service_arn_suffix = service_arn.split(':service/')[-1]
                        if '/' in service_arn_suffix:
                            arn_type = 'LONG_SERVICE_ARN'
                        else:
                            arn_type = 'SHORT_SERVICE_ARN'

                        existing_services[service_arn] = {
                            'cluster_arn': cluster_arn,
                            'launch_type': launch_type,
                            'service_platform_version': service_platform_version,
                            'arn_type': arn_type
                        }

            # List tasks per cluster
            task_arns = []
            task_paginator = client.get_paginator('list_tasks')
            for task_page in task_paginator.paginate(cluster=cluster_arn):
                task_arns.extend(task_page['taskArns'])

            if task_arns:
                task_batches = [task_arns[i:i + 100] for i in range(0, len(task_arns), 100)]
                for batch in task_batches:
                    task_desc = client.describe_tasks(cluster=cluster_arn, tasks=batch)
                    for task in task_desc.get('tasks', []):
                        if task.get('launchType') == 'FARGATE':
                            pv = task.get('platformVersion', 'Unknown')
                            cluster_task_pv_map.setdefault(cluster_arn, []).append(pv)

        # For case-insensitive lookup
        clusters_lower = {c.lower(): c for c in clusters}
        services_lower = {k.lower(): (k, v) for k, v in existing_services.items()}

        for arn in arns:
            print(f"[INFO] Processing ARN: {arn}")

            if ":service/" in arn:
                # Check for service ARN
                if arn in existing_services:
                    data = existing_services[arn]
                    env_value = get_env_tag(session, arn, region)

                    log_result(
                        arn, 'ecs', account_id, region, "FOUND",
                        f"CONFIGURED_PV_{data['service_platform_version']}, "
                        f"Launch Type: {data['launch_type']}, "
                        f"Cluster: {data['cluster_arn']}, "
                        f"ARN Type: {data['arn_type']}",
                        env=env_value
                    )

                elif arn.lower() in services_lower:
                    orig_arn, data = services_lower[arn.lower()]
                    env_value = get_env_tag(session, orig_arn, region)

                    log_result(
                        orig_arn, 'ecs', account_id, region, "FOUND",
                        f"CONFIGURED_PV_{data['service_platform_version']} (Case-Insensitive), "
                        f"Launch Type: {data['launch_type']}, "
                        f"Cluster: {data['cluster_arn']}, "
                        f"ARN Type: {data['arn_type']}",
                        env=env_value
                    )

                else:
                    log_result(arn, 'ecs', account_id, region, 'MISSING_SERVICE', "ECS Service Not Found", env="")

            elif ":cluster/" in arn:
                # Check for cluster ARN and running Fargate PVs
                if arn in clusters:
                    fargate_pvs = cluster_task_pv_map.get(arn, [])
                    if not fargate_pvs:
                        status = 'SAFE_NO_FARGATE_TASKS'
                        details = "No Fargate tasks in this cluster."
                    elif '1.3.0' in fargate_pvs:
                        status = 'RISK_RUNNING_PV_1.3.0'
                        details = f"Fargate tasks with PV 1.3.0 found: {fargate_pvs}"
                    else:
                        status = 'SAFE_FARGATE_TASKS'
                        details = f"Fargate PVs running: {set(fargate_pvs)}"

                    log_result(arn, 'ecs', account_id, region, "FOUND", f"{status}, {details}", env="")

                elif arn.lower() in clusters_lower:
                    orig_arn = clusters_lower[arn.lower()]
                    fargate_pvs = cluster_task_pv_map.get(orig_arn, [])
                    if not fargate_pvs:
                        status = 'SAFE_NO_FARGATE_TASKS (Case-Insensitive)'
                        details = "No Fargate tasks in this cluster."
                    elif '1.3.0' in fargate_pvs:
                        status = 'RISK_RUNNING_PV_1.3.0 (Case-Insensitive)'
                        details = f"Fargate tasks with PV 1.3.0 found: {fargate_pvs}"
                    else:
                        status = 'SAFE_FARGATE_TASKS (Case-Insensitive)'
                        details = f"Fargate PVs running: {set(fargate_pvs)}"

                    log_result(orig_arn, 'ecs', account_id, region, "FOUND", f"{status}___{details}", env="")

                else:
                    log_result(arn, 'ecs', account_id, region, 'MISSING_CLUSTER', "ECS Cluster Not Found", env="")

            else:
                log_result(arn, 'ecs', account_id, region, 'UNKNOWN_ARN_TYPE', "ARN is neither ECS service nor cluster", env="")

    except Exception as e:
        for arn in arns:
            log_result(arn, 'ecs', account_id, region, 'ERROR', str(e))


def check_beanstalk_batch(account_id, region, arns, session):
    try:
        client = session.client('elasticbeanstalk', region_name=region)
        paginator = client.get_paginator('describe_environments')
        arn_map = {}
        env_name_map = {}

        for page in paginator.paginate():
            for env in page['Environments']:
                env_arn = env.get('EnvironmentArn', '')
                env_name = env.get('EnvironmentName', '')
                platform_arn = env.get('PlatformArn', 'Unknown')
                env_status = env.get('Status', 'Unknown')

                if "Python 3.8 running on 64bit Amazon Linux 2" in platform_arn:
                    status = 'PYTHON3.8_EOL'
                else:
                    status = f"EB_{platform_arn.split('/')[-1]}"

                arn_map[env_arn.lower()] = (env_arn, status, env_status)
                env_name_map[env_name.lower()] = (env_arn, status, env_status)

        for arn in arns:
            print(f"[INFO] Processing Beanstalk Environment: {arn}")

            if arn.lower() in arn_map:
                env_arn, env_status, runtime_status = arn_map[arn.lower()]
                env_value = get_env_tag(session, env_arn, region)
                log_result(env_arn, 'elasticbeanstalk', account_id, region, "FOUND", f"{env_status}, Env Status: {runtime_status}", env=env_value)

            else:
                # Try to match with environment name if ARN match fails
                env_name_key = arn.split('/')[-1].lower()
                if env_name_key in env_name_map:
                    env_arn, env_status, runtime_status = env_name_map[env_name_key]
                    env_value = get_env_tag(session, env_arn, region)
                    log_result(env_arn, 'elasticbeanstalk', account_id, region, "FOUND", f"{env_status} + ' (EnvName Match)', Env Status: {runtime_status}", env=env_value)
                else:
                    log_result(arn, 'elasticbeanstalk', account_id, region, 'MISSING', "Elastic Beanstalk Env Not Found (ARN/Name)", env="")

    except Exception as e:
        for arn in arns:
            log_result(arn, 'elasticbeanstalk', account_id, region, 'ERROR', str(e))
        
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

def check_glue_version_batch(account_id, region, arns, session):
    try:
        client = session.client('glue', region_name=region)
        paginator = client.get_paginator('get_jobs')
        existing = {}

        for page in paginator.paginate():
            for job in page['Jobs']:
                job_name = job['Name']
                glue_version = job.get('GlueVersion', 'Unknown')
                job_arn = f"arn:aws:glue:{region}:{account_id}:job/{job_name}"

                if glue_version == '2.0':
                    status = 'GLUE_2.0_EOL'
                else:
                    status = f"GLUE_{glue_version}"

                existing[job_arn] = status

        existing_lower = {k.lower(): (k, v) for k, v in existing.items()}

        for arn in arns:
            print(f"[INFO] Processing Glue Job ARN: {arn}")

            if arn in existing:
                glue_status = existing[arn]
                env_value = get_env_tag(session, arn, region)

                log_result(arn, 'glue', account_id, region,"FOUND", glue_status, env=env_value)

            elif arn.lower() in existing_lower:
                orig_arn, glue_status = existing_lower[arn.lower()]
                env_value = get_env_tag(session, orig_arn, region)

                log_result(orig_arn, 'glue', account_id, region, "FOUND(CASE_SENSI)", glue_status, env=env_value)

            else:
                log_result(arn, 'glue', account_id, region, 'MISSING', "Glue Job Not Found", env="")

    except Exception as e:
        for arn in arns:
            log_result(arn, 'glue', account_id, region, 'ERROR', str(e))

def check_kinesisanalytics_sql_batch(account_id, region, arns, session):
    try:
        client = session.client('kinesisanalytics', region_name=region)  # v1 API for SQL apps
        response = client.list_applications()
        existing = {}

        for app in response['ApplicationSummaries']:
            app_name = app['ApplicationName']
            app_arn = f"arn:aws:kinesisanalytics:{region}:{account_id}:application/{app_name}"

            existing[app_arn] = 'KDA_SQL_DEPRECATED'

        existing_lower = {k.lower(): (k, v) for k, v in existing.items()}

        for arn in arns:
            print(f"[INFO] Processing Kinesis Analytics SQL ARN: {arn}")

            if arn in existing:
                env_value = get_env_tag(session, arn, region)
                log_result(arn, 'kinesisanalytics-sql', account_id, region, "FOUND", "KDA_SQL_DEPRECATED - SQL App Detected", env=env_value)

            elif arn.lower() in existing_lower:
                orig_arn, _ = existing_lower[arn.lower()]
                env_value = get_env_tag(session, orig_arn, region)
                log_result(orig_arn, 'kinesisanalytics-sql', account_id, region, "FOUND", "KDA_SQL_DEPRECATED - SQL App Detected", env=env_value)

            else:
                log_result(arn, 'kinesisanalytics-sql', account_id, region, 'MISSING', "Kinesis SQL App Not Found", env="")

    except Exception as e:
        for arn in arns:
            log_result(arn, 'kinesisanalytics-sql', account_id, region, 'ERROR', str(e))

def check_redshift_batch(account_id, region, arns, session):
    try:
        client = session.client('redshift', region_name=region)
        paginator = client.get_paginator('describe_clusters')
        existing = {}

        for page in paginator.paginate():
            for cluster in page['Clusters']:
                cluster_id = cluster['ClusterIdentifier']
                node_type = cluster.get('NodeType', 'Unknown')
                cluster_arn = f"arn:aws:redshift:{region}:{account_id}:cluster:{cluster_id}"

                if node_type.lower().startswith('dc2'):
                    status = 'DC2_EOL'
                else:
                    status = f"REDHSIFT_{node_type}"

                existing[cluster_arn] = status

        existing_lower = {k.lower(): (k, v) for k, v in existing.items()}

        for arn in arns:
            print(f"[INFO] Processing Redshift Cluster ARN: {arn}")

            if arn in existing:
                redshift_status = existing[arn]
                env_value = get_env_tag(session, arn, region)
                log_result(arn, 'redshift', account_id, region, "FOUND", redshift_status, env=env_value)

            elif arn.lower() in existing_lower:
                orig_arn, redshift_status = existing_lower[arn.lower()]
                env_value = get_env_tag(session, orig_arn, region)
                log_result(orig_arn, 'redshift', account_id, region, "FOUND (Case-Insensitive)", redshift_status, env=env_value)

            else:
                log_result(arn, 'redshift', account_id, region, 'MISSING', "Redshift Cluster Not Found", env="")

    except Exception as e:
        for arn in arns:
            log_result(arn, 'redshift', account_id, region, 'ERROR', str(e))

def check_rekognition_face_collections_batch(account_id, region, arns, session):
    try:
        client = session.client('rekognition', region_name=region)
        response = client.list_collections()
        existing = {}

        for collection_id in response['CollectionIds']:
            desc = client.describe_collection(CollectionId=collection_id)
            model_version = desc.get('FaceModelVersion', 'Unknown')
            collection_arn = f"arn:aws:rekognition:{region}:{account_id}:collection/{collection_id}"

            if model_version in ['1.0', '2.0', '3.0', '4.0']:
                status = f'DEPRECATED_MODEL_{model_version}'
            elif model_version == '7.0':
                status = 'CURRENT_MODEL_V7'
            else:
                status = f'UNKNOWN_MODEL_{model_version}'

            existing[collection_arn] = status

        existing_lower = {k.lower(): (k, v) for k, v in existing.items()}

        for arn in arns:
            print(f"[INFO] Processing Rekognition Collection ARN: {arn}")

            if arn in existing:
                coll_status = existing[arn]
                env_value = get_env_tag(session, arn, region)
                log_result(arn, 'rekognition', account_id, region, coll_status, "Collection Version Check", env=env_value)

            elif arn.lower() in existing_lower:
                orig_arn, coll_status = existing_lower[arn.lower()]
                env_value = get_env_tag(session, orig_arn, region)
                log_result(orig_arn, 'rekognition', account_id, region, coll_status + ' (Case-Insensitive)', "Collection Version Check", env=env_value)

            else:
                log_result(arn, 'rekognition', account_id, region, 'MISSING', "Collection Not Found", env="")

    except Exception as e:
        for arn in arns:
            log_result(arn, 'rekognition', account_id, region, 'ERROR', str(e))

def check_es_by_arn(account_id, region, arns, session):
    import re

    def extract_es_name_from_arn(arn):
        match = re.match(r"^arn:aws:es:[^:]+:[^:]+:domain/(.+)$", arn)
        return match.group(1) if match else None

    try:
        client = session.client('es', region_name=region)

        # Direct call (no paginator)
        domains_resp = client.list_domain_names()
        existing_domains = {}
        existing_lower = {}

        for domain in domains_resp.get('DomainNames', []):
            domain_name = domain['DomainName']
            existing_domains[domain_name] = domain_name
            existing_lower[domain_name.lower()] = domain_name

        for arn in arns:
            arn = arn.strip()
            domain_name = extract_es_name_from_arn(arn)

            if not domain_name:
                log_result(arn, 'es', account_id, region, 'INVALID', "Invalid OpenSearch/ES ARN format", env="")
                continue

            # Case-sensitive match first, then case-insensitive
            if domain_name in existing_domains:
                matched_name = existing_domains[domain_name]
            elif domain_name.lower() in existing_lower:
                matched_name = existing_lower[domain_name.lower()]
            else:
                matched_name = None

            if matched_name:
                try:
                    desc = client.describe_elasticsearch_domain(DomainName=matched_name)
                    domain_status = desc['DomainStatus']
                    engine_version = domain_status.get('ElasticsearchVersion', 'Unknown')
                    instance_type = domain_status.get('ElasticsearchClusterConfig', {}).get('InstanceType', 'Unknown')
                    instance_count = domain_status.get('ElasticsearchClusterConfig', {}).get('InstanceCount', 'Unknown')

                    # Fetch all tags for the domain
                    try:
                        tags_resp = client.list_tags(ARN=domain_status['ARN'])
                        tags = tags_resp.get('TagList', [])
                        tags_str = "; ".join([f"{t['Key']}={t['Value']}" for t in tags]) if tags else "NO_TAGS_FOUND"
                    except Exception as tag_err:
                        tags_str = f"TagFetchError: {tag_err}"

                    log_result(
                        arn, 'es', account_id, region, 'FOUND',
                        f"Engine Version: {engine_version}; Instance Type: {instance_type}; Instance Count: {instance_count}",
                        env=tags_str
                    )

                except Exception as e:
                    log_result(arn, 'es', account_id, region, 'ERROR', str(e), env="")
            else:
                log_result(arn, 'es', account_id, region, 'MISSING', "Domain Not Found", env="")

    except Exception as e:
        for arn in arns:
            log_result(arn, 'es', account_id, region, 'ERROR', str(e))

'''def check_ecs_batch(account_id, region, arns, session):
    try:
        client = session.client('ecs', region_name=region)
        paginator = client.get_paginator('list_clusters')
        all_services = {}

        for page in paginator.paginate():
            for cluster_arn in page['clusterArns']:
                cluster_name = cluster_arn.split('/')[-1]
                service_arns = client.list_services(cluster=cluster_arn).get('serviceArns', [])

                for svc_arn in service_arns:
                    # Determine short or long ARN format
                    if f"/{cluster_name}/" in svc_arn:
                        arn_type = 'LONG_ARN'
                    else:
                        arn_type = 'SHORT_ARN'

                    all_services[svc_arn] = {
                        'cluster_name': cluster_name,
                        'arn_type': arn_type
                    }

        # Case-insensitive dict
        existing_lower = {k.lower(): (k, v) for k, v in all_services.items()}

        for arn in arns:
            print(f"[INFO] Checking ECS Service ARN: {arn}")

            if arn in all_services:
                svc_data = all_services[arn]
                env_value = get_env_tag(session, arn, region)

                log_result(
                    arn, 'ecs-service', account_id, region, svc_data['arn_type'],
                    f"Service in Cluster: {svc_data['cluster_name']}",
                    env=env_value
                )

            elif arn.lower() in existing_lower:
                orig_arn, svc_data = existing_lower[arn.lower()]
                env_value = get_env_tag(session, orig_arn, region)

                log_result(
                    orig_arn, 'ecs-service', account_id, region, svc_data['arn_type'] + ' (Case-Insensitive)',
                    f"Service in Cluster: {svc_data['cluster_name']}",
                    env=env_value
                )

            else:
                log_result(arn, 'ecs-service', account_id, region, 'MISSING', "ECS Service Not Found", env="")

    except Exception as e:
        for arn in arns:
            log_result(arn, 'ecs-service', account_id, region, 'ERROR', str(e))'''

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
    'ec2': check_ec2_by_arn,
    'glue': check_glue_version_batch,
    'kinesisanalytics': check_kinesisanalytics_sql_batch,
    'redshift': check_redshift_batch,
    'rekognition': check_rekognition_face_collections_batch,
    'es': check_es_by_arn
}

#_______________MAIN EXECUTION_________________
def main():
    input_file = 'arns.txt'
    BASE_PROFILE = "tr-enterprise-cicd-prod"
    ROLE_NAME = "human-role/207950-SupportReadOnly"
    username = input("Enter the username like MGMT...: ")
    password = getpass.getpass("Enter the Cyberark Password: ")
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
