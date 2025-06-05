#Author- Tejesh Kumar Reddy .C
#Version-2.4
#Purpose - Updating the lambda function's runtime
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
#____SERVICE UPDATE FUNCTIONS______
def get_lambda_layers_batch(account_id, region, arns, session):
    try:
        client = session.client('lambda', region_name=region)
        paginator = client.get_paginator('list_functions')
        existing = {}

        # Collect all available Lambda ARNs
        for page in paginator.paginate():
            for fn in page['Functions']:
                existing[fn['FunctionArn']] = fn.get('Runtime', 'Unknown')

        # Case-insensitive match mapping
        existing_lower = {k.lower(): k for k in existing}

        for arn in arns:
            print(f"[INFO] Processing ARN: {arn}")
            matched_arn = None

            if arn in existing:
                matched_arn = arn
            elif arn.lower() in existing_lower:
                matched_arn = existing_lower[arn.lower()]
            else:
                log_result(arn, 'lambda', account_id, region, 'MISSING', "Lambda Not Found", env="")
                continue

            # Fetch and log layers
            try:
                config = client.get_function_configuration(FunctionName=matched_arn)
                layers = config.get('Layers', [])
                layer_arns = [l['Arn'] for l in layers]
                env_value = get_env_tag(session, matched_arn, region)
                if layer_arns:
                    log_result(matched_arn, 'lambda', account_id, region, 'FOUND',
                               f"Layers attached: {len(layer_arns)} | {', '.join(layer_arns)}", env=env_value)
                else:
                    log_result(matched_arn, 'lambda', account_id, region, 'FOUND',
                               "No layers attached", env=env_value)
            except Exception as e:
                log_result(matched_arn, 'lambda', account_id, region, 'ERROR',
                           f"Could not fetch layers: {e}", env="")

    except Exception as e:
        for arn in arns:
            log_result(arn, 'lambda', account_id, region, 'ERROR', str(e), env="")            

#___________SERVICE FUNCTION MAP______________
SERVICE_FUNCTION_MAP = {
    'lambda': get_lambda_layers_batch
}

#_______________MAIN EXECUTION_________________
def main():
    input_file = 'arns.txt'
    #global desired_runtime
    #desired_runtime = input("Enter the desired runtime")
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
