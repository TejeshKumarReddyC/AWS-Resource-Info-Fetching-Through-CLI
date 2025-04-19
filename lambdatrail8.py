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
arn_pattern = re.compile(r"^arn:aws:([^:]+):([^:]+):([^:]+):([^:]+):(.+)$")
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

#Function for reading arns from a text file(arns.txt)
def read_arns(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]
#Function for extracting SERVICE, REGION, ACCOUNT_ID from the arn
def parse_arn(arn):
    match = arn_pattern.match(arn)
    if not match:
       return None
    service, region, account, resource = match.group(1), match.group(2), match.group(3), match.group(5)
    return {
          'service': service,
          'region': region,
          'account': account,
          'resource': resource,
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
def log_result(arn, service, account_id, region, status, message):
    with output_lock:
        with open(log_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([arn, service, account_id, region, status, message])
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
    #print(account_id)
    try:
        client = session.client('lambda', region_name=region)
        paginator = client.get_paginator('list_functions')
        existing = {}
        for page in paginator.paginate():
            for fn in page['Functions']:
                existing[fn['FunctionArn']] = fn.get('Runtime', 'Unknown')
        print(len(existing))
        for arn in arns:
            print(f"[INFO] Processing ARN: {arn}")
            if arn in existing:
                runtime = existing[arn]
                log_result(arn, 'lambda', account_id, region, 'FOUND', f"Exists (Runtime: {runtime})")
            else:
                log_result(arn, 'lambda', account_id, region, 'MISSING', "Lambda Not Found")
    except Exception as e:
        for arn in arns:
            log_result(arn, 'lambda', account_id, region, 'ERROR', str(e))

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
        for arn in arns:
            matched = False
            for instance in all_instances:
                if instance.get('DBInstanceArn') == arn:
                    engine = instance.get('Engine', 'Unknown')
                    engine_version = instance.get('EngineVersion', 'Unknown')
                    instance_class = instance.get('DBInstanceClass', 'Unknown')
                    ca_cert = instance.get('CACertificateIdentifier', 'Unknown')
                    log_result(arn, 'rds', account_id, region, 'FOUND', f"Engine: {engine} {engine_version}, Class: {instance_class}, CA: {ca_cert}")
                    matched = True
                    break
            if not matched:
                    for cluster in all_clusters:
                        if cluster.get('DBClusterArn') == arn:
                            engine = cluster.get('Engine', 'Unknown')
                            engine_version = cluster.get('EngineVersion', 'Unknown')
                            ca_cert = cluster.get('CACertificateIdentifier', 'Unknown')
                            instances = cluster.get('DBClusterMembers', [])
                            instance_ids = [inst['DBInstanceIdentifier'] for inst in instances]
                            instance_count = len(instance_ids)
                            log_result(arn, 'rds', account_id, region, 'FOUND', f"Engine: {engine} {engine_version}, Instance_count: {instance_count}, Instances: {', '.join(instance_ids)}, CA: {ca_cert}")
                            matched = True
                            break
            if not matched:
                log_result(arn, 'rds', account_id, region, 'MISSING', 'RDS ARN Not found')
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
                    log_result(arn, 'dms', account_id, region, 'FOUND', f"Class: {instance_class}, EngineVersion: {engine_version}")
                    found = True
                    break
            if not found:
                log_result(arn, 'dms', account_id, region, 'MISSING', "DMS Instance Not found")
    except Exception as e:
        for arn in arns:
            log_result(arn, 'dms', account_id, region, 'ERROR', str(e))

def check_sagemaker_batch(account_id, region, arns, session):
    try:
        client = session.client('sagemaker', region_name=region)
        notebooks = client.list_notebook_instances()['NotebookInstances']
        sagemaker_map = {}
        for nb in notebooks:
            name = nb['NotebookInstanceName']
            nb_details = client.describe_notebook_instance(NotebookInstanceName=name)
            arn = nb_details['NotebookInstanceArn']
            jupyter_version = nb_details.get('NotebookInstanceLifecycleConfigName', 'Unknown')
            sagemaker_map[arn] = jupyter_version
            for arn in arns:
                if arn in sagemaker_map:
                    version = sagemaker_map[arn]
                    log_result(arn, 'sagemaker', account_id, region, 'FOUND', f"Jupyter Version:{version}")
                else:
                    log_result(arn, 'sagemaker', account_id, region, 'MISSING', f"Notebook Instance Not found")
    except Exception as e:
        log_result(arn, 'sagemaker', account_id, region, "ERROR", str(e))

#___________SERVICE FUNCTION MAP______________
SERVICE_FUNCTION_MAP = {
    'lambda': check_lambda_batch,
    'rds' : check_rds_batch,
    'dms' : check_dms_batch,
    'sagemaker': check_sagemaker_batch
}

#_______________MAIN EXECUTION_________________
def main():
    input_file = 'arns.txt'
    BASE_PROFILE = input("Enter base account profile: ")
    ROLE_NAME = input("Enter the ROLE_NAME: ")
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
         writer.writerow(['ARN', 'Service', 'AccountId', 'Region', 'Status', 'Message'])

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


       
