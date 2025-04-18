import boto3
import threading
import re
import csv
import subprocess
from collections import defaultdict
from botocore.exceptions import ClientError

output_lock = threading.Lock()
log_file = 'results.csv'

arn_pattern = re.compile(r"^arn:aws:([^:]+):([^:]+):([^:]+):([^:]+):(.+)$")

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
        paginator = client.get_paginator('describe_db_instances')
        existing = {}
        page_iterator = paginator.paginate(PaginationConfig={'MaxItems':1000, 'PageSize': 100})
        for page in page_iterator:
            for db in page['DBInstances']:
                arn = db['DBInstanceArn']
                version = db.get('EngineVersion', 'Unknown')
                instance_class = db.get('DBInstanceClass', 'Unknown')
                ca_cert = db.get('CACertificateIdentifier', 'Unknown')
                existing[arn] = f"Engine: {version}, Class: {instance_class}, CA: {ca_cert}"
        print(len(existing))
        for arn in arns:
                if arn in existing:
                   info = existing[arn]
                   log_result(arn, 'rds', account_id, region, 'FOUND', info)  
                else:
                   log_result(arn, 'rds', account_id, region, 'MISSING', "RDS Instance Not found") 
    except Exception as e:
        for arn in arns:
            log_result(arn, 'rds', account_id, region, 'ERROR', str(e))
def check_dms_batch(account_id, region, arns, session):
    try:
        client = session.client('dms', region_name=region)
        instances = client.describe_replication_instances()['ReplicationInstances']
        dms_map = {
            inst['ReplicationInstanceArn']: (inst['ReplicationInstanceClass'], inst.get('EngineVersion', 'Unknown')) for inst in instances 
        } 
        for arn in arns:
            if arn in dms_map:
                instance_type, version = dms_map[arn]
                log_result(arn, 'dms', account_id, region, 'FOUND', f"InstanceType:{instance_type}, Version:{version}")
            else:
                log_result(arn, 'dms', account_id, region, 'MISSING', "DMS Instance not found")
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
if __name__ == "__main__":
    main()


       