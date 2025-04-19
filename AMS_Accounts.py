import boto3
import re
import subprocess
from botocore.exceptions import ClientError

arn_pattern = re.compile(r"^arn:aws:([^:]+):([^:]+):([^:]+):([^:]+):(.+)$")

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
#Account-Profile Map
def get_account_profile_map(account_id, file_path='accounts.txt'):
    with open(file_path, 'r') as f:
       for line in f:
           if '=' in line:
               account, profile_name = map(str.strip, line.split('=', 1) )
               #print(f"[DEBUG] checking {account} == {account_id}")
               if account == account_id:
                  return profile_name
    return None 
#Function for reading arns from a Textfile
def read_arns_from_file(file_path):
   with open(file_path,'r') as f:
        return [line.strip() for line in f if line.strip()]
   
#Service Handlers
last_account_id = None
last_region = None
current_profile = None
def check_lambda(arn_parts):
    global last_account_id, last_region, current_profile
    region, account_id, target_arn = arn_parts['region'], arn_parts['account'], arn_parts['full_arn']
    if last_account_id != account_id:
       profile_name = get_account_profile_map(account_id)
       if not profile_name:
          return False, f"No Profile found for account {account_id} in accounts.txt, please add it before running this script"
       cloud_tool_auth(region, profile_name, username, password)
       last_account_id = account_id
       current_profile = profile_name
       
    else:
       profile_name = current_profile

    if last_region != region:
       cloud_tool_auth(region, profile_name, username, password)
       last_region = region
 
    try: 
        client = boto3.session.Session(profile_name=profile_name).client('lambda',region_name=region)
        paginator = client.get_paginator('list_functions')
        for page in paginator.paginate():
            for fn in page['Functions']: 
               if fn['FunctionArn'] == target_arn:
                  return True, "Lambda exists"
        return False, "Arn not found"
    except ClientError as e:
        return False, e.response['Error']['Message']

#Map service to their handlers
service_handlers = {
        'lambda': check_lambda,
        #'s3': check_s3
      }
# ARN Processing
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
input_file = 'arns.txt'
username = input('Enter MGMT... :')
password = input('Enter cyberark password')
#profile_name = input("enter profile name")
arns = read_arns_from_file(input_file)

# ****************MAIN EXECUTION***************
for arn in arns:
    parts = parse_arn(arn)
    if not parts:
       print(f"{arn} -> Invalid ARN")
       continue
    service = parts['service']
    handler = service_handlers.get(service)
    if not handler:
       print(f"{arn} -> No handler present for {service}")
       continue
    exists, msg = handler(parts)
    status = "Exists" if exists else "Not exists"
    print(f"{arn} -> {status} | {msg}")

