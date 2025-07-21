# AWS-Resource-Info-Fetching-Through-CLI
## Tools Used
  1. AWS CLI
  2. Python 3.12
  3. Custom Cloud Tool ( For Authenticating to AWS via IdP)
## Modules Used
  1. boto3 (Python SDK)
  2. subprocess
  3. re
  4. csv
  5. threading
  6. collections
  7. getpass
## Features
  1. Supports Multiple AWS Services ( Data of multiple AWS Resources from different services, regions and accounts can be fetched dynamically.)
  2. Threading (Groups arns based on service, region and account. Threading will be used for each group so that fetching parallelly.)
  3. Auto-Authentication (Auto Authentication For Every 4 Minutes to Get rid of Session Token Expiration of Base Account.)
  4. Lowercase mapping for fallback case-insensitive match.( It catches the arns with  Lower or Upper case so that not a single arn will be missed by case sensitivity.)
  5. Modular 
