#This file is part of Lightspin EKS Creation Engine.
#SPDX-License-Identifier: Apache-2.0

#Licensed to the Apache Software Foundation (ASF) under one
#or more contributor license agreements.  See the NOTICE file
#distributed with this work for additional information
#regarding copyright ownership.  The ASF licenses this file
#to you under the Apache License, Version 2.0 (the
#"License"); you may not use this file except in compliance
#with the License.  You may obtain a copy of the License at

#http://www.apache.org/licenses/LICENSE-2.0

#Unless required by applicable law or agreed to in writing,
#software distributed under the License is distributed on an
#"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#KIND, either express or implied.  See the License for the
#specific language governing permissions and limitations
#under the License.
import boto3
import os
import requests
import json
import re
from botocore.config import Config
import botocore

config = Config(
   retries = {
      'max_attempts': 10,
      'mode': 'adaptive'
   }
)
s3 = boto3.client('s3')
sts = boto3.client('sts')
sesh = boto3.session.Session()

# Env Vars
awsAccountId = sts.get_caller_identity()['Account']
awsRegion = sesh.region_name
tenantIdParam = os.environ['AZURE_APP_TENANT_ID_PARAM']
clientIdParam = os.environ['AZURE_APP_CLIENT_ID_PARAM']
secretIdParam = os.environ['AZURE_APP_SECRET_ID_PARAM']
quicksightS3Bucket = os.environ['QUICKSIGHT_S3_BUCKET_NAME']

def get_opted_in_aws_regions():
    ec2 = boto3.client('ec2')
    print('Getting all AWS Regions')
    # create empty list for all opted-in Regions
    regionList = []

    try:
        # Get all Regions we are opted in for
        for r in ec2.describe_regions()['Regions']:
            regionName = str(r['RegionName'])
            optInStatus = str(r['OptInStatus'])
            if optInStatus == 'not-opted-in':
                pass
            else:
                regionList.append(regionName)
        
        print('All Regions retrieved from EC2 service')
    except Exception as e:
        raise e
        
    print('Got all AWS Regions')

    return regionList

def get_token():
    ssm = boto3.client('ssm')

    tenantId = ssm.get_parameter(Name=tenantIdParam,WithDecryption=True)['Parameter']['Value']
    clientId = ssm.get_parameter(Name=clientIdParam,WithDecryption=True)['Parameter']['Value']
    secretId = ssm.get_parameter(Name=secretIdParam,WithDecryption=True)['Parameter']['Value']

    tokenUrl = f'https://login.microsoftonline.com/{tenantId}/oauth2/token'
    resourceAppIdUri = 'https://api.securitycenter.microsoft.com'

    data = {
        'grant_type': 'client_credentials',
        'client_id': clientId,
        'resource' : resourceAppIdUri,
        'client_secret': secretId
    }

    r = requests.post(
        tokenUrl,
        data=data
    )

    token = r.json()['access_token']

    print('SSM Parameters processed and OAuth Token created')

    del data
    del ssm

    return token

def get_machines():
    # Retrieve OAuth token for Bearer AuthN
    token = get_token()
    # Create empty list to hold MDE Machine data
    mdeMachines = []
    # Set filename for upload
    fileName = 'processed_machines'

    headers = {'Authorization': f'Bearer {token}'}

    # Compile Regex for EC2
    ec2IdRegex = re.compile('(?i)\\b[a-z]+-[a-z0-9]+')
    # S3 Waiter
    waiter = s3.get_waiter('object_exists')

    # Retrieve all Machines
    r = requests.get(
        'https://api-us.securitycenter.microsoft.com/api/machines',
        headers=headers
    )
    # As we loop through Machine data from MDE, we want to pull out only AWS EC2 Instances which should be tagged with the Instance ID
    # provided you set up properly...
    for v in r.json()['value']:
        # drop the IP address details
        del v['ipAddresses']
        # Skip "Inactive" Machines
        if str(v['healthStatus']) == 'Inactive':
            continue
        # ensure the regex matches to select EC2 machines if there are tags for them
        if v['machineTags']:
            # now to loop the list and find a match if possible...
            for tag in v['machineTags']:
                if ec2IdRegex.search(tag):
                    instanceId = str(tag)
                    v['instanceId'] = instanceId
                    break
        else:
            v['instanceId'] = 'NON_AWS'
        mdeMachines.append(v)

    with open(f'./{fileName}.json', 'w') as jsonfile:
        json.dump(mdeMachines, jsonfile, indent=4, default=str)

    # Upload the MDE Machines JSON file to S3
    try:
        s3.upload_file(
            f'./{fileName}.json',
            quicksightS3Bucket,
            f'quicksight/{fileName}.json'
        )
        # Wait for eventual consistency
        waiter.wait(
            Bucket=quicksightS3Bucket,
            Key=f'quicksight/{fileName}.json',
            WaiterConfig={
                'Delay': 2,
                'MaxAttempts': 20
            }
        )
        print('All machines from MDE retrieved and JSON uploaded to S3.')
    except Exception as e:
        raise e

    # Generate a QuickSight Manifest and upload file to S3
    manifest = {
        'fileLocations':[
            {
                'URIs':[
                    f'https://{quicksightS3Bucket}.s3.{awsRegion}.amazonaws.com/quicksight/{fileName}.json'
                ]
            }
        ],
        'globalUploadSettings':{
            'format':'JSON'
        }
    }

    with open(f'{fileName}_manifest.json', 'w') as jsonfile:
        json.dump(manifest, jsonfile, indent=2)

    try:
        s3.upload_file(
            f'./{fileName}_manifest.json',
            quicksightS3Bucket,
            f'quicksight/{fileName}_manifest.json'
        )
        # Wait for eventual consistency
        waiter.wait(
            Bucket=quicksightS3Bucket,
            Key=f'quicksight/{fileName}_manifest.json',
            WaiterConfig={
                'Delay': 2,
                'MaxAttempts': 20
            }
        )
        print('MDE Machines Manifest file sent to S3.')
    except Exception as e:
        raise e

    return mdeMachines

def get_machine_vulns():
    mdeMachines = get_machines()
    # Retrieve OAuth token for Bearer AuthN
    token = get_token()
    headers = headers = {'Authorization': f'Bearer {token}'}
    # Create an empty list to house all of the machine vulnerabilities
    machineVulns = []
    # Set filename for upload
    fileName = 'processed_machine_vulns'
    # S3 Waiter
    waiter = s3.get_waiter('object_exists')
    print('Gathering all MDE machine vulnerabilities.')

    for machine in mdeMachines:
        machineId = str(machine['id'])

        r = requests.get(
            f'https://api-us.securitycenter.microsoft.com/api/machines/{machineId}/vulnerabilities',
            headers=headers
        )
        # We will provide some basic shaping of the data returned for Vulnerabilities - namely around Exploit data
        for v in r.json()['value']:
            # check for exploit types, gather the first object if present and overwrite the dict
            # otherwise, write in String "None"
            if v['exploitTypes']:
                exploitTypes = str(v['exploitTypes'][0])
                # delete the original key
                del v['exploitTypes']
                # re-insert the new one
                v['exploitTypes'] = exploitTypes
            else:
                # This means there is not any exploit type data
                exploitTypes = 'None'
                # delete the original key
                del v['exploitTypes']
                # re-insert the new one
                v['exploitTypes'] = exploitTypes
            
            # Repeat the same process for Exploit URIs
            if v['exploitUris']:
                exploitUris = str(v['exploitUris'][0])
                # delete the original key
                del v['exploitUris']
                # re-insert the new one
                v['exploitUris'] = exploitUris
            else:
                # This means there is not any exploit type data
                exploitUris = 'None'
                # delete the original key
                del v['exploitUris']
                # re-insert the new one
                v['exploitUris'] = exploitUris
            # Create a CVE URL, as the Machine Vulnerability Object does not return it...
            vulnId = str(v['id'])
            cveUrl = f'https://cve.mitre.org/cgi-bin/cvename.cgi?name={vulnId}'
            v['cveInformation'] = cveUrl
            # Write in the Machine ID into the Vuln dict so we can merge the data sets later
            v['vuln_MachineId'] = machineId
            machineVulns.append(v)

    with open(f'./{fileName}.json', 'w') as jsonfile:
        json.dump(machineVulns, jsonfile, indent=4, default=str)

    # Upload the MDE Machines JSON file to S3
    try:
        s3.upload_file(
            f'./{fileName}.json',
            quicksightS3Bucket,
            f'quicksight/{fileName}.json'
        )
        # Wait for eventual consistency
        waiter.wait(
            Bucket=quicksightS3Bucket,
            Key=f'quicksight/{fileName}.json',
            WaiterConfig={
                'Delay': 2,
                'MaxAttempts': 20
            }
        )
        print('All MDE machine vulnerabilities retrieved and JSON uploaded to S3.')
    except Exception as e:
        raise e

    # Generate a QuickSight Manifest and upload file to S3
    manifest = {
        'fileLocations':[
            {
                'URIs':[
                    f'https://{quicksightS3Bucket}.s3.{awsRegion}.amazonaws.com/quicksight/{fileName}.json'
                ]
            }
        ],
        'globalUploadSettings':{
            'format':'JSON'
        }
    }

    with open(f'{fileName}_manifest.json', 'w') as jsonfile:
        json.dump(manifest, jsonfile, indent=2)

    try:
        s3.upload_file(
            f'./{fileName}_manifest.json',
            quicksightS3Bucket,
            f'quicksight/{fileName}_manifest.json'
        )
        # Wait for eventual consistency
        waiter.wait(
            Bucket=quicksightS3Bucket,
            Key=f'quicksight/{fileName}_manifest.json',
            WaiterConfig={
                'Delay': 2,
                'MaxAttempts': 20
            }
        )
        print('MDE Vulnerabilities Manifest file sent to S3.')
    except Exception as e:
        raise e

def get_ec2_metadata():
    regionList = get_opted_in_aws_regions()
    # Create an empty list to house all EC2 Data
    ec2Data = []
    # Set filename for upload
    fileName = 'processed_ec2_instances'
    # S3 Waiter
    waiter = s3.get_waiter('object_exists')

    print('Retrieving EC2 data for all Regions.')

    for region in regionList:
        # We will pass the Region to a Boto3 Session which will create an Authentication Object
        # In the specific Account and Region so you can create additional Clients which are thread/process safe
        session = boto3.Session(region_name=region)
        tempEc2 = session.client('ec2', config=config)
        paginator = tempEc2.get_paginator('describe_instances')
        iterator = paginator.paginate()
        for page in iterator:
            for r in page['Reservations']:
                for i in r['Instances']:
                    # Now we pull out the information we want - some of it we can write to the dict
                    # directly and others we will need to ensure they're there
                    try:
                        pubIp = str(i['PublicIpAddress'])
                    except KeyError:
                        pubIp = None
                    try:
                        pubDns = str(i['PublicDnsName'])
                        # Public DNS is cheeky and will return an empty string instead of None >:(
                        if pubDns == '':
                            pubDns = None
                        else:
                            pubDns = pubDns
                    except KeyError:
                        pubDns = None
                    # Create our own Bool for Public-facing EC2 instances
                    if pubIp != None or pubDns != None:
                        isPublic = True
                    else:
                        isPublic = False
                    # Not all machines have an IAM Role...
                    try:
                        instanceProfileArn = str(i['IamInstanceProfile']['Arn'])
                    except KeyError:
                        instanceProfileArn = None

                    ec2DataDict = {
                        'ImageId': str(i['ImageId']),
                        'InstanceId': str(i['InstanceId']),
                        'InstanceType': str(i['InstanceType']),
                        'LaunchTime': str(i['LaunchTime']),
                        'PrivateDnsName': str(i['PrivateDnsName']),
                        'PrivateIpAddress': str(i['PrivateIpAddress']),
                        'PublicIpAddress': pubIp,
                        'PublicDnsName': pubDns,
                        'IsPublic': isPublic,
                        'State': str(i['State']['Name']),
                        'SubnetId': str(i['SubnetId']),
                        'VpcId': str(i['VpcId']),
                        'Architecture': str(i['Architecture']),
                        'VolumeId': str(i['BlockDeviceMappings'][0]['Ebs']['VolumeId']),
                        'IamInstanceProfileArn': instanceProfileArn,
                        'NetworkInterfaceId': str(i['NetworkInterfaces'][0]['NetworkInterfaceId']),
                        'SecurityGroupId': str(i['SecurityGroups'][0]['GroupId']),
                        'SecurityGroupName': str(i['SecurityGroups'][0]['GroupName']),
                        'MetadataOptionsHttpTokens': str(i['MetadataOptions']['HttpTokens']),
                        'MetadataOptionsHttpPutResponseHopLimit': str(i['MetadataOptions']['HttpPutResponseHopLimit']),
                        'MetadataOptionsHttpEndpoint': str(i['MetadataOptions']['HttpEndpoint']),
                        'MetadataOptionsInstanceMetadataTags': str(i['MetadataOptions']['InstanceMetadataTags']),
                        'EnclaveOptions': str(i['EnclaveOptions']['Enabled'])
                    }
                    ec2Data.append(ec2DataDict)
        print(f'EC2 collection for AWS Region {region} complete.')

    del regionList

    with open(f'./{fileName}.json', 'w') as jsonfile:
        json.dump(ec2Data, jsonfile, indent=4, default=str)

    # Upload the MDE Machines JSON file to S3
    try:
        s3.upload_file(
            f'./{fileName}.json',
            quicksightS3Bucket,
            f'quicksight/{fileName}.json'
        )
        # Wait for eventual consistency
        waiter.wait(
            Bucket=quicksightS3Bucket,
            Key=f'quicksight/{fileName}.json',
            WaiterConfig={
                'Delay': 2,
                'MaxAttempts': 20
            }
        )
        print('Finished retrieving EC2 data for all Regions and JSON uploaded to S3.')
    except Exception as e:
        raise e

    # Generate a QuickSight Manifest and upload file to S3
    manifest = {
        'fileLocations':[
            {
                'URIs':[
                    f'https://{quicksightS3Bucket}.s3.{awsRegion}.amazonaws.com/quicksight/{fileName}.json'
                ]
            }
        ],
        'globalUploadSettings':{
            'format':'JSON'
        }
    }

    with open(f'{fileName}_manifest.json', 'w') as jsonfile:
        json.dump(manifest, jsonfile, indent=2)

    try:
        s3.upload_file(
            f'./{fileName}_manifest.json',
            quicksightS3Bucket,
            f'quicksight/{fileName}_manifest.json'
        )
        # Wait for eventual consistency
        waiter.wait(
            Bucket=quicksightS3Bucket,
            Key=f'quicksight/{fileName}_manifest.json',
            WaiterConfig={
                'Delay': 2,
                'MaxAttempts': 20
            }
        )
        print('EC2 Manifest file sent to S3.')
    except Exception as e:
        raise e

def send_to_quicksight():
    '''
    This function uploads the final merged dataset to S3 and creates a Data Source within QuickSight
    '''
    get_ec2_metadata()
    get_machine_vulns()
    # Filenames & Group name for Quicksight - add all file names to an empty list
    dataSourceList = []
    machinesFileName = 'processed_machines'
    dataSourceList.append(machinesFileName)
    machineVulnsFileName = 'processed_machine_vulns'
    dataSourceList.append(machineVulnsFileName)
    ec2FileName = 'processed_ec2_instances'
    dataSourceList.append(ec2FileName)
    groupName = 'MDE_Viewers'

    quicksight = boto3.client('quicksight')
    session = boto3.Session(region_name='us-east-1')
    quicksightUsEast1 = session.client('quicksight')

    print('Creating or updating QuickSight Group for MDE')
    try:
        response = quicksightUsEast1.create_group(
            GroupName=groupName,
            Description='MDE Group consists of all current Admins and Authors within QuickSight',
            AwsAccountId=awsAccountId,
            Namespace='default' # this MUST be 'default'
        )
        groupPrincipalArn = str(response['Group']['Arn'])
        print(groupName + ' was created succesfully')
        print(groupName + ' ARN is ' + groupPrincipalArn)
    except botocore.exceptions.ClientError as error:
        # If the Group exists already, handle the error gracefully
        if error.response['Error']['Code'] == 'ResourceExistsException':
            response = quicksightUsEast1.describe_group(
                GroupName=groupName,
                AwsAccountId=awsAccountId,
                Namespace='default' # this MUST be 'default'
            )
            groupArn = str(response['Group']['Arn'])
            print('A Group with the name ' + groupName + ' already exists! Attempting to add Users into it')
            print('As a reminder the ARN for ' + groupName + ' is: ' + groupArn)
        else:
            raise error
    
    try:
        response = quicksightUsEast1.list_users(
            AwsAccountId=awsAccountId,
            MaxResults=100,
            Namespace='default' # this MUST be 'default'
        )
        for u in response['UserList']:
            userName = str(u['UserName'])
            roleLevel = str(u['Role'])
            if roleLevel == 'ADMIN' or 'AUTHOR':
                quicksightUsEast1.create_group_membership(
                    MemberName=userName,
                    GroupName=groupName,
                    AwsAccountId=awsAccountId,
                    Namespace='default' # this MUST be 'default'
                )
                print('User ' + userName + ' added to Group ' + groupName)
            else:
                pass
    except Exception as e:
        print(e)


    print('Creating QuickSight Datasources based off MDE Machines, Vulns and EC2 Instances')
    for filename in dataSourceList:
        if filename == 'processed_machines':
            dataSourceName = 'MDE_Machines'
        elif filename == 'processed_machine_vulns':
            dataSourceName = 'MDE_Vulnerabilities'
        elif filename == 'processed_ec2_instances':
            dataSourceName = 'EC2_Instances'
        try:
            response = quicksight.create_data_source(
                AwsAccountId=awsAccountId,
                DataSourceId=dataSourceName,
                Name=dataSourceName,
                Type='S3',
                Permissions=[
                    {
                        'Principal': f'arn:aws:quicksight:us-east-1:{awsAccountId}:group/default/{groupName}',
                        'Actions': [
                            'quicksight:DescribeDataSource',
                            'quicksight:DescribeDataSourcePermissions',
                            'quicksight:PassDataSource',
                            'quicksight:UpdateDataSource',
                            'quicksight:DeleteDataSource',
                            'quicksight:UpdateDataSourcePermissions'
                        ]
                    }
                ],
                DataSourceParameters={
                    'S3Parameters': {
                        'ManifestFileLocation': {
                            'Bucket': quicksightS3Bucket,
                            'Key': f'quicksight/{filename}_manifest.json'
                        }
                    } 
                }
            )
            print('Data Source ' + dataSourceName + ' was created')
        except botocore.exceptions.ClientError as error:
            # If the Group exists already, handle the error gracefull
            if error.response['Error']['Code'] == 'ResourceExistsException':
                print('The Data Source ' + dataSourceName + ' already exists, attempting to update it')
                response = quicksight.update_data_source(
                    AwsAccountId=awsAccountId,
                    DataSourceId=dataSourceName,
                    Name=dataSourceName,
                    DataSourceParameters={
                        'S3Parameters': {
                            'ManifestFileLocation': {
                                'Bucket': quicksightS3Bucket,
                                'Key': f'quicksight/{filename}_manifest.json'
                            }
                        } 
                    }
                )
                print('Data Source ' + dataSourceName + ' was updated')
            else:
                raise error

send_to_quicksight()