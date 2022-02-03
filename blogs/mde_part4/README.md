# Lightspin Office of the CISO - Public Artifacts - Blog Code - Microsoft Defender of AWS: Part 4

Open source code associated with the Microsoft Defender of AWS: Part 4 created by the Lightspin Office of the CISO

Originally Posted At: !TODO...

![diagram](https://github.com/lightspin-tech/lightspin-office-of-the-ciso/blob/main//pics/MdePart4Diagram.jpg)

## How do I use this :thinking: :thinking: ??

Ensure you have an Azure AD Application, named **`MDE-AWSAutomation-App`** created that has the following permissions

> - AdvancedQuery.Read.All
> - Alert.Read.All
> - Alert.ReadWrite.All
> - File.Read.All
> - Ip.Read.All
> - Machine.Read.All
> - Machine.ReadWrite.All
> - Machine.Scan
> - Score.Read.All
> - SecurityConfiguration.Read.All
> - SecurityConfiguration.ReadWrite.All
> - SecurityRecommendation.Read.All
> - Software.Read.All
> - Ti.Read.All
> - Ti.ReadWrite
> - Ti.ReadWrite.All
> - Url.Read.All
> - User.Read.All
> - Vulnerability.Read.All

Save your AAD Tenant ID, and the Azure AD Application Client and Client Secret ID into the following AWS SSM Parameters. **The values are hardcoded into the CloudFormation template**.

```bash
aws ssm put-parameter \
    --name MDE-AWSAutomation-App-ClientID \
    --description 'Application (client) ID for the MDE-AWSAutomation-App Azure Application' \
    --type SecureString \
    --value $PLACEHOLDER
aws ssm put-parameter \
    --name MDE-AWSAutomation-App-DirectoryID \
    --description 'Directory (tenant) ID for the MDE-AWSAutomation-App Azure Application' \
    --type SecureString \
    --value $PLACEHOLDER
aws ssm put-parameter \
    --name MDE-AWSAutomation-App-SecretID \
    --description 'Secret ID for the MDE-AWSAutomation-App Azure Application' \
    --type SecureString \
    --value $PLACEHOLDER
```

Donwload the provided scripts, upload them to S3, then create a CloudFormation stack.

```bash
wget https://raw.githubusercontent.com/lightspin-tech/lightspin-office-of-the-ciso/main/blogs/mde_part4/MDE_Reporter_CloudFormation.yml
wget https://raw.githubusercontent.com/lightspin-tech/lightspin-office-of-the-ciso/main/blogs/mde_part4/report.py
pip3 install --upgrade awscli
S3_BUCKET='insert_bucket_here'
AWS_REGION=$(aws configure get region)
aws s3 cp ./report.py s3://$S3_BUCKET/quicksight/report.py
aws s3 cp ./MDE_Reporter_CloudFormation.yml s3://$S3_BUCKET/quicksight/MDE_Reporter_CloudFormation.yml
aws cloudformation create-stack \
    --stack-name MDEonAWSPart4 \
    --template-url https://$S3_BUCKET.s3.$AWS_REGION.amazonaws.com/quicksight/MDE_Reporter_CloudFormation.yml \
    --parameters ParameterKey=OCISOGenericArtifacts,ParameterValue=$S3_BUCKET \
    --capabilities CAPABILITY_NAMED_IAM
```

You should receive an output similar to this, so you can find your CloudFormation stack easier within the Console or query the status using the CLI.

```json
{
    "StackId": "arn:aws:cloudformation:mars-west-2:123456789101:stack/MDEonAWSPart4/EXAMPLE0-8449-11ec-a3d7-EXAMPLE36f0e"
}
```

Run your CodeBuild Project manually or wait 24 hours for the Automation to kick in.

## Contact Us :telephone_receiver: :telephone_receiver:

For more information, contact us at support@lightspin.io.

## License :eight_spoked_asterisk: :eight_spoked_asterisk:

This repository and all contents therein is available under the [Apache License 2.0](https://github.com/lightspin-tech/red-kube/blob/main/LICENSE).