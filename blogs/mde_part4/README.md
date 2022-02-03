# Lightspin Office of the CISO - Public Artifacts - Blog Code - Microsoft Defender of AWS: Part 4

Open source code associated with the Microsoft Defender of AWS: Part 4 created by the Lightspin Office of the CISO

Originally Posted At: !TODO...

![diagram](lightspin-office-of-the-ciso/pics/MdePart4Diagram.jpg)

## How do I use this :thinking: :thinking: ??

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

## Contact Us :telephone_receiver: :telephone_receiver:

For more information, contact us at support@lightspin.io.

## License :eight_spoked_asterisk: :eight_spoked_asterisk:

This repository and all contents therein is available under the [Apache License 2.0](https://github.com/lightspin-tech/red-kube/blob/main/LICENSE).