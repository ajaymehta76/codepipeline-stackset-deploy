# Title
Support for CodePipeline StackSet Deployment using Lambda Action

CodePipelne CloudFormation integration currently supports creating, updating and deleting CloudFormation stacks. However, it does not natively support deploying CloudFormation Stacksets.
CloudFormation Stacksets are particularly helpful when you want to deploy a CloudFormation stack to multiple accounts and regions. This is often times the need for enterprises using the multi-account strategy. 

CloudFormation Stacksets are commonly used by Cloud platform, Security and Operations teams to deliver common capabilities across multiple accounts and regions.
Often times, these teams want to use the continuous integration and deployment process to have their changes tested in their test environment and then be able to deploy them to multiple accounts/regions using StackSet.
The solution described here, provides the ability for users to deploy CloudFormation stacksets using a Lambda function integration with CodePipeline.
With this solution, teams can use CodePipeline to automate build, test and deployment of capabilities that need to be deployed across multiple accounts and regions.

# Repo Contents:

StackSetDeployLambda: This folder contains a Lambda function that can be invoked via CodePipeline to create or update StackSet. This folder contains Lambda source code and CloudFormation to deploy the lambda. 
The Lambda function uses a cross account role in the StackSetAdmin account to create/update StackSet. This role needs to be created in the StackSet admin account before the Lambda can be invoked.
A reference cloudformation template to create the role can be found under StackSetDeployLambda/CloudFormation/StackSetAdminAccountLambdaRole.yaml

## SampleCodePipeline:
A reference pipeline that uses the StackSetDeployLambda to create a StackSet in the specified accounts. The stackset deploys a CloudFormation in every account to block S3 buckets from being made public.
The pipeline uses S3 for source stage. Reference source stage artifacts can be found in the SampleSourceArtifact bucket. These contents need to be uploaded to the S3 bucket configured for source stage in this pipeline.

## SampleSourceArtifact:
Provides reference source artifacts to create a stackset for preventing S3 buckets from being made public. 
This stackset is deployed to the account and regions specified in a config file (SampleSourceArtifact/StackSetConfig/AccountInfo.json)

# Solution Deployment:
In this solution we will be deploying a Lambda based custom action to allow CodePipeline to deploy CloudFormation stack set.
The solution's lambda function as well as the pipeline can be deployed in any account of your choice. 

## Prerequisites:
1. Install aws cli from https://aws.amazon.com/cli/
2. Login to the AWS console for the account where you want to deploy the solution and obtain credentials (Access key and Secret Key) for your user.
3. Configure the AWS CLI with the Access Key and Secret Key obtained in the previous step. For additional information on how to configure AWS CLI refer here https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html
2. Create an S3 bucket to use as the source for the reference pipeline 
3. Identify the CloudFormation StackSet administrator account and set up the required permissions for creating Stack set with self-managed permissions https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-prereqs-self-managed.html
4. Create an S3 bucket or identify an existing bucket to use for uploading the solutions lambda code.

## Steps to deploy and test:
1. Deploy the StackSetDeployLambda function using its CloudFormation template. The CloudFormation template (StackSetLambdaTemplate.yaml) needs to be packaged so that Lambda code can be uploaded to S3 bucket.
   Please run the below command to package the template and deploy the packaged template. The S3-BUCKET-TO-STAGE-LAMBDA-CODE should be replaced with the name of the S3 bucket from Step 4 in Prerequisites 
   
   aws cloudformation package --template-file ./StackSetLambdaTemplate.yaml --output-template-file ./StackSetLambdaTemplate-packaged.yaml --s3-bucket <S3-BUCKET-TO-STAGE-LAMBDA-CODE>

   aws cloudformation deploy --template-file ./StackSetLambdaTemplate-packaged.yaml --stack-name CodePipelineStackSetLambda

2. Login to the AWS account, navigate to CloudFormation console and then open the stack that you created in step 1 above. Go to Output tab and note down the value of StackSetDeployLambdaRole. You will be using this in the next step.

3. Login to the CloudFormation stack set admin account, navigate to the CloudFormation console and deploy the StackSetAdminAccountLambdaRole.yaml (located in the StackSetDeployLambda folder) to create StackSetAdminRole 

4. Login to the Pipeline account and deploy the sample pipeline CloudFormation template (located at SampleCodePipeline/SamplePipeline.yaml). This will create a test pipeline with a stage to deploy stackset using the stackset deploy lambda.

5. In the SampleSourceArtifact folder, update the AccountInfo.json with the accounts and regions where you would like to create the stack set instances.
   Once done, create a zip file for the contents of the SampleSourceArtifact folder and Upload the zip to artifact bucket specified (Prerequisites step 1) when creating the sample pipeline. This will trigger the sample pipeline to deploy
   and you will see the pipeline creating CloudFormation stack set in the admin account with stack instances in the target accounts.
   
