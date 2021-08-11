## Lambda function to create/update/delete stackset using CodePipeline

from boto3.session import Session

import json
import urllib
import boto3
import zipfile
import tempfile
import botocore
import traceback
import os
from datetime import datetime
from dateutil.tz import tzutc

ROLE_NAME = os.environ['ROLE_NAME']
STACK_SET_ADMIN_ACCOUNT = os.environ['STACK_SET_ADMIN_ACCOUNT']
STACK_SET_OPERATION_TYPE_CREATE = "CREATE"
STACK_SET_OPERATION_TYPE_UPDATE = "UPDATE"

cf = None
code_pipeline = boto3.client('codepipeline')

def get_session(account, role_name):
    """Assumes the roles in the specified account and returns session credentials

    Downloads the artifact from the S3 artifact store to a temporary file
    then extracts the zip and returns the file containing the CloudFormation
    template.

    Args:
        account: The account to assume the role in
        role_name: Name of the role

    Returns:
        Returns a session object containing aws_access_key_id,
        aws_secret_access_key and aws_session_token

    Raises:
        Exception: None

    """
    sts_client = boto3.client('sts')
    # Call the assume_role method of the STSConnection object and pass the role
    # ARN and a role session name.
    try:
        role_arn = "arn:aws:iam::{}:role/{}".format(account, role_name)
        assumedRoleObject = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="AssumeRoleSession"
        )
    except Exception as e:
        print("Error assuming role: %s Error: %s" %(role_name, str(e)))
        return None

    credentials = assumedRoleObject['Credentials']
    session = boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
    )
    return session


def find_artifact(artifacts, name):
    """Finds the artifact 'name' among the 'artifacts'

    Args:
        artifacts: The list of artifacts available to the function
        name: The artifact we wish to use
    Returns:
        The artifact dictionary found
    Raises:
        Exception: If no matching artifact is found

    """
    for artifact in artifacts:
        if artifact['name'] == name:
            return artifact

    raise Exception('Input artifact named "{0}" not found in event'.format(name))


def get_file_from_artifact(s3, artifact, file_in_zip):
    """Gets the template artifact

    Downloads the artifact from the S3 artifact store to a temporary file
    then extracts the zip and returns the file containing the CloudFormation
    template.

    Args:
        artifact: The artifact to download
        file_in_zip: The path to the file within the zip containing the template

    Returns:
        The CloudFormation template as a string

    Raises:
        Exception: Any exception thrown while downloading the artifact or unzipping it

    """
    tmp_file = tempfile.NamedTemporaryFile()
    bucket = artifact['location']['s3Location']['bucketName']
    key = artifact['location']['s3Location']['objectKey']

    with tempfile.NamedTemporaryFile() as tmp_file:
        s3.download_file(bucket, key, tmp_file.name)
        with zipfile.ZipFile(tmp_file.name, 'r') as zip:
            return str(zip.read(file_in_zip), 'utf-8')


def update_stackset(stackset, template, parameters, capabilities, preferences):
    """Start a CloudFormation stack update

    Args:
        stackset: The stackset to update
        template: The template to apply
        parameters: Parameters for the stacks
        capabilities: IAM capabilities for CloudFormation to create/update the stack
        preferences: Preferences for stackset instance creation or update

    Returns:
        True if an update was started, false if there were no changes
        to the template since the last update.

    Raises:
        Exception: Any exception besides "No updates are to be performed."

    """
    try:
        response = cf.update_stack_set(StackSetName=stackset, TemplateBody=template, Parameters=parameters,
                                       Capabilities=capabilities, OperationPreferences=preferences)
        return True

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Message'] == 'No updates are to be performed.':
            return False
        else:
            raise Exception('Error updating CloudFormation stack "{0}"'.format(stackset), e)


def stackset_exists(stackset):
    """Check if a stack set exists or not

    Args:
        stackset: The stack set to check

    Returns:
        True or False depending on whether the stack exists

    Raises:
        Any exceptions raised .describe_stacksets() besides that
        the stack doesn't exist.

    """
    try:
        cf.describe_stack_set(StackSetName=stackset)
        return True
    except botocore.exceptions.ClientError as e:
        if "not found" in e.response['Error']['Message']:
            return False
        else:
            raise e


def get_stackset_instances_info_current(stackset):
    """ For a given stackset, gets a list of accounts and regions in which stack instances
        exists and are in current state

        Args:
            stackset: The stackset for which stack instances need to be looked up

        Throws:
            Exception: Any exception thrown by .list_stack_instances()
    """
    print("looking up Stack set instances for stackset: %s" %(stackset))
    response = cf.list_stack_instances(StackSetName=stackset)
    stack_instances = {}
    accounts = []
    regions = []
    instances = response['Summaries']

    firstPass = True
    nextToken = None
    while firstPass or nextToken is not None:
        firstPass = False
        if nextToken:
            response = cf.list_stack_instances(StackSetName=stackset, NextToken=nextToken)
        else:
            response = cf.list_stack_instances(StackSetName=stackset)
        instances = response['Summaries']
        if 'NextToken' in response:
            nextToken = response['NextToken']
        else:
            nextToken = None

        for instance in instances:
            account = instance['Account']
            region = instance['Region']
            status = instance['Status']
            status = instance['Status']
            if 'StatusReason' in instance:
                reason = instance['StatusReason']
            else:
                reason = ''
            if status == 'CURRENT' or (status == 'OUTDATED' and reason == 'Attempt to perform create operation on already existing stack'):
            #if status == 'CURRENT':
                if account not in accounts:
                    accounts.append(account)
                if region not in regions:
                    regions.append(region)

    stack_instances['Accounts'] = accounts
    stack_instances['Regions'] = regions
    return stack_instances

def get_stackset_instances_info_all(stackset):
    """ For a given stackset, gets a list of accounts and regions in which stack instances are created

        Args:
            stackset: The stackset for which stack instances need to be looked up

        Throws:
            Exception: Any exception thrown by .list_stack_instances()
    """
    print("looking up Stack set instances for stackset: %s" %(stackset))
    response = cf.list_stack_instances(StackSetName=stackset)
    stack_instances = {}
    accounts = []
    regions = []
    instances = response['Summaries']

    firstPass = True
    nextToken = None
    while firstPass or nextToken is not None:
        firstPass = False
        if nextToken:
            response = cf.list_stack_instances(StackSetName=stackset, NextToken=nextToken)
        else:
            response = cf.list_stack_instances(StackSetName=stackset)
        instances = response['Summaries']
        if 'NextToken' in response:
            nextToken = response['NextToken']
        else:
            nextToken = None

        for instance in instances:
            account = instance['Account']
            region = instance['Region']
            status = instance['Status']
            if account not in accounts:
                accounts.append(account)
            if region not in regions:
                regions.append(region)

    stack_instances['Accounts'] = accounts
    stack_instances['Regions'] = regions
    return stack_instances

def get_stack_parameters_as_dict(parameters):
    params = {}
    for param in parameters:
        params[param['ParameterKey']] = param['ParameterValue']
    return params

def stack_instances_to_create(currentStackInstances, accounts, regions):
    currentAccounts = currentStackInstances['Accounts']
    currentRegions = currentStackInstances['Regions']
    stackInstanceToAdd = {}
    newAccounts = []
    newRegions = []

    for region in regions:
        if region not in currentRegions:
            newRegions.append(region)

    for account in accounts:
        if account not in currentAccounts:
            newAccounts.append(account)

    if currentAccounts:
        ## TODO: Currently we are only supporting either a region update or account update but not both
        if newAccounts:
            stackInstanceToAdd['Accounts'] = newAccounts
            stackInstanceToAdd['Regions'] = currentRegions
        elif newRegions:
            stackInstanceToAdd['Accounts'] = currentAccounts
            stackInstanceToAdd['Regions'] = newRegions
    else:
        if newAccounts:
            stackInstanceToAdd['Accounts'] = newAccounts
            stackInstanceToAdd['Regions'] = newRegions

    return stackInstanceToAdd

def stack_instances_to_delete(currentStackInstances, accounts, regions):
    currentAccounts = currentStackInstances['Accounts']
    currentRegions = currentStackInstances['Regions']
    stackInstanceToRemove = {}
    accountsToRemove = []
    regionsToRemove = []

    for region in currentRegions:
        if region not in regions:
            regionsToRemove.append(region)

    for account in currentAccounts:
        if account not in accounts:
            accountsToRemove.append(account)

    # TODO: Currently we are only supporting either a region update or account update but not both
    if regionsToRemove:
        stackInstanceToRemove['Accounts'] = currentAccounts
        stackInstanceToRemove['Regions'] = regionsToRemove
    elif accountsToRemove:
        stackInstanceToRemove['Accounts'] = accountsToRemove
        stackInstanceToRemove['Regions'] = currentRegions

    return stackInstanceToRemove


def get_stack_set_templates_and_params(stack_set):
    print("looking up Stack set info for stackset: %s" %(stack_set))
    response = cf.describe_stack_set(StackSetName=stack_set)
    stack_set_info = {}
    stack_set_info['Template'] = response['StackSet']['TemplateBody']
    stack_set_info['Parameters'] = response['StackSet']['Parameters']
    return stack_set_info


def create_stack_set(stack_set, template, parameters, capabilities):
    """Starts a new CloudFormation stack set creation

    Args:
        stack_set: Name of Stack set to be created
        template: The template for the stack to be created with

    Throws:
        Exception: Any exception thrown by .create_stack()
    """
    print("Creating Stack Set: %s" %(stack_set))
    response = cf.create_stack_set(StackSetName=stack_set, TemplateBody=template, Parameters=parameters,
                                   Capabilities=capabilities)
    print(response)
    return response['StackSetId']


def create_stack_instances(stack_set_name, accounts, regions, preferences):
    """Starts stack instances creation

    Args:
        stack_set_name: The stack to be created
        accounts: The list of accounts to create the stack instances
        regions: List of regions to deploy the stack instances

    Throws:
        Exception: Any exception thrown by .create_stack_instances()
    """
    print("Creating Stack Instances for stack set: %s in accounts: %s, regions: %s" %(stack_set_name, accounts, str(regions)))
    response = cf.create_stack_instances(StackSetName=stack_set_name, Accounts=accounts, Regions=regions,
                                         OperationPreferences=preferences)
    print(response)


def delete_stack_instances(stack_set_name, accounts, regions, preferences):
    """Starts stack instances deletion

    Args:
        stack_set_name: The stack set name
        accounts: The list of accounts to create the stack instances
        regions: List of regions to deploy the stack instances

    Throws:
        Exception: Any exception thrown by .create_stack_instances()
    """
    print("Deleting Stack Instances for stack set: %s in accounts: %s, regions: %s" %(stack_set_name, accounts, str(regions)))
    response = cf.delete_stack_instances(StackSetName=stack_set_name, Accounts=accounts, Regions=regions,
                                         OperationPreferences=preferences, RetainStacks=False)
    print(response)


def get_stack_set_last_operation_status(stack_set):
    """Get the status CloudFormation stack set most recent operation

    Args:
        stack_set: The name of the stack set to check

    Returns:
        The CloudFormation status string of the stack such as SUCCEEDED

    Raises:
        Exception: Any exception thrown by .list_stack_set_operations()

    """
    latestOperationTime = datetime(1970, 1, 1, 00, 00, 00, 0, tzinfo=tzutc())
    response = cf.list_stack_set_operations(StackSetName=stack_set)
    operations = response['Summaries']
    status = 'NONE'
    for operation in operations:
        if operation['CreationTimestamp'] > latestOperationTime:
            status = operation['Status']
            latestOperationTime = operation['CreationTimestamp']

    return status


def get_stack_set_last_operation_action(stack_set):
    """Get the status of CloudFormation stack set most recent operation

    Args:
        stack_set: The name of the stack set to check

    Returns:
        The CloudFormation status string of the stack such as SUCCEEDED

    Raises:
        Exception: Any exception thrown by .list_stack_set_operations()

    """
    latestOperationTime = datetime(1970, 1, 1, 00, 00, 00, 0, tzinfo=tzutc())
    response = cf.list_stack_set_operations(StackSetName=stack_set)
    operations = response['Summaries']
    action = 'NONE'
    for operation in operations:
        if operation['CreationTimestamp'] > latestOperationTime:
            action = operation['Action']
            latestOperationTime = operation['CreationTimestamp']

    return action


def put_job_success(job, message):
    """Notify CodePipeline of a successful job

    Args:
        job: The CodePipeline job ID
        message: A message to be logged relating to the job status

    Raises:
        Exception: Any exception thrown by .put_job_success_result()

    """
    print('Putting job success')
    print(message)
    code_pipeline.put_job_success_result(jobId=job)


def put_job_failure(job, message):
    """Notify CodePipeline of a failed job

    Args:
        job: The CodePipeline job ID
        message: A message to be logged relating to the job status

    Raises:
        Exception: Any exception thrown by .put_job_failure_result()

    """
    print('Putting job failure')
    code_pipeline.put_job_failure_result(jobId=job, failureDetails={'message': message, 'type': 'JobFailed'})


def continue_job_later(job, message):
    """Notify CodePipeline of a continuing job

    This will cause CodePipeline to invoke the function again with the
    supplied continuation token.

    Args:
        job: The JobID
        message: A message to be logged relating to the job status
        continuation_token: The continuation token

    Raises:
        Exception: Any exception thrown by .put_job_success_result()

    """

    # Use the continuation token to keep track of any job execution state
    # This data will be available when a new job is scheduled to continue the current execution
    continuation_token = json.dumps({'previous_job_id': job})

    print('Putting job continuation')
    code_pipeline.put_job_success_result(jobId=job, continuationToken=continuation_token)


def start_stack_set_update_or_create(job_id, stack_set_name, newTemplate, account_info, parameters, capabilities):
    """Starts the stack set update or create process

    If the stack set exists then update, otherwise create.

    Args:
        job_id: The ID of the CodePipeline job
        stack_set_name: The stack set to create or update
        template: The template to create/update the stack with
        account_info: Accounts and regions to create/update the stack instances in
        parameters: Stack parameters
        capabilities: Stack set IAM capabilities
    """
    if stackset_exists(stack_set_name):
        ## check if
        status = get_stack_set_last_operation_status(stack_set_name)
        if status not in ['SUCCEEDED', 'FAILED', 'STOPPED', 'NONE']:
            # If the CloudFormation stack is not in a state where
            # it can be updated again then fail the job right away.
            put_job_failure(job_id, 'Stack set cannot be updated when status is: ' + status)
            return

        currentStackSetInfo = get_stack_set_templates_and_params(stack_set_name)
        status = get_stack_set_last_operation_status(stack_set_name)
        stack_update = False
        if newTemplate != currentStackSetInfo['Template']:
            print("Stack set template has changed, performing stack set update")
            stack_update = True
        elif status != 'SUCCEEDED':
            print("Previous stack update process didn't go through. Retrying...")
            stack_update = True
        else:
            print("No updates to the stack set template, checking for parameter update")
            currentStackSetParams = get_stack_parameters_as_dict(currentStackSetInfo['Parameters'])
            newStackSetParams = get_stack_parameters_as_dict(parameters)
            for k, v in newStackSetParams.items():
                if k in currentStackSetParams and currentStackSetParams[k] != v:
                    stack_update = True
                    print("Stack parameters have changed, performing stack set update")
                    break

        if stack_update:
            update_stackset(stack_set_name, newTemplate, parameters, capabilities, account_info['OperationPreferences'])
            # operation_info['Type'] = STACK_SET_OPERATION_TYPE_UPDATE
            # global STACK_SET_OPERATION_INFO
            # STACK_SET_OPERATION_INFO[stack_set_name] = operation_info
            continue_job_later(job_id, 'Stack set update started')
        else:
            print("No Update to Stack template or parameters, checking if there are any changes to accounts or regions")
            response = update_stack_instances(stack_set_name, account_info['Accounts'], account_info['Regions'],
                                              account_info['OperationPreferences'])
            if response:
                # Continue the job so the pipeline will wait for the CloudFormation stack set to be created.
                continue_job_later(job_id, 'Updating stack set instances')
            else:
                # If there were no updates then succeed the job immediately
                put_job_success(job_id, 'There were no updates to the stack set')
    else:
        # If the stack doesn't already exist then create it instead
        # of updating it.
        stack_set_id = create_stack_set(stack_set_name, newTemplate, parameters, capabilities)
        ## create stack instances
        if stack_set_id:
            create_stack_instances(stack_set_name, account_info['Accounts'], account_info['Regions'],
                                              account_info['OperationPreferences'])
            # Continue the job so the pipeline will wait for the CloudFormation stack set to be created.
            continue_job_later(job_id, 'Stack set instance creation started')
        else:
            put_job_failure(job_id, 'Stack set creation failed')


def update_stack_instances(stack_set_name, accounts, regions, preferences):
    """Adds or removes stack instances for the given stackset as per the new
       accounts and regions

    Args:
        stack_set_name: The stack set to create or update
        template: The template to update the stackset with
        accounts: Accounts to create/remove the stack instances
        regions: New regions to create/remove the stack instances
        preferences: preferences for stackset instance creation
    """
    currentStackInstances = get_stackset_instances_info_current(stack_set_name)
    add_stack_instances = stack_instances_to_create(currentStackInstances, accounts, regions)
    currentStackInstances = get_stackset_instances_info_all(stack_set_name)
    remove_stack_instances = stack_instances_to_delete(currentStackInstances, accounts, regions)
    were_updates = False

    if add_stack_instances:
        print('Creating new stack set instances for: %s' % add_stack_instances.items())
        create_stack_instances(stack_set_name,
                               add_stack_instances['Accounts'],
                               add_stack_instances['Regions'],
                               preferences)
        were_updates = True
    elif remove_stack_instances:
        print('Removing stack set instances from %s' % remove_stack_instances.items())
        delete_stack_instances(stack_set_name,
                               remove_stack_instances['Accounts'],
                               remove_stack_instances['Regions'],
                               preferences)
        were_updates = True
    return were_updates


def convert_params_to_list_from_dict(parameters):
    params = []
    key = "ParameterKey"
    value = "ParameterValue"
    for k, v in parameters.items():
        param = {}
        param[key] = k
        param[value] = v
        params.append(param)
    return params


def check_stack_set_create_update_status(job_id, stack, account_info):
    """Monitor an already-running CloudFormation update/create

    Succeeds, fails or continues the job depending on the stack status.

    Args:
        job_id: The CodePipeline job ID
        stack: The stack to monitor

    """
    print("Checking status for existing statckset: %s" %(stack))
    status = get_stack_set_last_operation_status(stack)
    if status in ['SUCCEEDED']:
        # Check if there are any changes to accounts and/or regions and create/delete stack sets accordingly
        stack_set_operation_type = get_stack_set_last_operation_action(stack)
        if stack_set_operation_type == STACK_SET_OPERATION_TYPE_UPDATE:
            print("Stack update completed. Now checking if there are any changes to accounts or regions")
            response = update_stack_instances(stack, account_info['Accounts'], account_info['Regions'],
                                              account_info['OperationPreferences'])
            if response:
                print("Stack set update started, continuing pipeline job ..")
                # Continue the job so the pipeline will wait for the CloudFormation stack set to be created.
                continue_job_later(job_id, 'Updating stack set instances')
            else:
                print("No new changes in accounts or regions")
                # If the update/create finished successfully then
                # succeed the job and don't continue.
                put_job_success(job_id, 'Stack set update complete')
        else:
            put_job_success(job_id, 'Stack set instances created/updated')

    elif status in ['RUNNING', 'STOPPING']:
        # If the job isn't finished yet then continue it
        continue_job_later(job_id, 'Stack set update still in progress')

    else:
        # If the Stack is a state which isn't "in progress" or "complete"
        # then the stack update/create has failed so end the job with
        # a failed result.
        print("Stack Set creation or update failed, returning failure to codepipeline")
        put_job_failure(job_id, 'Update failed: ' + status)


def get_user_params(job_data):
    """Decodes the JSON user parameters and validates the required properties.

    Args:
        job_data: The job data structure containing the UserParameters string which should be a valid JSON structure

    Returns:
        The JSON parameters decoded as a dictionary.

    Raises:
        Exception: The JSON can't be decoded or a property is missing.

    """
    try:
        # Get the user parameters which contain the stack, artifact and file settings
        user_parameters = job_data['actionConfiguration']['configuration']['UserParameters']
        decoded_parameters = json.loads(user_parameters)

    except Exception as e:
        # We're expecting the user parameters to be encoded as JSON
        # so we can pass multiple values. If the JSON can't be decoded
        # then fail the job with a helpful message.
        raise Exception('UserParameters could not be decoded as JSON')

    if 'StackSetName' not in decoded_parameters:
        # Validate that the stack is provided, otherwise fail the job
        # with a helpful message.
        raise Exception('Your UserParameters JSON must include the stack set name')

    if 'TemplateInfo' not in decoded_parameters:
        # Validate that the template file is provided, otherwise fail the job
        # with a helpful message.
        raise Exception('Your UserParameters JSON must include the template info')

    if 'AccountInfo' not in decoded_parameters:
        # Validate that the template file is provided, otherwise fail the job
        # with a helpful message.
        raise Exception('Your UserParameters JSON must include the AccountInfo file')
    return decoded_parameters


def setup_s3_client(job_data):
    """Creates an S3 client

    Uses the credentials passed in the event by CodePipeline. These
    credentials can be used to access the artifact bucket.

    Args:
        job_data: The job data structure

    Returns:
        An S3 client with the appropriate credentials

    """
    key_id = job_data['artifactCredentials']['accessKeyId']
    key_secret = job_data['artifactCredentials']['secretAccessKey']
    session_token = job_data['artifactCredentials']['sessionToken']

    session = Session(aws_access_key_id=key_id,
                      aws_secret_access_key=key_secret,
                      aws_session_token=session_token)
    return session.client('s3', config=botocore.client.Config(signature_version='s3v4'))


def lambda_handler(event, context):
    """The Lambda function handler

    If a continuing job then checks the CloudFormation stack status
    and updates the job accordingly.

    If a new job then kick of an update or creation of the target
    CloudFormation stack set.

    Args:
        event: The event passed by Lambda
        context: The context passed by Lambda

    """

    try:
        # Extract the Job ID
        job_id = event['CodePipeline.job']['id']

        # Extract the Job Data
        job_data = event['CodePipeline.job']['data']

        # Extract the params
        params = get_user_params(job_data)

        # Get the list of artifacts passed to the function
        artifacts = job_data['inputArtifacts']

        stack_set_name = params['StackSetName']
        session = get_session(STACK_SET_ADMIN_ACCOUNT, ROLE_NAME)

        if 'StackSetRegion' in params:
            stack_set_region = params['StackSetRegion']
        else:
            stack_set_region = None

        global cf
        cf = session.client('cloudformation', region_name=stack_set_region)
        # artifact = params['Artifact']
        template_info = json.loads(params['TemplateInfo'])
        account_info = json.loads(params['AccountInfo'])

        if 'TemplateFile' in template_info:
            template_file = template_info['TemplateFile']
        else:
            raise Exception('Your TemplateInfo JSON must include the TemplateFile name')

        if 'Artifact' in template_info:
            template_artifact = template_info['Artifact']
        else:
            raise Exception('Your TemplateInfo JSON must include the Artifact')

        if 'TemplateParamFile' in template_info:
            template_param_file = template_info['TemplateParamFile']
        else:
            template_param_file = None

        if 'Capabilities' in template_info:
            capabilities = [template_info['Capabilities']]
        else:
            capabilities = []

        if 'FileName' in account_info:
            account_info_file = account_info['FileName']
        else:
            raise Exception('Your AccountInfo JSON must include the File name')

        if 'Artifact' in account_info:
            account_info_artifact = account_info['Artifact']
        else:
            raise Exception('Your AccountInfo JSON must include the Artifact')

        # Get S3 client to access artifact with
        s3 = setup_s3_client(job_data)

        account_info_artifact_data = find_artifact(artifacts, account_info_artifact)
        account_info = json.loads(get_file_from_artifact(s3, account_info_artifact_data, account_info_file))

        if 'continuationToken' in job_data:
            # If we're continuing then the create/update has already been triggered
            # we just need to check if it has finished.
            check_stack_set_create_update_status(job_id, stack_set_name, account_info)
        else:
            # Get the template artifact details
            template_artifact_data = find_artifact(artifacts, template_artifact)

            # Get the template file and parameter file out of the artifact
            template = get_file_from_artifact(s3, template_artifact_data, template_file)

            if template_param_file:
                param_file = get_file_from_artifact(s3, template_artifact_data, template_param_file)
                parameters = json.loads(param_file)
                if type(parameters) is dict:
                    if 'Parameters' in parameters:
                        parameters = parameters['Parameters']
                    parameters = convert_params_to_list_from_dict(parameters)
            else:
                parameters = []

            # Kick off a stack set update or create
            start_stack_set_update_or_create(job_id, stack_set_name, template, account_info, parameters, capabilities)

    except Exception as e:
        # If any other exceptions which we didn't expect are raised
        # then fail the job and log the exception message.
        print('Function failed due to exception.')
        print(e)
        traceback.print_exc()
        put_job_failure(job_id, 'Function exception: ' + str(e))

    return "Complete."
