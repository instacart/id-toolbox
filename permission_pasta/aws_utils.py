import logging
import os
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger('permissionpasta')

def initialize_aws_session():
    """
    Initialize AWS session using environment variables or default credentials
    
    Returns:
        A boto3 session object
    """
    profile_name = os.environ.get('AWS_PROFILE')
    region_name = os.environ.get('AWS_REGION', 'us-east-1')  # Default to us-east-1 if not specified
    role_arn = os.environ.get('AWS_ROLE_ARN')
    
    try:
        # Print debugging information about profiles and credentials
        logger.info(f"AWS Region: {region_name}")
        logger.info(f"AWS Profile from env: {profile_name if profile_name else 'Not set'}")
        logger.info(f"AWS Role ARN: {role_arn if role_arn else 'Not set'}")
        
        # Check if AWS CLI config exists
        aws_config_file = os.path.expanduser("~/.aws/config")
        aws_credentials_file = os.path.expanduser("~/.aws/credentials")
        
        if os.path.exists(aws_config_file):
            logger.info(f"AWS config file found: {aws_config_file}")
        else:
            logger.warning(f"AWS config file not found: {aws_config_file}")
            
        if os.path.exists(aws_credentials_file):
            logger.info(f"AWS credentials file found: {aws_credentials_file}")
        else:
            logger.warning(f"AWS credentials file not found: {aws_credentials_file}")
            
        # List available profiles (debug info)
        try:
            import configparser
            config = configparser.ConfigParser()
            profiles = []
            
            if os.path.exists(aws_config_file):
                config.read(aws_config_file)
                profiles.extend([section.replace('profile ', '') for section in config.sections() 
                                if section.startswith('profile ')])
                
            if os.path.exists(aws_credentials_file):
                config.read(aws_credentials_file)
                profiles.extend([section for section in config.sections() 
                               if section != 'default' and section not in profiles])
                
            if 'default' in config.sections():
                profiles.append('default')
                
            logger.info(f"Available AWS profiles: {', '.join(profiles) if profiles else 'None found'}")
        except Exception as e:
            logger.warning(f"Could not list AWS profiles: {e}")
        
        # Create a session with the available credentials
        session = None
        
        # First try with profile if specified
        if profile_name:
            try:
                logger.info(f"Attempting to create session with profile: {profile_name}")
                session = boto3.Session(profile_name=profile_name, region_name=region_name)
                logger.info(f"Successfully created session with profile {profile_name}")
            except Exception as profile_err:
                logger.warning(f"Failed to create session with profile {profile_name}: {profile_err}")
                session = None
        
        # If no profile specified or profile failed, try with default credentials
        if not session:
            try:
                # Check for environment credentials first
                if os.environ.get('AWS_ACCESS_KEY_ID') and os.environ.get('AWS_SECRET_ACCESS_KEY'):
                    logger.info("Using AWS credentials from environment variables")
                    session = boto3.Session(
                        aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                        aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
                        aws_session_token=os.environ.get('AWS_SESSION_TOKEN'),
                        region_name=region_name
                    )
                else:
                    # Create default session (uses environment variables or ~/.aws/credentials)
                    logger.info(f"Using default AWS credentials (no profile specified)")
                    session = boto3.Session(region_name=region_name)
            except Exception as default_err:
                logger.warning(f"Failed to create session with default credentials: {default_err}")
                session = None
        
        # If we've managed to create a session, test it
        if session:
            try:
                sts_client = session.client('sts')
                identity = sts_client.get_caller_identity()
                account_id = identity.get('Account')
                user_arn = identity.get('Arn')
                logger.info(f"AWS session initialized successfully")
                logger.info(f"Account: {account_id}, User: {user_arn}")
                
                # Assume role if specified
                if role_arn:
                    logger.info(f"Assuming role: {role_arn}")
                    try:
                        response = sts_client.assume_role(
                            RoleArn=role_arn,
                            RoleSessionName='PermissionPastaSession'
                        )
                        credentials = response['Credentials']
                        
                        session = boto3.Session(
                            aws_access_key_id=credentials['AccessKeyId'],
                            aws_secret_access_key=credentials['SecretAccessKey'],
                            aws_session_token=credentials['SessionToken'],
                            region_name=region_name
                        )
                        
                        # Verify assumed role identity
                        assumed_identity = session.client('sts').get_caller_identity()
                        logger.info(f"Successfully assumed role. New identity: {assumed_identity.get('Arn')}")
                    except Exception as assume_err:
                        logger.error(f"Failed to assume role {role_arn}: {assume_err}")
                        logger.warning("Continuing with original credentials")
                
                return session
            except Exception as test_err:
                logger.warning(f"Created AWS session but failed to validate it: {test_err}")
                # Return the session even if we couldn't validate it
                # Some operations might still work
                return session
        
        # If we reached here, we couldn't create a valid session
        logger.warning("Could not create a valid AWS session. Creating minimal session for offline operation.")
        
        # Create a minimal "offline" session that will work for non-AWS operations
        # This intentionally bypasses profile validation by not accessing config
        from botocore.session import Session
        from botocore.credentials import Credentials
        
        # Create dummy credentials
        dummy_creds = Credentials('dummy', 'dummy')
        botocore_session = Session()
        botocore_session._credentials = dummy_creds
        botocore_session.set_config_variable('region', region_name)
        
        # Create a boto3 session from the botocore session
        session = boto3.Session(botocore_session=botocore_session)
        
        return session
        
    except Exception as e:
        logger.error(f"Failed to initialize AWS session: {e}")
        logger.warning("Creating minimal session for offline operation")
        
        # Create a very minimal session as last resort
        # This will allow the script to continue but AWS operations will fail
        session = boto3.Session(region_name=region_name, 
                               aws_access_key_id='dummy',
                               aws_secret_access_key='dummy')
        return session

def resolve_resource_arns(session, resources):
    """
    Resolve resource names to ARNs using AWS APIs
    
    Args:
        session: AWS session
        resources: List of resource dictionaries
        
    Returns:
        Updated resources with ARNs filled in
    """
    try:
        # Get account ID and region from the session
        sts_client = session.client('sts')
        account_identity = sts_client.get_caller_identity()
        account_id = account_identity.get('Account')
        region = session.region_name
        
        logger.info(f"Resolving resource ARNs for account {account_id} in region {region}")
    except Exception as e:
        logger.error(f"Failed to get AWS account information: {e}")
        logger.warning("Will use placeholder values for ARNs")
        account_id = "ACCOUNT_ID"
        region = "REGION"
    
    for resource in resources:
        # Initialize the resolved_arns dictionary if it doesn't exist
        if 'resolved_arns' not in resource:
            resource['resolved_arns'] = {}
        
        for service_type in resource.get('possible_types', []):
            # Try to construct ARN based on service type
            try:
                if service_type == 's3':
                    arn = f"arn:aws:s3:::{resource['resource_name']}"
                    # Verify the bucket exists
                    try:
                        session.client('s3').head_bucket(Bucket=resource['resource_name'])
                        resource['resolved_arns'][service_type] = arn
                        resource['exists'] = True
                        logger.info(f"VERIFIED - S3 bucket exists and is accessible: {resource['resource_name']}")
                    except Exception as bucket_err:
                        logger.warning(f"NOT VERIFIED - S3 bucket not found or not accessible with current credentials: {resource['resource_name']}")
                        resource['resolved_arns'][service_type] = arn
                        resource['exists'] = False
                
                elif service_type == 'dynamodb':
                    arn = f"arn:aws:dynamodb:{region}:{account_id}:table/{resource['resource_name']}"
                    # Verify the table exists
                    try:
                        session.client('dynamodb').describe_table(TableName=resource['resource_name'])
                        resource['resolved_arns'][service_type] = arn
                        resource['exists'] = True
                        logger.info(f"VERIFIED - DynamoDB table exists and is accessible: {resource['resource_name']}")
                    except Exception as ddb_err:
                        logger.warning(f"NOT VERIFIED - DynamoDB table not found or not accessible with current credentials: {resource['resource_name']}")
                        resource['resolved_arns'][service_type] = arn
                        resource['exists'] = False
                
                elif service_type == 'sqs':
                    # For SQS, we need to get the queue URL first
                    try:
                        sqs_client = session.client('sqs')
                        response = sqs_client.get_queue_url(QueueName=resource['resource_name'])
                        queue_url = response.get('QueueUrl')
                        # Extract the account ID and region from the queue URL if needed
                        arn = f"arn:aws:sqs:{region}:{account_id}:{resource['resource_name']}"
                        resource['resolved_arns'][service_type] = arn
                        resource['exists'] = True
                        logger.info(f"VERIFIED - SQS queue exists and is accessible: {resource['resource_name']}")
                    except Exception as sqs_err:
                        logger.warning(f"NOT VERIFIED - SQS queue not found or not accessible with current credentials: {resource['resource_name']}")
                        arn = f"arn:aws:sqs:{region}:{account_id}:{resource['resource_name']}"
                        resource['resolved_arns'][service_type] = arn
                        resource['exists'] = False
                
                elif service_type == 'sns':
                    arn = f"arn:aws:sns:{region}:{account_id}:{resource['resource_name']}"
                    try:
                        sns_client = session.client('sns')
                        # Check if the topic exists (this will throw an exception if it doesn't)
                        sns_client.get_topic_attributes(TopicArn=arn)
                        resource['resolved_arns'][service_type] = arn
                        resource['exists'] = True
                        logger.info(f"VERIFIED - SNS topic exists and is accessible: {resource['resource_name']}")
                    except Exception as sns_err:
                        logger.warning(f"NOT VERIFIED - SNS topic not found or not accessible with current credentials: {resource['resource_name']}")
                        resource['resolved_arns'][service_type] = arn
                        resource['exists'] = False
                
                elif service_type == 'lambda':
                    arn = f"arn:aws:lambda:{region}:{account_id}:function:{resource['resource_name']}"
                    try:
                        lambda_client = session.client('lambda')
                        lambda_client.get_function(FunctionName=resource['resource_name'])
                        resource['resolved_arns'][service_type] = arn
                        resource['exists'] = True
                        logger.info(f"VERIFIED - Lambda function exists and is accessible: {resource['resource_name']}")
                    except Exception as lambda_err:
                        logger.warning(f"NOT VERIFIED - Lambda function not found or not accessible with current credentials: {resource['resource_name']}")
                        resource['resolved_arns'][service_type] = arn
                        resource['exists'] = False
                
                elif service_type == 'rds':
                    # RDS has different ARN formats for different resource types (DB, cluster, etc.)
                    arn = f"arn:aws:rds:{region}:{account_id}:db:{resource['resource_name']}"
                    try:
                        rds_client = session.client('rds')
                        rds_client.describe_db_instances(DBInstanceIdentifier=resource['resource_name'])
                        resource['resolved_arns'][service_type] = arn
                        resource['exists'] = True
                        logger.info(f"VERIFIED - RDS instance exists and is accessible: {resource['resource_name']}")
                    except Exception as rds_err:
                        # Try as a cluster instead
                        try:
                            cluster_arn = f"arn:aws:rds:{region}:{account_id}:cluster:{resource['resource_name']}"
                            rds_client.describe_db_clusters(DBClusterIdentifier=resource['resource_name'])
                            resource['resolved_arns'][service_type] = cluster_arn
                            resource['exists'] = True
                            logger.info(f"VERIFIED - RDS cluster exists and is accessible: {resource['resource_name']}")
                        except Exception as cluster_err:
                            logger.warning(f"NOT VERIFIED - RDS instance/cluster not found or not accessible with current credentials: {resource['resource_name']}")
                            resource['resolved_arns'][service_type] = arn
                            resource['exists'] = False
                
                elif service_type == 'secretsmanager':
                    arn = f"arn:aws:secretsmanager:{region}:{account_id}:secret:{resource['resource_name']}"
                    try:
                        sm_client = session.client('secretsmanager')
                        # This will list all secrets and check if the name matches
                        paginator = sm_client.get_paginator('list_secrets')
                        found = False
                        for page in paginator.paginate():
                            for secret in page.get('SecretList', []):
                                if secret.get('Name') == resource['resource_name']:
                                    arn = secret.get('ARN', arn)
                                    found = True
                                    break
                            if found:
                                break
                        
                        if found:
                            resource['resolved_arns'][service_type] = arn
                            resource['exists'] = True
                            logger.info(f"VERIFIED - Secrets Manager secret exists and is accessible: {resource['resource_name']}")
                        else:
                            logger.warning(f"NOT VERIFIED - Secrets Manager secret not found or not accessible with current credentials: {resource['resource_name']}")
                            resource['resolved_arns'][service_type] = arn
                            resource['exists'] = False
                    except Exception as sm_err:
                        logger.warning(f"NOT VERIFIED - Could not check Secrets Manager: {sm_err}")
                        resource['resolved_arns'][service_type] = arn
                        resource['exists'] = False
                
                # Add more service types as needed
                else:
                    logger.warning(f"NOT VERIFIED - Unsupported service type: {service_type}, using generic ARN")
                    arn = f"arn:aws:{service_type}:{region}:{account_id}:{resource['resource_name']}"
                    resource['resolved_arns'][service_type] = arn
                    resource['exists'] = False
                
                # If we have at least one confirmed resource type, set it as the resolved type
                if resource.get('exists'):
                    resource['resolved_type'] = service_type
                    break
            
            except Exception as e:
                logger.warning(f"Failed to resolve ARN for {resource['resource_name']} as {service_type}: {e}")
                # Still add a placeholder ARN
                arn = f"arn:aws:{service_type}:{region}:{account_id}:{resource['resource_name']}"
                resource['resolved_arns'][service_type] = arn
                resource['exists'] = False
    
    return resources

def find_roles_with_resource_access(session, resource_arn, resource_service):
    """
    Find IAM roles that have access to the specified resource
    
    Args:
        session: AWS session
        resource_arn: ARN of the resource to check
        resource_service: AWS service type (s3, dynamodb, etc.)
        
    Returns:
        Dictionary with 'human_roles' and 'machine_roles' lists containing roles that have access to the resource
    """
    # Try to use Veza first if it's available
    try:
        from veza_utils import initialize_veza_connection, get_roles_with_resource_access
        
        # Extract resource name from ARN
        resource_name = None
        if resource_service == 's3':
            # For S3, the resource name is everything after the last colon
            resource_name = resource_arn.split(':')[-1]
        elif resource_service in ['dynamodb', 'sqs', 'sns', 'lambda', 'secretsmanager']:
            # For these services, the resource name is everything after the last /
            resource_name = resource_arn.split('/')[-1]
        elif resource_service == 'rds':
            # For RDS, we need to check if it's a cluster or instance
            if ':db:' in resource_arn:
                resource_name = resource_arn.split(':db:')[-1]
            elif ':cluster:' in resource_arn:
                resource_name = resource_arn.split(':cluster:')[-1]
        
        if resource_name:
            logger.info(f"Attempting to use Veza to find roles with access to {resource_service} resource: {resource_name}")
            veza_connection = initialize_veza_connection()
            if veza_connection:
                veza_roles = get_roles_with_resource_access(resource_name, resource_service, veza_connection)
                
                # Add validation to ensure the result has the expected structure
                if veza_roles and isinstance(veza_roles, dict):
                    # Ensure human_roles and machine_roles fields exist and are lists
                    if not 'human_roles' in veza_roles:
                        logger.warning("Veza result missing 'human_roles' field, adding empty list")
                        veza_roles['human_roles'] = []
                    
                    if not 'machine_roles' in veza_roles:
                        logger.warning("Veza result missing 'machine_roles' field, adding empty list")
                        veza_roles['machine_roles'] = []
                    
                    # Check if we got any roles from Veza
                    total_roles = len(veza_roles.get('human_roles', [])) + len(veza_roles.get('machine_roles', []))
                    logger.info(f"Found {total_roles} roles with access to {resource_name} using Veza")
                    
                    if total_roles > 0:
                        return veza_roles
                    else:
                        logger.warning(f"No roles found with access to {resource_name} using Veza, falling back to AWS IAM policy analysis")
                else:
                    logger.warning(f"Invalid response format from Veza: {veza_roles}, falling back to AWS IAM policy analysis")
            else:
                logger.warning("Veza connection not available, using AWS IAM policy analysis instead")
        else:
            logger.warning(f"Could not extract resource name from ARN: {resource_arn}, using AWS IAM policy analysis instead")
    except ImportError:
        logger.warning("Veza utilities not available, using AWS IAM policy analysis instead")
    except Exception as e:
        logger.error(f"Error using Veza to find roles with access: {e}")
        logger.warning("Falling back to AWS IAM policy analysis")
    
    # Fall back to AWS IAM policy analysis if Veza is not available or failed
    iam_client = session.client('iam')
    
    # Get all roles in the account
    try:
        roles_response = iam_client.list_roles()
        roles = roles_response['Roles']
        
        # Respect the maximum number of roles to check
        max_roles = int(os.environ.get('MAX_ROLES_TO_CHECK', 100))
        if len(roles) > max_roles:
            logger.warning(f"Found {len(roles)} roles, limiting check to {max_roles}")
            roles = roles[:max_roles]
    except ClientError as e:
        logger.error(f"Failed to list IAM roles: {e}")
        return {'human_roles': [], 'machine_roles': []}
    
    # Get admin role patterns to identify admin roles
    admin_patterns = os.environ.get('ADMIN_ROLE_PATTERNS', 'admin,root,super').split(',')
    
    # Check each role for access to the resource
    human_roles = []
    machine_roles = []
    
    for role in roles:
        role_name = role['RoleName']
        
        # Check if this role matches admin patterns
        is_admin = any(pattern.lower() in role_name.lower() for pattern in admin_patterns)
        
        # TODO: Implement policy evaluation logic to check if role can access the resource
        # This is a placeholder that would need to be replaced with actual policy evaluation
        has_access = False  # placeholder
        access_actions = []  # placeholder
        
        if has_access:
            role_info = {
                'role_name': role_name,
                'is_admin': is_admin,
                'actions': access_actions
            }
            
            # Determine if this is a human-assumable role by checking trust relationship for 'okta'
            is_human_role = False
            try:
                # Get the trust relationship document for this role
                assume_role_policy = role.get('AssumeRolePolicyDocument', {})
                
                if assume_role_policy:
                    # Convert to string to easily search for 'okta'
                    policy_str = str(assume_role_policy).lower()
                    
                    # Check if 'okta' is in the trust relationship
                    if 'okta' in policy_str:
                        is_human_role = True
                        logger.debug(f"Role {role_name} has 'okta' in trust relationship, classified as human role")
                    
                    # Also check for SAML provider which often indicates human-assumable roles
                    if not is_human_role and ('saml' in policy_str or 'saml-provider' in policy_str):
                        is_human_role = True
                        logger.debug(f"Role {role_name} has SAML provider in trust relationship, classified as human role")
            except Exception as e:
                logger.warning(f"Failed to check trust relationship for role {role_name}: {e}")
                # Fall back to heuristic in case of error
                is_human_role = ('developer' in role_name.lower() or 'analyst' in role_name.lower())
            
            if is_human_role:
                role_info['type'] = 'human'
                human_roles.append(role_info)
            else:
                role_info['type'] = 'machine'
                machine_roles.append(role_info)
    
    return {'human_roles': human_roles, 'machine_roles': machine_roles} 