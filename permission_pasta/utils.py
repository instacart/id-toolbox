"""
General-purpose utility functions for PermissionPasta.
"""

import logging
import os
import yaml
import sys

logger = logging.getLogger('permissionpasta')

# Required environment variables
REQUIRED_ENV_VARS = [
    'AWS_REGION',                  # AWS region to use
    'GITHUB_TOKEN',                # GitHub token for creating PRs
    'GITHUB_REPO',                 # GitHub repository for Terraform code
    'TERRAFORM_MODULE_PATH',       # Path to Terraform module within the repo
    'OPENAI_API_KEY',              # OpenAI API key for resource extraction
]

# Optional environment variables with defaults
DEFAULT_ENV_VARS = {
    'LOG_LEVEL': 'INFO',                        # Logging level
    'ADMIN_ROLE_PATTERNS': 'admin,root,super',  # Comma-separated patterns that indicate admin roles
    'PR_TEMPLATE': 'templates/pr_template.md',  # Template for GitHub PRs
    'AWS_PROFILE': 'default',                   # AWS profile to use (if not using default)
    'AWS_ROLE_ARN': '',                         # AWS role to assume (if needed)
    'VEZA_API_KEY': '',                         # Veza API key (if available)
    'VEZA_ENDPOINT': '',                        # Veza API endpoint (if available)
    'SUPPORTED_SERVICES': 's3,dynamodb,ec2,lambda,kms,secretsmanager,rds',  # Services to analyze
    'MAX_ROLES_TO_CHECK': '100',                # Maximum number of roles to check
    'MAX_RESOURCES_TO_ANALYZE': '50',           # Maximum number of resources to analyze
    'OPENAI_MODEL': 'gpt-3.5-turbo',            # OpenAI model to use
    'OKTA_API_TOKEN': '',                       # Okta API token for user role lookups
    'OKTA_DOMAIN': '',                          # Okta domain URL (e.g., company.okta.com)
    'OKTA_AWS_GROUP_PREFIX': 'AWS-',            # Prefix for Okta groups that grant AWS access
}

def safe_get(obj, key, default=None):
    """
    Safely get a value from a dictionary or object, with fallback to default
    Handles the case where obj might be a boolean or other non-dictionary type
    
    Args:
        obj: The object or dictionary to get a value from
        key: The key to look up
        default: The default value to return if the key is not found
        
    Returns:
        The value from the object, or the default if not found
    """
    if obj is None:
        return default
    
    # If obj is a dictionary, use get method
    if isinstance(obj, dict):
        return obj.get(key, default)
    
    # If obj has the attribute, use getattr
    if hasattr(obj, key):
        return getattr(obj, key)
    
    # For any other case, return the default
    return default

def validate_environment(interactive_mode=False):
    """
    Validates that required environment variables are set
    
    Args:
        interactive_mode (bool): If True, will warn but not exit when variables are missing
    """
    missing_vars = []
    
    for var in REQUIRED_ENV_VARS:
        if not os.environ.get(var):
            missing_vars.append(var)
    
    if missing_vars:
        if 'OPENAI_API_KEY' in missing_vars:
            logger.error("Missing OpenAI API key. Resource extraction will not work.")
            if not interactive_mode:
                logger.error("Please set OPENAI_API_KEY and try again.")
                sys.exit(1)
        
        # Only validate AWS-related variables if we're not in interactive mode
        aws_vars = ['AWS_REGION']
        missing_aws_vars = [var for var in missing_vars if var in aws_vars]
        if missing_aws_vars and not interactive_mode:
            logger.error(f"Missing required AWS environment variables: {', '.join(missing_aws_vars)}")
            logger.error("Please set these environment variables and try again.")
            sys.exit(1)
        
        # GitHub variables are only needed for PR creation
        github_vars = ['GITHUB_TOKEN', 'GITHUB_REPO', 'TERRAFORM_MODULE_PATH']
        missing_github_vars = [var for var in missing_vars if var in github_vars]
        if missing_github_vars:
            logger.warning(f"Missing GitHub environment variables: {', '.join(missing_github_vars)}")
            logger.warning("Pull request creation will be disabled.")
        
        if interactive_mode:
            logger.warning("Some environment variables are missing, but continuing in interactive mode.")
            logger.warning("Some features may be limited.")
        elif missing_vars:
            logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
            logger.error("Please set these environment variables and try again.")
            sys.exit(1)
    
    # Check for Okta credentials
    if not os.environ.get('OKTA_API_TOKEN') or not os.environ.get('OKTA_DOMAIN'):
        logger.warning("Okta API credentials not found. Okta group membership lookups will be disabled.")
        logger.warning("Set OKTA_API_TOKEN and OKTA_DOMAIN to enable Okta integration.")
    
    # Set defaults for optional environment variables if not already set
    for var, default in DEFAULT_ENV_VARS.items():
        if not os.environ.get(var):
            os.environ[var] = default
            
    # Set log level based on environment variable
    log_level = os.environ.get('LOG_LEVEL', 'INFO')
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        logger.warning(f"Invalid log level: {log_level}, defaulting to INFO")
        numeric_level = logging.INFO
    logger.setLevel(numeric_level)
    
    logger.debug("Environment validation complete")

def load_prompt(prompt_key):
    """
    Load a prompt from the prompts.yaml file
    
    Args:
        prompt_key: The key of the prompt to load
        
    Returns:
        The prompt configuration or None if it could not be loaded
    """
    try:
        # Path to the prompts.yaml file
        script_dir = os.path.dirname(os.path.abspath(__file__))
        prompts_file = os.path.join(script_dir, "prompts.yaml")
        
        with open(prompts_file, 'r') as file:
            prompts = yaml.safe_load(file)
            
        if prompt_key in prompts:
            return prompts[prompt_key]
        else:
            logger.warning(f"Prompt key '{prompt_key}' not found in prompts.yaml")
            return None
    except Exception as e:
        logger.error(f"Error loading prompt: {e}")
        return None 