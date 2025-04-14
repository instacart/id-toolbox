import logging
import os
import requests

logger = logging.getLogger('permissionpasta')

def get_user_current_roles(session, username):
    """
    Get the current AWS roles that a user has access to via Okta group memberships.
    Looks for Okta groups with names starting with 'AWS-' prefix.
    
    Args:
        session: AWS session (not used in this implementation, kept for compatibility)
        username: Okta username to lookup
        
    Returns:
        List of AWS role names the user has access to via Okta
    """
    okta_api_token = os.environ.get('OKTA_API_TOKEN')
    okta_domain = os.environ.get('OKTA_DOMAIN')
    aws_group_prefix = os.environ.get('OKTA_AWS_GROUP_PREFIX', 'AWS-')
    
    # If Okta credentials are missing, return empty list
    if not okta_api_token or not okta_domain:
        logger.warning("Okta API credentials not found. Cannot check user's Okta group memberships.")
        return []
    
    # Log the user we're checking
    logger.info(f"Looking up Okta groups for user: {username}")
    
    try:
        # First, get the user ID from the username
        user_endpoint = f"https://{okta_domain}/api/v1/users/{username}"
        headers = {
            'Authorization': f'SSWS {okta_api_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        # Get user information
        response = requests.get(user_endpoint, headers=headers)
        
        # Check if the request was successful
        if response.status_code != 200:
            logger.error(f"Failed to find user {username} in Okta: {response.status_code} - {response.text}")
            return []
        
        user_id = response.json().get('id')
        logger.info(f"Found Okta user ID for {username}: {user_id}")
        
        # Now get the user's groups
        groups_endpoint = f"https://{okta_domain}/api/v1/users/{user_id}/groups"
        response = requests.get(groups_endpoint, headers=headers)
        
        # Check if the request was successful
        if response.status_code != 200:
            logger.error(f"Failed to get groups for user {username}: {response.status_code} - {response.text}")
            return []
        
        # Extract AWS groups (those with the AWS prefix)
        groups = response.json()
        aws_roles = []
        
        for group in groups:
            group_name = group.get('profile', {}).get('name', '')
            
            # Check if the group name starts with the AWS prefix
            if group_name.startswith(aws_group_prefix):
                # Extract the role name (everything after the prefix)
                role_name = group_name[len(aws_group_prefix):]
                aws_roles.append(role_name)
                logger.info(f"Found AWS role for user: {role_name}")
        
        logger.info(f"User {username} has access to {len(aws_roles)} AWS roles via Okta")
        return aws_roles
    
    except requests.RequestException as e:
        logger.error(f"Error during Okta API request: {str(e)}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error during Okta role lookup: {str(e)}")
        return [] 