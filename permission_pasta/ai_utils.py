import logging
import os
import re
import json
import openai
from utils import load_prompt

logger = logging.getLogger('permissionpasta')

def extract_resources_from_justification_ai(justification):
    """
    Use OpenAI to analyze justification text and extract AWS resources mentioned
    Returns a list of dictionaries with resource details and possible types
    
    Args:
        justification: The business justification text
        
    Returns:
        List of dictionaries containing resource details
    """
    if not justification:
        return []
    
    logger.info("Using OpenAI to analyze justification for resources")
    
    # Get the list of supported services
    supported_services = os.environ.get('SUPPORTED_SERVICES', '').split(',')
    
    # Load the system prompt from YAML file
    prompt_config = load_prompt("resource_extraction")
    
    if not prompt_config or "system" not in prompt_config:
        logger.error("Could not load resource extraction prompt from prompts.yaml")
        return extract_resources_fallback(justification)
    
    # Format the prompt with the supported services
    system_prompt = prompt_config["system"].format(supported_services=', '.join(supported_services))
    
    # User prompt is simply the justification text
    user_prompt = justification
    
    try:
        # Set up the OpenAI client 
        client = openai.OpenAI(
            api_key=os.environ.get('OPENAI_API_KEY')
        )
        
        # Create the completion using the ChatCompletion API
        response = client.chat.completions.create(
            model=os.environ.get('OPENAI_MODEL', 'gpt-3.5-turbo'),
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1,  # Low temperature for more deterministic outputs
            max_tokens=1000
        )
        
        # Extract the content from the response
        content = response.choices[0].message.content
        
        # Find the JSON part in the response
        json_match = re.search(r'```json\s*(.*?)\s*```', content, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            # If no code block, try to find array directly
            json_match = re.search(r'\[\s*{.*}\s*\]', content, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
            else:
                # Use the entire content as fallback
                json_str = content
        
        try:
            # Parse the JSON
            resources = json.loads(json_str)
            
            # Verify the result is a list
            if not isinstance(resources, list):
                logger.warning("AI response was not a list, using empty list instead")
                return []
            
            return resources
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response: {e}")
            logger.debug(f"AI response content: {content}")
            
            # Fallback - try a simpler approach with another prompt
            return extract_resources_fallback(justification)
    
    except Exception as e:
        logger.error(f"OpenAI API error: {e}")
        return extract_resources_fallback(justification)

def extract_resources_fallback(justification):
    """
    Fallback method to extract resources using basic pattern matching
    Used when OpenAI API fails
    
    Args:
        justification: The business justification text
        
    Returns:
        List of dictionaries containing resource details
    """
    logger.info("Using fallback method to extract resources")
    
    # Very simple pattern matching for common resources
    resources = []
    
    # Look for S3 buckets - common pattern is "bucket name" or "s3 bucket name"
    s3_matches = re.findall(r'(?:s3|bucket)[:\s]+([a-z0-9.-]+)', justification.lower())
    for match in s3_matches:
        resources.append({
            "resource_name": match,
            "possible_types": ["s3"],
            "access_level": "read",  # Default to read as it's safer
            "confidence": "medium"
        })
    
    # Look for tables - could be DynamoDB or RDS
    table_matches = re.findall(r'(?:table|db|database)[:\s]+([a-zA-Z0-9_-]+)', justification.lower())
    for match in table_matches:
        resources.append({
            "resource_name": match,
            "possible_types": ["dynamodb", "rds"],
            "access_level": "read",  # Default to read as it's safer
            "confidence": "low"
        })
    
    return resources

def generate_terraform_code(resource, role_name):
    """
    Generate Terraform code to grant a role access to a resource
    Uses OpenAI to generate the code instead of hardcoded templates
    
    Args:
        resource (dict): The resource details including name, type, and access level
        role_name (str): The name of the role to grant access to
        
    Returns:
        str: The generated Terraform code
    """
    # Load the prompt from YAML file
    prompt_config = load_prompt("terraform_generation")
    
    if not prompt_config or "system" not in prompt_config:
        logger.error("Could not load terraform generation prompt from prompts.yaml")
        # Fall back to a simple template
        return f"""
# Could not generate detailed Terraform code - missing prompt
# Resource: {resource['resource_name']}
# Role: {role_name}
# Please implement the appropriate permissions manually
"""
    
    # Get the access level (read or read-write)
    access_level = resource.get('access_level', 'read')
    
    # Get the service type(s)
    service_type = None
    if 'resolved_type' in resource:
        service_type = resource['resolved_type']
    elif 'possible_types' in resource and resource['possible_types']:
        if len(resource['possible_types']) == 1:
            service_type = resource['possible_types'][0]
        else:
            service_type = resource['possible_types'][0]
            logger.warning(f"Ambiguous resource type for {resource['resource_name']}, using {service_type}")
    
    if not service_type:
        logger.error(f"Could not determine resource type for {resource['resource_name']}")
        return f"""
# Cannot generate Terraform: unknown resource type
# Resource: {resource['resource_name']}
# Please specify the resource type manually
"""
    
    # Get the ARN if available
    arn = None
    if 'resolved_arns' in resource and service_type in resource['resolved_arns']:
        arn = resource['resolved_arns'][service_type]
    else:
        # Create a generic ARN
        if service_type == 's3':
            arn = f"arn:aws:s3:::{resource['resource_name']}"
        else:
            arn = f"arn:aws:{service_type}:REGION:ACCOUNT_ID:{resource['resource_name']}"
        logger.warning(f"No ARN available for {resource['resource_name']}, using placeholder: {arn}")
    
    # Prepare the request to OpenAI
    try:
        # Format the system prompt with the resource details
        system_prompt = prompt_config["system"].format(
            resource_name=resource['resource_name'],
            resource_type=service_type,
            access_level=access_level,
            role_name=role_name,
            resource_arn=arn
        )
        
        # Set up the OpenAI client
        client = openai.OpenAI(
            api_key=os.environ.get('OPENAI_API_KEY')
        )
        
        # Create the completion using the ChatCompletion API
        response = client.chat.completions.create(
            model=os.environ.get('OPENAI_MODEL', 'gpt-3.5-turbo'),
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Generate Terraform code for {access_level} access to {service_type} resource '{resource['resource_name']}' for role '{role_name}'"}
            ],
            temperature=0.1,  # Low temperature for more deterministic outputs
            max_tokens=1000
        )
        
        # Extract the content from the response
        content = response.choices[0].message.content
        
        # Find the Terraform code part in the response (usually in a code block)
        terraform_match = re.search(r'```(?:terraform|hcl)?\s*(.*?)\s*```', content, re.DOTALL)
        if terraform_match:
            terraform_code = terraform_match.group(1).strip()
        else:
            # If no code block, use the entire content
            terraform_code = content.strip()
        
        # Add a header comment to indicate this was generated
        terraform_code = f"""
# Generated by PermissionPasta using AI
# Grants {role_name} {access_level} access to {resource['resource_name']} ({service_type})
# Resource ARN: {arn}

{terraform_code}
"""
        
        return terraform_code
        
    except Exception as e:
        logger.error(f"Error generating Terraform with OpenAI: {e}")
        # Return an error message instead of generating fallback code
        return f"""
# Error generating Terraform code with AI: {str(e)}
# Resource: {resource['resource_name']} ({service_type})
# Role: {role_name}
# Access Level: {access_level}
# Resource ARN: {arn}
#
# Please implement the appropriate permissions manually by creating:
# - An IAM policy for {role_name} 
# - With appropriate {access_level} permissions to the resource
""" 