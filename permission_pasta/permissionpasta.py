#!/usr/bin/env python3

"""
PermissionPasta: AWS Access Path Analyzer

This script helps determine the appropriate access path for AWS resources:
1. Analyzes business justification for resource access
2. Identifies resources mentioned in the justification
3. Determines existing roles with access to those resources
4. Recommends the least-privileged way to grant access
5. Can generate Terraform code for appropriate access when needed
"""

import os
import sys
import json
import logging
import argparse
from dotenv import load_dotenv

# Import utility modules
from utils import safe_get, validate_environment
from aws_utils import initialize_aws_session, resolve_resource_arns, find_roles_with_resource_access
from okta_utils import get_user_current_roles
from ai_utils import extract_resources_from_justification_ai, generate_terraform_code
from github_utils import create_github_pr
from display_utils import display_results

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('permissionpasta')

# Load environment variables from .env file if it exists
load_dotenv()

def parse_args():
    """
    Parse command line arguments
    """
    parser = argparse.ArgumentParser(description="PermissionPasta: An AI-driven AWS IAM permission generator")
    
    # General script behavior
    parser.add_argument('--interactive', action='store_true', help='Run in interactive mode, prompting for inputs')
    parser.add_argument('--example', action='store_true', help='Run with example justification for demonstration')
    parser.add_argument('--no-aws', action='store_true', help='Skip AWS validation (can still generate Terraform)')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--output', choices=['text', 'json'], default='text', help='Output format (default: text)')
    
    # Direct inputs for non-interactive use
    parser.add_argument('--user', help='AWS username to check')
    parser.add_argument('--justification', help='Description of the resource access needed')
    parser.add_argument('--role', help='Specific role to add permissions to')
    
    # PR creation
    parser.add_argument('--create-pr', action='store_true', help='Create GitHub PR with Terraform changes')
    
    # Veza integration
    parser.add_argument('--use-veza', action='store_true', 
                      help='Prefer Veza for role access evaluation (requires VEZA_API_KEY and VEZA_ENDPOINT env vars)')
    
    # Machine roles display
    parser.add_argument('--show-machine-roles', action='store_true',
                      help='Show details for machine roles along with human roles')
    
    return parser.parse_args()

def prompt_for_input():
    """Prompt the user for input in interactive mode"""
    print("\n=== PermissionPasta - Interactive Mode ===\n")
    print("This mode allows you to analyze AWS resource access permissions")
    print("Enter information below or leave blank where not applicable\n")
    
    try:
        user = input("Username (leave blank if unknown): ").strip()
        requested_role = input("Requested role (leave blank if unknown): ").strip()
        
        print("\nPlease provide a business justification for the requested access.")
        print("Be specific about which AWS resources you need to access and why.")
        print("Example: \"I need to read data from the customer-data S3 bucket for analysis\"")
        
        justification = ""
        while not justification:
            justification = input("\nJustification: ").strip()
            if not justification:
                print("Justification cannot be empty. Please provide a brief explanation.")
        
        print("\nAnalyzing your request...")
        
        return {
            "user": user if user else None,
            "requested_role": requested_role if requested_role else None,
            "justification": justification
        }
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user. Exiting.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error during input: {e}")
        print("\nAn error occurred while processing your input.")
        sys.exit(1)

def main():
    """Main function"""
    try:
        # Step 1: Parse command line arguments first to check for interactive mode
        args = parse_args()
        
        # Step 2: Validate environment variables, but be more lenient in interactive mode
        validate_environment(interactive_mode=args.interactive)
        
        # Step 3: Get input - either from args, example, or interactive mode
        if args.example:
            # Use an example justification
            user = "example-user"
            requested_role = "developer-data"
            justification = "I need access to the Cost and Usage S3 bucket to analyze our AWS spending patterns."
            print(f"\nUsing example justification: '{justification}'")
        elif args.interactive:
            inputs = prompt_for_input()
            user = inputs["user"]
            requested_role = inputs["requested_role"]
            justification = inputs["justification"]
        else:
            user = args.user
            requested_role = args.role
            justification = args.justification
        
        # Validate that we have a justification
        if not justification:
            logger.error("No justification provided. Please provide a business justification.")
            sys.exit(1)
        
        # Step 4: Extract resources from justification using AI
        # This doesn't require AWS, so do it before AWS initialization
        logger.info("Analyzing justification for AWS resources...")
        identified_resources = extract_resources_from_justification_ai(justification)
        
        if not identified_resources:
            logger.warning("No AWS resources were identified in the justification.")
            print("\nNo AWS resources were identified in your justification. Please provide more specific information about which AWS resources you need access to.")
            sys.exit(0)
        
        # Print identified resources before AWS initialization
        print("\nIdentified resources from your justification:")
        for i, resource in enumerate(identified_resources, 1):
            resource_name = resource.get('resource_name', 'Unknown resource')
            resource_types = ', '.join(resource.get('possible_types', ['unknown']))
            access_level = resource.get('access_level', 'read')
            print(f"  {i}. {resource_name} ({resource_types}) - {access_level} access")
        print()
        
        # Initialize AWS related variables with defaults
        roles_with_access = {}  # Initialize the dictionary to store roles with access to resources
        user_roles = []
        aws_available = False
        veza_available = False
        
        # Check for Veza availability if requested
        if args.use_veza and not args.no_aws:
            try:
                from veza_utils import initialize_veza_connection
                veza_connection = initialize_veza_connection()
                if veza_connection:
                    veza_available = True
                    print("\nVeza integration is enabled for role access evaluation.")
                    logger.info("Veza integration enabled for role access evaluation")
                else:
                    print("\nVeza integration was requested but could not be initialized.")
                    print("Falling back to AWS IAM policy analysis for role access evaluation.")
                    logger.warning("Veza integration requested but not available, falling back to AWS IAM policy analysis")
            except ImportError:
                print("\nVeza integration was requested but the module could not be imported.")
                print("Falling back to AWS IAM policy analysis for role access evaluation.")
                logger.warning("Veza utils module could not be imported, falling back to AWS IAM policy analysis")
            except Exception as e:
                print(f"\nError initializing Veza: {e}")
                print("Falling back to AWS IAM policy analysis for role access evaluation.")
                logger.error(f"Error initializing Veza: {e}")
        
        # Step 5: Initialize AWS session (skip if --no-aws was specified)
        if args.no_aws:
            logger.info("Skipping AWS authentication (--no-aws specified)")
            print("\nRunning in offline mode (no AWS authentication)")
            print("Resource validation and role lookup will be skipped.\n")
        else:
            # This might fail in interactive mode if AWS isn't configured
            logger.info("Initializing AWS session...")
            aws_session = initialize_aws_session()
            
            # Check if we have a valid AWS session by trying a simple STS operation
            try:
                # Simple test to see if we have valid credentials
                aws_session.client('sts').get_caller_identity()
                aws_available = True
                logger.info("AWS session is valid, proceeding with AWS operations")
            except Exception as e:
                logger.warning(f"AWS session is not fully functional: {e}")
                if args.interactive:
                    print("\nAWS credentials are not properly configured or accessible.")
                    print("Continuing in offline mode with limited functionality.")
                    print("Resource validation and role lookup will be skipped.\n")
                else:
                    logger.error("AWS credentials are required in non-interactive mode.")
                    sys.exit(1)
        
        # Step 6-8: AWS operations (only if AWS is available)
        if aws_available:
            try:
                # Step 6: Resolve resource ARNs
                logger.info("Validating resources against AWS...")
                identified_resources = resolve_resource_arns(aws_session, identified_resources)
                
                # Step 7: For each resource, find roles with access
                if veza_available:
                    logger.info("Finding roles with access to identified resources using Veza...")
                    print("Using Veza to find roles with access to identified resources...")
                else:
                    logger.info("Finding roles with access to identified resources using AWS IAM policy analysis...")
                
                for resource in identified_resources:
                    resource_name = resource['resource_name']
                    roles_with_access[resource_name] = {}
                    
                    # Check each possible resource type
                    for service_type, arn in resource.get('resolved_arns', {}).items():
                        if arn:
                            # Find roles with access to this resource
                            role_access = find_roles_with_resource_access(
                                aws_session, 
                                arn, 
                                service_type
                            )
                            
                            # Add debugging for the role_access data structure
                            logger.info(f"Role access result type: {type(role_access)}")
                            if role_access:
                                logger.info(f"Role access keys: {list(role_access.keys()) if isinstance(role_access, dict) else 'not a dict'}")
                            
                            # Add to the roles_with_access dictionary
                            if role_access and (role_access.get('human_roles') or role_access.get('machine_roles')):
                                human_roles_count = len(role_access.get('human_roles', []))
                                machine_roles_count = len(role_access.get('machine_roles', []))
                                
                                logger.info(f"Found {human_roles_count} human roles and {machine_roles_count} machine roles with access to {resource_name} ({service_type})")
                                
                                # Ensure the structure exists in the roles_with_access dictionary
                                if resource_name not in roles_with_access:
                                    roles_with_access[resource_name] = {}
                                
                                # Make sure human_roles and machine_roles are properly initialized
                                if 'human_roles' not in roles_with_access[resource_name]:
                                    roles_with_access[resource_name]['human_roles'] = []
                                if 'machine_roles' not in roles_with_access[resource_name]:
                                    roles_with_access[resource_name]['machine_roles'] = []
                                
                                # More defensive code with detailed error logging
                                try:
                                    # Add human roles using a for loop to avoid extend issues
                                    if 'human_roles' in role_access and isinstance(role_access['human_roles'], list):
                                        for role in role_access['human_roles']:
                                            roles_with_access[resource_name]['human_roles'].append(role)
                                    else:
                                        logger.warning(f"Missing or invalid 'human_roles' in role_access for {resource_name}")
                                        
                                    # Add machine roles using a for loop to avoid extend issues
                                    if 'machine_roles' in role_access and isinstance(role_access['machine_roles'], list):
                                        for role in role_access['machine_roles']:
                                            roles_with_access[resource_name]['machine_roles'].append(role)
                                    else:
                                        logger.warning(f"Missing or invalid 'machine_roles' in role_access for {resource_name}")
                                    
                                    # Verify the data was correctly saved
                                    saved_human_count = len(roles_with_access[resource_name].get('human_roles', []))
                                    saved_machine_count = len(roles_with_access[resource_name].get('machine_roles', []))
                                    logger.info(f"Successfully saved {saved_human_count} human roles and {saved_machine_count} machine roles for {resource_name}")
                                    
                                except Exception as role_err:
                                    logger.error(f"Error processing roles for {resource_name}: {role_err}")
                                    logger.error(f"Role access data: {role_access}")
                                    
                                    # Ensure we have valid data structures even if there was an error
                                    if not isinstance(roles_with_access.get(resource_name, {}).get('human_roles'), list):
                                        roles_with_access[resource_name]['human_roles'] = []
                                    if not isinstance(roles_with_access.get(resource_name, {}).get('machine_roles'), list):
                                        roles_with_access[resource_name]['machine_roles'] = []
                            else:
                                logger.info(f"No roles found with access to {resource_name} ({service_type})")
                                
                                # Ensure the structure exists in the roles_with_access dictionary even when no roles are found
                                if resource_name not in roles_with_access:
                                    roles_with_access[resource_name] = {'human_roles': [], 'machine_roles': []}
                                elif not isinstance(roles_with_access[resource_name], dict):
                                    roles_with_access[resource_name] = {'human_roles': [], 'machine_roles': []}
                
                # Step 8: Get user's current roles
                if user:
                    logger.info(f"Getting current roles for user: {user}")
                    user_roles = get_user_current_roles(aws_session, user)
            
            except Exception as aws_err:
                logger.error(f"Error during AWS operations: {aws_err}")
                logger.exception(aws_err)  # Log the full stack trace for better debugging
                
                # Create a sanitized version of roles_with_access with validated structure
                sanitized_roles = {}
                for res_name, roles in roles_with_access.items():
                    sanitized_roles[res_name] = {
                        'human_roles': roles.get('human_roles', []) if isinstance(roles, dict) else [],
                        'machine_roles': roles.get('machine_roles', []) if isinstance(roles, dict) else []
                    }
                
                # Replace the potentially problematic dictionary with the sanitized version
                roles_with_access = sanitized_roles
                
                if args.interactive:
                    print(f"\nAWS operations failed: {aws_err}")
                    print("Continuing with limited functionality.\n")
                else:
                    raise
        
        # Try to get user's Okta roles even if AWS is not available
        elif user and not args.no_aws:
            logger.info(f"AWS not available but attempting to get Okta roles for user: {user}")
            # Pass None for the session since we'll use Okta instead of AWS
            user_roles = get_user_current_roles(None, user)
        
        # Step 9: Generate recommendations (works with or without AWS)
        logger.info("Generating recommendations...")
        recommendations = []
        
        # Generate recommendations based on available information
        for resource in identified_resources:
            resource_name = resource['resource_name']
            service_types = ', '.join(resource.get('possible_types', []))
            access_level = resource.get('access_level', 'read')
            
            # Check if any of the user's roles already have access
            user_has_access = False
            user_access_role = None
            
            if aws_available and user_roles and resource_name in roles_with_access:
                # Check human roles first
                for role in roles_with_access[resource_name].get('human_roles', []):
                    role_name = safe_get(role, 'role_name')
                    if role_name in user_roles:
                        user_has_access = True
                        user_access_role = role_name
                        break
            
            if user_has_access:
                # User already has access via one of their roles
                recommendations.append({
                    'recommendation': f"User already has access to {resource_name}",
                    'details': f"The user already has access to this resource via the {user_access_role} role.",
                    'action': 'existing_access'
                })
                continue
                
            # If we have AWS data on existing roles with access
            if resource_name in roles_with_access:
                # Validate the structure of roles_with_access for this resource
                if not isinstance(roles_with_access[resource_name], dict):
                    logger.warning(f"Invalid structure for roles_with_access['{resource_name}']: {type(roles_with_access[resource_name])}")
                    roles_with_access[resource_name] = {'human_roles': [], 'machine_roles': []}
                
                # Focus on human roles as requested
                human_roles = roles_with_access[resource_name].get('human_roles', [])
                if not isinstance(human_roles, list):
                    logger.warning(f"Invalid human_roles type: {type(human_roles)}, using empty list")
                    human_roles = []
                    
                machine_roles = roles_with_access[resource_name].get('machine_roles', [])
                if not isinstance(machine_roles, list):
                    logger.warning(f"Invalid machine_roles type: {type(machine_roles)}, using empty list")
                    machine_roles = []
                    
                machine_roles_count = len(machine_roles)
                
                if not human_roles and machine_roles_count > 0:
                    logger.info(f"Found {machine_roles_count} machine roles with access to {resource_name}, but focusing on human roles as requested")
                
                # Use safe_get to handle various types of is_admin values
                non_admin_roles = [r for r in human_roles if not safe_get(r, 'is_admin', False)]
                
                if non_admin_roles:
                    # Recommend using an existing non-admin role
                    recommendations.append({
                        'recommendation': f"Use existing role for access to {resource_name}",
                        'details': f"The following non-admin human roles already have access: {', '.join([safe_get(r, 'role_name', 'unknown') for r in non_admin_roles])}",
                        'action': 'use_existing_role'
                    })
                else:
                    # Only admin roles have access, recommend adding to an appropriate existing role or creating new
                    if requested_role:
                        # Generate Terraform code for adding access to requested role
                        terraform_code = generate_terraform_code(resource, requested_role)
                        
                        # Check if the terraform code generation failed
                        if terraform_code and terraform_code.strip().startswith("# Error"):
                            recommendations.append({
                                'recommendation': f"Add access to {resource_name} ({service_types}) to role {requested_role}",
                                'details': f"Terraform code generation failed. Please manually create appropriate {access_level} permissions.",
                                'action': 'manual',
                                'terraform_code': terraform_code
                            })
                        else:
                            recommendations.append({
                                'recommendation': f"Add access to {resource_name} ({service_types}) to role {requested_role}",
                                'details': f"Generate Terraform code to add the minimal required permissions",
                                'action': 'terraform',
                                'terraform_code': terraform_code
                            })
                            
                            # Create PR if requested
                            if args.create_pr and aws_available:
                                try:
                                    pr_url = create_github_pr(resource, requested_role, terraform_code)
                                    recommendations[-1]['pr_url'] = pr_url
                                except Exception as e:
                                    logger.error(f"Failed to create PR: {e}")
            else:
                # If we couldn't check roles or no existing roles have access, provide basic recommendation
                if requested_role:
                    terraform_code = generate_terraform_code(resource, requested_role)
                    
                    # Check if the terraform code generation failed
                    if terraform_code and terraform_code.strip().startswith("# Error"):
                        recommendations.append({
                            'recommendation': f"Add access to {resource_name} ({service_types}) to role {requested_role}",
                            'details': f"Terraform code generation failed. Please manually create appropriate {access_level} permissions.",
                            'action': 'manual',
                            'terraform_code': terraform_code
                        })
                    else:
                        recommendations.append({
                            'recommendation': f"Add access to {resource_name} ({service_types}) to role {requested_role}",
                            'details': f"Generate Terraform code to add {access_level} permissions",
                            'action': 'terraform',
                            'terraform_code': terraform_code
                        })
                        
                        # Create PR if requested
                        if args.create_pr and aws_available:
                            try:
                                pr_url = create_github_pr(resource, requested_role, terraform_code)
                                recommendations[-1]['pr_url'] = pr_url
                            except Exception as e:
                                logger.error(f"Failed to create PR: {e}")
                else:
                    recommendations.append({
                        'recommendation': f"Request access to {resource_name} ({service_types}) via an appropriate role",
                        'details': f"Specify which role should have {access_level} access to this resource.",
                        'action': 'request_role'
                    })
        
        # Step 10: Display results
        display_results(
            identified_resources,
            roles_with_access,
            user_roles,
            recommendations,
            args.output,
            aws_available,
            veza_available,
            args.show_machine_roles  # Pass the new flag to the display function
        )
        
        logger.info("PermissionPasta execution completed")
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(130)  # Standard exit code for SIGINT
    except Exception as e:
        logger.error(f"Unhandled error: {e}")
        if args.interactive:
            print(f"\nAn error occurred: {e}")
            print("Please check your inputs and try again.")
        else:
            # Re-raise in non-interactive mode
            raise

if __name__ == "__main__":
    main()






