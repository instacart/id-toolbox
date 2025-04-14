import json
import logging
from utils import safe_get

logger = logging.getLogger('permissionpasta')

def display_results(resources, roles_with_access, user_roles, recommendations, output_format="text", aws_available=False, veza_available=False, show_machine_roles=False):
    """
    Display the analysis results
    
    Args:
        resources (list): List of resources identified
        roles_with_access (dict): Dictionary mapping resource names to a dict with 'human_roles' and 'machine_roles'
        user_roles (list): List of roles the user has access to
        recommendations (list): List of recommendations
        output_format (str): Output format ("text" or "json")
        aws_available (bool): Whether AWS session is available
        veza_available (bool): Whether Veza integration is available and active
        show_machine_roles (bool): Whether to show machine roles details in the output
    """
    if output_format == "json":
        # Output JSON format
        result = {
            "identified_resources": resources,
            "roles_with_access": roles_with_access,
            "user_current_roles": user_roles,
            "recommendations": recommendations,
            "aws_available": aws_available,
            "veza_available": veza_available,
            "show_machine_roles": show_machine_roles
        }
        print(json.dumps(result, indent=2))
    else:
        # Output text format
        print("\n=== PermissionPasta Analysis Results ===\n")
        
        # Resources
        print("Identified Resources:")
        if not resources:
            print("  No AWS resources were identified in the justification.")
        else:
            for i, resource in enumerate(resources, 1):
                print(f"  {i}. Resource: {safe_get(resource, 'resource_name', 'Unknown resource')}")
                print(f"     Possible types: {', '.join(safe_get(resource, 'possible_types', []))}")
                print(f"     Access level: {safe_get(resource, 'access_level', 'read')}")
                
                # Show if the resource exists for each type
                if 'resolved_arns' in resource:
                    print(f"     Verification status:")
                    if aws_available:
                        for service_type, arn in resource['resolved_arns'].items():
                            if arn:
                                exists = safe_get(resource, 'exists', False)
                                # Check if any of the user's roles have access to this resource
                                user_has_access = False
                                if user_roles and resource['resource_name'] in roles_with_access:
                                    for role_name in user_roles:
                                        # Check if this user role is in the human roles with access for this resource
                                        human_roles = roles_with_access.get(resource['resource_name'], {}).get('human_roles', [])
                                        for role in human_roles:
                                            if safe_get(role, 'role_name') == role_name:
                                                user_has_access = True
                                                break
                                        if user_has_access:
                                            break
                                
                                if exists:
                                    if user_has_access:
                                        status = "VERIFIED - Resource exists and is accessible by the user"
                                    else:
                                        status = "VERIFIED - Resource exists but is NOT accessible by the user"
                                    print(f"       - {service_type}: {status}")
                                else:
                                    # Updated message to be clearer about access vs existence
                                    status = "NOT VERIFIED - Resource not found or not accessible with current credentials"
                                    print(f"       - {service_type}: {status}")
                                print(f"         ARN: {arn}")
                    else:
                        print(f"       Resource verification skipped - AWS session not active")
                        if 'resolved_arns' in resource and resource['resolved_arns']:
                            print(f"       Placeholder ARNs generated:")
                            for service_type, arn in resource['resolved_arns'].items():
                                print(f"         - {service_type}: {arn}")
                else:
                    print(f"     Status: Resource verification not attempted")
        
        # Roles with access
        print("\nRoles with access to resources:")
        if not roles_with_access:
            if aws_available:
                print("  No roles with access were found. The resources may not exist or could not be verified.")
                print("  Try running with a different AWS profile or check resource names in your justification.")
            else:
                print("  No role information available. AWS session is not active.")
                print("  To check role information, run without the --no-aws flag and ensure AWS credentials are configured.")
        else:
            for resource_name, role_data in roles_with_access.items():
                # Validate role data structure
                if not isinstance(role_data, dict):
                    print(f"  For {resource_name}: Invalid role data format")
                    continue
                
                human_roles = role_data.get('human_roles', [])
                if not isinstance(human_roles, list):
                    human_roles = []
                
                machine_roles = role_data.get('machine_roles', [])
                if not isinstance(machine_roles, list):
                    machine_roles = []
                
                if not human_roles and not machine_roles:
                    print(f"  For {resource_name}: No roles with access found")
                    continue
                
                print(f"  For {resource_name}:")
                
                # Human roles section
                if human_roles:
                    admin_roles = [r for r in human_roles if safe_get(r, 'is_admin', False)]
                    non_admin_roles = [r for r in human_roles if not safe_get(r, 'is_admin', False)]
                    
                    print("    Human roles with access:")
                    
                    if non_admin_roles:
                        print("      Non-admin roles:")
                        for role in non_admin_roles:
                            access_vector = safe_get(role, 'access_vector', '')
                            
                            # If we have detailed information from Veza, show it
                            if access_vector:
                                print(f"        - {safe_get(role, 'role_name', 'unknown role')} (Access via: {access_vector})")
                            else:
                                print(f"        - {safe_get(role, 'role_name', 'unknown role')}")
                    else:
                        print("      No non-admin human roles found with access")
                    
                    if admin_roles:
                        print("      Admin roles (not recommended):")
                        for role in admin_roles:
                            access_vector = safe_get(role, 'access_vector', '')
                            
                            # If we have detailed information from Veza, show it
                            if access_vector:
                                print(f"        - {safe_get(role, 'role_name', 'unknown role')} (Access via: {access_vector})")
                            else:
                                print(f"        - {safe_get(role, 'role_name', 'unknown role')}")
                else:
                    print("    No human roles found with access")
                
                # Machine roles section
                if machine_roles:
                    if show_machine_roles:
                        # Show machine roles details if flag is set
                        admin_roles = [r for r in machine_roles if safe_get(r, 'is_admin', False)]
                        non_admin_roles = [r for r in machine_roles if not safe_get(r, 'is_admin', False)]
                        
                        print("    Machine roles with access:")
                        
                        if non_admin_roles:
                            print("      Non-admin machine roles:")
                            for role in non_admin_roles:
                                access_vector = safe_get(role, 'access_vector', '')
                                
                                if access_vector:
                                    print(f"        - {safe_get(role, 'role_name', 'unknown role')} (Access via: {access_vector})")
                                else:
                                    print(f"        - {safe_get(role, 'role_name', 'unknown role')}")
                        else:
                            print("      No non-admin machine roles found with access")
                        
                        if admin_roles:
                            print("      Admin machine roles (not recommended):")
                            for role in admin_roles:
                                access_vector = safe_get(role, 'access_vector', '')
                                
                                if access_vector:
                                    print(f"        - {safe_get(role, 'role_name', 'unknown role')} (Access via: {access_vector})")
                                else:
                                    print(f"        - {safe_get(role, 'role_name', 'unknown role')}")
                    else:
                        # Just show count if flag is not set
                        machine_count = len(machine_roles)
                        print(f"    Machine roles: {machine_count} roles have access (details hidden)")
                        print("    Run with '--show-machine-roles' flag to view machine role details")
                else:
                    print("    No machine roles found with access")
        
        # User's current roles
        if user_roles:
            print("\nUser's current roles:")
            for role in user_roles:
                print(f"  - {role}")
        else:
            print("\nUser's current roles: None or not available")
        
        # Recommendations
        print("\nRecommendations:")
        if not recommendations:
            print("  No recommendations available.")
        else:
            for i, rec in enumerate(recommendations, 1):
                print(f"  {i}. {safe_get(rec, 'recommendation', 'No recommendation details')}")
                if safe_get(rec, 'details'):
                    print(f"     {rec['details']}")
                if safe_get(rec, 'action') == 'terraform' and safe_get(rec, 'terraform_code'):
                    print(f"\n     Terraform Code Snippet:")
                    print(f"     ```")
                    for line in rec['terraform_code'].split('\n'):
                        print(f"     {line}")
                    print(f"     ```")
                elif safe_get(rec, 'action') == 'manual' and safe_get(rec, 'terraform_code'):
                    print(f"\n     Error Information:")
                    for line in rec['terraform_code'].split('\n'):
                        print(f"     {line}")
                if safe_get(rec, 'pr_url'):
                    print(f"\n     Pull Request: {rec['pr_url']}")
        
        # Footer with status
        print("\n=== End of Analysis ===")
        if not aws_available:
            print("\nAnalysis Mode: OFFLINE (No AWS session)")
            print("- Resource verification was skipped")
            print("- Role access checks were skipped")
            print("- Terraform code was generated with placeholder ARNs")
            if user_roles:
                print("- User role lookup was performed via Okta integration")
                print("- Resource accessibility for user roles could not be verified (requires AWS session)")
            else:
                print("- User role lookup was skipped")
            print("\nFor complete functionality, configure AWS credentials and run without --no-aws flag.")
        else:
            if veza_available:
                print("\nAnalysis Mode: ONLINE (AWS + Veza)")
                print("- Resources were validated against AWS")
                print("- Role access information was retrieved using Veza integration")
                if show_machine_roles:
                    print("- Showing both human and machine roles with access")
                else:
                    print("- Showing human roles with access (machine roles counted but details hidden)")
                    print("- Use --show-machine-roles flag to see machine role details")
                if not roles_with_access or all(not role_data.get('human_roles', []) and not role_data.get('machine_roles', []) for role_data in roles_with_access.values()):
                    print("- No roles with access were found for the identified resources")
                else:
                    print("- Role permissions include additional detail from Veza (access vector)")
            elif not roles_with_access or all(not role_data.get('human_roles', []) and not role_data.get('machine_roles', []) for role_data in roles_with_access.values()):
                print("\nAnalysis Mode: ONLINE (AWS session active)")
                print("- Resources were validated against AWS but no roles with access were found")
                if user_roles:
                    print("- User role lookup was performed successfully")
                    print("- None of the user's roles have access to the identified resources")
                else:
                    print("- User role lookup was attempted but found no roles")
                print("- This may be because resources exist but couldn't be accessed with current credentials")
                print("\nConsider trying a different AWS profile with more permissions.")
            else:
                print("\nAnalysis Mode: ONLINE (AWS session active)")
                print("- Resources were validated against AWS")
                print("- Role access checks were performed using AWS IAM policy analysis")
                if show_machine_roles:
                    print("- Showing both human and machine roles with access")
                else:
                    print("- Showing human roles with access (machine roles counted but details hidden)")
                    print("- Use --show-machine-roles flag to see machine role details")
                if user_roles:
                    # Check if any user role has access to any resource
                    user_has_access_to_any = False
                    for resource_name, role_data in roles_with_access.items():
                        human_roles = role_data.get('human_roles', [])
                        for role in human_roles:
                            if safe_get(role, 'role_name') in user_roles:
                                user_has_access_to_any = True
                                break
                        if user_has_access_to_any:
                            break
                    
                    if user_has_access_to_any:
                        print("- User role lookup was performed successfully")
                        print("- At least one of the user's roles has access to the identified resources")
                    else:
                        print("- User role lookup was performed successfully")
                        print("- None of the user's roles have access to the identified resources")
                else:
                    print("- User role lookup was attempted but found no roles") 