#!/usr/bin/env python3
import os
import logging
from typing import List, Dict, Any, Optional

def gather_terraform_files(terraform_path: str, filename_filter: Optional[List[str]] = None) -> str:
    """
    Recursively gather all Terraform files (.tf) from the specified path
    and combine their contents into a single string formatted for LLM analysis.
    
    Args:
        terraform_path: Path to the directory containing Terraform files
        filename_filter: Optional list of exact filenames to include. If provided,
                         only files with names matching this list will be processed.
        
    Returns:
        A string containing the combined contents of all Terraform files
    """
    logging.info(f"Gathering Terraform files from: {terraform_path}")
    
    if not os.path.exists(terraform_path):
        logging.error(f"Terraform path does not exist: {terraform_path}")
        return ""
    
    if not os.path.isdir(terraform_path):
        logging.error(f"Terraform path is not a directory: {terraform_path}")
        return ""
    
    combined_content = "# TERRAFORM INFRASTRUCTURE ANALYSIS\n\n"
    file_count = 0
    
    """
    # Walk through the directory and its subdirectories
    for root, _, files in os.walk(terraform_path):
        for file in files:
            if file.endswith('.tf'):
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, terraform_path)
                
                try:
                    with open(file_path, 'r') as f:
                        file_content = f.read()
                    
                    # Format file content with clear markdown-style headers
                    combined_content += f"## FILE: {relative_path}\n\n"
                    combined_content += "```hcl\n"  # Use HCL syntax highlighting
                    combined_content += file_content.strip()
                    combined_content += "\n```\n\n"
                    
                    file_count += 1
                    logging.debug(f"Added Terraform file: {relative_path}")
                except Exception as e:
                    logging.error(f"Error reading file {file_path}: {e}")
    """

    # Only process files in the top-level directory, not subdirectories
    for file in os.listdir(terraform_path):
        # Only process .tf files that start with "role-" or "policies-"
        # If filename_filter is provided, only include files that match exactly
        if file.endswith('.tf') and (file.startswith('role-') or file.startswith('policies-') or 'iam' in file):
            if filename_filter and file not in filename_filter:
                continue
                
            file_path = os.path.join(terraform_path, file)
            
            # Skip if it's not a file (e.g., a directory)
            if not os.path.isfile(file_path):
                continue
                
            try:
                with open(file_path, 'r') as f:
                    file_content = f.read()
                
                # Format file content with clear markdown-style headers
                combined_content += f"## FILE: {file}\n\n"
                combined_content += "```hcl\n"  # Use HCL syntax highlighting
                combined_content += file_content.strip()
                combined_content += "\n```\n\n"
                
                file_count += 1
                logging.debug(f"Added Terraform file: {file}")
            except Exception as e:
                logging.error(f"Error reading file {file_path}: {e}")
    
    # Add summary information
    combined_content += f"## SUMMARY\n\n"
    combined_content += f"Total Terraform files processed: {file_count}\n"
    
    logging.info(f"Gathered {file_count} Terraform files")
    
    return combined_content