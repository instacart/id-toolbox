import os
import re
import string
import random
import requests
from typing import Dict, Any

# GitHub API configuration
GITHUB_API_BASE = os.getenv("GITHUB_API_BASE") or "https://api.github.com"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO_OWNER = os.getenv("GITHUB_REPO_OWNER")
REPO_NAME = os.getenv("GITHUB_REPO_NAME")
REPO_BASE_BRANCH = os.getenv("GITHUB_REPO_BASE_BRANCH")

GITHUB_HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

def create_github_pr(role_name: str, file_content: str, file_path: str, commit_message: str, pr_title: str, pr_description: str, draft: bool = False) -> Dict[str, Any]:
    """
    Creates a new branch, commits a file, and opens a pull request in the GitHub repository.
    
    Args:
        role_name (str): Name of the role to be updated
        file_content (str): Content of the file to be created or updated
        file_path (str): Path where the file should be created/updated in the repository
        commit_message (str): Message for the commit
        pr_title (str): Title for the pull request
        pr_description (str): Description for the pull request
        draft (bool): Whether to create a draft PR (default: False)
        
    Returns:
        Dict[str, Any]: Response from the pull request creation API
    """
    # Step 1: Get the latest commit SHA from the base branch
    base_branch_url = f"{GITHUB_API_BASE}/repos/{REPO_OWNER}/{REPO_NAME}/git/ref/heads/{REPO_BASE_BRANCH}"
    base_branch_response = requests.get(base_branch_url, headers=GITHUB_HEADERS)
    base_branch_response.raise_for_status()
    base_commit_sha = base_branch_response.json()["object"]["sha"]
    
    # Step 2: Get the base tree SHA
    base_commit_url = f"{GITHUB_API_BASE}/repos/{REPO_OWNER}/{REPO_NAME}/git/commits/{base_commit_sha}"
    base_commit_response = requests.get(base_commit_url, headers=GITHUB_HEADERS)
    base_commit_response.raise_for_status()
    base_tree_sha = base_commit_response.json()["tree"]["sha"]
    
    # Step 3: Create a new blob with the file content
    blob_url = f"{GITHUB_API_BASE}/repos/{REPO_OWNER}/{REPO_NAME}/git/blobs"
    blob_payload = {
        "content": file_content,
        "encoding": "utf-8"
    }
    blob_response = requests.post(blob_url, headers=GITHUB_HEADERS, json=blob_payload)
    blob_response.raise_for_status()
    blob_sha = blob_response.json()["sha"]
    
    # Step 4: Create a new tree with the new blob
    tree_url = f"{GITHUB_API_BASE}/repos/{REPO_OWNER}/{REPO_NAME}/git/trees"
    tree_payload = {
        "base_tree": base_tree_sha,
        "tree": [
            {
                "path": file_path,
                "mode": "100644",  # File mode (100644 for file)
                "type": "blob",
                "sha": blob_sha
            }
        ]
    }
    tree_response = requests.post(tree_url, headers=GITHUB_HEADERS, json=tree_payload)
    tree_response.raise_for_status()
    new_tree_sha = tree_response.json()["sha"]
    
    # Step 5: Create a new commit
    commit_url = f"{GITHUB_API_BASE}/repos/{REPO_OWNER}/{REPO_NAME}/git/commits"
    commit_payload = {
        "message": commit_message,
        "tree": new_tree_sha,
        "parents": [base_commit_sha]
    }
    commit_response = requests.post(commit_url, headers=GITHUB_HEADERS, json=commit_payload)
    commit_response.raise_for_status()
    new_commit_sha = commit_response.json()["sha"]
    
    # Step 6: Create a new branch with a random name
    branch_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    role_name_lower = role_name.lower()
    new_branch_name = f"role-engineer-pr-{role_name_lower}-{branch_suffix}"
    refs_url = f"{GITHUB_API_BASE}/repos/{REPO_OWNER}/{REPO_NAME}/git/refs"
    branch_payload = {
        "ref": f"refs/heads/{new_branch_name}",
        "sha": new_commit_sha
    }
    branch_response = requests.post(refs_url, headers=GITHUB_HEADERS, json=branch_payload)
    branch_response.raise_for_status()
    
    # Step 7: Create a pull request
    pr_url = f"{GITHUB_API_BASE}/repos/{REPO_OWNER}/{REPO_NAME}/pulls"
    pr_payload = {
        "title": pr_title,
        "body": pr_description,
        "head": new_branch_name,
        "base": REPO_BASE_BRANCH,
        "draft": draft
    }
    pr_response = requests.post(pr_url, headers=GITHUB_HEADERS, json=pr_payload)
    pr_response.raise_for_status()

    
    return pr_response.json()

# Example usage:
# pr_result = create_github_pr(
#     file_content="# New File\nThis is a test file created via the GitHub API.",
#     file_path="docs/test-file.md",
#     commit_message="Add test file via API",
#     pr_title="Add new test documentation file",
#     pr_description="This PR adds a new test documentation file created programmatically.",
#     draft=True  # Create as draft PR
# )
# print(f"Draft pull request created: {pr_result['html_url']}")
