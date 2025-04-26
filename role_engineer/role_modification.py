import logging
import json
import boto3
from botocore.exceptions import ClientError
from typing import Dict, List, Set, Any, Tuple, Optional
from datetime import date, timedelta
from llm import LLMClient
from terraform_parser import gather_terraform_files
from github import create_github_pr


def get_policies_for_role(
    iam_client,
    role_name: str,
) -> List[Dict[str, Any]]:
    """
    For a given role, return a list of policy descriptors:
        [
          {
            "PolicyArn": <str or None if inline>,
            "PolicyName": <str>,
            "Document": <the JSON policy doc>,
          },
          ...
        ]
    """
    policy_descriptors = []

    # Inline policies
    inline_policies_resp = iam_client.list_role_policies(RoleName=role_name)
    for policy_name in inline_policies_resp.get("PolicyNames", []):
        policy_doc_resp = iam_client.get_role_policy(
            RoleName=role_name,
            PolicyName=policy_name
        )
        policy_document = policy_doc_resp["PolicyDocument"]
        policy_descriptors.append({
            "PolicyArn": None,
            "PolicyName": policy_name,
            "Document": policy_document,
        })

    # Attached policies
    attached_policies_resp = iam_client.list_attached_role_policies(RoleName=role_name)
    for attached_policy in attached_policies_resp.get("AttachedPolicies", []):
        arn = attached_policy["PolicyArn"]
        pol_name = attached_policy["PolicyName"]

        if arn.startswith("arn:aws:iam::aws:policy/"):
            logging.debug(f"Skipping AWS-managed policy: {arn}")
            continue

        try:
            policy_version = iam_client.get_policy(PolicyArn=arn)
            default_version_id = policy_version["Policy"]["DefaultVersionId"]
            version_resp = iam_client.get_policy_version(
                PolicyArn=arn,
                VersionId=default_version_id
            )
            policy_document = version_resp["PolicyVersion"]["Document"]
            policy_descriptors.append({
                "PolicyArn": arn,
                "PolicyName": pol_name,
                "Document": policy_document,
            })
        except ClientError as e:
            logging.warning(f"Failed to retrieve attached policy version for {arn}: {e}")

    return policy_descriptors


def collect_statements_from_policies(policy_descs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Given a list of policy descriptors, produce a list of statements:
        [
          {
            "PolicyArn": <str or None if inline>,
            "PolicyName": <str>,
            "Sid": <str>,
            "Actions": <set of str>,
          },
          ...
        ]
    """
    statements_list = []
    for desc in policy_descs:
        policy_arn = desc["PolicyArn"]
        policy_name = desc["PolicyName"]
        doc = desc["Document"]

        stmts = doc.get("Statement", [])
        if not isinstance(stmts, list):
            stmts = [stmts]

        for stmt in stmts:
            if stmt.get("Effect") != "Allow":
                continue

            sid = stmt.get("Sid", "(no-sid)")

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            # If the effect is Allow, there is no Action, and there is a NotAction,
            # this is a statement that says "allow everything except the listed actions".
            # For the purposes of this tool, we want to treat this as "allow everything".
            if stmt.get("NotAction") and not stmt.get("Action"):
                actions = ["*"]

            statements_list.append({
                "PolicyArn": policy_arn,
                "PolicyName": policy_name,
                "Sid": sid,
                "Actions": set(actions),
            })

    return statements_list


def flatten_all_actions(statements_list: List[Dict[str, Any]]) -> Set[str]:
    """Return the union of all actions across these statements."""
    all_actions = set()
    for stmt in statements_list:
        all_actions |= stmt["Actions"]
    return all_actions


def create_comment_pr(
    llm: LLMClient,
    role_name: str,
    role_definition_file: str,
    role_definition_file_path: str,
    stmt_list: List[Dict[str, Any]],
    terraform_path: str,
    terraform_content: str,
    days: int
) -> None:
    """
    Create a PR that adds comments to the role definition file about unused permissions.
    
    Args:
        llm: The LLM client to use for generating content
        role_name: The name of the role to analyze
        role_definition_file: The file content that contains the role definition
        role_definition_file_path: The path to the terraform file that contains the role definition
        stmt_list: List of statements with unused actions
        terraform_path: Path to the terraform directory
        terraform_content: Content of all terraform files
        days: Number of days in the lookback period
    """
    current_date_iso = date.today().isoformat()
    lookback_days_ago_iso = (date.today() - timedelta(days=days)).isoformat()
    
    # Format the unused statements for the LLM
    role_unneeded_statements_str = ""
    for stmt in stmt_list:
        policy_arn = stmt["PolicyArn"] or "(inline)"
        sid = stmt["Sid"]
        unused_actions = stmt["UnusedActions"]
        if unused_actions:
            role_unneeded_statements_str += f"  - In the last {days}, these actions from policy '{stmt['PolicyName']}' ARN={policy_arn} SID={sid} were not used:\n"
            for act in unused_actions:
                role_unneeded_statements_str += f"      {act}\n"
    role_unneeded_statements_str += "\n"

    response = llm.complete(
        system="You are an expert in Terraform and AWS IAM. You analyze Terraform files to understand the IAM roles and permissions defined in them. "
        "You respond exactly as instructed. You always check to ensure the resulting HCL code is valid.",
        prompt="Our identity security solution has reported that many IAM policy actions have been unused for the past "
        f"{days} days. Add a new comment above each action block that enumerates the actions that were unused, "
        f"in the format 'These actions were unused between the dates of YYYY-MM-DD and YYYY-MM-DD: action1, action2, action3, ...', "
        f"where the first date is {lookback_days_ago_iso} and the second date is {current_date_iso}. "
        f"There might be previous comments about unused actions already present above the action blocks; preserve those comments. "
        f"Output the entirety of the newly-updated Terraform file(s). "
        f"Leave all comments and other text in the file unchanged. Only comment above the action blocks. Do not remove any Terraform code. "
        f"Do not remove any existing comments.\n\nOutput a JSON object with the key "
        f"'updated_file' and the value being the updated Terraform file. The updated file should be in HCL format and have no markdown or other non-HCL text.\n\n"
        f"The recommendations from our identity security solution are as follows:\n"
        f"```text\n{role_unneeded_statements_str}```\n\n\n"
        f"The Terraform definition of this role is as follows:\n"
        f"```hcl\n{role_definition_file}\n```",
        reasoning_effort="high"
    )
    content = response.get("choices")[0].get("message", {}).get("content")
    json_content = json.loads(content)
    updated_file = json_content.get("updated_file")
    if not updated_file:
        raise Exception("No updated file found")

    pr_result = create_github_pr(
        role_name=role_name,
        file_content=updated_file,
        file_path=f"{role_definition_file_path}",
        commit_message=f"Note unused permissions from {role_name}",
        pr_title=f"Comment on unused permissions from {role_name} role for last {days} days",
        pr_description=f"This PR adds comments (non-functional changes) to the file containing the {role_name} role definition.\n\n"
        f"The {role_name} role has policy statements attached to it that have been unused for the past "
        f"{days} days. Please double-check the suggested removals before merging and use careful judgement. "
        f"The following analysis details the unused policy statements:\n\n"
        f"```text\n{role_unneeded_statements_str}\n```\n\n"
        f"These unused policy statements were fed into an LLM which located and commented on the relevant "
        f"statements from the role definition file.",
        draft=True
    )
    print(f"Pull request created: {pr_result['html_url']}")


def create_remove_pr(
    llm: LLMClient,
    role_name: str,
    role_definition_file: str,
    role_definition_file_path: str,
    stmt_list: List[Dict[str, Any]],
    terraform_path: str,
    terraform_content: str,
    days: int
) -> None:
    """
    Create a PR that removes unused permissions from the role definition file.
    
    Args:
        llm: The LLM client to use for generating content
        role_name: The name of the role to analyze
        role_definition_file: The file content that contains the role definition
        role_definition_file_path: The path to the terraform file that contains the role definition
        stmt_list: List of statements with unused actions
        terraform_path: Path to the terraform directory
        terraform_content: Content of all terraform files
        days: Number of days in the lookback period
    """

    # Format the unused statements for the LLM
    role_unneeded_statements_str = ""
    for stmt in stmt_list:
        policy_arn = stmt["PolicyArn"] or "(inline)"
        sid = stmt["Sid"]
        unused_actions = stmt["UnusedActions"]
        if unused_actions:
            role_unneeded_statements_str += f"  - Remove these actions from policy '{stmt['PolicyName']}' ARN={policy_arn} SID={sid}:\n"
            for act in unused_actions:
                role_unneeded_statements_str += f"      {act}\n"
    role_unneeded_statements_str += "\n"

    """
    response = llm.complete(
        system="You are an expert in Terraform and AWS IAM. You analyze Terraform files to understand the IAM roles and permissions defined in them. "
        "You respond exactly as instructed. You always check to ensure the resulting HCL code is valid.",
        prompt="Determine if any of the recommendations from our identity security "
        "solution can be applied to the Terraform role definition I will provide you. If so, output the entirety of the newly-updated Terraform file(s). "
        "Leave all comments and other text in the file unchanged. Only modify the action blocks. Output a JSON object with the key "
        "'updated_file' and the value being the updated Terraform file. The updated file should be in HCL format and have no markdown or other non-HCL text.\n\n"
        "The recommendations from our identity security solution are as follows:\n"
        f"```text\n{role_unneeded_statements_str}```\n\n"
        f"The Terraform definition of this role is as follows:\n"
        f"```hcl\n{role_definition_file}\n```"
    )
    content = response.get("choices")[0].get("message", {}).get("content")
    json_content = json.loads(content)
    updated_file = json_content.get("updated_file")
    if not updated_file:
        raise Exception("No updated file found")

    # Clean up the updated file to remove empty action blocks
    response = llm.complete(
        system="You are an expert in Terraform and AWS IAM. You analyze Terraform files to understand the IAM roles and permissions defined in them. "
        "You respond exactly as instructed. You always check to ensure the resulting HCL code is valid.",
        prompt="I am providing you a Terraform file which contains a role definition. "
        "Please clean up the file by commenting out any statements that are not needed. You will know "
        "which statements are not needed because their action blocks will be empty. "
        "Above the commented out statements, add a comment that says 'Removed unused permissions from this role' "
        "and the date of the removal in ISO 8601 format. Today is "
        "Leave all comments and other text in the file unchanged. Only modify the 'statement' blocks. "
        "Output a JSON object with the key 'updated_file' and the value being the updated Terraform file. "
        "The updated file should be in HCL format and have no markdown or other non-HCL text.\n\n"
        f"The Terraform definition of this role is as follows:\n"
        f"```hcl\n{updated_file}\n```"
    )
    content = response.get("choices")[0].get("message", {}).get("content")
    json_content = json.loads(content)
    updated_file = json_content.get("updated_file")
    if not updated_file:
        raise Exception("No updated file found")

    # Remove S3 blocks if the s3:ListBucket action is not present anymore (remove the "leftovers")
    # (because if ListBucket isn't being used, the other actions won't be used either)
    response = llm.complete(
        system="You are an expert in Terraform and AWS IAM. You analyze Terraform files to understand the IAM roles and permissions defined in them. "
        "You respond exactly as instructed. You always check to ensure the resulting HCL code is valid.",
        prompt="I am providing you a Terraform file which contains a role definition. "
        "Return a list of 'sid' values for all statements that contain the action s3:GetObject, "
        "s3:PutObject, s3:DeleteObject, s3:Get*, s3:Put*, s3:Delete*, but do not contain the action "
        "s3:ListBucket."
        "Output a JSON object with the key 'sids' and the value being an array of 'sid' values.\n\n"
        f"The Terraform definition of this role is as follows:\n"
        f"```hcl\n{updated_file}\n```"
    )
    content = response.get("choices")[0].get("message", {}).get("content")
    json_content = json.loads(content)
    s3_sids = json_content.get("sids")
    if s3_sids:
        # Remove statements with the given sids
        response = llm.complete(
            system="You are an expert in Terraform and AWS IAM. You analyze Terraform files to understand the IAM roles and permissions defined in them. "
            "You respond exactly as instructed. You always check to ensure the resulting HCL code is valid.",
            prompt="I am providing you a Terraform file which contains a role definition. "
            "Please clean up the file by removing any statements that are not needed and outputting the rest of the file. "
            "You will know which statements are not needed because their 'sid' values will be on the list below. "
            "Leave all comments and other text in the file unchanged. Only remove the 'statement' blocks. "
            "Output a JSON object with the key 'updated_file' and the value being the updated Terraform file. "
            "The updated file should be in HCL format and have no markdown or other non-HCL text.\n\n"
            f"The Terraform definition of this role is as follows:\n"
            f"```hcl\n{updated_file}\n```\n\n"
            f"The 'sid' values of the statements to remove are as follows:\n"
            f"```text\n{s3_sids}\n```"
        )
        content = response.get("choices")[0].get("message", {}).get("content")
        json_content = json.loads(content)
        updated_file = json_content.get("updated_file")
        if not updated_file:
            raise Exception("No updated file found")

    # Ask the LLM to double-check that the removals were done correctly
    response = llm.complete(
        system="You are an expert in Terraform and AWS IAM. You analyze Terraform files to understand the IAM roles and permissions defined in them. "
        "You respond exactly as instructed. You always check to ensure the resulting HCL code is valid.",
        prompt="I am providing you a Terraform file which had permissions removed from it by a novice infrastructure engineer. "
        "Please double-check that the removals were done correctly. "
        "Output a JSON object with the key 'score' and the value being an integer 1 to 10 where 1 "
        "means 'not done correctly' and 10 meaning 'done perfectly correctly'. Also output "
        "a JSON key 'reasoning' and the value being a string that explains your reasoning for the score.\n\n"
        f"The Terraform definition of this role's permissions before the removals were made is as follows:\n"
        f"```hcl\n{role_definition_file}\n```\n\n"
        f"The Terraform definition of this role's permissions after the removals were made is as follows:\n"
        f"```hcl\n{updated_file}\n```\n\n"
        f"The guidance the novice infrastructure engineer received was as follows:\n"
        f"```text\n{role_unneeded_statements_str}\n```"
    )
    content = response.get("choices")[0].get("message", {}).get("content")
    json_content = json.loads(content)
    score = json_content.get("score")
    reasoning = json_content.get("reasoning")
    print(f"Score: {score}")
    print(f"Reasoning: {reasoning}")
    """

    response = llm.complete(
        system="You are an expert in Terraform and AWS IAM. You analyze Terraform files to understand the IAM roles and permissions defined in them. "
        "You respond exactly as instructed. You always check to ensure the resulting HCL code is valid.",
        prompt="Determine if any of the recommendations from our identity security "
        "solution can be applied to the Terraform role definition I will provide you. If so, output the entirety of the newly-updated Terraform file(s). "
        "Leave all comments and other text in the file unchanged. Only modify the statement blocks. "
        "Don't add extraneous information to the file, such as new comments or other text, or alterations to the formatting. "
        "If an action block contains the action s3:ListBucket and you've been told to remove it, also remove all other data-level "
        "S3 actions from that block, like s3:GetObject, s3:PutObject, s3:DeleteObject, etc. If the resulting action block is empty, "
        "remove the entire statement block. Do not add any other text to the file, such as new comments or other text, or alterations to the formatting. "
        "Do not leave comments about what portions you removed. Keep the existing order of the statements in the file.\n\n"
        "Output a JSON object with the key "
        "'updated_file' and the value being the updated Terraform file. The updated file should be in HCL format and have no markdown or other non-HCL text.\n\n"
        "The recommendations from our identity security solution are as follows:\n"
        f"```text\n{role_unneeded_statements_str}```\n\n"
        f"The Terraform definition of this role is as follows:\n"
        f"```hcl\n{role_definition_file}\n```"
    )
    content = response.get("choices")[0].get("message", {}).get("content")
    json_content = json.loads(content)
    updated_file = json_content.get("updated_file")
    if not updated_file:
        raise Exception("No updated file found")

    pr_result = create_github_pr(
        role_name=role_name,
        file_content=updated_file,
        file_path=f"{role_definition_file_path}",
        commit_message=f"Remove unused permissions from {role_name}",
        pr_title=f"Remove unused permissions from {role_name} role",
        pr_description=f"This PR removes unused permissions from the {role_name} role definition. \n\n"
        f"The {role_name} role has policy statements attached to it that have been unused for the past "
        f"{days} days. Please double-check the suggested removals before merging and use careful judgement.\n\n"
        f"WARNING: data-level S3 actions like s3:GetObject, s3:PutObject, s3:DeleteObject, etc do not emit CloudTrail logs. "
        f"This tool infers those actions are not being used by looking to see if s3:ListBucket has been used. "
        f"If s3:ListBucket has not been used, this tool will remove all other S3 actions from the role definition. "
        f"Please be extremely careful and double-check this assumption before merging.\n\n"
        f"The following analysis details the unused policy statements:\n\n"
        f"```text\n{role_unneeded_statements_str}\n```\n\n"
        f"These unused policy statements were fed into an LLM which located and removed the relevant "
        f"statements from the role definition file.",
        draft=True
    )
    print(f"Pull request created: {pr_result['html_url']}")


def analyze_and_modify_roles(
    usage_map: Dict[str, Set[str]],
    role_events_map: Dict[str, List[Dict[str, Any]]],
    action_resources_map: Dict[str, Dict[str, Set[str]]],
    args: Any,
    actions_without_logging: List[str]
) -> None:
    """
    Analyze roles and their policies, then create PRs to modify them based on the analysis.
    
    Args:
        usage_map: A mapping of role ARNs to sets of used IAM actions
        role_events_map: A mapping of role ARNs to lists of event details
        action_resources_map: A mapping of role ARNs to dictionaries mapping actions to sets of resource ARNs
        args: The parsed command-line arguments
        actions_without_logging: A list of IAM actions that don't emit CloudTrail logs
    """
    # Set up structures to hold final results
    role_unneeded_statements = {}
    unmatched_events_per_role = {}

    # For each role in usage_map, retrieve policies and analyze usage
    logging.info("Getting IAM policies...")
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    iam_client = session.client("iam")

    for role_arn, used_actions in usage_map.items():
        role_name = role_arn.split("/")[-1]
        logging.info(f"Analyzing role: {role_arn}")

        # Gather policy descriptors
        try:
            policy_descs = get_policies_for_role(
                iam_client, role_name
            )
        except ClientError as e:
            logging.error(f"Failed to retrieve policies for role {role_name}: {e}")
            continue

        # Collect statements & find all allowed actions
        statements = collect_statements_from_policies(policy_descs)
        all_allowed_actions = flatten_all_actions(statements)
        if not all_allowed_actions:
            logging.error(f"No allowed actions found for role {role_name}. If this "
            "is unexpected, it's likely because the role only has AWS-managed policies "
            "attached to it.")
            continue

        # Identify which actions are unused
        for stmt in statements:
            unused_actions = set()
            for action in stmt["Actions"]:
                # Skip actions that don't emit CloudTrail logs
                if action in actions_without_logging:
                    continue
                    
                if action == "*": 
                    logging.warning(f"Unscoped wildcard action found. This is extremely dangerous and "
                    "should not be used in policy documents. Because the IAM policy does not "
                    "explicitly list actions, this tool will not be able to suggest "
                    "where to reduce permissions.")
                elif "*" in action:
                    # Get the service prefix if it exists (e.g., "s3:" from "s3:*")
                    parts = action.split(":")
                    if len(parts) > 1 and parts[1] == "*":
                        # This is a service-specific wildcard like "s3:*"
                        service_prefix = parts[0] + ":"
                        # Check if any used actions match this service prefix
                        if not any(used_action.startswith(service_prefix) for used_action in used_actions):
                            # Check if any actions without logging match this prefix
                            if not any(no_log_action.startswith(service_prefix) for no_log_action in actions_without_logging):
                                unused_actions.add(action)
                    else:
                        # This is a partial wildcard like "s3:Get*"
                        # Extract the prefix before the wildcard
                        prefix = action.split("*")[0]
                        # Check if any used actions start with this prefix
                        if not any(used_action.startswith(prefix) for used_action in used_actions):
                            # Check if any actions without logging match this prefix
                            if not any(no_log_action.startswith(prefix) for no_log_action in actions_without_logging):
                                unused_actions.add(action)
                elif action not in used_actions:
                    # For non-wildcard actions, directly check if they were used
                    unused_actions.add(action)

            if unused_actions:
                role_unneeded_statements.setdefault(role_name, []).append({
                    "PolicyArn": stmt["PolicyArn"],
                    "PolicyName": stmt["PolicyName"],
                    "Sid": stmt["Sid"],
                    "UnusedActions": sorted(unused_actions),
                })

        # Identify unmatched CloudTrail events
        unique_unmatched = set()
        for entry in role_events_map[role_arn]:
            action_used = entry["mapped_iam_action"]
            event_source = entry["event_source"]
            event_name = entry["event_name"]

            if action_used not in all_allowed_actions:
                prefix = action_used.split(":")[0].lower() + ":"
                wildcard_covered = any(
                    ("*" in pol_action and pol_action.split(":")[0].lower() == prefix[:-1])
                    for pol_action in all_allowed_actions
                )
                if not wildcard_covered:
                    unique_unmatched.add((event_source, event_name, action_used))

        if unique_unmatched:
            unmatched_events_per_role[role_name] = unique_unmatched

    # Output
    print("===== RESULTS =====\n")

    # Show unmatched events
    if unmatched_events_per_role:
        print("===== UNMATCHED EVENTS (Unique) =====\n")
        for role_name, unmatched_set in unmatched_events_per_role.items():
            print(f"Role: {role_name}")
            for (evt_source, evt_name, iam_used) in sorted(unmatched_set):
                print(
                    f"  - Service={evt_source}, EventName={evt_name}, IAMActionUsed={iam_used}"
                )
            print()

    # Analyze Terraform files
    print("===== TERRAFORM ANALYSIS =====\n")
    terraform_content = gather_terraform_files(args.terraform_path)

    # LLM Analysis
    print("===== LLM ANALYSIS =====\n")
    llm = LLMClient()

    for role_name, stmt_list in role_unneeded_statements.items():

        """
        # Get our candidate Terraform files that might contain the role definition
        response = llm.complete(
            system="You are an expert in Terraform and AWS IAM. You analyze Terraform files to understand the IAM roles and permissions defined in them. ",
            prompt="Please determine which of the following Terraform files may contain the role definition "
            f"for the AWS role named '{role_name}'. "
            f"You should determine the file you think is the correct one by looking for a Terraform document with a filename "
            f"that similarly matches the AWS role name I've provided you, or has a resource block that "
            f"contains a name field or filename that similarly matches the AWS role name I've provided you. "
            f"So, since you are looking for the '{role_name}' role, the role is likely defined by a file called "
            f"'role-{role_name.lower()}.tf' or '{role_name.lower()}.tf' and will contain a statement in it "
            f"like 'name = \"{role_name}\"'. "
            f"Respond only in JSON with the JSON key 'candidate_files' and the value being an array of the file names "
            f"that you think may contain the role definition. It's okay to include multiple files in the array, err on the side of caution. "
            f"Also respond with the JSON key 'reasoning' and the value being a short explanation of your reasoning. "
            f"If you cannot determine which file contains the role definition, respond with the JSON key 'candidate_files' and the value being null.\n\n"
            f"The Terraform content is as follows:\n{terraform_content}"
        )
        content = response.get("choices")[0].get("message", {}).get("content")
        json_content = json.loads(content)
        candidate_files = json_content.get("candidate_files")
        reasoning = json_content.get("reasoning")
        print(f"Candidate files: {candidate_files}" )
        print(f"Reasoning: {reasoning}")
        """

        # Now do a second pass to verify if one of the candidate files is the correct one
        #filtered_terraform_content = gather_terraform_files(args.terraform_path, candidate_files)
        response = llm.complete(
            system="You are an expert in Terraform and AWS IAM. You analyze Terraform files to understand the IAM roles and permissions defined in them. ",
            prompt="Please determine which of the following Terraform files likely contains the role definition "
            f"for the AWS role named '{role_name}'. "
            f"You should verify the role you think is the correct one is proper by looking for a resource block that "
            f"contains a name field that exactly matches the AWS role name I've provided you. "
            f"So, since you are looking for the '{role_name}' role, the role is likely defined by a file called "
            f"'role-{role_name.lower()}.tf' or '{role_name.lower()}.tf' and will contain a statement in it "
            f"like 'name = \"{role_name}\"' where the name is an EXACT match. "
            f"Respond only in JSON with the JSON key 'file' and the value being the file name. "
            f"Also respond with the JSON key 'reasoning' and the value being a short explanation of your reasoning. "
            f"If you cannot determine which file contains the role definition, respond with the JSON key 'file' and the value being null. "
            #f"The Terraform content is as follows:\n{filtered_terraform_content}"
            f"The Terraform content is as follows:\n{terraform_content}"
        )
        content = response.get("choices")[0].get("message", {}).get("content")
        json_content = json.loads(content)
        candidate_file = json_content.get("file")
        reasoning = json_content.get("reasoning")
        print(f"Candidate file: {candidate_file}")
        print(f"Reasoning: {reasoning}")
        
        if not candidate_file:
            raise Exception(f"No candidate file found. Reasoning: {reasoning}")

        role_definition_file = ""
        try:
            with open(f"{args.terraform_path}/{candidate_file}", 'r') as file:
                role_definition_file = file.read()
        except Exception as e:
            print(f"Error reading terraform file: {e}")
            role_definition_file = "Error reading file"
            return

        print(f"Role definition file exists at: {candidate_file}")
        print(f"Preparing to take the action of '{args.mode}' on this file.")
        if args.mode == "comment":
            create_comment_pr(
                llm=llm,
                role_name=role_name,
                role_definition_file=role_definition_file,
                role_definition_file_path=f"core/105-okta/{candidate_file}",
                stmt_list=stmt_list,
                terraform_path=args.terraform_path,
                terraform_content=terraform_content,
                days=args.days
            )
        elif args.mode == "remove":
            create_remove_pr(
                llm=llm,
                role_name=role_name,
                role_definition_file=role_definition_file,
                role_definition_file_path=f"core/105-okta/{candidate_file}",
                stmt_list=stmt_list,
                terraform_path=args.terraform_path,
                terraform_content=terraform_content,
                days=args.days
            ) 