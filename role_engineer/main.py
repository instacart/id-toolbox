#!/usr/bin/env python3.12
import argparse
import logging
import json
import os
from typing import Dict, List, Set, Any, Tuple, Optional
from datetime import date, timedelta

import boto3
from botocore.exceptions import ClientError

from datasource.wiz import fetch_cloudtrail_events as fetch_cloudtrail_events_wiz
from datasource.aws_cloudtrail import fetch_cloudtrail_events as fetch_cloudtrail_events_aws
from role_modification import analyze_and_modify_roles
from role_creation import create_role_with_least_privilege


# This dictionary maps (eventSource, eventName) -> IAM action.
# Only special or custom mappings go here; fallback logic will handle everything else.
EVENTNAME_TO_IAMACTION = {
    # Example special overrides:
    ("lambda.amazonaws.com", "GetPolicy20150331v2"): "lambda:GetPolicy",
    ("lambda.amazonaws.com", "ListFunctions20150331"): "lambda:ListFunctions",
    # etc.
}

ACTIONS_WITHOUT_LOGGING = [ 
    # Read (Retrieval) API Calls
    "s3:GetObject",
    "s3:HeadObject",
    "s3:SelectObjectContent",
    "s3:RestoreObject",
    "s3:GetObjectTagging",
    "s3:GetObjectAttributes",

    # Write (Modification) API Calls
    "s3:PutObject",
    "s3:PutObjectAcl",
    "s3:PutObjectTagging",
    "s3:PutObjectRetention",
    "s3:PutObjectLegalHold",
    "s3:DeleteObject",
    "s3:DeleteObjects",
    "s3:ReplicateObject",
    "s3:CopyObject",

    # Multipart Upload API Calls
    "s3:CreateMultipartUpload",
    "s3:UploadPart",
    "s3:UploadPartCopy",
    "s3:CompleteMultipartUpload",
    "s3:AbortMultipartUpload",
    "s3:ListParts",

    # Listing Multipart Uploads API Calls
    "s3:ListMultipartUploads",
    "s3:ListBucketMultipartUploads",
]


##############################################################################
# ARGUMENT & LOGGING SETUP
##############################################################################

def parse_arguments() -> argparse.Namespace:
    """
    Parse CLI arguments and return the parsed namespace.
    """
    parser = argparse.ArgumentParser(
        description="Analyze IAM roles' usage of AWS actions via CloudTrail to identify unused permissions."
    )

    parser.add_argument(
        "--role",
        default=None,
        help=(
            "If provided, CloudTrail will be filtered by Role ARN. "
            "Otherwise, no filter is applied. Use '*' to perform a wildcard search. "
            "Example: '--role arn:aws:iam::123456789123:role/Security' or '--role *Security'."
        )
    )
    parser.add_argument(
        "--mode",
        choices=["comment", "remove"], # "create" is not implemented yet
        default="comment",
        help="Mode of operation: 'comment' to add comments about unused permissions, 'remove' to remove unused "
        "permissions. "
        #, or 'create' to create a new policy with the unused permissions removed. "
        "Default is 'comment'."
    )
    parser.add_argument(
        "--terraform-path",
        required=True,
        help=(
            "Path to the Terraform directory containing IAM role definitions. "
            "This is required to analyze and compare actual usage against defined permissions."
        )
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region to use (default: us-east-1)"
    )
    parser.add_argument(
        "--days",
        type=int,
        default=2,
        help="Number of days in the past to look at CloudTrail logs (default: 2)"
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="AWS named profile to use (optional). If omitted, the default credentials are used."
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level (default: INFO)."
    )
    parser.add_argument(
        '--datasource',
        choices=["aws", "wiz"],
        default="wiz",
        help="The datasource to use for retrieving CloudTrail events. "
        "Default is 'wiz'. Native AWS CloudTrail is also supported, but Wiz is far superior in retrieval performance."
    )

    return parser.parse_args()


def setup_logging(log_level: str) -> None:
    """
    Set up basic logging configuration.
    """
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )


def extract_role_and_action_usage(
    events: List[Dict[str, Any]]
) -> Tuple[Dict[str, Set[str]], Dict[str, List[Dict[str, Any]]], Dict[str, Dict[str, Set[str]]]]:
    """
    Given CloudTrail event records, return:
      1) usage_map: role_arn -> set of used IAM actions
      2) role_events_map: role_arn -> list of event details (including the mapped IAM action)
      3) action_resources_map: role_arn -> {action -> set of resource ARNs}

    We look up (eventSource, eventName) in EVENTNAME_TO_IAMACTION. If it's not found,
    we guess the service prefix from eventSource by removing '.amazonaws.com' and map it to
    e.g., 'ec2:DescribeSubnets' if eventSource='ec2.amazonaws.com' and eventName='DescribeSubnets'.
    """
    usage_map: Dict[str, Set[str]] = {}
    role_events_map: Dict[str, List[Dict[str, Any]]] = {}
    action_resources_map: Dict[str, Dict[str, Set[str]]] = {}

    for event in events:
        ct_detail = json.loads(event.get("CloudTrailEvent", "{}"))
        role_arn = ct_detail.get("userIdentity", {}).get("sessionContext", {}).get("sessionIssuer", {}).get("arn")
        event_name = ct_detail.get("eventName")
        event_source_raw = ct_detail.get("eventSource", "").strip()
        event_source = event_source_raw.lower()
        
        # Extract resources from the event
        resources = ct_detail.get("resources", [])
        resource_arns = set()
        if resources:  # Check if resources is not None before iterating
            for resource in resources:
                if resource.get("ARN"):
                    resource_arns.add(resource.get("ARN"))

        if not role_arn or not event_name or not event_source:
            continue

        # Attempt explicit dictionary lookup
        dict_key = (event_source, event_name)
        if dict_key in EVENTNAME_TO_IAMACTION:
            iam_action = EVENTNAME_TO_IAMACTION[dict_key]
        else:
            # Fallback: parse out the service prefix
            service_prefix = event_source.replace(".amazonaws.com", "")
            service_prefix = service_prefix.replace(".amazonaws", "")
            service_prefix = service_prefix.replace("monitoring", "cloudwatch")  # Cloudwatch domain doesn't match policy permission prefix
            service_prefix = service_prefix.replace("servicecatalog-appregistry", "servicecatalog")
            service_prefix = service_prefix.replace("application-insights", "applicationinsights")
            iam_action = f"{service_prefix}:{event_name}"

        # Record usage
        usage_map.setdefault(role_arn, set()).add(iam_action)
        
        # Record resources used with this action
        action_resources_map.setdefault(role_arn, {}).setdefault(iam_action, set()).update(resource_arns)
        
        role_events_map.setdefault(role_arn, []).append({
            "cloudtrail_event": event,
            "mapped_iam_action": iam_action,
            "event_source": event_source,
            "event_name": event_name,
            "resources": resource_arns
        })

    logging.info(f"Built usage map for roles with the following keys: {usage_map.keys()}")
    return usage_map, role_events_map, action_resources_map


def main():
    args = parse_arguments()
    setup_logging(args.log_level)

    # Ensure required GitHub envs are set
    if not os.getenv("GITHUB_TOKEN") or not os.getenv("GITHUB_REPO_OWNER") or not os.getenv("GITHUB_REPO_NAME") or not os.getenv("GITHUB_REPO_BASE_BRANCH"):
        logging.error("Missing required GitHub environment variables. Please set GITHUB_API_BASE, GITHUB_TOKEN, REPO_OWNER, REPO_NAME, and REPO_BASE_BRANCH.")
        return 1

    try:
        identity = boto3.client('sts').get_caller_identity().get('Arn')
        logging.info(f"Authenticated to AWS as: {identity}")
    except ClientError as e:
        logging.error("Failed to authenticate to AWS. Please ensure you have "
                      "valid AWS credentials and are authenticated to the "
                      "correct account.")
        return 1

    # 1. Retrieve CloudTrail events from our new datasource function
    logging.info("Getting CloudTrail events...")

    fetch_cloudtrail_events = fetch_cloudtrail_events_wiz if args.datasource == "wiz" else fetch_cloudtrail_events_aws
    raw_events = fetch_cloudtrail_events(
        days=args.days,
        role=args.role,
        options={"region": args.region, "profile": args.profile},
    )
    if not raw_events:
        logging.error(f"No CloudTrail events found for role {args.role}.")
        return 1

    logging.info(f"Collected {len(raw_events)} CloudTrail events for analysis.")

    # 2. Build usage map & role->events map
    logging.info("Extracting role <> action combinations...")
    usage_map, role_events_map, action_resources_map = extract_role_and_action_usage(raw_events)

    # Process based on mode
    if args.mode in ["comment", "remove"]:
        analyze_and_modify_roles(
            usage_map=usage_map,
            role_events_map=role_events_map,
            action_resources_map=action_resources_map,
            args=args,
            actions_without_logging=ACTIONS_WITHOUT_LOGGING
        )
    elif args.mode == "create":
        create_role_with_least_privilege(
            usage_map=usage_map,
            role_events_map=role_events_map,
            action_resources_map=action_resources_map,
            args=args,
            actions_without_logging=ACTIONS_WITHOUT_LOGGING
        )

if __name__ == "__main__":
    main()

