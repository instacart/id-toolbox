# datasource/aws_cloudtrail.py
import datetime
import logging
from typing import List, Dict, Any, Optional

import boto3
from botocore.exceptions import ClientError

def fetch_cloudtrail_events(
    days: int,
    username: Optional[str],
    options: Optional[Dict],
) -> List[Dict[str, Any]]:
    """
    Retrieve CloudTrail events from the past `days` days.
    If `username` is provided, filter via LookupAttributes. Otherwise, no filter is applied.

    :param days: How many days' worth of events to fetch
    :param username: Username for CloudTrail filter; None = no filter
    :return: A list of CloudTrail event dictionaries
    """
    raise NotImplementedError("This datasource is not fully implemented yet")
    
    profile = options.get('profile')
    region = options.get('region')

    if profile:
        session = boto3.Session(profile_name=profile, region_name=region)
    else:
        session = boto3.Session(region_name=region)

    cloudtrail_client = session.client("cloudtrail")

    if username:
        logging.info(f"Fetching CloudTrail events for Username='{username}' from the past {days} days...")
    else:
        logging.info(f"Fetching CloudTrail events with no Username filter, from the past {days} days...")

    end_time = datetime.datetime.utcnow()
    start_time = end_time - datetime.timedelta(days=days)

    all_events = []
    next_token = None

    lookup_attrs = []
    if username:
        lookup_attrs = [{"AttributeKey": "Username", "AttributeValue": username}]

    while True:
        try:
            kwargs = {
                "StartTime": start_time,
                "EndTime": end_time,
                "MaxResults": 50,
            }
            if next_token:
                kwargs["NextToken"] = next_token
            if lookup_attrs:
                kwargs["LookupAttributes"] = lookup_attrs

            response = cloudtrail_client.lookup_events(**kwargs)

        except ClientError as e:
            logging.error(f"Error fetching events from CloudTrail: {e}")
            break

        events = response.get("Events", [])
        all_events.extend(events)

        next_token = response.get("NextToken")
        if not next_token:
            break

    logging.info(f"Total events fetched: {len(all_events)}")
    print(all_events)
    return all_events

