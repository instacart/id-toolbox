# Out-of-Office Checker Workflow (Tines)

## Overview
This Tines workflow automatically detects when access approval requests are assigned to approvers who appear to be out of office, and reassigns those tasks to the approver's manager to prevent delays in access management.

## Workflow Steps

1. **Search for Open Tasks** - Runs every hour to find open approval tasks in Conductor One
2. **Process Each Request** - For each open task, the workflow:
   - Gets the assigned approver's info from Conductor One
   - Checks if the approver is in the Security team (these requests are handled differently)
   - Looks up the approver in Slack by email
   - Checks if the approver has a Slack status message set
   - Uses GPT to analyze the Slack status to determine if it indicates the person is out of office
   - If the AI determines with high confidence (score ≥ 7/10) that the approver is OOO, the workflow:
     - Gets the approver's manager information
     - Checks that the manager isn't too senior (to avoid escalating to executives)
     - Reassigns the task to the manager with a note explaining the reassignment

## How the AI Analysis Works
The workflow uses GPT to analyze the approver's Slack status text along with the current date to determine:
- If the user is currently out of office (not just planning to be in the future)
- If the out-of-office period will last for more than 1 day
- The confidence level (0-10) that the user is indeed out of office

Only if the confidence rating is 7 or higher will the workflow reassign the task.

## Security Notes
- No actual credentials are stored in the workflow file. Credentials are referenced via placeholders (e.g., `<<CREDENTIAL.c1>>`) and are managed securely within the Tines platform.
- The workflow avoids escalating to very senior managers by checking job levels.
- The workflow excludes Security team approvers, as these have special handling requirements.

## Maintenance
If you need to modify this workflow:
1. Changes can be made directly in the Tines UI
2. The workflow JSON can be exported from Tines and saved to this repo
3. This automated process helps reduce access approval delays when approvers are unavailable 