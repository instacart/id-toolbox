# Role Engineer

A tool for analyzing AWS IAM roles against their actual usage in CloudTrail to identify unused permissions, promoting least privilege security.

## Overview

Role Engineer helps you maintain the principle of least privilege by:

1. Analyzing your AWS IAM roles defined in Terraform
2. Comparing actual usage data from CloudTrail
3. Identifying unused permissions
4. Creating Pull Requests to either comment on or remove unused permissions

This tool supports two datasources for CloudTrail events:
- Wiz (preferred for better performance)
- [coming soon] Native AWS CloudTrail

## Features

- **Usage Analysis**: Track which IAM permissions are actually being used by your roles
- **Terraform Integration**: Parse and modify your IAM role definitions in Terraform format
- **Automated PR Creation**: Generate pull requests with suggested changes
- **Multiple Modes**:
  - `comment`: Add comments to Terraform files noting unused permissions without changing functionality
  - `remove`: Create PRs that safely remove unused permissions (with human oversight)

## Prerequisites

- Python 3.8+
- AWS credentials with appropriate permissions
- Terraform codebase with IAM role definitions
- GitHub access token (for PR creation)

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/role_engineer.git
cd role_engineer

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Basic usage
python main.py --terraform-path /path/to/terraform --role "your-role-name" --mode comment

# Analyze access across an entire quarter for a given role
python main.py --terraform-path /path/to/terraform --role "your-role-name" --mode comment --days 90

# Use wildcard match for role names (only Wiz supports wildcarding)
python main.py --terraform-path /path/to/terraform --role "*Engineering*" --mode comment
```

## Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--role` | Role ARN or pattern to analyze (use '*' for wildcard w/Wiz as a Datasource) | None |
| `--mode` | Operation mode: 'comment' or 'remove' | comment |
| `--terraform-path` | Path to Terraform directory with IAM definitions | Required |
| `--region` | AWS region to use | us-east-1 |
| `--days` | Number of days to analyze CloudTrail logs | 2 |
| `--profile` | AWS named profile to use | None |
| `--log-level` | Logging level | INFO |
| `--datasource` | Data source for CloudTrail events ('aws' or 'wiz') | wiz |

## Environment Variables

The following environment variables are required:

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | API key for OpenAI (used for generating PR content) |
| `GITHUB_TOKEN` | GitHub personal access token (for creating PRs) |
| `GITHUB_REPO` | GitHub repository (format: 'owner/repo') |
| `GITHUB_USER_EMAIL` | Email address for GitHub commits |
| `GITHUB_USER_NAME` | Name for GitHub commits |

For the Wiz datasource:
| Variable | Description |
|----------|-------------|
| `WIZ_CLIENT_ID` | Wiz API client ID |
| `WIZ_CLIENT_SECRET` | Wiz API client secret |
| `WIZ_ENV` | Wiz environment (e.g., "fedramp", "gov") (optional) |
| `WIZ_API_PROXY` | Proxy URL for Wiz API requests (optional) |
| `WIZ_CLOUD_ACCOUNT_OR_ORGANIZATION_ID` | Specific cloud account or organization ID GUID to filter results for (e.g. "74d052ba-a967-50f3-bdd9-eb8bb836f9a9") |

## How It Works

1. **Role Analysis**:
   - Parses Terraform files to identify IAM role definitions
   - Extracts policy statements and actions

2. **CloudTrail Analysis**:
   - Fetches CloudTrail events for the specified role(s)
   - Maps (eventSource, eventName) to IAM actions
   - Builds a usage map of actions actually used by the role

3. **Permission Analysis**:
   - Compares defined permissions against actual usage
   - Identifies unused permissions
   - Accounts for actions that don't produce CloudTrail logs

4. **Modification**:
   - In 'comment' mode: Adds comments identifying unused permissions
   - In 'remove' mode: Creates a PR that removes unused permissions

## Limitations

- Relies on CloudTrail logs, which don't record all action types (the tool includes a list of known actions that don't generate logs)
- Analysis is limited to the time period specified (default: 2 days)
- Retrieval of CloudTrail logs directly from AWS is extraordinarily slow, which is why using some other source (like Wiz) is recommended

## Contributing

We welcome contributions from the community. We are especially interested in adding support for more CloudTrail log data sources.

## License

This project is licensed under the The **2.0** version of the **Apache License** - see the LICENSE file for details.

## Contact

For questions or support, please open an issue in the repository.

----------

Developed with ❤️ by Instacart