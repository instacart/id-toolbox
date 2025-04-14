# PermissionPasta 🍝

AWS Role and Resource Access Path Analyzer

## Overview

PermissionPasta helps security teams implement least privilege by analyzing which AWS resources a user needs access to and determining the most appropriate way to grant that access, avoiding permission sprawl and unnecessary role creation.

### What it does

1. **AI-powered resource extraction**: Uses OpenAI to intelligently identify AWS resources from natural language justifications
2. **Resolves ambiguous resource types**: Determines all possible AWS service types a resource could belong to (e.g., a "table" could be DynamoDB or RDS)
3. **Detects intended access level**: Determines if the user needs read-only or read-write access based on their justification
4. **Maps existing access paths** to see if access already exists through another role
5. **Integrates with Okta**: Checks user's Okta group memberships to identify AWS roles they already have access to
6. **Recommends the least-privileged approach**:
   - Use an existing role if appropriate access already exists
   - Add permissions to an existing role if needed
   - Create a new role only when necessary
7. **Generates Terraform code** when needed and creates a PR for review

## Setup

### Prerequisites

- Python 3.7 or higher
- AWS credentials with IAM read permissions
- GitHub access token (for creating PRs)
- OpenAI API key (for AI-powered resource extraction)
- [Optional] Okta API token (for role lookup via Okta group memberships)
- [Optional] Veza API access (for enhanced access path analysis)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-org/your-repo.git
   cd your-repo/security/iam/bsides2025
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create your environment configuration:
   ```bash
   cp permissionpasta.env.example .env
   # Edit .env to add your configuration
   ```

## Configuration

Configure PermissionPasta by setting the following environment variables (either in the .env file or directly in your environment):

### Required Variables

- `AWS_REGION`: AWS region to use
- `GITHUB_TOKEN`: GitHub personal access token with repo scope
- `GITHUB_REPO`: GitHub repository in format "owner/repo"
- `TERRAFORM_MODULE_PATH`: Path to Terraform IAM roles module
- `OPENAI_API_KEY`: OpenAI API key for AI-powered resource extraction

### Optional Variables

- `OPENAI_MODEL`: OpenAI model to use (defaults to gpt-3.5-turbo)
- `OKTA_API_TOKEN`: Okta API token for user role lookups via Okta groups
- `OKTA_DOMAIN`: Okta domain URL (e.g., company.okta.com)
- `OKTA_AWS_GROUP_PREFIX`: Prefix for Okta groups that grant AWS access (defaults to 'AWS-')

See the `permissionpasta.env.example` file for all optional configuration parameters.

### Okta Integration

PermissionPasta can integrate with Okta to determine which AWS roles a user already has access to. This feature:

- Queries the Okta API for a user's group memberships
- Identifies groups with names that match the `OKTA_AWS_GROUP_PREFIX` pattern (default: "AWS-")
- For each matching group, extracts the role name (e.g., group "AWS-developer" maps to role "developer")
- Uses this information to provide better recommendations for the user

To enable Okta integration, set the following environment variables:
```
OKTA_API_TOKEN=your-okta-api-token
OKTA_DOMAIN=your-company.okta.com
OKTA_AWS_GROUP_PREFIX=AWS-  # Optional, defaults to 'AWS-'
```

The Okta API token needs read access to users and groups.

### Prompt Configuration

PermissionPasta uses a separate YAML file (`prompts.yaml`) to store the prompts used for AI operations. This separation makes it easier to:

- Manage and iterate on prompt design without changing code
- Test different prompts for various use cases
- Save versions of prompts that work well

The `prompts.yaml` file includes sections for:
- `resource_extraction`: Prompts for identifying AWS resources in justification text
- Additional prompt sections can be added for other AI operations

To modify how PermissionPasta extracts resources, edit the system prompt in the `prompts.yaml` file rather than changing the code.

## Usage

### Basic Usage

```bash
python permissionpasta.py --justification "I need access to the data-lake-123 S3 bucket to analyze customer data for the marketing campaign"
```

### Interactive Mode

```bash
python permissionpasta.py --interactive
```

### Example Mode

Try the tool with a pre-defined example:

```bash
python permissionpasta.py --example
```

### With User Context

```bash
python permissionpasta.py --user john.doe --requested-role developer-data --justification "Need to query the customer-analytics DynamoDB table"
```

### Without AWS Authentication

You can run the script without AWS authentication and still benefit from AI resource extraction and Okta role lookups:

```bash
python permissionpasta.py --interactive --no-aws
```

### Test Resource Extraction Only

If you just want to test the AI-powered resource extraction without running the entire workflow:

```bash
python test_resource_extraction.py --justification "I need to access the billing-reports bucket"
```

### Quick Test (Minimal Dependencies)

For a quick test of just the OpenAI resource extraction without AWS dependencies:

```bash
# Set up a minimal .env file first
cp quick_test.env.example .env
# Edit .env to add your OpenAI API key

# Run with a specific justification
python quick_test.py "I need to access the billing-reports S3 bucket"

# Run with interactive mode (choose from examples)
python quick_test.py

# Run with a different OpenAI model
python quick_test.py --model gpt-4 "I need to update records in the users table"
```

This script only requires the OpenAI API key and doesn't need AWS credentials.

## How AI Resource Extraction Works

PermissionPasta uses OpenAI's language models to:

1. Parse natural language justifications for resource access
2. Identify specific AWS resources mentioned in the text
3. Determine all possible AWS service types the resource could belong to
4. Infer whether read-only or read-write access is needed based on context

For ambiguous resources (like "users table" which could be DynamoDB or RDS), the tool returns all possible service types and later attempts to validate which ones actually exist in your AWS environment.

The system includes:
- Intelligent inference of access needs (read vs read/write)
- Handling of ambiguous resource types
- Fallback pattern-matching if the AI service is unavailable

### Example Resource Extraction

Justification:
```
I need to update records in the peaches-and-cream table for our quarterly audit.
```

Extracted information:
```
Resource: peaches-and-cream
Possible types: dynamodb, rds
Access level: read-write
```

## Examples

### Example 1: Resource already accessible through existing role

Input:
```
python permissionpasta.py --user jane.doe --justification "Need to query transactions-2023 DynamoDB table for financial analysis"
```

Output:
```
Analysis Results:
✓ Resource identified: 'transactions-2023'
  - Possible types: dynamodb, rds
  - Access level: read
  - dynamodb: exists - arn:aws:dynamodb:us-east-1:123456789012:table/transactions-2023
  - rds: not found
✓ Access available through existing role: 'finance-analyst'
✓ User 'jane.doe' is not currently assigned to this role

Recommendation:
Request access to the 'finance-analyst' role instead of creating new permissions.
```

### Example 2: Generating new permissions

Input:
```
python permissionpasta.py --user john.smith --justification "Need to access monitoring-dashboard CloudWatch dashboard for incident response"
```

Output:
```
Analysis Results:
✓ Resource identified: 'monitoring-dashboard'
  - Possible types: cloudwatch
  - Access level: read
  - cloudwatch: exists - arn:aws:cloudwatch:us-east-1:123456789012:dashboard/monitoring-dashboard
✓ No existing non-admin roles have access to this resource
✓ User has 'support-engineer' role that can be extended with these permissions

Recommendation:
Added minimal CloudWatch permissions to 'support-engineer' role.
Created PR #123 for review: https://github.com/your-org/your-repo/pulls/123
```

## Development

Pull requests are welcome! Please ensure you:

1. Include tests for new functionality
2. Update documentation as needed
3. Follow our coding standards

## License

This project is licensed under the MIT License - see the LICENSE file for details.