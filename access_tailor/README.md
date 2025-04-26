# AccessTailor

> ⚠️ **Note**: This code will be released in the next few days. Stay tuned for updates!

AWS Role and Resource Access Path Analyzer

## Overview

AccessTailor helps security teams implement least privilege by analyzing which AWS resources a user needs access to and determining the most appropriate way to grant that access, avoiding permission sprawl and unnecessary role creation.

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


## How AI Resource Extraction Works

accesstailor uses OpenAI's language models to:

1. Parse natural language justifications for resource access
2. Identify specific AWS resources mentioned in the text
3. Determine all possible AWS service types the resource could belong to
4. Infer whether read-only or read-write access is needed based on context

For ambiguous resources (like "users table" which could be DynamoDB or RDS), the tool returns all possible service types and later attempts to validate which ones actually exist in your AWS environment.

The system includes:
- Intelligent inference of access needs (read vs read/write)
- Handling of ambiguous resource types
- Fallback pattern-matching if the AI service is unavailable

## License

This project is licensed under the MIT License - see the LICENSE file for details.