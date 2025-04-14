# Instacart Security Identity Toolbox (id-toolbox)

A collection of AI-powered identity and access management tools developed by the Instacart Security Team.

## Overview

This repository contains security tools that utilize AI to streamline and enhance identity and access management workflows. These tools are designed to solve common security team challenges by automating decision-making processes and providing intelligent insights.

## Tools

### PermissionPasta

A powerful AI-driven tool for managing and redirecting users' requests for entitlements. PermissionPasta helps security teams:

- Process access requests intelligently
- Streamline permission management workflows
- Generate contextually appropriate responses to entitlement requests
- Interface with various identity systems (AWS, GitHub, Okta, etc.)

[Learn more about PermissionPasta](./permission_pasta/README.md)

### OOO Checker

An automated workflow that validates an approver's Out-of-Office status and redirects time-sensitive approval requests. OOO Checker:

- Detects when access approval requests are assigned to unavailable approvers
- Uses AI to analyze OOO messages and estimate return times
- Automatically reassigns tasks to appropriate backup approvers
- Prevents delays in critical access management workflows

[Learn more about OOO Checker](./ooo_checker/README.md)

## Getting Started

Each tool has its own README with detailed setup and usage instructions. Please refer to the individual tool directories for specific requirements and configuration details.

## Requirements

- Python 3.x
- Additional dependencies are listed in the respective tool directories

## Contributing

We welcome contributions from the community! If you'd like to contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Development Team

This project is maintained by the Instacart Security Team:
- Dominic Zanardi
- Spencer Sheehan
- Stefan Petrovic

## Acknowledgments

- Thanks to the entire Instacart Security Team for their support and feedback
- Special thanks to all contributors who help improve these tools