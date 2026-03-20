# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Kingfisher, please report it
responsibly. **Do not open a public GitHub issue.**

### How to Report

Please submit vulnerability reports through:

- **Email:** [security@mongodb.com](mailto:security@mongodb.com)

### What to Include

- A description of the vulnerability and its potential impact
- Steps to reproduce the issue
- Any relevant logs, screenshots, or proof-of-concept code

### Response Timeline

| Stage | Timeframe |
|---|---|
| Acknowledgement | Within 5 business days |
| Initial assessment | Within 10 business days |
| Resolution target | Depends on severity |

## Supported Versions

Security updates are provided for the latest release only. We recommend
always running the most recent version of Kingfisher.

| Version | Supported |
|---|---|
| Latest release | ✅ |
| Older releases | ❌ |

## Security Best Practices

When using Kingfisher in your environment:

- Verify release artifact checksums before deployment
- Run Kingfisher with the minimum required filesystem permissions
- Review the [pre-commit hook configuration](.pre-commit-hooks.yaml) for
  integration into your development workflow
