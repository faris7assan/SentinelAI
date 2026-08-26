# Security Policy

SentinelAI is a security research and portfolio project. Deploy it only in environments you own or are explicitly authorized to administer.

## Reporting

Do not disclose credentials, tokens, private keys, or sensitive exploit details in public issues. Contact the project owner through the GitHub profile with the affected component, reproduction steps, impact, and remediation guidance.

## Secret Handling

Never commit `.env` files, API keys, passwords, JWT secrets, OAuth client secrets, cloud credentials, database passwords, or private keys. Rotate any secret immediately if it is exposed.

## Deployment Note

Production deployments must supply secrets through a dedicated secret-management mechanism or deployment environment, not through committed manifests or source code.
