# Credential Scanning Patterns Guide

## Overview
Patterns and techniques for detecting credentials in code and data.

## Secret Types

### API Keys
- AWS keys (AKIA...)
- Google API keys
- Azure credentials
- Stripe keys (sk_live)

### Tokens
- JWT tokens
- OAuth tokens
- Session tokens
- Bearer tokens

### Passwords
- Database connection strings
- Hardcoded passwords
- Configuration files
- Environment variables

## Regex Patterns

### Cloud Providers
```regex
AKIA[0-9A-Z]{16}  # AWS Access Key
AIza[0-9A-Za-z-_]{35}  # Google API
[0-9a-f]{32}  # Generic API Key
```

### Authentication
```regex
password\s*[=:]\s*['"][^'"]+  # Password assignment
Bearer\s+[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+  # JWT
```

## Scanning Locations

### Source Code
- Hardcoded strings
- Configuration files
- Test fixtures
- Comments

### Git History
- Removed credentials
- Past commits
- Stashed changes
- Branch history

### Infrastructure
- CI/CD configs
- Docker files
- Kubernetes secrets
- Terraform state

## False Positive Handling
- Example detection
- Placeholder filtering
- Context analysis

## Legal Notice
For authorized security scanning.
