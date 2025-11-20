# Azure Certificate Expiry Monitor

Automated monitoring and alerting for Azure AD enterprise application certificate and secret expirations.

## Overview

Integrates with Microsoft Graph API to monitor certificate and client secret expiration dates across Azure AD enterprise applications. Provides proactive Slack notifications with intelligent caching to minimize API calls and reduce alert noise.

**Key Features:**
- Monitors certificates and client secrets across all service principals
- Smart notifications for critical expirations, new certificates, or detected changes
- Categorizes by urgency: Expired, Tomorrow, 48 Hours, 2 Weeks
- Weekly scheduled runs with manual trigger support

## Prerequisites

- Azure AD App Registration with API permissions and federated credentials
- Slack webhook URL
- GitHub repository with Actions enabled

## Setup

### Azure AD App Registration

Create app registration `github-azure-cert-expiry-monitor` with the following Application permissions:

- **Application.Read.All** 
- **ServicePrincipalEndpoint.Read.All**

### GitHub Secrets

Add to repository settings (Settings → Secrets and variables → Actions):

```
AZURE_TENANT_ID
AZURE_CLIENT_ID
SLACK_WEBHOOK_URL
```

### Slack Webhook

1. Create incoming webhook at https://api.slack.com/apps
2. Add webhook URL to GitHub secrets

## Usage

**Automated:** Runs every Monday at 09:00 UTC

**Manual:** Actions → Certificate Expiry Check → Run workflow

## Local Development

```bash
git clone https://github.com/accelins/exp-azure-cert-expiry-monitor.git
cd exp-azure-cert-expiry-monitor

pip install -r requirements.txt
pip install -r requirements-dev.txt

# Configure environment (requires client secret)
cp .env.example .env
# Edit .env with credentials

python check_certificates.py
```

### Quality Checks

Enable pre-commit hooks:
```bash
git config core.hooksPath .githooks
```

Runs automatically before commit:
- `ruff check .` - Linting
- `ruff format --check .` - Formatting
- `mypy *.py` - Type checking
