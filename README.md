# Azure Certificate Expiry Monitor

Automated monitoring and alerting for Azure AD enterprise application certificate and secret expirations.

## Overview

This tool integrates with Microsoft Graph API to continuously monitor certificate and client secret expiration dates across all Azure AD enterprise applications. It provides proactive Slack notifications categorized by urgency levels, with intelligent caching to minimize API calls and reduce alert noise.

## Features

- **Comprehensive Coverage**: Monitors both certificates and client secrets across all Azure AD service principals
- **Intelligent Caching**: JSON-based state tracking with change detection to prevent redundant API calls
- **Smart Notifications**: Only alerts on critical expirations, new certificates, or detected changes
- **Urgency Categories**: Expired, Tomorrow, 48 Hours, 2 Weeks
- **OIDC Authentication**: Secure workload identity federation (no long-lived secrets in GitHub)
- **Automated Execution**: Weekly scheduled runs via GitHub Actions with manual trigger support

## Prerequisites

- Azure AD App Registration with appropriate API permissions and federated credentials
- Slack webhook URL for notifications
- GitHub repository with Actions enabled

## Setup

### Azure AD App Registration

Create an app registration named `github-azure-cert-expiry-monitor` with the following configuration:

**API Permissions** (Application-level, requires admin consent):
```
Application.Read.All
ServicePrincipalEndpoint.Read.All
```

**Federated Credentials** (for OIDC authentication):

1. Navigate to App Registration → Certificates & credentials → Federated credentials
2. Add credential for branch deployments:
   - Scenario: GitHub Actions deploying Azure resources
   - Organization: `accelins`
   - Repository: `exp-azure-cert-expiry-monitor`
   - Entity type: Branch
   - Branch name: `main`
3. Add credential for manual workflow runs:
   - Entity type: Environment
   - Environment name: (leave blank)

### GitHub Repository Configuration

Add the following secrets to repository settings (Settings → Secrets and variables → Actions):

```
AZURE_TENANT_ID         # Azure AD tenant ID
AZURE_CLIENT_ID         # App registration client ID
SLACK_WEBHOOK_URL       # Slack incoming webhook URL
```

### Slack Webhook Setup

1. Navigate to https://api.slack.com/apps
2. Create or select your application
3. Enable Incoming Webhooks
4. Add webhook to target channel
5. Copy webhook URL to GitHub secrets

## Usage

### Automated Execution

The workflow runs automatically every Monday at 09:00 UTC. This can be modified in `.github/workflows/check-certificates.yml`.

### Manual Execution

Navigate to Actions → Certificate Expiry Check → Run workflow

### Local Development

For local testing and development:

```bash
# Clone repository
git clone https://github.com/accelins/exp-azure-cert-expiry-monitor.git
cd exp-azure-cert-expiry-monitor

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Configure environment (requires client secret for local auth)
cp .env.example .env
# Edit .env with your credentials

# Execute check
python check_certificates.py
```

## Development

### Setup Git Hooks

Enable pre-commit hooks for automatic quality checks:

```bash
git config core.hooksPath .githooks
```

### Quality Checks

The pre-commit hook automatically runs:
- Ruff linting (`ruff check .`)
- Code formatting (`ruff format --check .`)
- Type checking (`mypy *.py`)

Manual execution:

```bash
ruff check .
ruff format .
mypy *.py
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed development guidelines.

## Architecture

- **check_certificates.py**: Main execution logic, Azure Graph API integration
- **cert_cache.py**: State management and change detection
- **slack_notifier.py**: Slack message formatting and delivery
- **.github/workflows/check-certificates.yml**: Automated execution workflow
- **.github/workflows/ci.yml**: Continuous integration checks
- **.github/workflows/security.yml**: Snyk security scanning

## Notification Logic

Notifications are sent when:
- Certificates or secrets have expired
- Expirations within 24 hours detected
- New certificates appear in estate
- Certificates are removed (potential rotation)
- Expiry dates change unexpectedly
- Weekly summary (every Monday, regardless of changes)

## License

Proprietary - Accelerant Holdings
