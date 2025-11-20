# Azure Certificate Expiry Monitor

Automated monitoring of Azure AD enterprise application certificate expiration dates with Slack notifications.

## Prerequisites

- Azure AD App Registration with API permissions and federated credentials
- Slack webhook URL
- GitHub repository with Actions enabled

## Setup

### Azure AD Configuration

**API Permissions (requires admin consent):**
- `Application.Read.All` (Application permission)
- `ServicePrincipalEndpoint.Read.All` (Application permission)

**Federated Credentials:**
1. App Registration → Certificates & credentials → Federated credentials
2. Add credential for branch deployments:
   - Scenario: GitHub Actions deploying Azure resources
   - Organization: `<your-github-org>`
   - Repository: `<repo-name>`
   - Entity type: Branch
   - Branch: `main`
3. Add credential for manual runs:
   - Entity type: Environment
   - Leave environment name blank

### GitHub Secrets

Add to repository settings:
```
AZURE_TENANT_ID
AZURE_CLIENT_ID
SLACK_WEBHOOK_URL
```

For local development, create `.env`:
```
AZURE_CLIENT_SECRET=your-secret-here
```

## Usage

**Automated:** Runs every Monday at 9:00 AM UTC

**Manual:** Actions → Certificate Expiry Check → Run workflow

## Local Testing

```bash
pip install -r requirements.txt
cp .env.example .env
# Edit .env with credentials
python check_certificates.py
```

## Development

```bash
pip install -r requirements-dev.txt
ruff check .
ruff format .
mypy *.py
```
