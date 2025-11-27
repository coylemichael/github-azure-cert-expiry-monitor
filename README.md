# Azure App Registration Certificate Expiry Monitor

Checks certificate and client secret expirations on Azure AD **App Registrations** (not enterprise apps) and posts Slack alerts with links straight to the Certificates & Secrets blade. Expired items are intentionally ignored; buckets start at "today" and beyond.

## How it works
- Auth: client secret locally; GitHub Actions can be wired with `azure/login` OIDC (optional).
- Data source: Microsoft Graph `/v1.0/applications`.
- Buckets (hard-coded in `check_certificates.py`): today, tomorrow, 48 hours, 2 weeks, 1/3 months (6/12 months disabled by default). Edit `EXPIRY_BUCKETS` to change.
- Caching: `cert_cache.json` tracks new/removed/changed creds and throttles notifications.
- Schedule: runs Monday and Thursday at 09:00 UTC via workflow cron; summary pings also fire on those days (see `SUMMARY_DAYS` in `check_certificates.py` if you want to change).
- Slack links: point straight to the App Registration Credentials (Certificates & Secrets) blade for quick action.

## Setup
- Secrets: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` (local only), `SLACK_WEBHOOK_URL`.
- Permissions for the app: `Application.Read.All` and `ServicePrincipalEndpoint.Read.All`.

## Run locally
```bash
pip install -r requirements.txt
python check_certificates.py
```

## GitHub Actions
Scheduled run Monday and Thursday (09:00 UTC) via `.github/workflows/check-certificates.yml`; manual trigger supported. To change cadence, edit the cron entries in that workflow. Configure secrets and optionally add `azure/login` for OIDC auth.
