# Azure App Registration Certificate Expiry Monitor

Checks certificate and client secret expirations on Azure AD **App Registrations** (not enterprise apps) and posts Slack alerts with links straight to the Certificates & Secrets blade. Expired items are intentionally ignored; buckets start at "today" and beyond.

## How it works
Data comes from Microsoft Graph `/v1.0/applications`; expired creds are ignored. Slack links open directly to the App Registration Credentials (Certificates & Secrets) blade.

Auth paths:
- CI: `azure/login` with OIDC/workload identity (no client secret needed).
- Local: client secret from `.env` is used if present.

Buckets and schedule are code constants in `check_certificates.py`:
```python
SUMMARY_DAYS = {0, 3}  # Monday, Thursday
EXPIRY_BUCKETS = {
    "today": {"days": None, "enabled": True},
    "tomorrow": {"days": None, "enabled": True},
    "forty_eight_hours": {"days": 2, "enabled": True},
    "two_weeks": {"days": 14, "enabled": True},
    "one_month": {"days": 30, "enabled": True},
    "three_months": {"days": 90, "enabled": True},
    "six_months": {"days": 180, "enabled": False},
    "one_year": {"days": 365, "enabled": False},
}
```
Edit these to change cadence or buckets. `cert_cache.json` tracks changes to cut alert noise.

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
