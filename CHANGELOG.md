# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-04-29

### Added
- "Recently Expired" bucket — credentials expired within the last 30 days are now reported instead of silently ignored.
- Credential type icons in Slack output — 🔑 for secrets, 📜 for certificates — with a legend in the message header.
- `_human_time_since()` in Slack notifier for "X days ago" formatting on expired items.
- `should_notify()` method on `CertificateChecker` — simple stateless logic (any items or summary day).
- Dev Slack webhook support via `.env` for safe local testing.
- `system_tests` job in CI workflow — satisfies org-wide universal test check requirement.
- `ci-docs.yml` bypass workflow for non-code PRs (README, docs, `.github` changes only).

### Changed
- Slack messages renamed from "Certificate" to "Credential" to accurately cover both certificates and client secrets.
- Notification logic is now fully stateless — each run is a live snapshot from Azure with no local persistence.
- Simplified GitHub Actions workflow: removed cache restore/save/delete steps and artifact upload.

### Removed
- `cert_cache.py` — certificate cache module and all change-detection logic.
- `no-cache-ci.yml` workflow — redundant now that the main workflow is stateless.

## [1.0.0] - 2025-11-27

### Added
- Converted to `src/` layout with editable install for CLI/module entry.
- Unit tests with coverage enabled in CI.
- Dependabot setup for pip and GitHub Actions updates.
- CODEOWNERS file recorded.

### Changed
- Schedule simplified to workflow cron (Monday and Thursday 09:00 UTC); summary notifications follow the same days.
- Bucket toggles are now hard-coded constants (no YAML configuration).
- Slack links now open directly to the Credentials (Certificates & Secrets) blade in Azure.
- CI authentication clarified to prefer OIDC/workload identity; client secret kept only for local runs.

## [0.1.0] - 2025-11-20

### Added
- Initial release of Azure Certificate Expiry Monitor
- Microsoft Graph API integration for querying enterprise applications
- Certificate and secret expiration checking for all service principals
- Multi-level urgency categorization (Expired, Tomorrow, 48 Hours, 2 Weeks)
- Slack Block Kit notification formatting with color-coded alerts
- GitHub Actions workflow for weekly automated checks (Monday 9AM UTC)
- Manual workflow trigger support (`workflow_dispatch`)
- Python 3.13 support
- OIDC/Workload Identity authentication for GitHub Actions
- Client secret fallback for local development
- Comprehensive error handling and logging
- CODEOWNERS file for repository governance
- Dependabot configuration for automated dependency updates
- Environment variable configuration via `.env` file

### Security
- Azure AD Workload Identity (OIDC) - no long-lived secrets in GitHub
- Secure credential management via GitHub Secrets
- Azure AD authentication using MSAL library for local dev
- No credential logging or exposure
- Minimum required permissions (Application.Read.All, ServicePrincipalEndpoint.Read.All)
