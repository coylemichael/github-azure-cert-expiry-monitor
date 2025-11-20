#!/usr/bin/env python3
"""
Azure Enterprise App Certificate Expiry Checker
Queries Microsoft Graph API to check certificate expiration dates
for Azure AD enterprise applications.
"""

import os
import sys
from datetime import datetime, timedelta
from typing import Any

import msal
import requests

from cert_cache import CertificateCache
from slack_notifier import send_slack_notification


class CertificateChecker:
    def __init__(self) -> None:
        self.tenant_id = os.environ.get("AZURE_TENANT_ID")
        self.client_id = os.environ.get("AZURE_CLIENT_ID")
        self.client_secret = os.environ.get("AZURE_CLIENT_SECRET")  # Optional for OIDC
        self.slack_webhook = os.environ.get("SLACK_WEBHOOK_URL")

        if not all([self.tenant_id, self.client_id, self.slack_webhook]):
            raise ValueError("Missing required environment variables")

        self.graph_endpoint = "https://graph.microsoft.com/v1.0"
        self.access_token: str | None = None
        self.cache = CertificateCache()

    def authenticate(self) -> None:
        """Authenticate with Azure AD - supports both OIDC and client secret"""
        # Try OIDC first (for GitHub Actions with workload identity)
        oidc_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        oidc_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")

        if oidc_token and oidc_url:
            # Running in GitHub Actions with OIDC
            print("Using OIDC authentication (workload identity)")
            # azure/login action already handled authentication
            # Get token using Azure CLI that was authenticated by azure/login
            import subprocess

            result = subprocess.run(
                ["az", "account", "get-access-token", "--resource", "https://graph.microsoft.com"],
                capture_output=True,
                text=True,
                check=True,
            )
            import json

            token_data = json.loads(result.stdout)
            self.access_token = token_data["accessToken"]
            print("✓ Successfully authenticated with Azure AD (OIDC)")
        elif self.client_secret:
            # Fallback to client secret (for local development)
            print("Using client secret authentication")
            authority = f"https://login.microsoftonline.com/{self.tenant_id}"
            app = msal.ConfidentialClientApplication(
                self.client_id, authority=authority, client_credential=self.client_secret
            )

            result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])

            if "access_token" in result:
                self.access_token = result["access_token"]
                print("✓ Successfully authenticated with Azure AD (client secret)")
            else:
                raise Exception(f"Authentication failed: {result.get('error_description')}")
        else:
            raise ValueError("No authentication method available. Set AZURE_CLIENT_SECRET for local dev.")

    def get_enterprise_apps(self) -> list[dict[str, Any]]:
        """Fetch all enterprise applications from Azure AD"""
        headers = {"Authorization": f"Bearer {self.access_token}", "Content-Type": "application/json"}

        all_apps: list[dict[str, Any]] = []
        url = f"{self.graph_endpoint}/servicePrincipals?$select=displayName,appId,keyCredentials,passwordCredentials"

        while url:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()

            all_apps.extend(data.get("value", []))
            url = data.get("@odata.nextLink")  # Handle pagination

        print(f"✓ Found {len(all_apps)} enterprise applications")
        return all_apps

    def categorize_certificates(self, apps: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        """Categorize certificates by expiration urgency"""
        now = datetime.utcnow()
        tomorrow = now + timedelta(days=1)
        two_days = now + timedelta(days=2)
        two_weeks = now + timedelta(days=14)

        categories: dict[str, list[dict[str, Any]]] = {
            "expired": [],
            "tomorrow": [],
            "forty_eight_hours": [],
            "two_weeks": [],
        }

        for app in apps:
            app_name = app.get("displayName", "Unknown")
            app_id = app.get("appId", "N/A")

            # Check key credentials (certificates)
            for cert in app.get("keyCredentials", []):
                end_date_str = cert.get("endDateTime")
                if not end_date_str:
                    continue

                # Parse the datetime string
                end_date = datetime.fromisoformat(end_date_str.replace("Z", "+00:00")).replace(tzinfo=None)
                days_until_expiry = (end_date - now).days

                cert_info = {
                    "app_name": app_name,
                    "app_id": app_id,
                    "type": cert.get("type", "Certificate"),
                    "key_id": cert.get("keyId", "N/A"),
                    "expiry_date": end_date,
                    "days_until_expiry": days_until_expiry,
                }

                if end_date < now:
                    categories["expired"].append(cert_info)
                elif end_date < tomorrow:
                    categories["tomorrow"].append(cert_info)
                elif end_date < two_days:
                    categories["forty_eight_hours"].append(cert_info)
                elif end_date < two_weeks:
                    categories["two_weeks"].append(cert_info)

            # Check password credentials (secrets)
            for secret in app.get("passwordCredentials", []):
                end_date_str = secret.get("endDateTime")
                if not end_date_str:
                    continue

                end_date = datetime.fromisoformat(end_date_str.replace("Z", "+00:00")).replace(tzinfo=None)
                days_until_expiry = (end_date - now).days

                secret_info = {
                    "app_name": app_name,
                    "app_id": app_id,
                    "type": "Secret",
                    "key_id": secret.get("keyId", "N/A"),
                    "expiry_date": end_date,
                    "days_until_expiry": days_until_expiry,
                }

                if end_date < now:
                    categories["expired"].append(secret_info)
                elif end_date < tomorrow:
                    categories["tomorrow"].append(secret_info)
                elif end_date < two_days:
                    categories["forty_eight_hours"].append(secret_info)
                elif end_date < two_weeks:
                    categories["two_weeks"].append(secret_info)

        return categories

    def run(self) -> None:
        """Main execution flow"""
        try:
            print("Starting Azure Enterprise App Certificate Check...")
            print("-" * 60)

            # Authenticate
            self.authenticate()

            # Get all enterprise apps
            apps = self.get_enterprise_apps()

            # Categorize certificates by expiration
            categories = self.categorize_certificates(apps)

            # Get all certificates for cache comparison
            all_certs = []
            for cert_list in categories.values():
                all_certs.extend(cert_list)

            # Detect changes from cache
            changes = self.cache.get_changes(all_certs)

            # Print summary
            print("\n" + "=" * 60)
            print("CERTIFICATE EXPIRATION SUMMARY")
            print("=" * 60)
            print(f"Expired: {len(categories['expired'])}")
            print(f"Expiring tomorrow: {len(categories['tomorrow'])}")
            print(f"Expiring in 48 hours: {len(categories['forty_eight_hours'])}")
            print(f"Expiring in 2 weeks: {len(categories['two_weeks'])}")
            print("-" * 60)
            print(f"New certificates: {len(changes['new'])}")
            print(f"Removed certificates: {len(changes['removed'])}")
            print(f"Expiry date changed: {len(changes['expiry_changed'])}")
            print("=" * 60)

            # Update cache with current state
            self.cache.update_certificates(all_certs)
            self.cache.save_cache()

            # Send to Slack if needed
            if self.cache.should_notify(categories, changes):
                if self.slack_webhook:
                    send_slack_notification(categories, self.slack_webhook, changes)
            else:
                print("ℹ No notification sent (no critical issues or changes)")

            print("\n✓ Certificate check completed successfully")

            # Exit with error code if any critical expirations found
            if categories["expired"] or categories["tomorrow"]:
                sys.exit(1)

        except Exception as e:
            print(f"✗ Error: {str(e)}")
            import traceback

            traceback.print_exc()
            sys.exit(1)


if __name__ == "__main__":
    checker = CertificateChecker()
    checker.run()
