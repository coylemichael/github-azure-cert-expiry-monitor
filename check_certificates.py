#!/usr/bin/env python3
"""
Azure App Registration Certificate Expiry Checker
Queries Microsoft Graph API to check certificate expiration dates
for Azure AD application registrations only.
"""

import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from typing import Any

import msal
import requests
from dotenv import load_dotenv

from cert_cache import CertificateCache
from slack_notifier import send_slack_notification

load_dotenv()

# --------------------------------------------------------------
# Default settings
# --------------------------------------------------------------
SUMMARY_DAYS: set[int] = {0, 3}  # Monday, Thursday
EXPIRY_BUCKETS: dict[str, dict[str, Any]] = {
    "today":             {"days": None, "enabled": True},   # same UTC calendar day
    "tomorrow":          {"days": None, "enabled": True},   # next UTC calendar day
    "forty_eight_hours": {"days": 2,    "enabled": True},
    "two_weeks":         {"days": 14,   "enabled": True},
    "one_month":         {"days": 30,   "enabled": True},
    "three_months":      {"days": 90,   "enabled": True},
    "six_months":        {"days": 180,  "enabled": False},
    "one_year":          {"days": 365,  "enabled": False},
}


class CertificateChecker:
    def __init__(self) -> None:
        self.tenant_id = os.environ.get("AZURE_TENANT_ID")
        self.client_id = os.environ.get("AZURE_CLIENT_ID")
        self.client_secret = os.environ.get("AZURE_CLIENT_SECRET")
        self.slack_webhook = os.environ.get("SLACK_WEBHOOK_URL")

        if not all([self.tenant_id, self.client_id, self.slack_webhook]):
            raise ValueError("Missing required environment variables")

        self.graph_endpoint = "https://graph.microsoft.com/v1.0"
        self.access_token: str | None = None
        self.cache = CertificateCache()

        # Bucket definitions: "days" is None for date-based buckets.
        self.expiry_buckets: dict[str, dict[str, Any]] = {
            name: cfg.copy() for name, cfg in EXPIRY_BUCKETS.items()
        }

        # Days of week (0=Monday) to always send summary notifications
        self.summary_days: set[int] = SUMMARY_DAYS.copy()

        # Slack truncation safety
        self.max_slack_items = int(os.environ.get("SLACK_MAX_ITEMS", "10"))

    # --------------------------------------------------------------
    # Build Portal Link for App Registrations
    # --------------------------------------------------------------

    def build_app_registration_link(self, object_id: str, app_id: str) -> str:
        return (
            "https://portal.azure.com/#view/"
            "Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/"
            "~/Credentials/"
            f"objectId/{object_id}/appId/{app_id}"
        )

    # --------------------------------------------------------------

    def authenticate(self) -> None:
        """Authenticate using GitHub OIDC or client secret."""

        oidc_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        oidc_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")

        if oidc_token and oidc_url:
            print("Using OIDC authentication (GitHub workload identity)")


            az_proc: subprocess.CompletedProcess[str] = subprocess.run(
                ["az", "account", "get-access-token", "--resource", "https://graph.microsoft.com"],
                capture_output=True,
                text=True,
                check=True,
            )
            token_data = json.loads(az_proc.stdout)
            self.access_token = token_data["accessToken"]
            print("✓ OIDC authentication successful")
            return

        # Local: client secret auth
        if self.client_secret:
            authority = f"https://login.microsoftonline.com/{self.tenant_id}"
            app = msal.ConfidentialClientApplication(
                self.client_id, authority=authority, client_credential=self.client_secret
            )
            msal_result: dict[str, Any] = app.acquire_token_for_client(
                scopes=["https://graph.microsoft.com/.default"]
            )

            if "access_token" in msal_result:
                self.access_token = msal_result["access_token"]
                print("✓ Client secret authentication successful")
                return

            raise Exception(f"Authentication failed: {msal_result.get('error_description')}")

        raise ValueError("No authentication method available")

    # --------------------------------------------------------------
    # Pull App Registrations Only
    # --------------------------------------------------------------

    def get_app_registrations(self) -> list[dict[str, Any]]:
        headers = {"Authorization": f"Bearer {self.access_token}"}
        all_apps: list[dict[str, Any]] = []

        url = (
            f"{self.graph_endpoint}/applications"
            f"?$select=displayName,appId,id,keyCredentials,passwordCredentials"
        )

        while url:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            all_apps.extend(data.get("value", []))
            url = data.get("@odata.nextLink")

        print(f"✓ Found {len(all_apps)} App Registrations")
        return all_apps

    # --------------------------------------------------------------
    # Categorize Expiring Certificates & Secrets
    # --------------------------------------------------------------

    def categorize_certificates(self, apps: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        # Use timezone-aware UTC, then strip tzinfo for arithmetic
        now = datetime.now(UTC).replace(tzinfo=None)
        today = now.date()
        tomorrow_date = today + timedelta(days=1)

        # Only build enabled buckets, in the defined order
        categories: dict[str, list[dict[str, Any]]] = {
            name: [] for name, cfg in self.expiry_buckets.items() if cfg["enabled"]
        }

        for app in apps:
            app_name = app.get("displayName")
            app_id = app.get("appId")
            object_id = app.get("id")
            portal_link = self.build_app_registration_link(object_id, app_id)

            # Process both certificates and secrets
            for source_list, source_type in [
                (app.get("keyCredentials", []), "Certificate"),
                (app.get("passwordCredentials", []), "Secret"),
            ]:
                for item in source_list:
                    end_str = item.get("endDateTime")
                    if not end_str:
                        continue

                    expiry = datetime.fromisoformat(
                        end_str.replace("Z", "+00:00")
                    ).replace(tzinfo=None)
                    delta = expiry - now
                    seconds = delta.total_seconds()

                    # Ignore already-expired creds (no "expired" bucket)
                    if seconds <= 0:
                        continue

                    delta_days = seconds / 86400.0
                    expiry_date = expiry.date()

                    cert_info = {
                        "app_name": app_name,
                        "app_id": app_id,
                        "object_id": object_id,
                        "type": source_type,
                        "key_id": item.get("keyId"),
                        "expiry_date": expiry,
                        "days_until_expiry": int(delta_days),
                        "portal_link": portal_link,
                        "source": "AppRegistration",
                    }

                    # ---------------------------
                    # TODAY (same UTC calendar date)
                    # ---------------------------
                    if (
                        self.expiry_buckets.get("today", {}).get("enabled")
                        and "today" in categories
                        and expiry_date == today
                    ):
                        categories["today"].append(cert_info)
                        continue

                    # ---------------------------
                    # TOMORROW (next UTC calendar date)
                    # ---------------------------
                    if (
                        self.expiry_buckets.get("tomorrow", {}).get("enabled")
                        and "tomorrow" in categories
                        and expiry_date == tomorrow_date
                    ):
                        categories["tomorrow"].append(cert_info)
                        continue

                    # ---------------------------
                    # OTHER RANGE-BASED BUCKETS
                    # (first matching enabled bucket wins)
                    # ---------------------------
                    for bucket_name, cfg in self.expiry_buckets.items():
                        if not cfg.get("enabled"):
                            continue
                        if bucket_name in ("today", "tomorrow"):
                            continue  # handled above

                        limit_days = cfg["days"]
                        if limit_days is None:
                            continue

                        if delta_days <= limit_days:
                            if bucket_name in categories:
                                categories[bucket_name].append(cert_info)
                            break

        return categories

    # --------------------------------------------------------------
    # Main Execution
    # --------------------------------------------------------------

    def run(self) -> None:
        try:
            print("Starting Azure App Registration Certificate Check...")
            print("-" * 60)

            self.authenticate()

            apps = self.get_app_registrations()

            categories = self.categorize_certificates(apps)

            all_certs = [cert for group in categories.values() for cert in group]

            changes = self.cache.get_changes(all_certs)

            # -------------------------------------------------
            # Print Summary
            # -------------------------------------------------
            print("\nCERTIFICATE EXPIRATION SUMMARY")
            print("=" * 60)
            for bucket in categories:
                print(f"{bucket.replace('_', ' ').title()}: {len(categories[bucket])}")
            print("-" * 60)
            print(f"New: {len(changes['new'])}")
            print(f"Removed: {len(changes['removed'])}")
            print(f"Changed: {len(changes['expiry_changed'])}")
            print("=" * 60)

            # -------------------------------------------------
            # IMPORTANT FIX:
            # Update cache BEFORE sending Slack alerts
            # -------------------------------------------------
            self.cache.update_certificates(all_certs)
            self.cache.save_cache()

            # Slack notification
            if self.cache.should_notify(categories, changes, summary_days=self.summary_days):
                send_slack_notification(categories, self.slack_webhook, changes)
            else:
                print("ℹ No notification sent.")

            print("\n✓ Certificate check completed successfully")

            if categories.get("expired") or categories.get("tomorrow"):
                sys.exit(1)

        except Exception as e:
            print(f"✗ Error: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)


if __name__ == "__main__":
    CertificateChecker().run()
