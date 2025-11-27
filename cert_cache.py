"""
Certificate cache management for tracking expiration states
Reduces API calls and enables change detection
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any


class CertificateCache:
    def __init__(self, cache_file: str = "cert_cache.json") -> None:
        self.cache_file = Path(cache_file)
        self.cache: dict[str, Any] = self._load_cache()

    def _load_cache(self) -> dict[str, Any]:
        """Load existing cache from disk."""
        if self.cache_file.exists():
            try:
                with self.cache_file.open() as f:
                    data: dict[str, Any] = json.load(f)
                    return data
            except (json.JSONDecodeError, OSError) as e:
                print(f"⚠ Warning: Could not load cache: {e}")
        return {"last_updated": None, "certificates": {}}

    def save_cache(self) -> None:
        """Save cache to disk."""
        self.cache["last_updated"] = datetime.utcnow().isoformat()
        with self.cache_file.open("w") as f:
            json.dump(self.cache, f, indent=2)
        print(f"✓ Cache saved to {self.cache_file}")

    def get_certificate_key(self, cert_info: dict[str, Any]) -> str:
        """Generate unique key for certificate."""
        return f"{cert_info['app_id']}:{cert_info['key_id']}"

    def update_certificates(self, new_certs: list[dict[str, Any]]) -> None:
        """Update cache with new certificate data."""
        cert_dict: dict[str, Any] = {}
        for cert in new_certs:
            key = self.get_certificate_key(cert)
            expiry = cert["expiry_date"]
            if isinstance(expiry, datetime):
                expiry_str = expiry.isoformat()
            else:
                expiry_str = str(expiry)

            cert_dict[key] = {
                "app_name": cert["app_name"],
                "app_id": cert["app_id"],
                "object_id": cert.get("object_id", ""),
                "type": cert.get("type", ""),
                "key_id": cert.get("key_id", ""),
                "expiry_date": expiry_str,
                "days_until_expiry": cert.get("days_until_expiry"),
                "portal_link": cert.get("portal_link", ""),
                "source": cert.get("source", ""),
                "last_seen": datetime.utcnow().isoformat(),
            }

        self.cache["certificates"] = cert_dict

    def get_changes(self, current_certs: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        """Detect new, removed, and changed certificates."""
        changes: dict[str, list[dict[str, Any]]] = {
            "new": [],
            "removed": [],
            "expiry_changed": [],
        }

        current_map = {self.get_certificate_key(c): c for c in current_certs}
        cached_map: dict[str, Any] = self.cache.get("certificates", {})

        current_keys = set(current_map.keys())
        cached_keys = set(cached_map.keys())

        # New certificates
        for key in current_keys - cached_keys:
            changes["new"].append(current_map[key])

        # Removed certificates
        for key in cached_keys - current_keys:
            changes["removed"].append(cached_map[key])

        # Certificates with changed expiry dates
        for key in current_keys & cached_keys:
            cached_cert = cached_map[key]
            cached_expiry = cached_cert.get("expiry_date")

            current_cert = current_map[key]
            current_expiry = current_cert.get("expiry_date")
            if isinstance(current_expiry, datetime):
                current_expiry_str = current_expiry.isoformat()
            else:
                current_expiry_str = str(current_expiry)

            if cached_expiry and cached_expiry != current_expiry_str:
                changes["expiry_changed"].append(current_cert)

        return changes

    def should_notify(
        self,
        categories: dict[str, list[dict[str, Any]]],
        changes: dict[str, list[dict[str, Any]]],
        summary_days: set[int] | list[int] | None = None,
    ) -> bool:
        """
        Determine if we should send a notification based on changes and urgency.

        Logic:
        - Always notify if something is expiring TODAY or TOMORROW.
        - Notify if there are new/removed/changed certificates.
        - Always send a scheduled summary on configured days (UTC).
        """
        # Critical expirations
        if categories.get("today") or categories.get("tomorrow"):
            return True

        # Structural changes in cert set
        if changes["new"] or changes["removed"] or changes["expiry_changed"]:
            return True

        # Scheduled summaries (defaults to Monday and Thursday)
        summary_day_set = set(summary_days) if summary_days else {0, 3}
        if datetime.utcnow().weekday() in summary_day_set:
            return True

        return False

    def get_last_updated(self) -> str | None:
        """Get when cache was last updated."""
        return self.cache.get("last_updated")
