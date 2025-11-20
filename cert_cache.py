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
        """Load existing cache from disk"""
        if self.cache_file.exists():
            try:
                with open(self.cache_file) as f:
                    data: dict[str, Any] = json.load(f)
                    return data
            except (json.JSONDecodeError, OSError) as e:
                print(f"⚠ Warning: Could not load cache: {e}")
        return {"last_updated": None, "certificates": {}}

    def save_cache(self) -> None:
        """Save cache to disk"""
        self.cache["last_updated"] = datetime.utcnow().isoformat()
        with open(self.cache_file, "w") as f:
            json.dump(self.cache, f, indent=2, default=str)
        print(f"✓ Cache saved to {self.cache_file}")

    def get_certificate_key(self, cert_info: dict[str, Any]) -> str:
        """Generate unique key for certificate"""
        return f"{cert_info['app_id']}:{cert_info['key_id']}"

    def update_certificates(self, new_certs: list[dict[str, Any]]) -> None:
        """Update cache with new certificate data"""
        cert_dict: dict[str, Any] = {}
        for cert in new_certs:
            key = self.get_certificate_key(cert)
            cert_dict[key] = {
                "app_name": cert["app_name"],
                "app_id": cert["app_id"],
                "type": cert["type"],
                "key_id": cert["key_id"],
                "expiry_date": cert["expiry_date"].isoformat()
                if isinstance(cert["expiry_date"], datetime)
                else cert["expiry_date"],
                "days_until_expiry": cert["days_until_expiry"],
                "last_seen": datetime.utcnow().isoformat(),
            }
        self.cache["certificates"] = cert_dict

    def get_changes(self, current_certs: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        """Detect new, removed, and changed certificates"""
        changes: dict[str, list[dict[str, Any]]] = {"new": [], "removed": [], "expiry_changed": []}

        current_keys = {self.get_certificate_key(cert): cert for cert in current_certs}
        cached_keys = set(self.cache.get("certificates", {}).keys())

        # Find new certificates
        for key, cert in current_keys.items():
            if key not in cached_keys:
                changes["new"].append(cert)

        # Find removed certificates
        for key in cached_keys:
            if key not in current_keys:
                cached_cert = self.cache["certificates"][key]
                changes["removed"].append(cached_cert)

        # Find certificates with changed expiry dates (rare but possible)
        for key, cert in current_keys.items():
            if key in cached_keys:
                cached_cert = self.cache["certificates"][key]
                cached_expiry = cached_cert.get("expiry_date")
                current_expiry = (
                    cert["expiry_date"].isoformat()
                    if isinstance(cert["expiry_date"], datetime)
                    else cert["expiry_date"]
                )
                if cached_expiry and cached_expiry != current_expiry:
                    changes["expiry_changed"].append(cert)

        return changes

    def should_notify(
        self, categories: dict[str, list[dict[str, Any]]], changes: dict[str, list[dict[str, Any]]]
    ) -> bool:
        """Determine if we should send a notification based on changes and urgency"""
        # Always notify if there are critical expirations
        if categories["expired"] or categories["tomorrow"]:
            return True

        # Notify if new certificates are expiring soon
        if changes["new"]:
            return True

        # Notify if certificates were removed (possible rotation)
        if changes["removed"]:
            return True

        # Notify if expiry dates changed
        if changes["expiry_changed"]:
            return True

        # For weekly runs, always send summary even if no changes (on Monday)
        day_of_week = datetime.utcnow().weekday()
        if day_of_week == 0:  # Monday
            return True

        return False

    def get_last_updated(self) -> str | None:
        """Get when cache was last updated"""
        return self.cache.get("last_updated")
