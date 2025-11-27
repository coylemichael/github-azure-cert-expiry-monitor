import json
import subprocess
from datetime import UTC, datetime, timedelta

import pytest

from check_certificates import EXPIRY_BUCKETS, SUMMARY_DAYS, CertificateChecker


@pytest.fixture(autouse=True)
def _chdir_tmp(tmp_path, monkeypatch):
    """Run tests in an isolated temp directory to avoid touching real cache files."""
    monkeypatch.chdir(tmp_path)


@pytest.fixture(autouse=True)
def _set_env(monkeypatch):
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://example.com/hook")
    yield
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)


def test_authenticate_prefers_oidc_when_running_in_actions(monkeypatch):
    """CI path: uses azure/login token via az; no client secret."""
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://example.com/hook")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)

    called = {}

    def fake_run(cmd, capture_output, text, check):
        called["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"accessToken": "oidc-token"}), stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    checker = CertificateChecker()
    checker.authenticate()

    assert checker.access_token == "oidc-token"
    assert called["cmd"][0:3] == ["az", "account", "get-access-token"]


def test_authenticate_uses_client_secret_locally(monkeypatch):
    """Local path: falls back to client secret auth when not in Actions."""
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://example.com/hook")
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)

    class FakeApp:
        def __init__(self, client_id, authority, client_credential):
            self.called_with = (client_id, authority, client_credential)

        def acquire_token_for_client(self, scopes):
            return {"access_token": "secret-token"}

    monkeypatch.setattr("check_certificates.msal.ConfidentialClientApplication", FakeApp)

    checker = CertificateChecker()
    checker.authenticate()

    assert checker.access_token == "secret-token"


def test_authenticate_raises_when_no_auth_available(monkeypatch):
    """No OIDC and no client secret should raise a ValueError to fail fast."""
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://example.com/hook")

    checker = CertificateChecker()
    with pytest.raises(ValueError):
        checker.authenticate()


def test_categorize_certificates_buckets_and_skips_expired(monkeypatch):
    """Bucket math: correct placement and expired items dropped."""
    # Fixed "now" so bucket math is deterministic
    fixed_now = datetime(2025, 1, 1, 12, 0, tzinfo=UTC)

    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_now if tz else fixed_now.replace(tzinfo=None)

    monkeypatch.setattr("check_certificates.datetime", FixedDateTime)

    def iso_in(days, hours=0):
        return (fixed_now + timedelta(days=days, hours=hours)).isoformat().replace("+00:00", "Z")

    apps = [
        {
            "displayName": "AppOne",
            "appId": "appid1",
            "id": "obj1",
            "keyCredentials": [
                {"keyId": "k1", "endDateTime": iso_in(0, 1)},  # today
                {"keyId": "k2", "endDateTime": iso_in(1)},  # tomorrow
                {"keyId": "k3", "endDateTime": iso_in(2)},  # forty_eight_hours
                {"keyId": "k4", "endDateTime": iso_in(10)},  # two_weeks
                {"keyId": "k5", "endDateTime": iso_in(25)},  # one_month
                {"keyId": "k6", "endDateTime": iso_in(-1)},  # expired -> skipped
            ],
            "passwordCredentials": [],
        }
    ]

    checker = CertificateChecker()
    categories = checker.categorize_certificates(apps)

    assert len(categories["today"]) == 1
    assert len(categories["tomorrow"]) == 1
    assert len(categories["forty_eight_hours"]) == 1
    assert len(categories["two_weeks"]) == 1
    assert len(categories["one_month"]) == 1
    assert all("k6" not in c["key_id"] for bucket in categories.values() for c in bucket)


def test_portal_link_points_to_credentials_blade():
    """Slack links should land on the Credentials blade with ids included."""
    checker = CertificateChecker()
    link = checker.build_app_registration_link("object-id", "app-id")
    assert "Credentials" in link
    assert "objectId/object-id" in link
    assert "appId/app-id" in link


def test_run_no_notification(monkeypatch):
    """Run path: no notify when nothing triggers; still updates cache."""
    # Environment already set by fixture
    checker = CertificateChecker()

    checker.authenticate = lambda: None
    checker.get_app_registrations = lambda: []
    checker.categorize_certificates = lambda apps: {"today": [], "tomorrow": [], "two_weeks": []}

    calls = {}

    class FakeCache:
        def get_changes(self, all_certs):
            calls["get_changes"] = True
            return {"new": [], "removed": [], "expiry_changed": []}

        def update_certificates(self, all_certs):
            calls["update"] = True

        def save_cache(self):
            calls["save"] = True

        def should_notify(self, categories, changes, summary_days=None):
            calls["should_notify"] = True
            return False

    checker.cache = FakeCache()
    monkeypatch.setattr(
        "check_certificates.send_slack_notification", lambda *args, **kwargs: calls.setdefault("slack", True)
    )

    checker.run()

    assert calls.get("get_changes")
    assert calls.get("update")
    assert calls.get("save")
    assert calls.get("should_notify")
    assert "slack" not in calls


def test_run_with_notification(monkeypatch):
    """Run path: when notify is True, Slack is called and cache saved."""
    checker = CertificateChecker()

    checker.authenticate = lambda: None
    checker.get_app_registrations = lambda: []
    checker.categorize_certificates = lambda apps: {"today": [], "tomorrow": [], "two_weeks": []}

    calls = {}

    class FakeCache:
        def get_changes(self, all_certs):
            return {"new": [], "removed": [], "expiry_changed": []}

        def update_certificates(self, all_certs):
            calls["update"] = True

        def save_cache(self):
            calls["save"] = True

        def should_notify(self, categories, changes, summary_days=None):
            return True

    checker.cache = FakeCache()
    monkeypatch.setattr(
        "check_certificates.send_slack_notification", lambda *args, **kwargs: calls.setdefault("slack", True)
    )

    checker.run()

    assert calls.get("update")
    assert calls.get("save")
    assert calls.get("slack")


def test_run_bubbles_exit_on_error(monkeypatch):
    """Run path: on exception we exit(1) after logging."""
    checker = CertificateChecker()
    checker.authenticate = lambda: (_ for _ in ()).throw(RuntimeError("boom"))

    exit_called = {}

    def fake_exit(code):
        exit_called["code"] = code
        raise SystemExit(code)

    monkeypatch.setattr("sys.exit", fake_exit)

    with pytest.raises(SystemExit):
        checker.run()

    assert exit_called.get("code") == 1


def test_constants_guardrails():
    """Protect default cadence/bucket switches from accidental edits."""
    assert SUMMARY_DAYS == {0, 3}
    assert EXPIRY_BUCKETS["today"]["enabled"] is True
    assert EXPIRY_BUCKETS["six_months"]["enabled"] is False
