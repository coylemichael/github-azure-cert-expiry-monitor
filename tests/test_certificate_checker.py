import json
import subprocess
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import time_machine
from pytest import MonkeyPatch

from check_certificates import EXPIRY_BUCKETS, SUMMARY_DAYS, CertificateChecker


@pytest.fixture(autouse=True)
def _set_env(monkeypatch: MonkeyPatch) -> Generator[None]:
    """Set required env vars for tests and clean up afterward."""
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/hook")
    yield
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)


def test_authenticate_prefers_oidc_when_running_in_actions(monkeypatch: MonkeyPatch) -> None:
    """CI path: uses azure/login token via az; no client secret."""
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/hook")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)

    called = {}

    def fake_run(cmd: list[str], capture_output: bool, text: bool, check: bool) -> subprocess.CompletedProcess[str]:
        called["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"accessToken": "oidc-token"}), stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    checker = CertificateChecker()
    checker.authenticate()

    assert checker.access_token == "oidc-token"
    assert called["cmd"][0:3] == ["az", "account", "get-access-token"]


def test_authenticate_uses_client_secret_locally(monkeypatch: MonkeyPatch) -> None:
    """Local path: falls back to client secret auth when not in Actions."""
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/hook")
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)

    class FakeApp:
        def __init__(self, client_id: str, authority: str, client_credential: str):
            self.called_with = (client_id, authority, client_credential)

        def acquire_token_for_client(self, scopes: list[str]) -> dict[str, str]:
            return {"access_token": "secret-token"}

    monkeypatch.setattr("check_certificates.msal.ConfidentialClientApplication", FakeApp)

    checker = CertificateChecker()
    checker.authenticate()

    assert checker.access_token == "secret-token"


def test_authenticate_raises_when_no_auth_available(monkeypatch: MonkeyPatch) -> None:
    """No OIDC and no client secret should raise a ValueError to fail fast."""
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/hook")

    checker = CertificateChecker()
    with pytest.raises(ValueError):
        checker.authenticate()


@time_machine.travel(datetime(2025, 1, 1, 12, 0, tzinfo=UTC), tick=False)
def test_categorize_certificates_buckets_and_skips_expired() -> None:
    """Bucket math: correct placement and old expired items dropped."""
    fixed_now = datetime(2025, 1, 1, 12, 0, tzinfo=UTC)

    def iso_in(days: int, hours: int = 0) -> str:
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
                {"keyId": "k6", "endDateTime": iso_in(-5)},  # recently expired
                {"keyId": "k7", "endDateTime": iso_in(-60)},  # expired too long ago -> skipped
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
    assert len(categories["recently_expired"]) == 1
    assert categories["recently_expired"][0]["key_id"] == "k6"
    # k7 expired more than 30 days ago, should not appear anywhere
    assert all("k7" not in c["key_id"] for bucket in categories.values() for c in bucket)


def test_portal_link_points_to_credentials_blade() -> None:
    """Slack links should land on the Credentials blade with ids included."""
    checker = CertificateChecker()
    link = checker.build_app_registration_link("object-id", "app-id")
    assert "Credentials" in link
    assert "objectId/object-id" in link
    assert "appId/app-id" in link


def test_run_no_notification(monkeypatch: MonkeyPatch) -> None:
    """Run path: no notify when nothing triggers; Slack not called."""
    # Environment already set by fixture
    checker = CertificateChecker()

    monkeypatch.setattr(checker, "authenticate", lambda: None)
    monkeypatch.setattr(checker, "get_app_registrations", lambda: [])
    monkeypatch.setattr(
        checker,
        "categorize_certificates",
        lambda apps: {"recently_expired": [], "today": [], "tomorrow": [], "two_weeks": []},
    )
    monkeypatch.setattr(checker, "should_notify", lambda cats: False)

    calls: dict[str, Any] = {}
    monkeypatch.setattr(
        "check_certificates.send_slack_notification", lambda *args, **kwargs: calls.setdefault("slack", True)
    )

    checker.run()

    assert "slack" not in calls


def test_run_with_notification(monkeypatch: MonkeyPatch) -> None:
    """Run path: when notify is True, Slack is called."""
    checker = CertificateChecker()

    monkeypatch.setattr(checker, "authenticate", lambda: None)
    monkeypatch.setattr(checker, "get_app_registrations", lambda: [])
    monkeypatch.setattr(
        checker,
        "categorize_certificates",
        lambda apps: {"recently_expired": [], "today": [], "tomorrow": [], "two_weeks": []},
    )
    monkeypatch.setattr(checker, "should_notify", lambda cats: True)

    calls: dict[str, Any] = {}
    monkeypatch.setattr(
        "check_certificates.send_slack_notification", lambda *args, **kwargs: calls.setdefault("slack", True)
    )

    checker.run()

    assert calls.get("slack")


def test_run_bubbles_exit_on_error(monkeypatch: MonkeyPatch) -> None:
    """Run path: on exception we exit(2) for runtime errors."""
    checker = CertificateChecker()

    def fail_auth() -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(checker, "authenticate", fail_auth)

    with pytest.raises(SystemExit) as exc_info:
        checker.run()

    assert exc_info.value.code == CertificateChecker.EXIT_ERROR


def test_constants_guardrails() -> None:
    """Protect default cadence/bucket switches from accidental edits."""
    assert SUMMARY_DAYS == {0, 3}
    assert EXPIRY_BUCKETS["recently_expired"]["enabled"] is True
    assert EXPIRY_BUCKETS["recently_expired"]["days"] == -30
    assert EXPIRY_BUCKETS["today"]["enabled"] is True
    assert EXPIRY_BUCKETS["six_months"]["enabled"] is False


def test_should_notify_true_when_items_exist(monkeypatch: MonkeyPatch) -> None:
    """Notify when any bucket has items."""
    checker = CertificateChecker()
    cats: dict[str, list[dict[str, Any]]] = {
        "recently_expired": [{"app_name": "test"}],
        "today": [],
        "tomorrow": [],
    }
    assert checker.should_notify(cats) is True


def test_should_notify_true_on_summary_day(monkeypatch: MonkeyPatch) -> None:
    """Notify on scheduled summary days even with empty buckets."""
    checker = CertificateChecker()
    checker.summary_days = {datetime.now(UTC).weekday()}  # force today to be a summary day
    cats: dict[str, list[dict[str, Any]]] = {"recently_expired": [], "today": [], "tomorrow": []}
    assert checker.should_notify(cats) is True


def test_should_notify_false_when_empty_not_summary_day(monkeypatch: MonkeyPatch) -> None:
    """No items and not a summary day should suppress."""
    checker = CertificateChecker()
    checker.summary_days = set()  # no summary days
    cats: dict[str, list[dict[str, Any]]] = {"recently_expired": [], "today": [], "tomorrow": []}
    assert checker.should_notify(cats) is False
