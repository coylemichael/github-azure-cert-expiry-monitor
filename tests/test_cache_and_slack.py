import re
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pytest import MonkeyPatch

from slack_notifier import build_slack_blocks, format_cert_list, send_slack_notification


def _fake_cert(app_name: str, days: int) -> dict[str, Any]:
    expiry = datetime.now(UTC) + timedelta(days=days)
    return {
        "app_name": app_name,
        "app_id": "app-id",
        "object_id": "obj-id",
        "type": "Certificate",
        "key_id": f"k-{app_name}",
        "expiry_date": expiry,
        "days_until_expiry": days,
        "portal_link": "https://example.com",
        "source": "AppRegistration",
    }


def test_format_cert_list_and_blocks_render() -> None:
    """Slack formatting renders items and sections correctly."""
    certs = [_fake_cert("app", 1)]
    text = format_cert_list(certs)
    assert "app" in text
    assert re.search(r"in \d+(d|h|m)", text)  # allow hour/day granularity

    blocks = build_slack_blocks({"today": certs, "tomorrow": []})
    assert any(block.get("type") == "header" for block in blocks)
    assert any(
        "today" in block.get("text", {}).get("text", "").lower() for block in blocks if block.get("type") == "section"
    )


def test_format_cert_list_expired_shows_ago() -> None:
    """Expired items should show 'X days ago' instead of 'in X days'."""
    certs = [_fake_cert("expired-app", -5)]
    text = format_cert_list(certs, is_expired=True)
    assert "expired-app" in text
    assert re.search(r"\d+d ago", text)


def test_format_cert_list_differentiates_cert_and_secret() -> None:
    """Cert and Secret types should render with distinct icons at line start."""
    cert = _fake_cert("cert-app", 5)
    cert["type"] = "Certificate"
    secret = _fake_cert("secret-app", 5)
    secret["type"] = "Secret"

    cert_text = format_cert_list([cert])
    assert cert_text.startswith("📜")
    assert "🔑" not in cert_text

    secret_text = format_cert_list([secret])
    assert secret_text.startswith("🔑")
    assert "📜" not in secret_text


def test_build_slack_blocks_all_clear() -> None:
    """All-clear state produces a clear header message."""
    blocks = build_slack_blocks({"today": [], "tomorrow": []})
    header = next((b for b in blocks if b.get("type") == "header"), {})
    assert "All Clear" in header.get("text", {}).get("text", "")


def test_build_slack_blocks_recently_expired_label() -> None:
    """Recently expired bucket should render with 'Expired Within Last 30 Days' label."""
    cats: dict[str, list[dict[str, Any]]] = {
        "recently_expired": [_fake_cert("old-app", -10)],
        "today": [],
        "tomorrow": [],
    }
    blocks = build_slack_blocks(cats)
    section_texts = [b["text"]["text"] for b in blocks if b.get("type") == "section"]
    assert any("Expired Within Last 30 Days" in t for t in section_texts)


def test_build_slack_blocks_recently_expired_triggers_alert_icon() -> None:
    """Recently expired items should trigger the alert icon."""
    cats: dict[str, list[dict[str, Any]]] = {
        "recently_expired": [_fake_cert("old-app", -3)],
        "today": [],
        "tomorrow": [],
    }
    blocks = build_slack_blocks(cats)
    header = next((b for b in blocks if b.get("type") == "header"), {})
    assert "🚨" in header.get("text", {}).get("text", "")


def test_send_slack_notification_sets_color(monkeypatch: MonkeyPatch) -> None:
    """Slack payload color matches urgency across buckets."""
    captured: dict[str, Any] = {}

    def fake_post(url: str, json: Any = None, timeout: int | float | None = None) -> Any:
        captured["payload"] = json

        class Resp:
            def raise_for_status(self) -> None:
                return None

        return Resp()

    class FakeSession:
        def post(self, url: str, json: Any = None, timeout: int | float | None = None) -> Any:
            return fake_post(url, json=json, timeout=timeout)

    monkeypatch.setattr("slack_notifier._get_session", lambda: FakeSession())

    # danger: today has items
    cats = {"today": [_fake_cert("one", 0)], "tomorrow": [], "forty_eight_hours": []}
    send_slack_notification(cats, "https://hooks.slack.com/hook")
    assert captured["payload"]["attachments"][0]["color"] == "danger"

    # danger: recently_expired has items
    cats_expired: dict[str, list[dict[str, Any]]] = {
        "recently_expired": [_fake_cert("old", -5)],
        "today": [],
        "tomorrow": [],
        "forty_eight_hours": [],
    }
    send_slack_notification(cats_expired, "https://hooks.slack.com/hook")
    assert captured["payload"]["attachments"][0]["color"] == "danger"

    # warning: forty_eight_hours
    cats_warning: dict[str, list[dict[str, Any]]] = {
        "today": [],
        "tomorrow": [],
        "forty_eight_hours": [_fake_cert("one", 2)],
    }
    send_slack_notification(cats_warning, "https://hooks.slack.com/hook")
    assert captured["payload"]["attachments"][0]["color"] == "warning"

    # good: nothing urgent
    cats_good: dict[str, list[dict[str, Any]]] = {"today": [], "tomorrow": [], "forty_eight_hours": []}
    send_slack_notification(cats_good, "https://hooks.slack.com/hook")
    assert captured["payload"]["attachments"][0]["color"] == "good"


def test_send_slack_notification_propagates_errors(monkeypatch: MonkeyPatch) -> None:
    """Slack HTTP errors should bubble up to fail the run."""

    class Boom(Exception):
        pass

    class FakeSession:
        def post(self, url: str, json: Any = None, timeout: int | float | None = None) -> Any:
            raise Boom("fail")

    monkeypatch.setattr("slack_notifier._get_session", lambda: FakeSession())

    cats: dict[str, list[dict[str, Any]]] = {"today": [], "tomorrow": [], "forty_eight_hours": []}
    with pytest.raises(Boom):
        send_slack_notification(cats, "https://hooks.slack.com/hook")
