import re
from datetime import UTC, datetime, timedelta

import pytest

from cert_cache import CertificateCache
from slack_notifier import build_slack_blocks, format_cert_list, send_slack_notification


def _fake_cert(app_name: str, days: int) -> dict:
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


def test_cache_detects_new_removed_changed(tmp_path, monkeypatch):
    """Cache diffing: finds new, removed, and expiry-changed certs."""
    monkeypatch.chdir(tmp_path)
    cache = CertificateCache()

    first = [_fake_cert("one", 5), _fake_cert("two", 10)]
    cache.update_certificates(first)
    cache.save_cache()

    # New cert, removed cert, changed expiry
    second = [_fake_cert("one", 7), _fake_cert("three", 2)]
    changes = cache.get_changes(second)

    assert len(changes["new"]) == 1  # three
    assert len(changes["removed"]) == 1  # two
    assert len(changes["expiry_changed"]) == 1  # one


def test_should_notify_on_today_tomorrow_and_changes(tmp_path, monkeypatch):
    """Notify when critical buckets or structural changes occur."""
    monkeypatch.chdir(tmp_path)
    cache = CertificateCache()

    cats = {"today": [_fake_cert("one", 0)], "tomorrow": [], "two_weeks": []}
    assert cache.should_notify(cats, {"new": [], "removed": [], "expiry_changed": []}) is True

    cats = {"today": [], "tomorrow": [], "two_weeks": []}
    changes = {"new": [_fake_cert("one", 5)], "removed": [], "expiry_changed": []}
    assert cache.should_notify(cats, changes, summary_days=set()) is True

    # Summary day default (Monday/Thursday)
    cats = {"today": [], "tomorrow": [], "two_weeks": []}
    assert (
        cache.should_notify(
            cats, {"new": [], "removed": [], "expiry_changed": []}, summary_days={datetime.now(UTC).weekday()}
        )
        is True
    )


def test_format_cert_list_and_blocks_render():
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


def test_should_notify_false_when_no_triggers_not_summary(tmp_path, monkeypatch):
    """No critical items and not a summary day should suppress alerts."""
    monkeypatch.chdir(tmp_path)
    cache = CertificateCache()
    cats = {"today": [], "tomorrow": [], "two_weeks": []}
    changes = {"new": [], "removed": [], "expiry_changed": []}
    # Sunday (6) not in default summary days {0,3}
    assert cache.should_notify(cats, changes, summary_days={6}) is False


def test_build_slack_blocks_all_clear():
    """All-clear state produces a clear header message."""
    blocks = build_slack_blocks({"today": [], "tomorrow": []})
    header = next((b for b in blocks if b.get("type") == "header"), {})
    assert "All Clear" in header.get("text", {}).get("text", "")


def test_send_slack_notification_sets_color(monkeypatch):
    """Slack payload color matches urgency across buckets."""
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["payload"] = json

        class Resp:
            def raise_for_status(self):
                return None

        return Resp()

    monkeypatch.setattr("slack_notifier.requests.post", fake_post)

    cats = {"today": [_fake_cert("one", 0)], "tomorrow": [], "forty_eight_hours": []}
    send_slack_notification(cats, "https://example.com/hook", changes=None)
    assert captured["payload"]["attachments"][0]["color"] == "danger"

    cats_warning = {"today": [], "tomorrow": [], "forty_eight_hours": [_fake_cert("one", 2)]}
    send_slack_notification(cats_warning, "https://example.com/hook", changes=None)
    assert captured["payload"]["attachments"][0]["color"] == "warning"

    cats_good = {"today": [], "tomorrow": [], "forty_eight_hours": []}
    send_slack_notification(cats_good, "https://example.com/hook", changes=None)
    assert captured["payload"]["attachments"][0]["color"] == "good"


def test_send_slack_notification_propagates_errors(monkeypatch):
    """Slack HTTP errors should bubble up to fail the run."""

    class Boom(Exception):
        pass

    def fake_post(url, json=None, timeout=None):
        raise Boom("fail")

    monkeypatch.setattr("slack_notifier.requests.post", fake_post)

    cats = {"today": [], "tomorrow": [], "forty_eight_hours": []}
    with pytest.raises(Boom):
        send_slack_notification(cats, "https://example.com/hook", changes=None)
