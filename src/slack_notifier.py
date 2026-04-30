"""
Slack notification module for certificate expiration alerts.

Key goals:
- Robust timezone handling (treat naive as UTC, normalize everything to UTC aware).
- Accept expiry as datetime, date, or ISO-8601 string (with or without "Z").
- Keep messages compact while still readable in Slack.
"""

from datetime import UTC, date, datetime
from typing import Any

import requests

UTC = UTC

MAX_SLACK_ITEMS = 10


def _to_utc_aware(dt: Any) -> datetime:
    """Coerce input into a UTC-aware datetime."""
    if isinstance(dt, datetime):
        d = dt
    elif isinstance(dt, date):
        d = datetime(dt.year, dt.month, dt.day)
    elif isinstance(dt, str):
        s = dt.strip()
        if s.endswith(("Z", "z")):
            s = s[:-1] + "+00:00"
        d = datetime.fromisoformat(s)
    else:
        raise TypeError(f"expiry must be datetime-date-ISO string, got: {type(dt)!r}")

    if d.tzinfo is None or d.utcoffset() is None:
        return d.replace(tzinfo=UTC)
    return d.astimezone(UTC)


def _human_time_until(expiry: Any) -> str:
    expiry_dt = _to_utc_aware(expiry)
    now = datetime.now(UTC)

    seconds = int((expiry_dt - now).total_seconds())
    if seconds <= 0:
        return "now"

    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)

    if days > 1:
        return f"in {days} days"
    if days == 1:
        return "in 1 day"
    if hours > 1:
        return f"in {hours} hours"
    if hours == 1:
        return "in 1 hour"
    if minutes > 1:
        return f"in {minutes} minutes"
    if minutes == 1:
        return "in 1 minute"
    return "in less than a minute"


def _human_time_since(expiry: Any) -> str:
    """Human-readable time since expiry (for recently expired items)."""
    expiry_dt = _to_utc_aware(expiry)
    now = datetime.now(UTC)

    seconds = int((now - expiry_dt).total_seconds())
    if seconds <= 0:
        return "just now"

    days, rem = divmod(seconds, 86400)
    hours, _ = divmod(rem, 3600)

    if days > 1:
        return f"{days} days ago"
    if days == 1:
        return "1 day ago"
    if hours > 1:
        return f"{hours} hours ago"
    if hours == 1:
        return "1 hour ago"
    return "less than an hour ago"


def _compact_when(when: str) -> str:
    return (
        when.replace(" days", "d")
        .replace(" day", "d")
        .replace(" hours", "h")
        .replace(" hour", "h")
        .replace(" minutes", "m")
        .replace(" minute", "m")
    )


def format_cert_list(certs: list[dict[str, Any]], is_expired: bool = False) -> str:
    if not certs:
        return "_None_"

    lines: list[str] = []
    for cert in certs[:MAX_SLACK_ITEMS]:
        app_name = cert.get("app_name", "(unknown app)")
        expiry_raw = cert.get("expiry_date")
        portal_link = cert.get("portal_link", "")

        try:
            expiry_dt = _to_utc_aware(expiry_raw)
            date_str = expiry_dt.strftime("%d-%m-%y")
            time_str = expiry_dt.strftime("%H:%M")
            if is_expired:
                when_full = _human_time_since(expiry_dt)
                when_compact = _compact_when(when_full)
            else:
                when_full = _human_time_until(expiry_dt)
                when_compact = _compact_when(when_full)
            date_link = f"<{portal_link}|{date_str}>" if portal_link else date_str
            type_icon = "📜" if cert.get("type") == "Certificate" else "🔑"
            lines.append(f"{type_icon} [`{app_name}`] · {when_compact} · {date_link} · {time_str}")
        except Exception as exc:  # pragma: no cover - defensive
            print(f"Skipping item due to expiry parse error: app={app_name!r} " f"expiry={expiry_raw!r} error={exc!r}")
            lines.append(f"[`{app_name}`] · (invalid expiry)")

    if len(certs) > MAX_SLACK_ITEMS:
        lines.append(f"_...and {len(certs) - MAX_SLACK_ITEMS} more_")

    return "\n".join(lines)


def build_slack_blocks(
    categories: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []

    total_items = sum(len(v) for v in categories.values())
    if total_items == 0:
        blocks.append(
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "Credential Status: All Clear", "emoji": False},
            }
        )
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "No credentials are expiring within the configured time windows.",
                },
            }
        )
        return blocks

    icon = (
        "🚨" if (categories.get("recently_expired") or categories.get("today") or categories.get("tomorrow")) else "🔔"
    )

    blocks.append(
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{icon} Azure Credential Expiration Alert", "emoji": False},
        }
    )

    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        f"Credential check - "
                        f"{datetime.now(UTC).strftime('%Y-%m-%d %H:%M')} "
                        f"(all times in UTC - DD-MM-YY) · 🔑 = Secret · 📜 = Certificate"
                    ),
                }
            ],
        }
    )

    blocks.append({"type": "divider"})

    for bucket_name, certs in categories.items():
        if not certs:
            continue

        is_expired = bucket_name == "recently_expired"
        label = "Expired Within Last 30 Days" if is_expired else bucket_name.replace("_", " ").title()
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"* {label} ({len(certs)})*\n{format_cert_list(certs, is_expired=is_expired)}",
                },
            }
        )
        blocks.append({"type": "divider"})

    return blocks


def send_slack_notification(
    categories: dict[str, list[dict[str, Any]]],
    webhook_url: str,
) -> None:
    blocks = build_slack_blocks(categories)

    if categories.get("recently_expired") or categories.get("today") or categories.get("tomorrow"):
        color = "danger"
    elif categories.get("forty_eight_hours") or categories.get("two_weeks"):
        color = "warning"
    else:
        color = "good"

    payload = {
        "blocks": blocks,
        "attachments": [
            {
                "color": color,
                "fallback": f"Credential expiration alert: {sum(len(v) for v in categories.values())} items need attention",
            }
        ],
    }

    response = requests.post(webhook_url, json=payload, timeout=10)
    response.raise_for_status()
    print("Successfully sent Slack notification")
