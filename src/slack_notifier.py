"""
Slack notification module for certificate expiration alerts
Formats and sends color-coded messages based on urgency levels
"""

from datetime import UTC, datetime, time
from typing import Any

import requests

MAX_SLACK_ITEMS = 10  # limit items per bucket to avoid huge messages


def _human_time_until(expiry: datetime) -> str:
    """
    Return strings like:
      - 'in 17 minutes'
      - 'in 3 hours'
      - 'in 5 days'
      - 'in less than a minute'
    """
    expiry_dt = _normalize_expiry(expiry)

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


def _compact_when(when: str) -> str:
    """
    Convert verbose 'in 57 days' / 'in 3 hours' / 'in 17 minutes'
    into 'in 57d' / 'in 3h' / 'in 17m'.
    """
    return (
        when.replace(" days", "d")
        .replace(" day", "d")
        .replace(" hours", "h")
        .replace(" hour", "h")
        .replace(" minutes", "m")
        .replace(" minute", "m")
    )


def _normalize_expiry(expiry: Any) -> datetime:
    """Coerce expiry into a timezone-aware UTC datetime."""
    if isinstance(expiry, datetime):
        if expiry.tzinfo is None:
            return expiry.replace(tzinfo=UTC)
        return expiry.astimezone(UTC)

    if isinstance(expiry, str):
        # Handle ISO strings with or without Z
        iso = expiry.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(iso)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)

    if hasattr(expiry, "year") and hasattr(expiry, "month") and hasattr(expiry, "day"):
        # date-like
        return datetime.combine(expiry, time(0, 0), tzinfo=UTC)

    raise TypeError(f"Unsupported expiry type: {type(expiry)}")


def format_cert_list(certs: list[dict[str, Any]]) -> str:
    """Format certificate list for Slack message."""
    if not certs:
        return "_None_"

    lines: list[str] = []

    for cert in certs[:MAX_SLACK_ITEMS]:
        app_name = cert["app_name"]
        expiry = _normalize_expiry(cert["expiry_date"])
        portal_link = cert.get("portal_link", "")

        # Date/time formatting:
        #   - hyperlink text: DD-MM-YY
        #   - time: HH:MM (plain text)
        date_str = expiry.strftime("%d-%m-%y")
        time_str = expiry.strftime("%H:%M")

        when_full = _human_time_until(expiry)  # e.g. "in 57 days"
        when_compact = _compact_when(when_full)  # e.g. "in 57d"

        if portal_link:
            # Only the date part is clickable
            date_link = f"<{portal_link}|{date_str}>"
        else:
            date_link = date_str

        # Final compact line:
        # [App Name] · in 57d · 22-01-26 - 17:54
        lines.append(f"[`{app_name}`] · {when_compact} · {date_link} - {time_str}")

    if len(certs) > MAX_SLACK_ITEMS:
        lines.append(f"_...and {len(certs) - MAX_SLACK_ITEMS} more_")

    return "\n".join(lines)


def build_slack_blocks(
    categories: dict[str, list[dict[str, Any]]],
    changes: dict[str, list[dict[str, Any]]] | None = None,
) -> list[dict[str, Any]]:
    """Build Slack Block Kit message."""
    blocks: list[dict[str, Any]] = []

    total_items = sum(len(v) for v in categories.values())
    if total_items == 0:
        blocks.append(
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "✅ Certificate Status: All Clear",
                    "emoji": True,
                },
            }
        )
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "No certificates are expiring within the configured time windows.",
                },
            }
        )
        return blocks

    urgent = bool(categories.get("today") or categories.get("tomorrow"))
    icon = "🚨" if urgent else "🔔"

    # Header
    blocks.append(
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{icon} Azure Certificate Expiration Alert",
                "emoji": True,
            },
        }
    )

    # Context with single UTC note + date format hint
    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        f"Certificate check | "
                        f"{datetime.now(UTC).strftime('%Y-%m-%d %H:%M')} "
                        f"(all times in UTC - DD-MM-YY)"
                    ),
                }
            ],
        }
    )

    blocks.append({"type": "divider"})

    # Render each non-empty bucket, in dict order
    for bucket_name, certs in categories.items():
        if not certs:
            continue

        label = bucket_name.replace("_", " ").title()

        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*• {label} ({len(certs)})*\n{format_cert_list(certs)}",
                },
            }
        )
        blocks.append({"type": "divider"})

    return blocks


def send_slack_notification(
    categories: dict[str, list[dict[str, Any]]],
    webhook_url: str,
    changes: dict[str, list[dict[str, Any]]] | None = None,
) -> None:
    """Send formatted notification to Slack."""
    blocks = build_slack_blocks(categories, changes)

    # Determine message color based on urgency
    if categories.get("today") or categories.get("tomorrow"):
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
                "fallback": f"Certificate expiration alert: {sum(len(v) for v in categories.values())} items need attention",
            }
        ],
    }

    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        print("✅ Successfully sent Slack notification")
    except requests.exceptions.RequestException as e:
        print(f"⚠ Failed to send Slack notification: {str(e)}")
        raise
