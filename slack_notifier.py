"""
Slack notification module for certificate expiration alerts
Formats and sends color-coded messages based on urgency levels
"""

from datetime import datetime
from typing import Any

import requests


def format_cert_list(certs: list[dict[str, Any]], limit: int = 10) -> str:
    """Format certificate list for Slack message"""
    if not certs:
        return "_None_"

    lines = []
    for _i, cert in enumerate(certs[:limit]):
        app_name = cert["app_name"]
        cert_type = cert["type"]
        expiry = cert["expiry_date"].strftime("%Y-%m-%d %H:%M UTC")
        days = cert["days_until_expiry"]

        if days < 0:
            day_text = f"*EXPIRED {abs(days)} days ago*"
        elif days == 0:
            day_text = "*TODAY*"
        elif days == 1:
            day_text = "*TOMORROW*"
        else:
            day_text = f"in {days} days"

        lines.append(f"• `{app_name}` - {cert_type} expires {day_text} ({expiry})")

    if len(certs) > limit:
        lines.append(f"\n_...and {len(certs) - limit} more_")

    return "\n".join(lines)


def build_slack_blocks(
    categories: dict[str, list[dict[str, Any]]], changes: dict[str, list[dict[str, Any]]] | None = None
) -> list[dict[str, Any]]:
    """Build Slack Block Kit message"""
    blocks = []

    # Header
    total_issues = sum(len(v) for v in categories.values())

    if total_issues == 0:
        blocks.append(
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "✅ Certificate Status: All Clear", "emoji": True},
            }
        )
        blocks.append(
            {"type": "section", "text": {"type": "mrkdwn", "text": "No certificates are expiring in the next 2 weeks."}}
        )
        return blocks

    # Alert header
    icon = "🚨" if (categories["expired"] or categories["tomorrow"]) else "⚠️"
    blocks.append(
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{icon} Azure Certificate Expiration Alert", "emoji": True},
        }
    )

    context_element: dict[str, str] = {
        "type": "mrkdwn",
        "text": f"Weekly certificate check | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
    }
    blocks.append({"type": "context", "elements": [context_element]})  # type: ignore[list-item]

    blocks.append({"type": "divider"})

    # Expired certificates (Critical)
    if categories["expired"]:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🔴 EXPIRED ({len(categories['expired'])})*\n{format_cert_list(categories['expired'])}",
                },
            }
        )
        blocks.append({"type": "divider"})

    # Expiring tomorrow (Critical)
    if categories["tomorrow"]:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🔴 EXPIRING TOMORROW ({len(categories['tomorrow'])})*\n{format_cert_list(categories['tomorrow'])}",
                },
            }
        )
        blocks.append({"type": "divider"})

    # Expiring in 48 hours (High)
    if categories["forty_eight_hours"]:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🟠 EXPIRING IN 48 HOURS ({len(categories['forty_eight_hours'])})*\n{format_cert_list(categories['forty_eight_hours'])}",
                },
            }
        )
        blocks.append({"type": "divider"})

    # Expiring in 2 weeks (Warning)
    if categories["two_weeks"]:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🟡 EXPIRING IN 2 WEEKS ({len(categories['two_weeks'])})*\n{format_cert_list(categories['two_weeks'])}",
                },
            }
        )

    return blocks


def send_slack_notification(
    categories: dict[str, list[dict[str, Any]]],
    webhook_url: str,
    changes: dict[str, list[dict[str, Any]]] | None = None,
) -> None:
    """Send formatted notification to Slack"""
    blocks = build_slack_blocks(categories, changes)

    # Determine message color based on urgency
    if categories["expired"] or categories["tomorrow"]:
        color = "danger"
    elif categories["forty_eight_hours"]:
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
        print("✓ Successfully sent Slack notification")
    except requests.exceptions.RequestException as e:
        print(f"✗ Failed to send Slack notification: {str(e)}")
        raise
