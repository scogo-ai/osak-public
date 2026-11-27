"""Small email adapters for Resend and local Mailpit-compatible development."""

from __future__ import annotations

import os
from typing import Any

import httpx


def _sender() -> str:
    return os.getenv("OSAK_EMAIL_FROM", "OSAK <noreply@osak.lab.scogo.ai>")


def send_email(*, to: str, subject: str, text: str, html: str | None = None) -> bool:
    """Send through Mailpit locally and Resend in production.

    A local process must never send real mail merely because a production
    Resend key leaked into its environment.
    """

    mailpit_url = os.getenv("MAILPIT_API_URL")
    if os.getenv("OSAK_ENV", "development").lower() not in {"production", "prod"}:
        if not mailpit_url:
            return False
        payload = {
            "From": {"Email": _sender().split("<")[-1].rstrip("> ")},
            "To": [{"Email": to}],
            "Subject": subject,
            "Text": text,
            "HTML": html or text,
        }
        response = httpx.post(f"{mailpit_url.rstrip('/')}/api/v1/send", json=payload, timeout=10)
        response.raise_for_status()
        return True

    resend_key = os.getenv("RESEND_API_KEY")
    if resend_key:
        payload: dict[str, Any] = {"from": _sender(), "to": [to], "subject": subject, "text": text}
        if html:
            payload["html"] = html
        response = httpx.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {resend_key}"},
            json=payload,
            timeout=10,
        )
        response.raise_for_status()
        return True

    if mailpit_url:
        payload = {
            "From": {"Email": _sender().split("<")[-1].rstrip("> ")},
            "To": [{"Email": to}],
            "Subject": subject,
            "Text": text,
            "HTML": html or text,
        }
        response = httpx.post(f"{mailpit_url.rstrip('/')}/api/v1/send", json=payload, timeout=10)
        response.raise_for_status()
        return True

    return False


def send_api_key_email(*, email: str, raw_key: str) -> bool:
    return send_email(
        to=email,
        subject="Your OSAK API key",
        text=f"Your OSAK API key is shown once:\n\n{raw_key}\n",
    )


__all__ = ["send_api_key_email", "send_email"]
