#!/usr/bin/env python3
"""Run the local Mailpit signup and authenticated admin smoke flow.

The command reports only status and counts. It never prints API keys, email
addresses, response bodies, or configured secrets. When compose options are
supplied, it seeds a unique scoped admin key through the local ``osak admin``
CLI before exercising the API.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import uuid
from collections.abc import Iterable
from typing import Any

import httpx

_API_KEY = re.compile(r"\bosak_(?:test|live)_[A-Za-z0-9_-]+\b")


def extract_api_key(text: str) -> str | None:
    match = _API_KEY.search(text)
    return match.group(0) if match else None


def _status_error(
    action: str, response: httpx.Response, expected: Iterable[int]
) -> RuntimeError | None:
    if response.status_code in set(expected):
        return None
    return RuntimeError(f"{action} returned HTTP {response.status_code}")


def _message_text(message: dict[str, Any]) -> str:
    values: list[str] = []
    for key in ("Text", "HTML", "text", "html", "Subject", "subject"):
        value = message.get(key)
        if isinstance(value, str):
            values.append(value)
    return "\n".join(values)


def _mailpit_messages(client: httpx.Client, mailpit_url: str, email: str) -> list[dict[str, Any]]:
    response = client.get(
        f"{mailpit_url.rstrip('/')}/api/v1/search",
        params={"query": f"to:{email}"},
    )
    if response.status_code != 200:
        return []
    payload = response.json()
    messages = payload.get("messages", []) if isinstance(payload, dict) else []
    return [message for message in messages if isinstance(message, dict)]


def _message_ids(messages: Iterable[dict[str, Any]]) -> set[str]:
    return {
        message_id
        for message in messages
        for message_id in (message.get("ID") or message.get("id"),)
        if isinstance(message_id, str)
    }


def _headers(api_key: str, origin_secret: str | None, admin_access: str | None) -> dict[str, str]:
    headers = {"X-API-Key": api_key}
    if origin_secret:
        headers["X-OSAK-Origin-Secret"] = origin_secret
    if admin_access:
        headers["X-OSAK-Admin-Access"] = admin_access
    return headers


def _cli_json(command: list[str], action: str) -> dict[str, Any]:
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"local admin CLI {action} failed") from exc
    try:
        payload = json.loads(result.stdout)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"local admin CLI {action} returned invalid metadata") from exc
    if not isinstance(payload, dict):
        raise TypeError(f"local admin CLI {action} returned invalid metadata")
    return payload


def _cli_json_list(command: list[str], action: str) -> list[dict[str, Any]]:
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        payload = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, TypeError, ValueError) as exc:
        raise RuntimeError(f"local admin CLI {action} failed") from exc
    if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
        raise TypeError(f"local admin CLI {action} returned invalid metadata")
    return payload


def _seed_admin_key(
    *,
    compose_env_file: str,
    compose_project: str,
    api_service: str,
) -> str:
    """Create a unique local admin and return its one-time test key in memory."""

    compose = [
        "docker",
        "compose",
        "--env-file",
        compose_env_file,
        "-p",
        compose_project,
        "exec",
        "-T",
        api_service,
        "osak",
    ]
    suffix = uuid.uuid4().hex[:12]
    email = f"osak-smoke-admin-{suffix}@example.com"
    user = _cli_json(
        compose
        + [
            "admin",
            "users",
            "create",
            "--name",
            "OSAK Smoke Admin",
            "--organization",
            "OSAK QA",
            "--email",
            email,
            "--admin",
            "--status",
            "active",
            "--plan",
            "free",
            "--rpm",
            "120",
            "--rpd",
            "1000",
            "--max-assets",
            "321",
        ],
        "user seed",
    )
    user_id = user.get("id")
    if not isinstance(user_id, str) or not user_id:
        raise RuntimeError("local admin CLI user seed returned no user id")
    key = _cli_json(
        compose
        + [
            "admin",
            "keys",
            "create",
            "--user-id",
            user_id,
            "--environment",
            "test",
            "--label",
            "qa-smoke",
        ],
        "key seed",
    )
    raw_key = key.get("api_key")
    prefix = key.get("prefix")
    if (
        not isinstance(raw_key, str)
        or not raw_key.startswith("osak_test_")
        or not isinstance(prefix, str)
        or prefix != raw_key[:18]
    ):
        raise RuntimeError("local admin CLI key seed returned mismatched key metadata")
    return raw_key


def run_smoke(
    *,
    base_url: str,
    mailpit_url: str,
    admin_key: str,
    origin_secret: str | None = None,
    admin_access: str | None = None,
    turnstile_token: str | None = None,
    email: str | None = None,
    compose_env_file: str | None = None,
    compose_project: str | None = None,
    compose_api_service: str = "api",
    client: httpx.Client | None = None,
) -> None:
    close_client = client is None
    http_client = client or httpx.Client(base_url=base_url.rstrip("/"), timeout=20)
    signup_email = email or f"osak-smoke-{uuid.uuid4().hex[:12]}@example.com"
    admin_headers = _headers(admin_key, origin_secret, admin_access)
    try:
        invalid_signup = http_client.post(
            "/api/v1/signup",
            json={
                "name": "OSAK Invalid Email",
                "organization": "OSAK QA",
                "email": f"osak-invalid-{uuid.uuid4().hex[:12]}@example.invalid",
                "accept_terms": True,
            },
        )
        error = _status_error("reserved-domain signup rejection", invalid_signup, (422,))
        if error:
            raise error

        signup_payload = {
            "name": "OSAK Smoke User",
            "organization": "OSAK QA",
            "email": signup_email,
            "turnstile_token": turnstile_token,
            "accept_terms": True,
        }
        response = http_client.post(
            "/api/v1/signup",
            json=signup_payload,
        )
        error = _status_error("signup", response, (200,))
        if error:
            raise error
        first_signup = response.json()
        signup_message = first_signup.get("message") if isinstance(first_signup, dict) else None
        if (
            not isinstance(signup_message, str)
            or not signup_message.strip()
            or any(
                term in signup_message.casefold()
                for term in ("verification", "token", "http://", "https://")
            )
        ):
            raise RuntimeError("signup returned an unexpected one-email response contract")
        key, first_message_ids = _wait_for_key(http_client, mailpit_url, signup_email)
        if len(first_message_ids) != 1 or not key.startswith("osak_test_"):
            raise RuntimeError("signup did not produce exactly one test API-key email")
        response = http_client.get("/api/v1/me", headers={"X-API-Key": key})
        error = _status_error("new signup key authentication", response, (200,))
        if error:
            raise error
        me = response.json()
        me_user = me.get("user") if isinstance(me, dict) else None
        if (
            not isinstance(me_user, dict)
            or me.get("key_prefix") != key[:18]
            or me_user.get("email") != signup_email
            or me_user.get("status") != "active"
            or me_user.get("email_verified") is not False
            or me_user.get("requests_per_minute") != 60
            or me_user.get("requests_per_day") != 10_000
            or me_user.get("max_assets_per_request") != 500
        ):
            raise RuntimeError("signup key /me fields did not match account defaults")
        signup_user_id = me_user.get("id")

        response = http_client.post("/api/v1/signup", json=signup_payload)
        error = _status_error("repeat signup", response, (200,))
        if error:
            raise error
        if response.json() != first_signup:
            raise RuntimeError("repeat signup did not return the generic response")
        repeated_message_ids = _message_ids(
            _mailpit_messages(http_client, mailpit_url, signup_email)
        )
        if repeated_message_ids != first_message_ids:
            raise RuntimeError("repeat signup sent a second API-key email")
        response = http_client.get("/api/v1/me", headers={"X-API-Key": key})
        error = _status_error("duplicate signup key stability", response, (200,))
        if error:
            raise error
        if response.json().get("key_prefix") != key[:18]:
            raise RuntimeError("duplicate signup rotated the original API key")
        if compose_env_file and compose_project and isinstance(signup_user_id, str):
            compose = [
                "docker",
                "compose",
                "--env-file",
                compose_env_file,
                "-p",
                compose_project,
                "exec",
                "-T",
                compose_api_service,
                "osak",
                "admin",
                "keys",
                "list",
                "--user-id",
                signup_user_id,
            ]
            active_keys = [
                row
                for row in _cli_json_list(compose, "signup key audit")
                if row.get("revoked_at") is None
            ]
            if len(active_keys) != 1 or active_keys[0].get("prefix") != key[:18]:
                raise RuntimeError("duplicate signup created or rotated an active key")

        admin_email = f"osak-admin-{uuid.uuid4().hex[:12]}@example.com"
        response = http_client.post(
            "/api/v1/admin/users",
            headers=admin_headers,
            json={
                "full_name": "OSAK Admin Smoke User",
                "organization": "OSAK QA",
                "email": admin_email,
                "verified": True,
            },
        )
        error = _status_error("admin user creation", response, (200,))
        if error:
            raise error
        created = response.json()
        user_id = created.get("id") if isinstance(created, dict) else None
        if not isinstance(user_id, str):
            raise TypeError("admin user creation returned no user id")
        if (
            created.get("email") != admin_email
            or created.get("status") != "active"
            or created.get("plan") != "free"
            or created.get("requests_per_minute") != 60
            or created.get("requests_per_day") != 10_000
            or created.get("max_assets_per_request") != 500
        ):
            raise RuntimeError("admin user creation returned incorrect defaults")

        response = http_client.patch(
            f"/api/v1/admin/users/{user_id}",
            headers=admin_headers,
            json={"plan": "qa", "max_assets_per_request": 321},
        )
        error = _status_error("admin user update", response, (200,))
        if error:
            raise error
        updated = response.json()
        if updated.get("plan") != "qa" or updated.get("max_assets_per_request") != 321:
            raise RuntimeError("admin user update did not persist scoped fields")

        response = http_client.get(
            "/api/v1/admin/users",
            headers=admin_headers,
            params={"q": admin_email},
        )
        error = _status_error("admin user query", response, (200,))
        if error:
            raise error
        users = response.json()
        if not isinstance(users, list) or len(users) != 1 or users[0].get("id") != user_id:
            raise RuntimeError("admin user query returned an unexpected result")

        response = http_client.post(
            "/api/v1/admin/keys",
            headers=admin_headers,
            json={"user_id": user_id, "environment": "test", "label": "qa-smoke"},
        )
        error = _status_error("admin key creation", response, (200,))
        if error:
            raise error
        created_key = response.json()
        issued_key = created_key.get("api_key") if isinstance(created_key, dict) else None
        key_id = created_key.get("id") if isinstance(created_key, dict) else None
        created_prefix = created_key.get("prefix") if isinstance(created_key, dict) else None
        if (
            not isinstance(issued_key, str)
            or not issued_key.startswith("osak_test_")
            or not isinstance(key_id, str)
            or created_key.get("user_id") != user_id
            or not isinstance(created_prefix, str)
            or created_prefix != issued_key[:18]
        ):
            raise TypeError("admin key creation returned incomplete metadata")
        response = http_client.get("/api/v1/me", headers={"X-API-Key": issued_key})
        error = _status_error("admin-issued key authentication", response, (200,))
        if error:
            raise error
        issued_me = response.json()
        issued_user = issued_me.get("user", {})
        mismatches = []
        if issued_me.get("key_prefix") != issued_key[:18]:
            mismatches.append("key_prefix")
        if issued_user.get("email") != admin_email:
            mismatches.append("email")
        if issued_user.get("is_admin") is not False:
            mismatches.append("is_admin")
        if issued_user.get("max_assets_per_request") != 321:
            mismatches.append("max_assets_per_request")
        if mismatches:
            raise RuntimeError(
                "admin-issued key fields did not match the created key: " + ",".join(mismatches)
            )
        response = http_client.get(
            "/api/v1/admin/usage",
            headers=admin_headers,
            params={"user": user_id},
        )
        error = _status_error("admin usage query", response, (200,))
        if error:
            raise error
        if not isinstance(response.json(), list):
            raise TypeError("admin usage query did not return a list")
        response = http_client.delete(f"/api/v1/admin/keys/{key_id}", headers=admin_headers)
        error = _status_error("admin key revocation", response, (200,))
        if error:
            raise error
        response = http_client.get("/api/v1/me", headers={"X-API-Key": issued_key})
        error = _status_error("revoked key rejection", response, (401,))
        if error:
            raise error
    finally:
        if close_client:
            http_client.close()


def _wait_for_key(
    client: httpx.Client,
    mailpit_url: str,
    email: str,
    *,
    timeout_seconds: float = 20.0,
) -> tuple[str, set[str]]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        messages = _mailpit_messages(client, mailpit_url, email)
        message_ids = _message_ids(messages)
        if len(message_ids) > 1:
            raise RuntimeError("signup produced multiple API-key emails")
        for message in messages:
            message_id = message.get("ID") or message.get("id")
            if isinstance(message_id, str):
                detail = client.get(f"{mailpit_url.rstrip('/')}/api/v1/message/{message_id}")
                if detail.status_code == 200 and isinstance(detail.json(), dict):
                    key = extract_api_key(_message_text(detail.json()))
                    if key:
                        return key, message_ids
        time.sleep(0.25)
    raise RuntimeError("Mailpit API-key email did not arrive before timeout")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=os.getenv("OSAK_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--mailpit-url", default=os.getenv("MAILPIT_URL", "http://127.0.0.1:8025"))
    parser.add_argument("--admin-key", default=os.getenv("OSAK_ADMIN_SMOKE_KEY", ""))
    parser.add_argument("--compose-env-file", default=os.getenv("OSAK_COMPOSE_ENV_FILE"))
    parser.add_argument("--compose-project", default=os.getenv("OSAK_COMPOSE_PROJECT"))
    parser.add_argument(
        "--compose-api-service", default=os.getenv("OSAK_COMPOSE_API_SERVICE", "api")
    )
    parser.add_argument("--origin-secret", default=os.getenv("OSAK_ORIGIN_SHARED_SECRET"))
    parser.add_argument("--admin-access", default=os.getenv("OSAK_ADMIN_ACCESS"))
    parser.add_argument("--turnstile-token", default=os.getenv("TURNSTILE_TEST_TOKEN"))
    parser.add_argument("--email", default=None)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        admin_key = args.admin_key
        if not admin_key:
            if not args.compose_env_file or not args.compose_project:
                print(
                    "provide OSAK_ADMIN_SMOKE_KEY/--admin-key or compose seed options",
                    file=sys.stderr,
                )
                return 2
            admin_key = _seed_admin_key(
                compose_env_file=args.compose_env_file,
                compose_project=args.compose_project,
                api_service=args.compose_api_service,
            )
        run_smoke(
            base_url=args.base_url,
            mailpit_url=args.mailpit_url,
            admin_key=admin_key,
            origin_secret=args.origin_secret,
            admin_access=args.admin_access,
            turnstile_token=args.turnstile_token,
            email=args.email,
            compose_env_file=args.compose_env_file,
            compose_project=args.compose_project,
            compose_api_service=args.compose_api_service,
        )
    except (RuntimeError, TypeError, ValueError, httpx.HTTPError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print("Signup, Mailpit delivery, key authentication, admin usage, and revocation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
