"""Capture device-qualified Cisco Software Checker observations.

The release-level oracle is deliberately separate. This file records the
platformAlias/model input used for each query so a QA loader never treats an
unqualified OS result as a hardware-scoped verdict.
"""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from urllib.parse import quote

import httpx
from dotenv import dotenv_values

from osak.connectors.cisco import CiscoOpenVulnConnector  # type: ignore[import-untyped]
from osak.connectors.oem_common import ConnectorFetchError  # type: ignore[import-untyped]

OUTPUT = Path("tests/golden/cisco-platform-oracles.jsonl")
CREDENTIALS = Path(".env")
QUERIES = (
    ("asa", "9.18.4", "FPR2100"),
    ("asa", "9.20.2", "FPR4100"),
    ("asa", "9.22.2", "FWL3100"),
    ("nxos", "9.3(10)", "NEXUS9000"),
    ("nxos", "10.3(4)", "NEXUS3000"),
    ("nxos", "10.4(2)", "NEXUS9000"),
    ("nxos", "10.5(1)", "MDS9000"),
)


def _query_url(connector: CiscoOpenVulnConnector, os_type: str, release: str, alias: str) -> str:
    return (
        f"{connector.base_url}/OSType/{quote(os_type, safe='')}?version={quote(release, safe='')}"
        f"&platformAlias={quote(alias, safe='')}"
    )


def _fixed_versions(advisory: dict[str, object]) -> list[str]:
    fixed: list[str] = []
    top = advisory.get("firstFixed")
    if isinstance(top, list):
        fixed.extend(value for value in top if isinstance(value, str))
    platforms = advisory.get("platforms")
    if isinstance(platforms, list):
        for platform in platforms:
            if not isinstance(platform, dict):
                continue
            values = platform.get("firstFixes")
            if isinstance(values, list):
                fixed.extend(
                    value["name"]
                    for value in values
                    if isinstance(value, dict) and isinstance(value.get("name"), str)
                )
    return list(dict.fromkeys(fixed))


def _model_name(platforms: object, alias: str) -> str:
    if isinstance(platforms, list):
        for platform in platforms:
            if not isinstance(platform, dict):
                continue
            name = platform.get("name")
            if isinstance(name, str) and name.strip():
                return name.strip()
    return alias


def _row(
    *,
    advisory: dict[str, object],
    os_type: str,
    release: str,
    alias: str,
    model: str,
    url: str,
    fetched_at: str,
    response_hash: str,
    expected: str,
    present: bool,
) -> dict[str, object]:
    cves = [value.upper() for value in advisory.get("cves", []) if isinstance(value, str)]
    return {
        "scope": "device",
        "vendor": "cisco",
        "os": {"asa": "ASA", "nxos": "NX-OS"}[os_type],
        "product": "cisco-asa" if os_type == "asa" else "cisco-nxos",
        "model": model,
        "platform_alias": alias,
        "advisory": advisory["advisoryId"],
        "cve": cves[0],
        "version": release,
        "expected": expected,
        "features": [],
        "evidence": {
            "source": "Cisco Software Checker",
            "query_url": url,
            "retrieved_at": fetched_at,
            "response_sha256": response_hash,
            "platform_alias": alias,
            "model": model,
            "release": release,
            "advisory_id": advisory["advisoryId"],
            "cves": cves,
            "fixed_versions": _fixed_versions(advisory),
            "present": present,
        },
    }


def main() -> None:
    values = dotenv_values(CREDENTIALS)
    connector = CiscoOpenVulnConnector(
        client_id=values.get("CISCO_CLIENT_ID"),
        client_secret=values.get("CISCO_CLIENT_SECRET"),
        timeout=30,
    )
    if connector._token() is None:
        raise RuntimeError("Cisco OAuth credentials did not produce a token")
    rows: list[dict[str, object]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for os_type, release, alias in QUERIES:
        url = _query_url(connector, os_type, release, alias)
        try:
            raw = connector._auth_get(url)
            payload = json.loads(raw.content)
        except (ConnectorFetchError, httpx.HTTPError, TypeError, ValueError, OSError) as exc:
            print(f"platform query unavailable {os_type} {release} {alias}: {type(exc).__name__}")
            continue
        advisories = payload.get("advisories", []) if isinstance(payload, dict) else []
        candidates = [
            item
            for item in advisories
            if isinstance(item, dict) and isinstance(item.get("advisoryId"), str)
            and _fixed_versions(item) and item.get("cves")
        ]
        if not candidates:
            continue
        advisory = min(candidates, key=lambda item: str(item["advisoryId"]))
        model = _model_name(advisory.get("platforms"), alias)
        fetched_at = raw.fetched_at.isoformat()
        response_hash = sha256(raw.content).hexdigest()
        key = (os_type, release, alias, str(advisory["advisoryId"]))
        if key not in seen:
            rows.append(
                _row(
                    advisory=advisory,
                    os_type=os_type,
                    release=release,
                    alias=alias,
                    model=model,
                    url=url,
                    fetched_at=fetched_at,
                    response_hash=response_hash,
                    expected="affected",
                    present=True,
                )
            )
            seen.add(key)
        # The first platform fix is a candidate boundary. The follow-up query
        # is required to prove absence for this exact advisory/platform.
        fixed = _fixed_versions(advisory)[0]
        fixed_url = _query_url(connector, os_type, fixed, alias)
        try:
            fixed_raw = connector._auth_get(fixed_url)
            fixed_payload = json.loads(fixed_raw.content)
        except (ConnectorFetchError, httpx.HTTPError, TypeError, ValueError, OSError) as exc:
            print(f"platform fixed boundary unavailable {os_type} {fixed} {alias}: {type(exc).__name__}")
            continue
        fixed_advisories = fixed_payload.get("advisories", []) if isinstance(fixed_payload, dict) else []
        still_present = any(
            isinstance(item, dict) and item.get("advisoryId") == advisory["advisoryId"]
            for item in fixed_advisories
        )
        if not still_present:
            rows.append(
                _row(
                    advisory=advisory,
                    os_type=os_type,
                    release=fixed,
                    alias=alias,
                    model=model,
                    url=fixed_url,
                    fetched_at=fixed_raw.fetched_at.isoformat(),
                    response_hash=sha256(fixed_raw.content).hexdigest(),
                    expected="not_affected",
                    present=False,
                )
            )
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    print(f"captured device oracle rows: {len(rows)}")


if __name__ == "__main__":
    main()
