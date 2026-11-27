"""Capture minimal, authenticated Cisco Software Checker oracle facts.

This script intentionally never writes or prints credentials, headers, tokens,
or source response bodies.  It writes only the query URL, retrieval timestamp,
response digest, and structured advisory/version facts needed by the golden
case loader.
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast
from urllib.parse import quote

import httpx
from dotenv import dotenv_values

from osak.connectors.base import RawDocument  # type: ignore[import-untyped]
from osak.connectors.cisco import CiscoCsafConnector, CiscoOpenVulnConnector  # type: ignore[import-untyped]
from osak.connectors.oem_common import ConnectorFetchError  # type: ignore[import-untyped]
from osak.versions import get_scheme  # type: ignore[import-untyped]

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
DEFAULT_CREDENTIALS = Path(".env")
DEFAULT_ORACLE = Path("tests/golden/cisco-oracles.jsonl")
DEFAULT_SOURCE = Path("tests/golden/cisco-csaf/manifest.json")

QUERIES: dict[str, tuple[str, ...]] = {
    "iosxe": ("17.3.7", "17.6.8", "17.9.4", "17.12.4", "17.15.4"),
    "nxos": ("9.3(10)", "10.3(4)", "10.4(2)", "10.5(1)"),
    "asa": ("9.16.4", "9.18.4", "9.20.2", "9.22.2"),
}
OS_LABELS = {"iosxe": "IOS XE", "nxos": "NX-OS", "asa": "ASA"}
PRODUCT_IDS = {"iosxe": "cisco-iosxe", "nxos": "cisco-nxos", "asa": "cisco-asa"}
SCHEMES = {"iosxe": "cisco_iosxe", "nxos": "cisco_nxos", "asa": "cisco_asa"}


def _cves(value: object) -> list[str]:
    values = [value] if isinstance(value, str) else value if isinstance(value, list) else []
    return [item.upper() for item in values if isinstance(item, str) and CVE_RE.fullmatch(item)]


def _strings(value: object) -> list[str]:
    values = [value] if isinstance(value, str) else value if isinstance(value, list) else []
    return [item.strip() for item in values if isinstance(item, str) and item.strip()]


def _facts(os_type: str, release: str, payload: Mapping[str, object]) -> list[dict[str, object]]:
    values = payload.get("advisories")
    advisories = values if isinstance(values, list) else []
    result: list[dict[str, object]] = []
    for value in advisories:
        if not isinstance(value, Mapping):
            continue
        advisory_id = value.get("advisoryId")
        cves = _cves(value.get("cves"))
        if not isinstance(advisory_id, str) or not cves:
            continue
        fixed = _strings(value.get("firstFixed"))
        states: list[str] = []
        platform_fixes: list[str] = []
        platforms = value.get("platforms")
        if isinstance(platforms, list):
            for platform in platforms:
                if not isinstance(platform, Mapping):
                    continue
                state = platform.get("vulnerabilityState")
                if isinstance(state, str):
                    states.append(state)
                fixes = platform.get("firstFixes")
                if isinstance(fixes, list):
                    for fix in fixes:
                        if isinstance(fix, Mapping) and isinstance(fix.get("name"), str):
                            platform_fixes.append(fix["name"].strip())
        fixed = list(dict.fromkeys([*fixed, *platform_fixes]))
        result.append(
            {
                "advisory_id": advisory_id,
                "cves": cves,
                "fixed_versions": fixed,
                "vulnerability_states": list(dict.fromkeys(states)),
                "status": value.get("status") if isinstance(value.get("status"), str) else None,
                "csaf_url": value.get("csafUrl") if isinstance(value.get("csafUrl"), str) else None,
                "cvss": value.get("cvssBaseScore") if isinstance(value.get("cvssBaseScore"), str) else None,
                "sir": value.get("sir") if isinstance(value.get("sir"), str) else None,
                "product": PRODUCT_IDS[os_type],
                "platform": os_type,
                "release": release,
            }
        )
    return result


def _query_url(connector: CiscoOpenVulnConnector, os_type: str, release: str) -> str:
    return f"{connector.base_url}/OSType/{quote(os_type, safe='')}?version={quote(release, safe='')}"


def _query(
    connector: CiscoOpenVulnConnector,
    os_type: str,
    release: str,
    cache: dict[tuple[str, str], tuple[str, str, str, list[dict[str, object]]]],
) -> tuple[str, str, str, list[dict[str, object]]]:
    key = (os_type, release)
    if key in cache:
        return cache[key]
    url = _query_url(connector, os_type, release)
    raw = connector._auth_get(url)
    payload = json.loads(raw.content)
    if not isinstance(payload, Mapping):
        raise TypeError("Cisco Software Checker returned a non-object payload")
    result = (url, raw.fetched_at.isoformat(), sha256(raw.content).hexdigest(), _facts(os_type, release, payload))
    cache[key] = result
    return result


def _same_train_candidate(os_type: str, release: str, values: list[str]) -> str | None:
    scheme = get_scheme(SCHEMES[os_type])
    source = scheme.parse(release) if scheme else None
    if source is None:
        return None
    candidates = []
    for value in values:
        parsed = scheme.parse(value) if scheme else None
        if parsed is None or parsed.train != source.train:
            continue
        if scheme.compare(release, value) is not None and scheme.compare(release, value) < 0:
            candidates.append((parsed.order, parsed.normalized))
    return min(candidates)[1] if candidates else None


def _checker_release(os_type: str, release: str) -> str:
    """Use the Software Checker spelling for a vendor fixed release."""

    if os_type == "asa":
        return re.sub(r"^(\d+\.\d+)\((\d+)\)$", r"\1.\2", release)
    return release


def _oracle_row(
    *,
    os_type: str,
    release: str,
    fact: Mapping[str, object],
    expected: str,
    query_url: str,
    retrieved_at: str,
    response_hash: str,
    present: bool,
) -> dict[str, object]:
    return {
        "vendor": "cisco",
        "os": OS_LABELS[os_type],
        "advisory": fact["advisory_id"],
        "cve": cast(list[str], fact["cves"])[0],
        "version": release,
        "expected": expected,
        "features": [],
        "evidence": {
            "source": "Cisco Software Checker",
            "query_url": query_url,
            "retrieved_at": retrieved_at,
            "response_sha256": response_hash,
            "product": PRODUCT_IDS[os_type],
            "platform": os_type,
            "release": release,
            "advisory_id": fact["advisory_id"],
            "cves": fact["cves"],
            "fixed_versions": fact["fixed_versions"],
            "vulnerability_states": fact["vulnerability_states"],
            "status": fact["status"],
            "present": present,
        },
    }


def _source_projection(
    *, source_url: str, retrieved_at: str, response_hash: str,
    content: bytes, advisory_id: str, directory: Path,
) -> dict[str, object]:
    """Retain complete product/status facts after checking the original bytes."""
    original = json.loads(content)
    tracking = original["document"]["tracking"]
    if tracking["id"] != advisory_id or not re.fullmatch(r"[a-zA-Z0-9_-]+", advisory_id):
        raise ValueError("CSAF tracking ID differs from the advisory")
    raw = RawDocument(url=source_url, fetched_at=datetime.fromisoformat(retrieved_at), content=content)
    basename = advisory_id.lower() + ".json"
    with TemporaryDirectory() as temp:
        full_document = Path(temp) / basename
        full_document.write_bytes(content)
        validation = CiscoCsafConnector().validate_document(raw, path=full_document)
        if not validation.ok:
            raise ValueError("Original document failed gocsaf validation")

    def product(item: Mapping[str, Any]) -> dict[str, object]:
        return {key: item[key] for key in ("name", "product_id") if key in item}

    def branch(item: Mapping[str, Any]) -> dict[str, object]:
        result = {key: item[key] for key in ("name", "category") if key in item}
        product_value = item.get("product")
        if isinstance(product_value, Mapping):
            result["product"] = product(product_value)
        branches = item.get("branches")
        if isinstance(branches, list):
            result["branches"] = [branch(child) for child in branches if isinstance(child, Mapping)]
        return result

    tree = original["product_tree"]
    relationships = [
        {**{key: r[key] for key in ("category", "product_reference", "relates_to_product_reference") if key in r},
         "full_product_name": product(r["full_product_name"])}
        for r in tree.get("relationships", [])
    ]
    notes = _applicability_notes(original)
    projection = {
        "document": {
            "tracking": {
                k: v
                for k, v in tracking.items()
                if k in ("id", "status", "current_release_date", "initial_release_date")
            },
            **({"notes": notes} if notes else {}),
        },
        "product_tree": {"branches": [branch(x) for x in tree.get("branches", [])],
                         "relationships": relationships},
        "vulnerabilities": [{k: v[k] for k in ("cve", "product_status") if k in v}
                            for v in original["vulnerabilities"]],
    }
    encoded = json.dumps(projection, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    directory.mkdir(parents=True, exist_ok=True)
    filename = basename + ".gz"
    (directory / filename).write_bytes(gzip.compress(encoded, compresslevel=9, mtime=0))
    result: dict[str, object] = {
        "advisory_id": advisory_id,
        "source_url": source_url,
        "retrieved_at": retrieved_at,
        "response_sha256": response_hash,
        "applicability_fixture": filename,
        "projection_sha256": sha256(encoded).hexdigest(),
    }
    return result


def _applicability_notes(document: Mapping[str, object]) -> list[dict[str, object]]:
    """Project the first source applicability paragraph without synthesis."""

    meta = document.get("document")
    if not isinstance(meta, Mapping) or not isinstance(meta.get("notes"), list):
        return []
    projected: list[dict[str, object]] = []
    for title in ("Vulnerable Products", "Products Confirmed Not Vulnerable"):
        matching = [note for note in meta["notes"] if isinstance(note, Mapping) and note.get("title") == title]
        if len(matching) != 1 or not isinstance(matching[0].get("text"), str):
            return []
        note = matching[0]
        paragraph = re.split(r"\r?\n\s*\r?\n", note["text"], maxsplit=1)[0].strip()
        if not paragraph:
            return []
        projected.append({"category": note["category"], "title": title, "text": paragraph})
    # Keep a physical platform declaration, without importing the remainder
    # of the bulletin or software-only descriptions into the test dataset.
    if not re.search(r"\b[0-9]+ Series (?:switches|device)\b", str(projected[0]["text"]), re.IGNORECASE):
        return []
    return projected


def project_originals(
    source_dir: Path,
    manifest_path: Path,
    output_dir: Path,
) -> int:
    """Regenerate gz projections from checked original CSAF bytes.

    The upstream response hash and retrieval metadata come from the existing
    manifest; the original bytes must match before any projection is written.
    """

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows: list[dict[str, object]] = []
    for entry in manifest:
        advisory_id = entry["advisory_id"]
        original_path = source_dir / f"{str(advisory_id).lower()}.json"
        content = original_path.read_bytes()
        response_hash = sha256(content).hexdigest()
        if response_hash != entry["response_sha256"]:
            raise ValueError(f"original CSAF hash changed: {advisory_id}")
        rows.append(
            _source_projection(
                source_url=entry["source_url"],
                retrieved_at=entry["retrieved_at"],
                response_hash=response_hash,
                content=content,
                advisory_id=advisory_id,
                directory=output_dir,
            )
        )
    manifest_path.write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return len(rows)


def capture(credentials: Path, oracle_path: Path, source_path: Path) -> tuple[int, int]:
    values = dotenv_values(credentials)
    connector = CiscoOpenVulnConnector(
        client_id=values.get("CISCO_CLIENT_ID"),
        client_secret=values.get("CISCO_CLIENT_SECRET"),
        timeout=30,
    )
    if connector._token() is None:
        raise RuntimeError("Cisco OAuth credentials did not produce a token")
    cache: dict[tuple[str, str], tuple[str, str, str, list[dict[str, object]]]] = {}
    oracle_rows: list[dict[str, object]] = []
    selected: dict[str, dict[str, object]] = {}
    for os_type, releases in QUERIES.items():
        for release in releases:
            try:
                url, retrieved_at, raw_hash, facts = _query(connector, os_type, release, cache)
            except (ConnectorFetchError, httpx.HTTPError, TypeError, ValueError, OSError) as exc:
                print(f"query unavailable {os_type} {release}: {type(exc).__name__}")
                continue
            candidates = [item for item in facts if item["fixed_versions"]]
            if not candidates:
                continue
            fact = min(candidates, key=lambda item: str(item["advisory_id"]))
            selected.setdefault(str(fact["advisory_id"]), fact)
            oracle_rows.append(
                _oracle_row(
                    os_type=os_type,
                    release=release,
                    fact=fact,
                    expected="affected",
                    query_url=url,
                    retrieved_at=retrieved_at,
                    response_hash=raw_hash,
                    present=True,
                )
            )
            fixed = _same_train_candidate(
                os_type, release, cast(list[str], fact["fixed_versions"])
            )
            if fixed is None:
                continue
            fixed_query_release = _checker_release(os_type, fixed)
            try:
                fixed_url, fixed_retrieved, fixed_hash, fixed_facts = _query(
                    connector, os_type, fixed_query_release, cache
                )
            except (ConnectorFetchError, httpx.HTTPError, TypeError, ValueError, OSError) as exc:
                print(f"fixed boundary unavailable {os_type} {fixed}: {type(exc).__name__}")
                continue
            if str(fact["advisory_id"]) in {str(item["advisory_id"]) for item in fixed_facts}:
                continue
            oracle_rows.append(
                _oracle_row(
                    os_type=os_type,
                    release=fixed_query_release,
                    fact=fact,
                    expected="not_affected",
                    query_url=fixed_url,
                    retrieved_at=fixed_retrieved,
                    response_hash=fixed_hash,
                    present=False,
                )
            )
    oracle_path.parent.mkdir(parents=True, exist_ok=True)
    with oracle_path.open("w", encoding="utf-8") as handle:
        for row in oracle_rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")

    source_rows: list[dict[str, object]] = []
    with httpx.Client(
        headers={"User-Agent": "OSAK/0.1.0 (+https://osak.lab.scogo.ai)"},
        follow_redirects=True,
        timeout=30,
    ) as client:
        for advisory_id, fact in sorted(selected.items()):
            csaf_url = fact.get("csaf_url")
            if not isinstance(csaf_url, str) or not csaf_url.startswith("https://"):
                continue
            try:
                response = client.get(csaf_url)
                response.raise_for_status()
                projection = _source_projection(
                    source_url=csaf_url, advisory_id=advisory_id, directory=source_path.parent,
                    retrieved_at=datetime.now(UTC).isoformat(),
                    response_hash=sha256(response.content).hexdigest(),
                    content=response.content,
                )
            except (ConnectorFetchError, httpx.HTTPError, TypeError, ValueError, OSError) as exc:
                print(f"CSAF unavailable {advisory_id}: {type(exc).__name__}")
                continue
            if projection is not None:
                source_rows.append(projection)
            time.sleep(0.2)
    source_path.write_text(json.dumps(source_rows, indent=2) + "\n")
    return len(oracle_rows), len(source_rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--credentials", type=Path, default=DEFAULT_CREDENTIALS)
    parser.add_argument("--oracle", type=Path, default=DEFAULT_ORACLE)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--source-originals", type=Path)
    args = parser.parse_args()
    if args.source_originals is not None:
        count = project_originals(
            args.source_originals,
            args.source,
            args.source.parent,
        )
        print(f"projected original CSAF sources: {count}")
        return
    oracle_count, source_count = capture(args.credentials, args.oracle, args.source)
    print(f"captured oracle rows: {oracle_count}; source projections: {source_count}")


if __name__ == "__main__":
    main()
