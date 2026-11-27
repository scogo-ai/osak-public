#!/usr/bin/env python3
"""Fail when the committed OpenAPI contract drifts from the FastAPI app."""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path
from typing import Any


def _load_app(import_path: str) -> Any:
    module_name, separator, attribute = import_path.partition(":")
    if not separator or not module_name or not attribute:
        raise ValueError(f"invalid app import path: {import_path!r}")
    module = importlib.import_module(module_name)
    return getattr(module, attribute)


def _normalise(value: Any) -> Any:
    """Drop generated metadata that is allowed to differ between builds."""

    if isinstance(value, dict):
        return {
            key: _normalise(item)
            for key, item in value.items()
            if key not in {"servers"}
        }
    if isinstance(value, list):
        return [_normalise(item) for item in value]
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("contract", type=Path)
    parser.add_argument("--app", default="osak.api.app:app")
    args = parser.parse_args()

    expected = json.loads(args.contract.read_text(encoding="utf-8"))
    app = _load_app(args.app)
    actual = app.openapi()
    if _normalise(expected) != _normalise(actual):
        print(
            f"OpenAPI contract drift detected between {args.contract} and {args.app}",
            file=sys.stderr,
        )
        return 1
    print(f"OpenAPI contract matches {args.app}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
