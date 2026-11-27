"""Cisco product releases that have no safe ordering grammar."""

from __future__ import annotations

import re

from osak.core.models import VersionRange
from osak.versions.base import ParsedVersion

_VERSION = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2,3}$", re.ASCII)


class CiscoLiteralScheme:
    """Match exact dotted publisher releases without inventing ordering."""

    def parse(self, value: str) -> ParsedVersion | None:
        candidate = value.strip()
        if _VERSION.fullmatch(candidate) is None:
            return None
        return ParsedVersion(normalized=candidate, train=candidate, order=())

    def normalize(self, value: str) -> str | None:
        parsed = self.parse(value)
        return parsed.normalized if parsed is not None else None

    def compare(self, left: str, right: str) -> int | None:
        left_parsed = self.parse(left)
        right_parsed = self.parse(right)
        if left_parsed is None or right_parsed is None:
            return None
        return 0 if left_parsed.normalized == right_parsed.normalized else None

    def in_range(self, value: str, bounds: VersionRange) -> bool | None:
        """Evaluate exact bounds only; intervals and defaults are unknown."""

        if bounds.train is not None or bounds.lower is not None or bounds.upper is not None:
            return None
        if bounds.exact is None:
            return None
        parsed = self.parse(value)
        expected = self.parse(bounds.exact)
        if parsed is None or expected is None:
            return None
        return parsed.normalized == expected.normalized

    def normalize_train(self, value: str) -> None:
        return None
