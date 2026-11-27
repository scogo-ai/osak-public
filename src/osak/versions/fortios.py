"""FortiOS branch-aware version scheme."""

from __future__ import annotations

import re

from osak.versions._common import VersionSchemeBase
from osak.versions.base import ParsedVersion

_VERSION = re.compile(
    r"^v?(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)"
    r"(?:\s*(?:,|-|\()?\s*(?:build|b)\s*[-_ ]?\s*(?P<build>[0-9]+)\s*\)?)?$",
    re.IGNORECASE | re.ASCII,
)
_TRAIN = re.compile(r"^(?P<major>[0-9]+)\.(?P<minor>[0-9]+)$", re.ASCII)


class FortiOSScheme(VersionSchemeBase):
    """Parse FortiOS branch releases and optional build numbers.

    Builds refine one release only; the major/minor pair is the train, so a
    range bounded on 7.2 cannot accidentally compare against 7.4.
    """

    def parse(self, value: str) -> ParsedVersion | None:
        match = _VERSION.fullmatch(value.strip())
        if match is None:
            return None
        major = int(match.group("major"))
        minor = int(match.group("minor"))
        patch = int(match.group("patch"))
        build_text = match.group("build")
        build = int(build_text) if build_text else 0
        normalized = f"{major}.{minor}.{patch}"
        if build_text is not None:
            normalized += f"-build{build}"
        return ParsedVersion(
            normalized=normalized,
            train=f"{major}.{minor}",
            order=(major, minor, patch, build),
        )

    def normalize_train(self, value: str) -> str | None:
        match = _TRAIN.fullmatch(value.strip())
        if match is None:
            return None
        return f"{int(match.group('major'))}.{int(match.group('minor'))}"
