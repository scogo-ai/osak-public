"""Cisco ASA release train scheme."""

from __future__ import annotations

import re

from osak.versions._common import VersionSchemeBase
from osak.versions.base import ParsedVersion

_VERSION = re.compile(
    r"^(?P<major>[0-9]+)\.(?P<minor>[0-9]+)"
    r"(?:"
    r"\((?P<paren>[0-9]+)\)(?:\.?(?P<paren_rebuild>[0-9]+))?"
    r"|"
    r"\.(?P<dotted>[0-9]+)(?:\.(?P<dotted_rebuild>[0-9]+))?"
    r")$",
    re.ASCII,
)
_TRAIN = re.compile(r"^(?P<major>[0-9]+)\.(?P<minor>[0-9]+)$", re.ASCII)


class CiscoASAScheme(VersionSchemeBase):
    """Parse ASA's parenthesized releases and dotted CPE spellings.

    ``9.18.3`` is normalized to the vendor-facing ``9.18(3)`` form while
    retaining the same train and ordering as ``9.18(3)``.
    """

    def parse(self, value: str) -> ParsedVersion | None:
        match = _VERSION.fullmatch(value.strip())
        if match is None:
            return None
        major = int(match.group("major"))
        minor = int(match.group("minor"))
        release_text = match.group("paren") or match.group("dotted")
        if release_text is None:
            return None
        release = int(release_text)
        normalized = f"{major}.{minor}({release})"
        rebuild_text = match.group("paren_rebuild") or match.group("dotted_rebuild")
        rebuild = int(rebuild_text) if rebuild_text is not None else 0
        if rebuild_text is not None:
            normalized += f".{rebuild}"
        return ParsedVersion(
            normalized=normalized,
            train=f"{major}.{minor}",
            order=(major, minor, release, rebuild),
        )

    def normalize_train(self, value: str) -> str | None:
        match = _TRAIN.fullmatch(value.strip())
        if match is None:
            return None
        return f"{int(match.group('major'))}.{int(match.group('minor'))}"
