"""Cisco IOS XE release train scheme."""

from __future__ import annotations

import re

from osak.versions._common import VersionSchemeBase
from osak.versions.base import ParsedVersion

_VERSION = re.compile(
    r"^(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)"
    r"(?P<suffix>[A-Za-z]+[0-9]*)?$",
    re.ASCII,
)
_TRAIN = re.compile(
    r"^(?P<major>[0-9]+)\.(?P<minor>[0-9]+)(?P<suffix>[A-Za-z]+)?$",
    re.ASCII,
)


def _letters_order(value: str) -> int:
    """Return a deterministic ordinal for a letter rebuild suffix."""

    result = 0
    for character in value.casefold():
        result = result * 26 + ord(character) - ord("a") + 1
    return result


class CiscoIOSXEScheme(VersionSchemeBase):
    """Parse IOS XE versions such as ``17.9.4a``.

    The major/minor pair identifies the train.  A letter suffix is a rebuild
    of the same patch release and sorts after the unsuffixed release.
    """

    def parse(self, value: str) -> ParsedVersion | None:
        match = _VERSION.fullmatch(value.strip())
        if match is None:
            return None
        major = int(match.group("major"))
        minor = int(match.group("minor"))
        patch = int(match.group("patch"))
        suffix = (match.group("suffix") or "").lower()
        suffix_letters = suffix.rstrip("0123456789")
        suffix_number_text = suffix[len(suffix_letters) :]
        suffix_number = int(suffix_number_text) if suffix_number_text else 0
        suffix_order = _letters_order(suffix_letters) if suffix_letters else 0
        normalized = f"{major}.{minor}.{patch}{suffix}"
        return ParsedVersion(
            normalized=normalized,
            train=f"{major}.{minor}",
            order=(major, minor, patch, suffix_order, suffix_number),
        )

    def normalize_train(self, value: str) -> str | None:
        match = _TRAIN.fullmatch(value.strip())
        if match is None:
            return None
        major = int(match.group("major"))
        minor = int(match.group("minor"))
        return f"{major}.{minor}"
