"""Cisco NX-OS release train scheme."""

from __future__ import annotations

import re

from osak.versions._common import VersionSchemeBase
from osak.versions.base import ParsedVersion

_VERSION = re.compile(
    r"^(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\((?P<release>[0-9]+)"
    r"(?P<release_suffix>[A-Za-z]*)\)"
    r"(?:(?P<variant>[A-Za-z]+)(?P<variant_number>[0-9]+)?"
    r"(?:\((?P<patch>[0-9]+)(?P<patch_suffix>[A-Za-z]*)\))?)?$",
    re.ASCII,
)
_TRAIN = re.compile(
    r"^(?P<major>[0-9]+)\.(?P<minor>[0-9]+)(?P<variant>[A-Za-z]+)?(?P<number>[0-9]+)?$",
    re.ASCII,
)


def _letters_order(value: str) -> int:
    """Return a deterministic ordinal for a release suffix."""

    result = 0
    for character in value.casefold():
        result = result * 26 + ord(character) - ord("a") + 1
    return result


class CiscoNXOSScheme(VersionSchemeBase):
    """Parse NX-OS versions including ``7.0(3)I7(9)`` trains."""

    def parse(self, value: str) -> ParsedVersion | None:
        match = _VERSION.fullmatch(value.strip())
        if match is None:
            return None
        major = int(match.group("major"))
        minor = int(match.group("minor"))
        release = int(match.group("release"))
        release_suffix = (match.group("release_suffix") or "").upper()
        variant = match.group("variant")
        variant_normalized = variant.upper() if variant else ""
        variant_number_text = match.group("variant_number")
        variant_number = int(variant_number_text) if variant_number_text else 0
        patch_text = match.group("patch")
        patch = int(patch_text) if patch_text else 0
        patch_suffix = (match.group("patch_suffix") or "").upper()
        normalized = f"{major}.{minor}({release}{release_suffix})"
        if variant_number_text is not None:
            normalized += f"{variant_normalized}{variant_number}"
        elif variant:
            normalized += variant_normalized
        if patch_text is not None:
            normalized += f"({patch}{patch_suffix})"
        variant_train = variant_number_text is not None or patch_text is not None
        train = f"{major}.{minor}"
        if variant_train:
            train += variant_normalized
            if variant_number_text is not None:
                train += str(variant_number)
        order: tuple[int, ...]
        if variant_train:
            order = (
                major,
                minor,
                release,
                patch,
                _letters_order(patch_suffix),
            )
        else:
            order = (major, minor, release, _letters_order(release_suffix))
        return ParsedVersion(
            normalized=normalized,
            train=train,
            order=order,
        )

    def normalize_train(self, value: str) -> str | None:
        match = _TRAIN.fullmatch(value.strip())
        if match is None:
            return None
        variant = match.group("variant")
        number = match.group("number")
        if number is not None and variant is None:
            return None
        return f"{int(match.group('major'))}.{int(match.group('minor'))}{variant.upper() if variant else ''}{number or ''}"
