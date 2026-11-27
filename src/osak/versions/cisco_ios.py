"""Cisco IOS classic release train scheme."""

from __future__ import annotations

import re

from osak.versions._common import VersionSchemeBase
from osak.versions.base import ParsedVersion

_VERSION = re.compile(
    r"^(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\((?P<release>[0-9]+)\)"
    r"(?P<train>[A-Za-z]+)(?P<patch>[0-9]*)$",
    re.ASCII,
)
_TRAIN = re.compile(r"^(?P<major>[0-9]+)\.(?P<minor>[0-9]+)(?P<train>[A-Za-z]+)$", re.ASCII)


class CiscoIOSScheme(VersionSchemeBase):
    """Parse versions such as ``15.2(7)E4`` and ``15.6(2)T``.

    Cisco IOS trains are not globally ordered.  The major/minor release and
    train letter therefore form the comparison key's train; only releases in
    that same train are comparable.
    """

    def parse(self, value: str) -> ParsedVersion | None:
        match = _VERSION.fullmatch(value.strip())
        if match is None:
            return None
        major = int(match.group("major"))
        minor = int(match.group("minor"))
        release = int(match.group("release"))
        train = match.group("train").upper()
        patch_text = match.group("patch")
        patch = int(patch_text) if patch_text else 0
        normalized = f"{major}.{minor}({release}){train}"
        if patch_text:
            normalized += str(patch)
        return ParsedVersion(normalized=normalized, train=f"{major}.{minor}{train}", order=(major, minor, release, patch))

    def normalize_train(self, value: str) -> str | None:
        match = _TRAIN.fullmatch(value.strip())
        if match is None:
            return None
        return f"{int(match.group('major'))}.{int(match.group('minor'))}{match.group('train').upper()}"
