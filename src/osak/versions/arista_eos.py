"""Arista EOS train-aware release scheme."""

from __future__ import annotations

import re

from osak.core.models import VersionRange
from osak.versions._common import VersionSchemeBase
from osak.versions.base import ParsedVersion

_VERSION = re.compile(
    r"^(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)"
    r"(?:\.(?P<release>[0-9]+))?(?P<phase>[FMfm])?"
    r"(?:-(?P<build>[0-9]+))?$",
    re.ASCII,
)
_TRAIN = re.compile(
    r"^(?P<major>[0-9]+)\.(?P<minor>[0-9]+)(?:[FMfm])?$",
    re.ASCII,
)


class AristaEOSScheme(VersionSchemeBase):
    """Parse EOS versions such as ``4.29.2`` and ``4.27.3.1M``.

    Arista's F (new functionality) and M (maintenance) suffixes describe
    lifecycle phases inside a major/minor train.  They do not create separate
    trains.  When the same numeric release is labeled both ways, comparison is
    deliberately unknown because the labels cannot be ordered from the version
    string alone.
    """

    def parse(self, value: str) -> ParsedVersion | None:
        match = _VERSION.fullmatch(value.strip())
        if match is None:
            return None
        major = int(match.group("major"))
        minor = int(match.group("minor"))
        patch = int(match.group("patch"))
        release_text = match.group("release")
        release = int(release_text) if release_text else 0
        phase_text = match.group("phase")
        phase = phase_text.upper() if phase_text else ""
        build_text = match.group("build")
        build = int(build_text) if build_text else 0
        normalized = f"{major}.{minor}.{patch}"
        if release_text is not None:
            normalized += f".{release}"
        normalized += phase
        if build_text is not None:
            normalized += f"-{build}"
        return ParsedVersion(
            normalized=normalized,
            train=f"{major}.{minor}",
            order=(major, minor, patch, release, build),
        )

    def in_range(self, value: str, bounds: VersionRange) -> bool | None:
        # Some Arista CNA records expressly publish a range spanning multiple
        # EOS trains. Single-ended conditions still apply only to their train.
        if bounds.train or bounds.exact or not bounds.lower or not bounds.upper:
            return super().in_range(value, bounds)
        lower, upper = self.parse(bounds.lower), self.parse(bounds.upper)
        release = self.parse(value)
        if lower is None or upper is None or release is None or lower.order > upper.order:
            return None
        if lower.train == upper.train:
            return super().in_range(value, bounds)
        if not lower.order[:2] <= release.order[:2] <= upper.order[:2]:
            return False
        scoped = VersionRange(
            train=release.train,
            lower=bounds.lower if release.train == lower.train else None,
            upper=bounds.upper if release.train == upper.train else None,
            include_lower=bounds.include_lower,
            include_upper=bounds.include_upper,
        )
        return super().in_range(value, scoped)

    def _ambiguous_equal(self, left: ParsedVersion, right: ParsedVersion) -> bool:
        left_phase = self._phase(left)
        right_phase = self._phase(right)
        return left_phase != right_phase and bool(left_phase) and bool(right_phase)

    @staticmethod
    def _phase(version: ParsedVersion) -> str | None:
        match = _VERSION.fullmatch(version.normalized)
        return match.group("phase").upper() if match and match.group("phase") else None

    def normalize_train(self, value: str) -> str | None:
        match = _TRAIN.fullmatch(value.strip())
        if match is None:
            return None
        return f"{int(match.group('major'))}.{int(match.group('minor'))}"
