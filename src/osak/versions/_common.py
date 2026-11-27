"""Shared behavior for vendor-specific version schemes."""

from __future__ import annotations

from abc import ABC, abstractmethod

from osak.core.models import VersionRange
from osak.versions.base import ParsedVersion


class VersionSchemeBase(ABC):
    """Base implementation of comparison and train-aware range semantics.

    A scheme's parser owns the vendor grammar.  The shared methods deliberately
    return ``None`` when a version cannot be parsed or compared safely; callers
    can therefore map that result to OSAK's conservative ``unknown`` verdict.
    """

    @abstractmethod
    def parse(self, value: str) -> ParsedVersion | None:
        """Parse a vendor version into its canonical representation."""

    def _compare_parsed(self, left: ParsedVersion, right: ParsedVersion) -> int | None:
        if left.train != right.train:
            return None
        if left.order < right.order:
            return -1
        if left.order > right.order:
            return 1
        if self._ambiguous_equal(left, right):
            return None
        return 0

    def _ambiguous_equal(self, left: ParsedVersion, right: ParsedVersion) -> bool:
        """Return whether equal numeric keys lack enough evidence to compare."""

        return False

    def normalize(self, value: str) -> str | None:
        parsed = self.parse(value)
        return parsed.normalized if parsed is not None else None

    def compare(self, left: str, right: str) -> int | None:
        left_parsed = self.parse(left)
        right_parsed = self.parse(right)
        if left_parsed is None or right_parsed is None:
            return None
        return self._compare_parsed(left_parsed, right_parsed)

    def in_range(self, value: str, bounds: VersionRange) -> bool | None:
        parsed = self.parse(value)
        if parsed is None:
            return None

        requested_train = self.normalize_train(bounds.train) if bounds.train is not None else None
        if bounds.train is not None and requested_train is None:
            return None

        exact = self.parse(bounds.exact) if bounds.exact is not None else None
        if bounds.exact is not None and exact is None:
            return None

        lower = self.parse(bounds.lower) if bounds.lower is not None else None
        if bounds.lower is not None and lower is None:
            return None
        upper = self.parse(bounds.upper) if bounds.upper is not None else None
        if bounds.upper is not None and upper is None:
            return None

        if lower is not None and upper is not None and lower.train != upper.train:
            # A version on a third, explicitly parsed train is known to be
            # outside this interval.  Only a value on one of the boundary
            # trains is incomparable; never infer ordering between trains.
            if parsed.train not in {lower.train, upper.train}:
                return False
            return None
        boundary_trains = {
            boundary.train
            for boundary in (exact, lower, upper)
            if boundary is not None
        }
        if requested_train is not None and any(
            boundary_train != requested_train for boundary_train in boundary_trains
        ):
            return None
        if requested_train is not None and requested_train != parsed.train:
            return False
        if exact is not None:
            if exact.train != parsed.train:
                return False
            comparison = self._compare_parsed(parsed, exact)
            if comparison is None:
                return None
            if comparison != 0:
                return False
        if lower is not None:
            if lower.train != parsed.train:
                return False
            comparison = self._compare_parsed(parsed, lower)
            if comparison is None:
                return None
            if comparison < 0 or (comparison == 0 and not bounds.include_lower):
                return False
        if upper is not None:
            if upper.train != parsed.train:
                return False
            comparison = self._compare_parsed(parsed, upper)
            if comparison is None:
                return None
            if comparison > 0 or (comparison == 0 and not bounds.include_upper):
                return False

        return True

    def normalize_train(self, value: str) -> str | None:
        """Normalize a train selector used by :class:`VersionRange`.

        Vendor schemes override this for their train grammar.  The default is
        intentionally strict about whitespace but otherwise useful for a
        scheme whose train is already canonical text.
        """

        normalized = value.strip()
        return normalized or None
