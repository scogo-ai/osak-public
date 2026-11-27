from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from osak.core.models import VersionRange


@dataclass(frozen=True)
class ParsedVersion:
    normalized: str
    train: str
    order: tuple[int, ...]


@runtime_checkable
class VersionScheme(Protocol):
    """None denotes unsupported syntax, incomparable trains or insufficient evidence."""

    def parse(self, value: str) -> ParsedVersion | None: ...
    def normalize(self, value: str) -> str | None: ...
    def compare(self, left: str, right: str) -> int | None: ...
    def in_range(self, value: str, bounds: VersionRange) -> bool | None: ...
