from collections.abc import Iterable
from datetime import datetime
from typing import ClassVar

from osak.connectors.base import HealthStatus, RawDocument, SourceLicense
from osak.core.models import CanonicalRecord


class Source:
    id = "{{ cookiecutter.source_id }}"
    vendor_scope: ClassVar[list[str]] = ["{{ cookiecutter.vendor_id }}"]
    kind = "advisory"
    tier = "free"
    auth = "none"
    schedule = 3600
    rate_limit = "Pending publisher review"
    license = SourceLicense(
        name="Unreviewed", url="", attribution="{{ cookiecutter.vendor_id }}",
        redistribution="review",
    )

    def healthcheck(self) -> HealthStatus:
        return HealthStatus(available=False, detail="Connector implementation pending")

    def fetch(self, since: datetime | None) -> Iterable[RawDocument]:
        raise NotImplementedError("Implement bounded bootstrap and incremental retrieval")

    def normalize(self, raw: RawDocument) -> Iterable[CanonicalRecord]:
        raise NotImplementedError("Map sourced facts to canonical records")
