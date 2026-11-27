from collections.abc import Iterable
from datetime import datetime
from importlib.metadata import entry_points
from typing import Literal, Protocol

from pydantic import AwareDatetime

from osak.core.models import CanonicalRecord, Model


class SourceLicense(Model):
    name: str
    url: str
    attribution: str
    redistribution: Literal["facts", "restricted", "review"]


class RawDocument(Model):
    url: str
    fetched_at: AwareDatetime
    content: bytes
    media_type: str = "application/json"


class HealthStatus(Model):
    available: bool
    detail: str


class Connector(Protocol):
    id: str
    vendor_scope: list[str]
    kind: Literal["advisory", "enrichment", "eol"]
    tier: Literal["free", "paid"]
    license: SourceLicense
    auth: Literal["none", "api_key", "oauth_client_credentials"]
    rate_limit: str
    schedule: int  # seconds between successful polls

    def fetch(self, since: datetime | None) -> Iterable[RawDocument]: ...
    def normalize(self, raw: RawDocument) -> Iterable[CanonicalRecord]: ...
    def healthcheck(self) -> HealthStatus: ...


def discover() -> dict[str, Connector]:
    plugins = {}
    for entry in entry_points(group="osak.connectors"):
        connector = entry.load()()
        if entry.name != connector.id or entry.name in plugins:
            raise ValueError(f"Invalid connector registration: {entry.name}")
        plugins[entry.name] = connector
    return plugins
