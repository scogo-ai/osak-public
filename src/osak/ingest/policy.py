"""Publication policy for connector data.

The ingestion worker may be run by a private operator with additional
connectors, but the public deployment must not accidentally redistribute a
paid feed or a source whose terms have not been reviewed.  Policy is evaluated
before a connector is fetched, and the resulting decision is retained in
source status so an excluded source is visible rather than silently missing.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    state: str
    reason: str


@dataclass(frozen=True, slots=True)
class PublicationPolicy:
    """Decide whether a connector may be polled and published.

    ``public=True`` is the production/public-instance posture.  In that mode
    paid sources are always rejected, even if an operator accidentally puts
    their id in the reviewed allowlist.  Restricted/review sources are allowed
    only when explicitly approved on the host.
    """

    public: bool = False
    reviewed_source_ids: frozenset[str] = frozenset()
    disabled_source_ids: frozenset[str] = frozenset()
    enabled_source_ids: frozenset[str] | None = None
    allow_paid_private: bool = False

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> PublicationPolicy:
        env = os.environ if environ is None else environ

        def csv(name: str) -> frozenset[str]:
            return frozenset(item.strip() for item in env.get(name, "").split(",") if item.strip())

        environment = env.get("OSAK_ENV", "development").strip().lower()
        public_value = env.get("OSAK_PUBLIC_MODE", "").strip().lower()
        public = public_value in {"1", "true", "yes", "on"} or environment in {
            "production",
            "prod",
        }
        allow_paid = env.get("OSAK_ALLOW_PAID_SOURCES", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        return cls(
            public=public,
            reviewed_source_ids=csv("OSAK_REVIEWED_SOURCE_ALLOWLIST"),
            disabled_source_ids=csv("OSAK_DISABLED_SOURCES"),
            enabled_source_ids=csv("OSAK_ENABLED_SOURCES") or None,
            allow_paid_private=allow_paid,
        )

    def evaluate(self, connector: Any) -> PolicyDecision:
        source_id = str(connector.id)
        if source_id in self.disabled_source_ids:
            return PolicyDecision(False, "disabled", "source disabled by host configuration")
        if self.enabled_source_ids is not None and source_id not in self.enabled_source_ids:
            return PolicyDecision(False, "disabled", "source is not in the host enabled-source list")

        if self.enabled_source_ids is None and getattr(connector, "requires_opt_in", False):
            return PolicyDecision(False, "disabled", "optional source requires explicit host selection")

        tier = str(getattr(connector, "tier", "free"))
        license_info = getattr(connector, "license", None)
        redistribution = str(getattr(license_info, "redistribution", "review"))
        if self.public and tier == "paid":
            return PolicyDecision(False, "unapproved", "paid sources are excluded in public mode")
        if tier == "paid" and not self.public and not self.allow_paid_private:
            return PolicyDecision(False, "unapproved", "paid source requires explicit private-mode enablement")
        if tier not in {"free", "paid"}:
            return PolicyDecision(False, "unapproved", f"unknown source tier {tier!r}")
        if tier == "free" and redistribution == "facts":
            return PolicyDecision(True, "never_synced", "structured facts are approved for redistribution")
        if source_id in self.reviewed_source_ids:
            return PolicyDecision(True, "never_synced", "source is explicitly approved by host allowlist")
        return PolicyDecision(
            False,
            "unapproved",
            f"license redistribution={redistribution!r} requires explicit host review",
        )

