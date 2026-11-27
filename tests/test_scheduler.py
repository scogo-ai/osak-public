from __future__ import annotations

from threading import Event
from typing import ClassVar

from osak.connectors.base import Connector, HealthStatus, RawDocument, SourceLicense
from osak.ingest import __main__ as ingest_main
from osak.ingest.policy import PublicationPolicy
from osak.ingest.scheduler import DatabaseSourceScheduler
from osak.ingest.worker import PollResult


class ScheduledFixture:
    vendor_scope: ClassVar[list[str]] = ["fixture"]
    kind = "advisory"
    tier = "free"
    license = SourceLicense(
        name="fixture",
        url="https://example.invalid/license",
        attribution="fixture",
        redistribution="facts",
    )
    auth = "none"
    rate_limit = "1/s"
    schedule = 1

    def __init__(self, source_id: str, *, fail: bool = False) -> None:
        self.id = source_id
        self.fail = fail

    def fetch(self, since):  # type: ignore[no-untyped-def]
        if self.fail:
            raise RuntimeError("fixture source failed")
        return iter(())

    def normalize(self, raw: RawDocument):  # type: ignore[no-untyped-def]
        return ()

    def healthcheck(self) -> HealthStatus:
        return HealthStatus(available=True, detail="fixture")


def test_slow_source_does_not_block_another_due_source() -> None:
    slow_started = Event()
    slow_release = Event()
    fast_done = Event()
    slow = ScheduledFixture("slow")
    fast = ScheduledFixture("fast")

    def poller(source_id: str, connector: Connector, policy: PublicationPolicy) -> list[PollResult]:
        del connector, policy
        if source_id == "slow":
            slow_started.set()
            assert slow_release.wait(2)
        else:
            fast_done.set()
        return [PollResult(source_id=source_id, success=True)]

    scheduler = DatabaseSourceScheduler(
        {slow.id: slow, fast.id: fast},
        PublicationPolicy(),
        max_workers=2,
        poller=poller,
    )
    try:
        scheduler.tick()
        assert slow_started.wait(1)
        assert fast_done.wait(0.5)
        assert "slow" in scheduler.active_source_ids
    finally:
        slow_release.set()
        scheduler.close(wait_for_tasks=True)


def test_one_shot_failure_returns_nonzero_and_missing_source_is_explicit(
    monkeypatch, tmp_path
) -> None:  # type: ignore[no-untyped-def]
    connector = ScheduledFixture("broken", fail=True)
    monkeypatch.setattr(ingest_main, "discover", lambda: {connector.id: connector})
    monkeypatch.setenv("OSAK_ENV", "development")
    monkeypatch.setenv("INGEST_ENABLED", "true")

    assert (
        ingest_main.main(
            ["--memory", "--once", "--source", "broken", "--data-dir", str(tmp_path / "failed")]
        )
        == 1
    )
    assert (
        ingest_main.main(
            ["--memory", "--once", "--source", "missing", "--data-dir", str(tmp_path / "missing")]
        )
        == 2
    )

