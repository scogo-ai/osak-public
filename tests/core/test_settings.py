from pathlib import Path

from osak.core.settings import Settings


def test_settings_reads_deployment_environment_names(monkeypatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./test.db")
    monkeypatch.setenv("RAW_STORE_PATH", "/var/lib/osak/raw")
    monkeypatch.setenv("MAX_MATCH_ASSETS", "250")

    settings = Settings()

    assert settings.database_url == "sqlite:///./test.db"
    assert settings.raw_store_path == Path("/var/lib/osak/raw")
    assert settings.max_match_assets == 250
