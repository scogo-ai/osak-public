from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from osak.core.settings import get_settings


def test_core_migration_creates_and_drops_schema(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite:///{tmp_path / 'osak.sqlite'}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config("alembic.ini")

    command.upgrade(config, "head")
    tables = set(inspect(create_engine(database_url)).get_table_names())
    assert {"vendors", "advisories", "affected_ranges", "raw_documents", "changes"} <= tables

    command.downgrade(config, "base")
    assert inspect(create_engine(database_url)).get_table_names() == ["alembic_version"]
