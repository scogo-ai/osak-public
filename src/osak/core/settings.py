"""Application settings used by the API, worker and migration commands."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration.

    Settings deliberately use the unprefixed names from the deployment contract so
    ``DATABASE_URL`` works for both the application and Alembic.  Additional
    application options are kept here rather than read directly from ``os.environ``
    so every process has one source of truth.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        populate_by_name=True,
    )

    database_url: str = Field(default="sqlite:///./osak.db", validation_alias="DATABASE_URL")
    raw_store_path: Path = Field(default=Path("./data/raw"), validation_alias="RAW_STORE_PATH")
    max_match_assets: int = Field(default=500, ge=1, validation_alias="MAX_MATCH_ASSETS")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings object."""

    return Settings()
