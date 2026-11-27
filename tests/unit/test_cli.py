from typer.testing import CliRunner

from osak import cli
from osak.cli import app


def test_cli_exposes_seed_and_admin_commands():
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "seed" in result.stdout
    assert "admin" in result.stdout


def test_admin_help_exposes_users_keys_and_usage():
    result = CliRunner().invoke(app, ["admin", "--help"])

    assert result.exit_code == 0
    assert "users" in result.stdout
    assert "keys" in result.stdout
    assert "usage" in result.stdout


def test_dev_seed_refuses_production_before_opening_database(monkeypatch):
    monkeypatch.setenv("OSAK_ENV", "production")
    monkeypatch.setattr(cli, "_session", lambda: (_ for _ in ()).throw(AssertionError("opened DB")))

    result = CliRunner().invoke(app, ["seed", "--dev"])

    assert result.exit_code != 0
