from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_production_workflow_keeps_database_and_sink_inputs_on_origin() -> None:
    workflow = (ROOT / ".github/workflows/qa.yml").read_text(encoding="utf-8")

    assert "environment: production" in workflow
    assert "github.ref == 'refs/heads/main'" in workflow
    assert "osak-origin zdr" in workflow
    assert "OSAK_ZDR_DATABASE_URL" not in workflow
    assert "OSAK_ZDR_LOG_SINK_TOKEN" not in workflow
    assert "OSAK_ZDR_LOG_SINK_URL" not in workflow


def test_origin_wrapper_allows_only_the_fixed_zdr_operation() -> None:
    wrapper = (ROOT / "deploy/scripts/osak-release-ssh-wrapper").read_text(encoding="utf-8")

    assert '  zdr) zdr ;;' in wrapper
    assert 'SSH_ORIGINAL_COMMAND:-' in wrapper
    assert "docker.sock" not in wrapper
    assert 'printf %s "$DATABASE_URL"' in wrapper
    assert 'docker-compose.ct203.production.yml' in wrapper
    assert 'project=osak-ct203-prod' in wrapper
    assert 'python /app/scripts/qa/zdr_canary.py' in wrapper
