import json
import os
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

ROOT = Path(__file__).resolve().parents[2]


def test_release_workflow_uses_origin_ssh_and_last_deployed_revision() -> None:
    workflow = (ROOT / ".github/workflows/deploy.yml").read_text(encoding="utf-8")

    assert "runs-on: [self-hosted, linux, osak-origin]" not in workflow
    assert "setup-origin-ssh.sh" in workflow
    assert "DEPLOY_PATH" not in workflow
    assert "Read last successfully deployed revision" in workflow
    assert "osak-origin state" in workflow
    assert "git merge-base --is-ancestor" in workflow
    assert "git ls-tree -r --name-only" in workflow
    assert "full_redeploy=true" in workflow
    assert "osak-origin smoke" in workflow
    assert "wrangler@4.168.0 rollback" in workflow
    assert "secrets.OSAK_GHCR_TOKEN" not in workflow
    assert "secrets.OSAK_GHCR_USERNAME" not in workflow
    assert "github.token" in workflow
    backend_part, website_part = workflow.split("  website:", 1)
    assert "smoke_mcp.py" not in backend_part
    assert "smoke_mcp.py" in website_part
    assert "REPOSITORY_URL:${{ github.server_url }}/${{ github.repository }}" in workflow
    assert "TURNSTILE_SITE_KEY" in website_part
    assert "previous-worker-version.jq" in website_part
    assert "rollback --yes" in workflow
    assert "not found" in workflow

    fixture = json.loads(
        (ROOT / "tests/deploy/fixtures/wrangler-deployments.json").read_text(encoding="utf-8")
    )
    command = ["jq", "-er", "-f", str(ROOT / ".github/scripts/previous-worker-version.jq")]
    active = subprocess.run(command, input=json.dumps(fixture), capture_output=True, text=True, check=True)
    assert active.stdout.strip() == "active-worker-version"
    initial = subprocess.run(command, input="[]", capture_output=True, text=True, check=True)
    assert initial.stdout.strip() == ""
    for version in fixture[-1]["versions"]:
        version["percentage"] = 50
    split = subprocess.run(command, input=json.dumps(fixture), capture_output=True, text=True, check=False)
    assert split.returncode != 0


def test_release_scripts_support_ct_override_and_first_release_rollback() -> None:
    deploy = (ROOT / "deploy/scripts/deploy-backend.sh").read_text(encoding="utf-8")
    rollback = (ROOT / "deploy/scripts/rollback.sh").read_text(encoding="utf-8")

    assert "docker-compose.ct203.production.yml" in deploy
    assert "COMPOSE_PROFILES" in deploy
    assert "deployed-revision" in deploy
    assert "previous_tag" in deploy
    assert "stop api worker cloudflared" not in deploy
    assert "up -d --no-deps --no-recreate backup cloudflared" in deploy
    assert "up -d --no-deps api worker" in deploy
    assert "docker-compose.ct203.production.yml" in rollback
    assert "previous-deployed-revision" in rollback
    assert '[[ "$previous_tag" == "none" ]]' in rollback
    assert "stop api worker cloudflared" not in rollback
    assert "stop api worker || true" in rollback


def test_forced_command_wrapper_has_fixed_operations_and_path() -> None:
    wrapper = (ROOT / "deploy/scripts/osak-release-ssh-wrapper").read_text(encoding="utf-8")

    assert "DEPLOY_PATH=/opt/osak" in wrapper
    assert 'case "${SSH_ORIGINAL_COMMAND:-}" in' in wrapper
    for operation in (
        "state",
        "install",
        "ghcr-login",
        "deploy",
        "rollback",
        "smoke",
        "record-release",
        "logout",
    ):
        assert f"{operation})" in wrapper
    assert "*) die ;;" in wrapper
    assert "docker login ghcr.io --username github-actions[bot]" in wrapper
    assert "SSH_ORIGINAL_COMMAND" in wrapper
    assert '"scripts/osak-release-ssh-wrapper"' not in wrapper.split("allowed = ", 1)[1].split("seen = ", 1)[0]


def test_host_smoke_can_override_base_url_and_mcp_transport() -> None:
    smoke = (ROOT / "deploy/scripts/smoke.sh").read_text(encoding="utf-8")
    mcp = (ROOT / "deploy/scripts/smoke_mcp.py").read_text(encoding="utf-8")

    assert "OSAK_SMOKE_BASE_URL" in smoke
    assert "OSAK_SMOKE_BASE_URL" in mcp


def test_release_shell_scripts_parse() -> None:
    paths = [
        *sorted((ROOT / "deploy/scripts").glob("*.sh")),
        ROOT / ".github/scripts/setup-origin-ssh.sh",
    ]
    for path in paths:
        result = subprocess.run(
            ["bash", "-n", str(path)], check=False, capture_output=True, text=True
        )
        assert result.returncode == 0, f"{path}: {result.stderr}"


def test_release_wrapper_installs_complete_archive_only(tmp_path):
    import io
    import os
    import tarfile

    wrapper = tmp_path / "receiver"
    source = ROOT / "deploy/scripts/osak-release-ssh-wrapper"
    wrapper.write_text(source.read_text().replace("DEPLOY_PATH=/opt/osak", f"DEPLOY_PATH={tmp_path}"))
    sha = "a" * 40
    files = ["docker-compose.prod.yml", "docker-compose.ct203.production.yml", "scripts/deploy-backend.sh",
             "scripts/rollback.sh", "scripts/smoke.sh", "scripts/smoke_mcp.py"]
    for names, success in [(files[:-1], False), (files, True)]:
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as tgz:
            for name in names:
                tgz.add(ROOT / "deploy" / name, arcname=name, recursive=False)
        result = subprocess.run(["bash", str(wrapper)], env={**os.environ, "SSH_ORIGINAL_COMMAND": "install"},
                                input=sha.encode() + b"\n" + data.getvalue(), capture_output=True, check=False)
        assert (result.returncode == 0) is success, result.stderr
        marker = tmp_path / ".osak-deploy/installed-revision"
        assert marker.exists() is success
        if success:
            assert marker.read_text().strip() == sha


def test_origin_smoke_authenticates_each_probe_to_the_protected_origin() -> None:
    observed = []

    class Origin(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            trusted = self.headers.get("X-OSAK-Origin-Secret") == "origin-fixture"
            bearer = self.headers.get("Authorization") == "Bearer test"
            observed.append((self.path, trusted, bearer))
            if not trusted:
                status = 403
            elif self.path == "/mcp" or (self.path.endswith("/vendors") and not bearer):
                status = 401
            else:
                status = 200
            self.send_response(status)
            self.end_headers()

    with ThreadingHTTPServer(("127.0.0.1", 0), Origin) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            subprocess.run(
                ["bash", str(ROOT / "deploy/scripts/smoke.sh")],
                env={**os.environ, "OSAK_SMOKE_BASE_URL": f"http://127.0.0.1:{server.server_port}",
                     "OSAK_SMOKE_TEST_KEY": "test", "OSAK_ORIGIN_SHARED_SECRET": "origin-fixture",
                     "CURL_RETRIES": "0"}, capture_output=True, check=True,
            )
        finally:
            server.shutdown()
            thread.join()
    assert {path for path, _, _ in observed} == {
        "/api/v1/health", "/docs", "/openapi.json", "/api/v1/vendors", "/mcp",
    }
    assert all(trusted for _, trusted, _ in observed)
    assert [path for path, _, bearer in observed if bearer] == ["/api/v1/vendors"]
