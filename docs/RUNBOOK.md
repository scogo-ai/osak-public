# OSAK operations runbook

This runbook covers the Docker Compose origin, the GitHub Actions release, and
the Cloudflare edge. It is intentionally written so a new operator can run it
without access to this development checkout.

## Safety boundaries

- The origin has no published API or PostgreSQL port in production. Only the
  `cloudflared` container makes outbound tunnel connections.
- Keep the production `.env` on the origin host with mode `0600`. It contains
  the database password, key pepper, Resend key, Turnstile secret and tunnel
  token. It never belongs in Git, an image, or a GitHub issue.
- Request bodies are not part of OSAK request logs. Do not paste an asset
  inventory into `docker compose logs`, CI output or an incident ticket.
- Backups contain the database. Store the backup volume on encrypted storage
  and restrict the Docker host account; retain only the documented period.

## Local stack

From the repository root:

```sh
cp .env.example .env
docker compose up --build
```

The root `compose.yaml` includes `deploy/docker-compose.yml` and uses the
isolated project name `osak-local`. API and Mailpit are loopback-only:

- API: <http://127.0.0.1:8000>
- Swagger: <http://127.0.0.1:8000/docs>
- Mailpit: <http://127.0.0.1:8025>
- PostgreSQL: `127.0.0.1:5433`

The one-shot `migrate` service waits for PostgreSQL, runs `alembic upgrade
head`, and must exit successfully before Compose starts the API and worker.
The worker must update
`OSAK_WORKER_HEARTBEAT_FILE` after each completed ingestion poll; a stale file
marks the worker unhealthy.

The worker image pins gocsaf `v3.7.1` and includes the upstream
`csaf_downloader` and `csaf_validator` binaries. A local tool check is:

```sh
docker compose exec worker csaf_downloader --version
docker compose exec worker csaf_validator --version
```

Connectors should invoke the downloader with a destination under
`/var/lib/osak/data`, strict validation, a descriptive User-Agent and an
explicit `--log_file` under that directory; the default current-directory log
would be read-only in the hardened image.

Create a local key in a second terminal. The plaintext is printed once:

```sh
docker compose run --rm api osak seed --dev
export OSAK_TEST_KEY='osak_test_<printed-value>'
curl -H "Authorization: Bearer $OSAK_TEST_KEY" http://127.0.0.1:8000/api/v1/vendors
```

Use `docker compose -p osak-local ...` explicitly if another checkout is using
the default project name. Production uses `osak-prod` and must not share local
volumes.

## Origin host bootstrap

The current B1 target is an unprivileged LXC on Proxmox `srv2`; it must provide
the same operational envelope as the recommended Ubuntu 24.04 VM: at least 4
vCPU, 8 GB RAM, 100 GB SSD, Docker Engine plus the Compose plugin, outbound
HTTPS/DNS and a restricted SSH path for administrators. Kubernetes is not used by this
release. Clone the public OSAK repository into a dedicated path, for example
`/opt/osak`, then install the deployment controls and create the host-only
environment:

```sh
sudo install -d -m 0750 -o "$USER" -g "$USER" /opt/osak
cd /opt/osak
cp .env.example .env
chmod 600 .env
$EDITOR .env
```

Set all production values, including distinct image names:

```dotenv
OSAK_ENV=production
OSAK_API_IMAGE=ghcr.io/<owner>/<repository>-api
OSAK_WORKER_IMAGE=ghcr.io/<owner>/<repository>-worker
OSAK_IMAGE_TAG=<immutable-git-sha>
OSAK_PUBLIC_BASE_URL=https://osak.lab.scogo.ai
OSAK_EMAIL_FROM=OSAK <security@example.com>
OSAK_ADMIN_ACCESS_TOKEN=<random-secret>
POSTGRES_DB=osak
POSTGRES_USER=osak
POSTGRES_PASSWORD=<random-secret>
DATABASE_URL=postgresql+psycopg://osak:<url-escaped-password>@postgres:5432/osak
OSAK_KEY_PEPPER=<same-or-separate-random-secret>
OSAK_ORIGIN_SHARED_SECRET=<random-secret-shared-with-worker-binding>
EMAIL_BACKEND=resend
RESEND_API_KEY=re_...
TURNSTILE_SECRET_KEY=0x...
CLOUDFLARED_TUNNEL_TOKEN=<tunnel-token>
```

Validate the production configuration without starting services:

```sh
docker compose --env-file .env -f deploy/docker-compose.prod.yml config --quiet
```

The release uses a GitHub-hosted runner and reaches the LXC through the
dedicated Cloudflare Access SSH hostname (for example
`osak-ssh.scogo.ai`). The runner uses a pinned host-key file and a dedicated
deploy key; it never receives a privileged GitHub Actions runner installation.
The origin user must be restricted in `authorized_keys` with no agent or port
forwarding and a host-side command allowlist covering only the release
operations (`mkdir`, `chmod`, `docker login/logout`, the deploy/rollback
scripts and the host-network smoke commands). Keep the deploy key, Access
client ID/secret and host public key in GitHub environment secrets; do not
print them.

Install the wrapper as root on the CT and point the release key at it. The
wrapper has a fixed `/opt/osak` deployment path and accepts only `state`,
`install`, `ghcr-login`, `deploy`, `rollback`, `smoke`, `zdr`, `record-release` and
`logout`; it rejects shell syntax, paths and extra arguments. `install` accepts
only the allowlisted tar archive produced by the workflow and never touches
`.env`, SSH keys or other host files.

```sh
sudo install -o root -g root -m 0755 \
  deploy/scripts/osak-release-ssh-wrapper \
  /usr/local/sbin/osak-release-ssh-wrapper
sudo install -d -o scogo -g scogo -m 0750 /opt/osak/.osak-deploy
sudo chmod 0700 /opt/osak/.osak-deploy
```

Add the deploy public key as one restricted line (replace the key only through
the host's administrator procedure):

```text
restrict,command="/usr/local/sbin/osak-release-ssh-wrapper" ssh-ed25519 AAAA... osak-release
```

The wrapper runs as the restricted `scogo` account, which may run Docker and
write only the prepared `/opt/osak` checkout/state. The root-owned wrapper is
the only SSH command boundary; do not enable an unrestricted shell, SFTP,
agent forwarding or port forwarding for this key.

## Release and deploy

Every merge to `main` runs CI first. `.github/workflows/deploy.yml` is triggered
only by the successful CI `workflow_run` for that exact main-branch SHA (or an
explicit manual SHA whose CI run is verified). The workflow:

1. Verifies the same-SHA CI run, including the source-backed golden accuracy
   job. Docs-only commits produce no deployment jobs.
2. Classifies changed paths. Backend changes build and push separate API and
   worker images to GHCR, each tagged with the full commit SHA.
3. Reads `.osak-deploy/deployed-revision` over the restricted SSH path. A
   missing or invalid revision means an initial full redeploy; otherwise the
   path scope is the diff from that last successful revision through the target
   SHA, so missed pushes are included.
4. Installs only Compose and release controls on the origin LXC through SSH.
5. Logs in to GHCR on the origin with the workflow's short-lived
   `GITHUB_TOKEN`; no long-lived GHCR credential is required.
5. Recreates the migration gate, which runs `alembic upgrade head`.
6. Starts PostgreSQL, API, worker, backup and cloudflared with the immutable
   SHA tag, then checks all service states.
7. Runs host-network API and MCP smoke tests inside the LXC. If they fail after
   a successful backend deployment, the previous image tag/revision is
   restored automatically. A first-ever deployment has no prior image, so the
   release services are stopped rather than pretending a rollback succeeded.

When a commit changes both backend and website, the website deploy waits for a
successful backend deploy. Public MCP smoke runs only after the Worker has been
released; the previous Worker deployment is restored when a later website
smoke fails. The `rollback-shared` job then restores the backend image on the
origin host. A website-only change never starts a backend image job; a
backend-only change never invokes Wrangler.

The deploy job needs these GitHub Actions secrets/variables:

- `OSAK_ORIGIN_SSH_KEY`, `OSAK_ORIGIN_SSH_KNOWN_HOSTS` (restricted deploy key
  and pinned host key)
- `OSAK_CF_ACCESS_CLIENT_ID`, `OSAK_CF_ACCESS_CLIENT_SECRET` (dedicated Access
  service token for `osak-ssh.scogo.ai`)
- `OSAK_ORIGIN_SSH_HOST` and `OSAK_ORIGIN_SSH_USER` (repository variables,
  defaulting to `osak-ssh.scogo.ai` and `scogo`)
- `OSAK_SMOKE_TEST_KEY` (a production key used only by smoke tests)
- `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`
- optional repository variable `OSAK_BASE_URL` (defaults to
  `https://osak.lab.scogo.ai`)

Keep the production `.env` and the host-side authorized-key restriction
outside the repository. Administrative SSH access to the LXC remains a
separate, operator-controlled path; the release key is narrower and only
reaches the origin through Cloudflare Access.

Website-only changes under `web/**` run only the website job and production
Wrangler deployment. Changes to the Cloudflare desired-state JSON/runbook are
review-only and do not silently mutate edge policy. Backend-only changes do not
invoke Wrangler.

The manual equivalents for a release on an already bootstrapped host are:

```sh
./deploy/scripts/deploy-backend.sh <full-git-sha>
OSAK_BASE_URL=https://osak.lab.scogo.ai \
OSAK_SMOKE_TEST_KEY='osak_live_...' \
  ./deploy/scripts/smoke.sh
```

The smoke test is intentionally narrow: it checks `/api/v1/health`, `/docs`,
`/openapi.json`, an authenticated `/api/v1/vendors` request, and the MCP auth
boundary (`401`, `403` or `405` for an unauthenticated request). It never sends
an inventory body.

## Rollback

The deploy script records the prior tag in `.osak-deploy/previous-image-tag`.
When a post-deploy smoke test fails, CI calls:

```sh
./deploy/scripts/rollback.sh
```

To invoke it manually, SSH to the origin and run it from the deployment path.
It pulls and starts only the previous API/worker images and leaves the
database, backup and tunnel services intact.

Migrations are forward-only. Image rollback does not downgrade PostgreSQL
schema. If the release introduced an incompatible migration, stop API/worker,
take a fresh backup, obtain incident approval, restore the selected database
snapshot, and rerun the migration gate before bringing traffic back.

## Backups and restore

The production `backup` service writes PostgreSQL custom-format dumps and
SHA-256 sidecars to the Compose `backup-data` volume every 24 hours, retaining
14 days by default. A manual host backup is:

```sh
./deploy/scripts/backup.sh
```

Verify a dump before relying on it:

```sh
sha256sum -c backups/osak-<timestamp>.dump.sha256
docker run --rm -v "$PWD/backups:/backups:ro" \
  postgres:16.6-alpine pg_restore --list /backups/osak-<timestamp>.dump >/dev/null
```

On srv2 CT 203, use both Compose files so the commands target the production
services and PostgreSQL port. If the selected dump is in the scheduled
backup volume, copy it to the host with `docker compose cp` and verify its
checksum inside the backup service before restoring it.

```bash
cd /opt/osak
compose=(docker compose --env-file .env -f deploy/docker-compose.prod.yml \
  -f deploy/docker-compose.ct203.production.yml --profile public)
dump_name=osak-YYYYMMDDTHHMMSSZ.dump
umask 077
mkdir -p backups
"${compose[@]}" exec -T backup sha256sum -c "/backups/$dump_name.sha256"
"${compose[@]}" cp "backup:/backups/$dump_name" "backups/$dump_name"
```

After incident approval, stop API, worker and cloudflared, then take a current
backup with `./deploy/scripts/backup.sh`. Restore a dump into a fresh database
when its schema differs from the current one so objects created by later
migrations cannot interfere. Keep the original database available until the
restored service passes smoke tests.

```bash
restore_db=osak_restore_YYYYMMDD
"${compose[@]}" stop api worker cloudflared
./deploy/scripts/backup.sh
"${compose[@]}" exec -T postgres sh -ec '
  createdb --port "${POSTGRES_PORT:-5432}" --username "$POSTGRES_USER" \
    --template template0 "$1"
' sh "$restore_db"
"${compose[@]}" exec -T postgres sh -ec '
  pg_restore --port "${POSTGRES_PORT:-5432}" --username "$POSTGRES_USER" \
    --dbname "$1" --single-transaction --no-owner --no-privileges
' sh "$restore_db" < "backups/$dump_name"
```

Set `POSTGRES_DB` in the protected `.env` to the restored database name.
Update the database name in any explicit database URL set there. Run the
migration gate with the intended release image, then smoke-test REST and MCP
before closing the incident.

```bash
"${compose[@]}" up -d --wait postgres
"${compose[@]}" up -d --force-recreate migrate
"${compose[@]}" wait migrate
"${compose[@]}" run --rm --no-deps --entrypoint python api -c '
from osak.accounts.service import roll_up_usage
from osak.core.db import session_scope

with session_scope() as session:
    roll_up_usage(session)
'
"${compose[@]}" up -d api worker backup cloudflared
```

## Secret rotation

1. Generate replacement values in a secure password manager; do not put them
   in a pull request.
2. Update the host `.env` atomically and `chmod 600` it.
3. For `OSAK_ORIGIN_SHARED_SECRET`, update the Worker secret binding and the
   origin in one controlled window. The Worker sends it as the
   `x-osak-origin-secret` header; a mismatch should fail closed.
4. For `CLOUDFLARED_TUNNEL_TOKEN`, create/revoke the token in Cloudflare and
   recreate only the cloudflared container.
5. For `RESEND_API_KEY` or `TURNSTILE_SECRET_KEY`, update the provider and
   recreate API/worker.
6. Rotating `OSAK_KEY_PEPPER` invalidates stored key
   hashes. Plan a maintenance window to issue replacement keys; never log or
   email the old plaintext again.
7. Run the authenticated smoke test and inspect only metadata logs.

```sh
docker compose --env-file .env -f deploy/docker-compose.prod.yml up -d --force-recreate api worker cloudflared
```

## Troubleshooting checks

```sh
docker compose --env-file .env -f deploy/docker-compose.prod.yml ps
docker compose --env-file .env -f deploy/docker-compose.prod.yml logs --since=10m api worker migrate
docker inspect --format '{{json .State.Health}}' "$(docker compose --env-file .env -f deploy/docker-compose.prod.yml ps -q worker)"
```

The worker is unhealthy when its heartbeat is older than five minutes. Check
the connector schedule and source rate limits before restarting it. Never use
debug logging that includes request bodies.

## Deployment state

[PROGRESS.md](../PROGRESS.md) tracks the active gates. The protected GitHub environment is named `production`, with a deployment policy allowing `main`. Its deployed origin account uses a dedicated SSH key restricted to the loopback Cloudflare connector and a fixed release command. The origin's Mac administration key remains separate.

GitHub holds environment secrets for the deployment SSH private key, pinned host public key, OSAK smoke key and Cloudflare account ID. At launch it also needs the scoped Workers deployment token and the SSH Access service-token pair. The OSAK origin shared secret stays on the guest and in Worker bindings. Data-provider credentials belong on the guest. Rotate the Cisco, NVD and Resend credentials supplied in chat before the final public rollout. Replace permissions and secrets through their respective provider consoles and verify the replacement before revocation.
