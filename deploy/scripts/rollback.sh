#!/usr/bin/env bash
set -Eeuo pipefail

# Roll back API and worker images only. Database migrations are intentionally
# forward-only; restoring a database snapshot is a separate, explicitly
# approved recovery operation described in docs/RUNBOOK.md.

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
COMPOSE_FILE=${COMPOSE_FILE:-"$ROOT_DIR/deploy/docker-compose.prod.yml"}
ENV_FILE=${ENV_FILE:-"$ROOT_DIR/.env"}
STATE_DIR=${STATE_DIR:-"$ROOT_DIR/.osak-deploy"}
COMPOSE_OVERRIDE_FILE=${OSAK_COMPOSE_OVERRIDE_FILE:-"$ROOT_DIR/deploy/docker-compose.ct203.production.yml"}

if [[ ! -f "$ENV_FILE" ]]; then
  printf 'Missing production environment file: %s\n' "$ENV_FILE" >&2
  exit 2
fi
if [[ ! -f "$STATE_DIR/previous-image-tag" ]]; then
  printf 'No previous image tag recorded in %s\n' "$STATE_DIR" >&2
  exit 2
fi

previous_tag=$(tr -d '\n' <"$STATE_DIR/previous-image-tag")
if [[ "$previous_tag" != "none" && ! "$previous_tag" =~ ^[[:alnum:]][[:alnum:]_.-]{6,127}$ ]]; then
  printf 'Previous image tag is unavailable or invalid: %q\n' "$previous_tag" >&2
  exit 2
fi
previous_revision=$(cat "$STATE_DIR/previous-deployed-revision" 2>/dev/null || true)
if [[ -z "$previous_revision" ]]; then
  previous_revision="none"
fi

compose=(docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE")
if [[ -n "$COMPOSE_OVERRIDE_FILE" && -f "$COMPOSE_OVERRIDE_FILE" ]]; then
  compose+=( -f "$COMPOSE_OVERRIDE_FILE" )
  export COMPOSE_PROFILES=${COMPOSE_PROFILES:-public}
  export OSAK_CT_BUILD_VERSION=${OSAK_CT_BUILD_VERSION:-$previous_revision}
fi

wait_ready() {
  local service=$1
  local attempts=${HEALTH_WAIT_ATTEMPTS:-90}
  local container state health info
  for _ in $(seq 1 "$attempts"); do
    container=$("${compose[@]}" ps -q "$service")
    if [[ -z "$container" ]]; then
      printf 'Compose service has no container: %s\n' "$service" >&2
      return 1
    fi
    info=$(docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container")
    state=${info%% *}
    health=${info#* }
    if [[ "$state" != "running" ]]; then
      printf 'Compose service stopped while waiting: %s (%s)\n' "$service" "$info" >&2
      return 1
    fi
    if [[ -z "$health" || "$health" == "healthy" ]]; then
      return 0
    fi
    if [[ "$health" == "unhealthy" ]]; then
      printf 'Compose service became unhealthy: %s\n' "$service" >&2
      return 1
    fi
    sleep 2
  done
  printf 'Timed out waiting for Compose service: %s\n' "$service" >&2
  return 1
}

wait_completed() {
  local service=$1
  local attempts=${MIGRATION_WAIT_ATTEMPTS:-90}
  local container state exit_code
  for _ in $(seq 1 "$attempts"); do
    container=$("${compose[@]}" ps -aq "$service")
    if [[ -z "$container" ]]; then
      printf 'Compose service has no container: %s\n' "$service" >&2
      return 1
    fi
    state=$(docker inspect --format '{{.State.Status}}' "$container")
    if [[ "$state" == "exited" ]]; then
      exit_code=$(docker inspect --format '{{.State.ExitCode}}' "$container")
      if [[ "$exit_code" == "0" ]]; then
        return 0
      fi
      printf 'Migration service exited with code %s\n' "$exit_code" >&2
      return 1
    fi
    if [[ "$state" != "running" ]]; then
      printf 'Migration service stopped unexpectedly: %s\n' "$state" >&2
      return 1
    fi
    sleep 2
  done
  printf 'Timed out waiting for migration service: %s\n' "$service" >&2
  return 1
}

write_env_tag() {
  local tag=$1
  export OSAK_IMAGE_TAG="$tag"
  local temporary="$ENV_FILE.osak.$$"
  awk -v tag="$tag" '
    BEGIN { found = 0 }
    $0 ~ /^OSAK_IMAGE_TAG=/ { print "OSAK_IMAGE_TAG=" tag; found = 1; next }
    { print }
    END { if (!found) print "OSAK_IMAGE_TAG=" tag }
  ' "$ENV_FILE" >"$temporary"
  chmod 600 "$temporary"
  mv "$temporary" "$ENV_FILE"
}

if [[ "$previous_tag" == "none" ]]; then
  # There is no prior release to restore on a first-ever deployment. Keep the
  # database/volumes, remove the unusable image tag, and leave services stopped.
  "${compose[@]}" stop api worker || true
  write_env_tag ""
  printf '%s\n' "none" >"$STATE_DIR/current-image-tag"
  printf '%s\n' "none" >"$STATE_DIR/deployed-revision"
  printf '%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$STATE_DIR/rolled-back-at"
  printf 'No previous release existed; stopped the first deployment.\n'
  exit 0
fi

write_env_tag "$previous_tag"
"${compose[@]}" config --quiet
# Keep a verified manual pre-GHCR release recoverable from its local tag.
# The previous binary need not know the *new* Alembic revision for an
# additive migration. Schema restoration is a separate backed-up procedure.
for service in api worker; do
  image=$("${compose[@]}" config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["services"][sys.argv[1]]["image"])' "$service")
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    "${compose[@]}" pull "$service"
  fi
done
"${compose[@]}" up -d --no-deps api worker

for service in postgres api worker; do
  wait_ready "$service"
done

printf '%s\n' "$previous_tag" >"$STATE_DIR/current-image-tag"
printf '%s\n' "$previous_revision" >"$STATE_DIR/deployed-revision"
printf '%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$STATE_DIR/rolled-back-at"
printf 'Rolled API and worker back to image %s\n' "$previous_tag"
