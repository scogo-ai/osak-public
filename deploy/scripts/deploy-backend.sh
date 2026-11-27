#!/usr/bin/env bash
set -Eeuo pipefail

# Deploy immutable GHCR image tags to the existing origin host. This script is
# intended to run on that host over a controlled SSH path from CI.

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
COMPOSE_FILE=${COMPOSE_FILE:-"$ROOT_DIR/deploy/docker-compose.prod.yml"}
ENV_FILE=${ENV_FILE:-"$ROOT_DIR/.env"}
STATE_DIR=${STATE_DIR:-"$ROOT_DIR/.osak-deploy"}
COMPOSE_OVERRIDE_FILE=${OSAK_COMPOSE_OVERRIDE_FILE:-"$ROOT_DIR/deploy/docker-compose.ct203.production.yml"}
IMAGE_TAG=${1:-${OSAK_IMAGE_TAG:-}}

if [[ ! "$IMAGE_TAG" =~ ^[[:alnum:]][[:alnum:]_.-]{6,127}$ ]]; then
  printf 'Expected a non-empty immutable image tag (usually a Git SHA), got %q\n' "$IMAGE_TAG" >&2
  exit 2
fi
if [[ ! -f "$ENV_FILE" ]]; then
  printf 'Missing production environment file: %s\n' "$ENV_FILE" >&2
  exit 2
fi

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
umask 077

compose=(docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE")
if [[ -n "$COMPOSE_OVERRIDE_FILE" && -f "$COMPOSE_OVERRIDE_FILE" ]]; then
  compose+=( -f "$COMPOSE_OVERRIDE_FILE" )
  export COMPOSE_PROFILES=${COMPOSE_PROFILES:-public}
  export OSAK_CT_BUILD_VERSION=${OSAK_CT_BUILD_VERSION:-$IMAGE_TAG}
fi

read_env_tag() {
  awk -F= '$1 == "OSAK_IMAGE_TAG" { print substr($0, index($0, "=") + 1); exit }' "$ENV_FILE"
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

previous_tag=$(read_env_tag || true)
if [[ -z "$previous_tag" ]]; then
  previous_tag="none"
fi
previous_revision=$(cat "$STATE_DIR/deployed-revision" 2>/dev/null || true)
if [[ -z "$previous_revision" ]]; then
  previous_revision="none"
fi

printf '%s\n' "$previous_tag" >"$STATE_DIR/previous-image-tag"
printf '%s\n' "$previous_revision" >"$STATE_DIR/previous-deployed-revision"
printf '%s\n' "$IMAGE_TAG" >"$STATE_DIR/requested-image-tag"
printf '%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$STATE_DIR/deploy-started-at"

rollback_on_error() {
  local exit_code=$?
  trap - ERR
  if [[ "$previous_tag" != "none" ]]; then
    printf 'Deployment failed; restoring image tag %s\n' "$previous_tag" >&2
    write_env_tag "$previous_tag" || true
    if ! "${compose[@]}" up -d --no-deps api worker; then
      printf 'Automatic image restoration failed; inspect the origin before retrying.\n' >&2
    fi
  else
    # A first-ever deployment has no image to restore. Leave the database and
    # volumes intact, but stop the newly exposed services.
    "${compose[@]}" stop api worker || true
  fi
  exit "$exit_code"
}
trap rollback_on_error ERR

write_env_tag "$IMAGE_TAG"
"${compose[@]}" config --quiet
"${compose[@]}" pull api worker
"${compose[@]}" up -d postgres
# `migrate` is a one-shot completion gate. It runs Alembic once and only then
# permits API and worker containers to start.
"${compose[@]}" up -d --force-recreate migrate
wait_completed migrate
"${compose[@]}" up -d --no-deps api worker
# This tunnel carries the release SSH connection. Replacing it here can
# disconnect the command while Docker still has application containers in Created.
"${compose[@]}" up -d --no-deps --no-recreate backup cloudflared

for service in postgres api worker backup cloudflared; do
  wait_ready "$service"
done

printf '%s\n' "$IMAGE_TAG" >"$STATE_DIR/current-image-tag"
printf '%s\n' "$IMAGE_TAG" >"$STATE_DIR/deployed-revision"
printf '%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$STATE_DIR/deployed-at"
printf 'Backend image %s is running. Previous image: %s\n' "$IMAGE_TAG" "$previous_tag"
