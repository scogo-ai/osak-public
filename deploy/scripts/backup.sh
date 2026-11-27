#!/usr/bin/env bash
set -Eeuo pipefail

# Create a consistent PostgreSQL custom-format dump from the production
# Compose service. The destination is deliberately an explicit, narrow path;
# this script never deletes outside BACKUP_DIR.

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
COMPOSE_FILE=${COMPOSE_FILE:-"$ROOT_DIR/deploy/docker-compose.prod.yml"}
ENV_FILE=${ENV_FILE:-"$ROOT_DIR/.env"}
BACKUP_DIR=${BACKUP_DIR:-"$ROOT_DIR/backups"}
RETENTION_DAYS=${RETENTION_DAYS:-14}
COMPOSE_OVERRIDE_FILE=${OSAK_COMPOSE_OVERRIDE_FILE:-"$ROOT_DIR/deploy/docker-compose.ct203.production.yml"}

if [[ ! -f "$ENV_FILE" ]]; then
  printf 'Missing production environment file: %s\n' "$ENV_FILE" >&2
  exit 2
fi

mkdir -p "$BACKUP_DIR"
umask 077
stamp=$(date -u +%Y%m%dT%H%M%SZ)
target="$BACKUP_DIR/osak-${stamp}.dump"
partial="$BACKUP_DIR/.osak-${stamp}.dump.partial"

compose=(docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE")
if [[ -n "$COMPOSE_OVERRIDE_FILE" && -f "$COMPOSE_OVERRIDE_FILE" ]]; then
  compose+=( -f "$COMPOSE_OVERRIDE_FILE" )
fi

cleanup() {
  if [[ -f "$partial" ]]; then
    rm -f "$partial"
  fi
}
trap cleanup EXIT

"${compose[@]}" exec -T postgres sh -ec \
  'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump --format=custom --no-owner --no-privileges \
     --port "${POSTGRES_PORT:-5432}" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB"' >"$partial"

if [[ ! -s "$partial" ]]; then
  printf 'Backup command produced an empty dump: %s\n' "$partial" >&2
  exit 1
fi

mv "$partial" "$target"
sha256sum "$target" >"$target.sha256"

# Retention is intentionally constrained to the two files this script owns.
find "$BACKUP_DIR" -type f -name 'osak-*.dump' -mtime "+$RETENTION_DAYS" -delete
find "$BACKUP_DIR" -type f -name 'osak-*.dump.sha256' -mtime "+$RETENTION_DAYS" -delete

printf 'Created %s\n' "$target"
