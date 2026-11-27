#!/usr/bin/env bash
set -Eeuo pipefail

# Configure a short-lived GitHub-hosted runner connection to the origin LXC.
# The SSH key is restricted by authorized_keys on the host; Cloudflare Access
# authenticates the dedicated osak-ssh.scogo.ai route before sshd sees it.

: "${OSAK_ORIGIN_SSH_HOST:?OSAK_ORIGIN_SSH_HOST is required}"
: "${OSAK_ORIGIN_SSH_USER:?OSAK_ORIGIN_SSH_USER is required}"
: "${OSAK_ORIGIN_SSH_KEY:?OSAK_ORIGIN_SSH_KEY is required}"
: "${OSAK_ORIGIN_SSH_KNOWN_HOSTS:?OSAK_ORIGIN_SSH_KNOWN_HOSTS is required}"
: "${TUNNEL_SERVICE_TOKEN_ID:?TUNNEL_SERVICE_TOKEN_ID is required}"
: "${TUNNEL_SERVICE_TOKEN_SECRET:?TUNNEL_SERVICE_TOKEN_SECRET is required}"

state_dir="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/osak-origin-ssh"
mkdir -p "$state_dir"
chmod 700 "$state_dir"
umask 077
printf '%s\n' "$OSAK_ORIGIN_SSH_KEY" >"$state_dir/id_ed25519"
printf '%s\n' "$OSAK_ORIGIN_SSH_KNOWN_HOSTS" >"$state_dir/known_hosts"

if command -v cloudflared >/dev/null 2>&1; then
  cloudflared_bin=$(command -v cloudflared)
else
  cloudflared_bin="$state_dir/cloudflared"
  version=2026.11.2
  curl --fail --silent --show-error --location --retry 3 \
    "https://github.com/cloudflare/cloudflared/releases/download/${version}/cloudflared-linux-amd64" \
    --output "$cloudflared_bin"
  printf '%s  %s\n' 56f13335143ec0e22772963290683a84a04114a35ec64cbc794a4d39ff9bb8cf "$cloudflared_bin" | sha256sum --check --status
  chmod 700 "$cloudflared_bin"
fi

config="$state_dir/config"
cat >"$config" <<EOF
Host osak-origin
  HostName ${OSAK_ORIGIN_SSH_HOST}
  User ${OSAK_ORIGIN_SSH_USER}
  IdentityFile ${state_dir}/id_ed25519
  UserKnownHostsFile ${state_dir}/known_hosts
  StrictHostKeyChecking yes
  IdentitiesOnly yes
  ProxyCommand ${cloudflared_bin} access ssh --hostname %h
EOF
chmod 600 "$config"
printf 'OSAK_SSH_CONFIG=%s\n' "$config" >>"${GITHUB_ENV:?GITHUB_ENV is required}"
