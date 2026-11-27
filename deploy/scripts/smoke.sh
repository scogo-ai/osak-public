#!/usr/bin/env bash
set -Eeuo pipefail

BASE_URL=${OSAK_SMOKE_BASE_URL:-${OSAK_BASE_URL:-https://osak.lab.scogo.ai}}
BASE_URL=${BASE_URL%/}
SMOKE_TEST_KEY=${OSAK_SMOKE_TEST_KEY:-}
CURL_RETRIES=${CURL_RETRIES:-5}
ORIGIN_SECRET=${OSAK_ORIGIN_SHARED_SECRET:-}

curl_common=(curl --silent --show-error --retry "$CURL_RETRIES" --retry-delay 2 --retry-connrefused)
if [[ -n "$ORIGIN_SECRET" ]]; then
  curl_common+=(--header "X-OSAK-Origin-Secret: $ORIGIN_SECRET")
fi

check_status() {
  local url=$1
  shift
  "${curl_common[@]}" --fail --output /dev/null "$@" "$url"
}

printf 'Checking API health: %s/api/v1/health\n' "$BASE_URL"
check_status "$BASE_URL/api/v1/health"

printf 'Checking Swagger UI: %s/docs\n' "$BASE_URL"
check_status "$BASE_URL/docs"

printf 'Checking OpenAPI: %s/openapi.json\n' "$BASE_URL"
check_status "$BASE_URL/openapi.json"

if [[ -z "$SMOKE_TEST_KEY" ]]; then
  printf 'OSAK_SMOKE_TEST_KEY is required for the authenticated smoke check.\n' >&2
  exit 2
fi

printf 'Checking authenticated API access\n'
auth_headers=(--header "Authorization: Bearer $SMOKE_TEST_KEY")
check_status "$BASE_URL/api/v1/vendors" "${auth_headers[@]}"

# The MCP endpoint is expected to reject an unauthenticated request. A 401/403
# proves the route is present without putting an inventory body in a smoke log.
printf 'Checking MCP authentication boundary\n'
mcp_status=$("${curl_common[@]}" --output /dev/null --write-out '%{http_code}' "$BASE_URL/mcp")
case "$mcp_status" in
  401|403) ;;
  *) printf 'Expected MCP auth boundary (401/403), got %s\n' "$mcp_status" >&2; exit 1 ;;
esac

printf 'Smoke checks passed for %s\n' "$BASE_URL"
