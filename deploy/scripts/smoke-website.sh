#!/usr/bin/env bash
set -Eeuo pipefail

BASE_URL=${OSAK_BASE_URL:-https://osak.lab.scogo.ai}
BASE_URL=${BASE_URL%/}

curl --fail --silent --show-error --location --retry 5 --retry-delay 2 \
  --retry-connrefused --output /dev/null "$BASE_URL/"

printf 'Website smoke check passed for %s\n' "$BASE_URL/"
