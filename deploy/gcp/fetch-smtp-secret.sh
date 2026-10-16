#!/usr/bin/env bash
# Copies the "qsoftwares-smtp" secret from Secret Manager into /etc/qsoftwares/smtp.ini.
# Runs at boot and hourly. If the secret is missing or unreadable, the current file is kept.
set -euo pipefail

SECRET="qsoftwares-smtp"
TARGET="/etc/qsoftwares/smtp.ini"
MD="http://metadata.google.internal/computeMetadata/v1"

PROJECT="$(curl -sf -H 'Metadata-Flavor: Google' "$MD/project/project-id")"
TOKEN="$(curl -sf -H 'Metadata-Flavor: Google' "$MD/instance/service-accounts/default/token" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"

RESPONSE="$(curl -sf -H "Authorization: Bearer $TOKEN" \
  "https://secretmanager.googleapis.com/v1/projects/$PROJECT/secrets/$SECRET/versions/latest:access")" || {
  echo "Secret $SECRET not readable; keeping $TARGET as is."
  exit 0
}

TMP="$(mktemp)"
printf '%s' "$RESPONSE" \
  | python3 -c 'import base64,json,sys; sys.stdout.write(base64.b64decode(json.load(sys.stdin)["payload"]["data"]).decode())' \
  > "$TMP"
if ! cmp -s "$TMP" "$TARGET"; then
  install -o root -g www-data -m 640 "$TMP" "$TARGET"
  echo "Updated $TARGET from Secret Manager."
fi
rm -f "$TMP"
