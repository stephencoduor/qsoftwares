#!/usr/bin/env bash
# Stores the Zoho SMTP login on the server, outside the web root and outside git.
# Run in Cloud Shell from deploy/gcp after create-vm.sh. Use a Zoho app-specific password.
set -euo pipefail

ZONE="us-central1-a"
VM="qsoftwares-web"

read -rp "Zoho mailbox (e.g. info@qsoftwares.org): " SMTP_USER
read -rsp "Zoho app password (hidden): " SMTP_PASS; echo
read -rp "SMTP host [smtp.zoho.com, or smtppro.zoho.com for paid Zoho Mail]: " SMTP_HOST
SMTP_HOST="${SMTP_HOST:-smtp.zoho.com}"

# Passed on stdin so the password never appears in a command line or shell history.
printf '%s\n%s\n%s\n' "$SMTP_HOST" "$SMTP_USER" "$SMTP_PASS" | gcloud compute ssh "$VM" --zone "$ZONE" --command '
  read -r HOST; read -r SUSER; read -r PASS
  sudo tee /etc/qsoftwares/smtp.ini >/dev/null <<INI
host = "$HOST"
port = 465
secure = "ssl"
username = "$SUSER"
password = "$PASS"
from = "$SUSER"
from_name = "QSOFTWARES Website"
rate_limit_dir = "/var/lib/qsoftwares/rate_limits"
INI
  sudo chown root:www-data /etc/qsoftwares/smtp.ini
  sudo chmod 640 /etc/qsoftwares/smtp.ini
  echo "Saved."
'
