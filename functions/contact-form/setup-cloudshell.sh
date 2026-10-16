#!/usr/bin/env bash
# One-step setup from Google Cloud Shell (opened by the "Open in Cloud Shell" link in README.md).
# Creates a dedicated project, links billing, asks for the Zoho login and deploys the function.
set -euo pipefail
cd "$(dirname "$0")"

PROJECT_NAME="QSOFTWARES website"

# Reuse the project from an earlier run, otherwise create one just for this function.
PROJECT_ID="$(gcloud projects list --filter="name:'$PROJECT_NAME' AND lifecycleState:ACTIVE" --format='value(projectId)' | head -n1)"
if [ -z "$PROJECT_ID" ]; then
  PROJECT_ID="qsoftwares-web-$(date +%s | tail -c 6)"
  echo "Creating project $PROJECT_ID ..."
  gcloud projects create "$PROJECT_ID" --name "$PROJECT_NAME"
fi
gcloud config set project "$PROJECT_ID" >/dev/null

# The free tier still needs billing linked. Use the only open billing account, or ask which one.
if [ "$(gcloud billing projects describe "$PROJECT_ID" --format='value(billingEnabled)')" != "True" ]; then
  mapfile -t ACCOUNTS < <(gcloud billing accounts list --filter=open=true --format='value(name,displayName)')
  if [ "${#ACCOUNTS[@]}" -eq 0 ]; then
    echo "No billing account found. Create one at https://console.cloud.google.com/billing and run this again." >&2
    exit 1
  fi
  CHOICE=0
  if [ "${#ACCOUNTS[@]}" -gt 1 ]; then
    for i in "${!ACCOUNTS[@]}"; do echo "  [$i] ${ACCOUNTS[$i]}"; done
    read -rp "Which billing account? [0]: " CHOICE
    CHOICE="${CHOICE:-0}"
  fi
  ACCOUNT="$(printf '%s' "${ACCOUNTS[$CHOICE]}" | awk '{print $1}')"
  gcloud billing projects link "$PROJECT_ID" --billing-account "${ACCOUNT#billingAccounts/}"
fi

echo
read -rp "Zoho mailbox that sends the emails [info@qsoftwares.org]: " SMTP_USER
SMTP_USER="${SMTP_USER:-info@qsoftwares.org}"
read -rsp "Zoho app password for that mailbox (typing is hidden): " SMTP_PASSWORD; echo
read -rp "Paid Zoho Mail plan? (y/N): " PAID
SMTP_HOST="smtp.zoho.com"
case "$PAID" in [yY]*) SMTP_HOST="smtppro.zoho.com" ;; esac
export PROJECT_ID SMTP_USER SMTP_PASSWORD SMTP_HOST

# New projects can take a minute to grant build permissions, so retry the deploy once.
if ! bash deploy.sh | tee /tmp/contact-deploy.log; then
  echo "Waiting 60 seconds for permissions to settle, then retrying ..."
  sleep 60
  bash deploy.sh | tee /tmp/contact-deploy.log
fi

URL="$(sed -n 's/^CONTACT_ENDPOINT=//p' /tmp/contact-deploy.log)"
cat <<DONE

==================================================================
 Done. Contact form function is live at:

   $URL

 Leave this window open; Claude will read the address from here.
==================================================================
DONE
