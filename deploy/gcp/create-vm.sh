#!/usr/bin/env bash
# Creates (or updates) the free-tier web server for qsoftwares.org. Safe to re-run.
# Normally run by the "Provision GCP server" GitHub Actions workflow; also works in Cloud Shell:
#   git clone https://github.com/stephencoduor/qsoftwares.git && cd qsoftwares/deploy/gcp && ./create-vm.sh
#
# Optional environment:
#   PROJECT_ID                 defaults to the active gcloud project
#   SMTP_USER, SMTP_PASSWORD   Zoho mailbox and app password, stored in Secret Manager
#   SMTP_HOST                  defaults to smtp.zoho.com (smtppro.zoho.com for paid Zoho Mail)
set -euo pipefail
cd "$(dirname "$0")"

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
REGION="us-central1"          # Free tier covers us-west1, us-central1 and us-east1 only.
ZONE="us-central1-a"
VM="qsoftwares-web"
IP_NAME="qsoftwares-ip"
VM_SA_NAME="qsoftwares-web"
SECRET="qsoftwares-smtp"

if [ -z "$PROJECT_ID" ]; then
  echo "Set PROJECT_ID or run: gcloud config set project YOUR_PROJECT_ID" >&2
  exit 1
fi
gcloud config set project "$PROJECT_ID" >/dev/null
VM_SA="$VM_SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"

gcloud services enable compute.googleapis.com secretmanager.googleapis.com iam.googleapis.com

# The VM runs as its own service account that can read only the SMTP secret.
gcloud iam service-accounts describe "$VM_SA" >/dev/null 2>&1 \
  || gcloud iam service-accounts create "$VM_SA_NAME" --display-name "qsoftwares.org web server"

# Zoho login → Secret Manager, never git. A new version is added only when it changed.
if [ -n "${SMTP_USER:-}" ] && [ -n "${SMTP_PASSWORD:-}" ]; then
  INI="$(cat <<INI
host = "${SMTP_HOST:-smtp.zoho.com}"
port = 465
secure = "ssl"
username = "$SMTP_USER"
password = "$SMTP_PASSWORD"
from = "$SMTP_USER"
from_name = "QSOFTWARES Website"
rate_limit_dir = "/var/lib/qsoftwares/rate_limits"
INI
)"
  gcloud secrets describe "$SECRET" >/dev/null 2>&1 \
    || gcloud secrets create "$SECRET" --replication-policy automatic
  CURRENT="$(gcloud secrets versions access latest --secret "$SECRET" 2>/dev/null || true)"
  if [ "$CURRENT" != "$INI" ]; then
    printf '%s' "$INI" | gcloud secrets versions add "$SECRET" --data-file=-
    echo "Stored new SMTP settings in Secret Manager."
  fi
  gcloud secrets add-iam-policy-binding "$SECRET" \
    --member "serviceAccount:$VM_SA" --role roles/secretmanager.secretAccessor >/dev/null
else
  echo "SMTP_USER/SMTP_PASSWORD not set; leaving mail settings unchanged."
fi

# Static IP so DNS never has to change after a reboot.
gcloud compute addresses describe "$IP_NAME" --region "$REGION" >/dev/null 2>&1 \
  || gcloud compute addresses create "$IP_NAME" --region "$REGION"

gcloud compute firewall-rules describe allow-web >/dev/null 2>&1 \
  || gcloud compute firewall-rules create allow-web \
       --allow tcp:80,tcp:443 --target-tags web --description "HTTP and HTTPS to web servers"

# Free tier shape: e2-micro, standard (not balanced) disk, at most 30 GB.
if gcloud compute instances describe "$VM" --zone "$ZONE" >/dev/null 2>&1; then
  gcloud compute instances add-metadata "$VM" --zone "$ZONE" \
    --metadata-from-file startup-script=setup-server.sh
else
  gcloud compute instances create "$VM" \
    --zone "$ZONE" \
    --machine-type e2-micro \
    --image-family debian-12 --image-project debian-cloud \
    --boot-disk-size 30GB --boot-disk-type pd-standard \
    --tags web \
    --address "$IP_NAME" \
    --service-account "$VM_SA" --scopes cloud-platform \
    --metadata-from-file startup-script=setup-server.sh
fi

# Budget alert. Needs billing permissions, so it is skipped (not fatal) when the caller lacks them.
BILLING_ACCOUNT="$(gcloud billing projects describe "$PROJECT_ID" --format='value(billingAccountName)' 2>/dev/null | sed 's#billingAccounts/##' || true)"
if [ -n "$BILLING_ACCOUNT" ]; then
  {
    gcloud services enable billingbudgets.googleapis.com
    gcloud billing budgets list --billing-account "$BILLING_ACCOUNT" --format='value(displayName)' | grep -qx 'qsoftwares-web' \
      || gcloud billing budgets create --billing-account "$BILLING_ACCOUNT" \
           --display-name qsoftwares-web --budget-amount 5USD \
           --threshold-rule percent=0.5 --threshold-rule percent=0.9 --threshold-rule percent=1.0
  } || echo "Could not create the budget alert; add a \$5 budget in Billing > Budgets & alerts."
else
  echo "No billing access from this account; add a \$5 budget in Billing > Budgets & alerts."
fi

IP="$(gcloud compute addresses describe "$IP_NAME" --region "$REGION" --format='value(address)')"
echo "SERVER_IP=$IP"
cat <<DONE

Server is ready at $IP (first boot takes about 3 minutes to finish installing).
Point these DNS records at it, replacing the GitHub Pages ones:
  qsoftwares.org      A  $IP
  www.qsoftwares.org  A  $IP
HTTPS turns on by itself within a few minutes of DNS updating.
DONE
