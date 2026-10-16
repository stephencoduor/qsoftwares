#!/usr/bin/env bash
# Creates the free-tier web server for qsoftwares.org. Run once, in Google Cloud Shell:
#   git clone https://github.com/stephencoduor/qsoftwares.git && cd qsoftwares/deploy/gcp && ./create-vm.sh
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
REGION="us-central1"          # Free tier covers us-west1, us-central1 and us-east1 only.
ZONE="us-central1-a"
VM="qsoftwares-web"
IP_NAME="qsoftwares-ip"

if [ -z "$PROJECT_ID" ]; then
  echo "Pick a project first: gcloud config set project YOUR_PROJECT_ID" >&2
  exit 1
fi
gcloud config set project "$PROJECT_ID" >/dev/null

if [ "$(gcloud billing projects describe "$PROJECT_ID" --format='value(billingEnabled)')" != "True" ]; then
  echo "Project $PROJECT_ID has no billing account linked. Link one in Billing, then re-run." >&2
  exit 1
fi

gcloud services enable compute.googleapis.com

# Static IP so DNS never has to change after a reboot.
gcloud compute addresses describe "$IP_NAME" --region "$REGION" >/dev/null 2>&1 \
  || gcloud compute addresses create "$IP_NAME" --region "$REGION"

gcloud compute firewall-rules describe allow-web >/dev/null 2>&1 \
  || gcloud compute firewall-rules create allow-web \
       --allow tcp:80,tcp:443 --target-tags web --description "HTTP and HTTPS to web servers"

# Free tier shape: e2-micro, standard (not balanced) disk, at most 30 GB.
gcloud compute instances describe "$VM" --zone "$ZONE" >/dev/null 2>&1 \
  || gcloud compute instances create "$VM" \
       --zone "$ZONE" \
       --machine-type e2-micro \
       --image-family debian-12 --image-project debian-cloud \
       --boot-disk-size 30GB --boot-disk-type pd-standard \
       --tags web \
       --address "$IP_NAME" \
       --metadata-from-file startup-script=setup-server.sh

# Budget alert so nothing surprises you on the invoice.
BILLING_ACCOUNT="$(gcloud billing projects describe "$PROJECT_ID" --format='value(billingAccountName)' | sed 's#billingAccounts/##')"
gcloud services enable billingbudgets.googleapis.com
gcloud billing budgets list --billing-account "$BILLING_ACCOUNT" --format='value(displayName)' | grep -qx 'qsoftwares-web' \
  || gcloud billing budgets create --billing-account "$BILLING_ACCOUNT" \
       --display-name qsoftwares-web --budget-amount 5USD \
       --threshold-rule percent=0.5 --threshold-rule percent=0.9 --threshold-rule percent=1.0

IP="$(gcloud compute addresses describe "$IP_NAME" --region "$REGION" --format='value(address)')"
cat <<DONE

Server created. It takes about 3 minutes to finish installing.

Next:
  1. Set the Zoho mailbox password:   ./set-smtp.sh
  2. At your DNS provider, point both records to $IP:
       qsoftwares.org      A  $IP
       www.qsoftwares.org  A  $IP
     (remove the GitHub Pages A/CNAME records for these names)
  3. HTTPS turns on by itself within a few minutes of DNS updating.
DONE
