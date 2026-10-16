#!/usr/bin/env bash
# Deploys the contact form mailer as a Cloud Run function (free tier: 2M requests/month).
# Normally run by .github/workflows/deploy-contact-function.yml. Safe to re-run.
#
# Environment:
#   PROJECT_ID                 required (or the active gcloud project)
#   SMTP_USER, SMTP_PASSWORD   Zoho mailbox and app password; stored in Secret Manager
#   SMTP_HOST                  optional, default smtp.zoho.com (smtppro.zoho.com for paid Zoho Mail)
#   MAIL_TO                    optional, default info@qsoftwares.org
# Prints CONTACT_ENDPOINT=<url> on success.
set -euo pipefail
cd "$(dirname "$0")"

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
REGION="us-central1"
FUNCTION="contact-form"
RUNTIME_SA_NAME="contact-form"

[ -n "$PROJECT_ID" ] || { echo "PROJECT_ID is not set" >&2; exit 1; }
gcloud config set project "$PROJECT_ID" >/dev/null
PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
RUNTIME_SA="$RUNTIME_SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"

gcloud services enable \
  cloudfunctions.googleapis.com run.googleapis.com cloudbuild.googleapis.com \
  artifactregistry.googleapis.com secretmanager.googleapis.com iam.googleapis.com

# The function runs as its own account that can only read the two SMTP secrets.
gcloud iam service-accounts describe "$RUNTIME_SA" >/dev/null 2>&1 \
  || gcloud iam service-accounts create "$RUNTIME_SA_NAME" --display-name "qsoftwares contact form"

# Builds run as the default compute account, which new projects no longer give build rights.
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member "serviceAccount:$PROJECT_NUMBER-compute@developer.gserviceaccount.com" \
  --role roles/cloudbuild.builds.builder --condition None >/dev/null

store_secret() {  # name value
  local name="$1" value="$2" current
  gcloud secrets describe "$name" >/dev/null 2>&1 \
    || gcloud secrets create "$name" --replication-policy automatic >/dev/null
  current="$(gcloud secrets versions access latest --secret "$name" 2>/dev/null || true)"
  if [ "$current" != "$value" ]; then
    printf '%s' "$value" | gcloud secrets versions add "$name" --data-file=- >/dev/null
    echo "Updated secret $name."
  fi
  gcloud secrets add-iam-policy-binding "$name" \
    --member "serviceAccount:$RUNTIME_SA" --role roles/secretmanager.secretAccessor >/dev/null
}
[ -n "${SMTP_USER:-}" ] && [ -n "${SMTP_PASSWORD:-}" ] \
  || { echo "SMTP_USER and SMTP_PASSWORD must be set" >&2; exit 1; }
store_secret smtp-user "$SMTP_USER"
store_secret smtp-password "$SMTP_PASSWORD"

# max-instances caps spend if the endpoint is ever flooded.
gcloud functions deploy "$FUNCTION" \
  --gen2 --region "$REGION" --runtime nodejs20 \
  --source . --entry-point contactForm \
  --trigger-http --allow-unauthenticated \
  --service-account "$RUNTIME_SA" \
  --memory 256Mi --max-instances 2 \
  --set-env-vars "SMTP_HOST=${SMTP_HOST:-smtp.zoho.com},MAIL_TO=${MAIL_TO:-info@qsoftwares.org}" \
  --set-secrets "SMTP_USER=smtp-user:latest,SMTP_PASSWORD=smtp-password:latest" \
  --quiet

URL="$(gcloud functions describe "$FUNCTION" --gen2 --region "$REGION" --format='value(serviceConfig.uri)')"
echo "CONTACT_ENDPOINT=$URL"
