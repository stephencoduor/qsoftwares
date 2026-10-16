#!/usr/bin/env bash
# Deploys the contact form mailer to AWS Lambda with a public function URL. Safe to re-run.
# Uses the AWS CLI's current profile (set AWS_PROFILE to choose another).
#
# The first run asks for the Zoho app password (typing is hidden) and stores it in SSM
# Parameter Store as a SecureString; later runs reuse it unless RESET_PASSWORD=1.
# Prints CONTACT_ENDPOINT=<url> on success.
#
# Run with SET_TURNSTILE=1 to type the Cloudflare Turnstile site key and secret key (hidden); the
# function then requires a valid Turnstile token on every submission.
#
# Environment (all optional):
#   AWS_REGION   default eu-central-1
#   SMTP_USER    default info@qsoftwares.org
#   SMTP_HOST    default smtp.zoho.com (smtppro.zoho.com for paid Zoho Mail)
#   MAIL_TO      default info@qsoftwares.org
#   ALERT_EMAIL  default info@qsoftwares.org; gets the usage alarm (confirm AWS's first email)
#   ALERT_DAILY  default 500; alarm when the function runs more often than this in a day
set -euo pipefail
cd "$(dirname "$0")"

REGION="${AWS_REGION:-eu-central-1}"
FUNCTION="qsoftwares-contact-form"
ROLE="qsoftwares-contact-form"
PARAM="/qsoftwares/contact/smtp-password"
TURNSTILE_PARAM="/qsoftwares/contact/turnstile-secret"
SMTP_USER="${SMTP_USER:-info@qsoftwares.org}"
export AWS_REGION="$REGION" AWS_PAGER=""

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
echo "Deploying to AWS account $ACCOUNT in $REGION"

# Zoho app password → Parameter Store (free standard parameter). Read from the keyboard,
# passed to the CLI on stdin so it never appears in a command line.
if [ "${RESET_PASSWORD:-0}" = 1 ] || ! aws ssm get-parameter --name "$PARAM" >/dev/null 2>&1; then
  read -rsp "Zoho app password for $SMTP_USER (typing is hidden): " SMTP_PASSWORD; echo
  printf '%s' "$SMTP_PASSWORD" | aws ssm put-parameter --name "$PARAM" --type SecureString \
    --overwrite --value file:///dev/stdin >/dev/null
  unset SMTP_PASSWORD
  echo "Stored the password in Parameter Store ($PARAM)."
fi

if [ "${SET_TURNSTILE:-0}" = 1 ]; then
  read -rp "Cloudflare Turnstile site key (public): " TURNSTILE_SITEKEY
  aws ssm put-parameter --name "/qsoftwares/contact/turnstile-sitekey" --type String \
    --overwrite --value "$TURNSTILE_SITEKEY" >/dev/null
  read -rsp "Cloudflare Turnstile secret key (typing is hidden): " TURNSTILE_SECRET; echo
  printf '%s' "$TURNSTILE_SECRET" | aws ssm put-parameter --name "$TURNSTILE_PARAM" --type SecureString \
    --overwrite --value file:///dev/stdin >/dev/null
  unset TURNSTILE_SECRET
  echo "Stored the Turnstile secret in Parameter Store ($TURNSTILE_PARAM)."
fi

# Execution role: CloudWatch logs plus reading that one parameter.
if ! aws iam get-role --role-name "$ROLE" >/dev/null 2>&1; then
  aws iam create-role --role-name "$ROLE" --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
  }' >/dev/null
  aws iam attach-role-policy --role-name "$ROLE" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
  echo "Created role $ROLE; waiting for it to propagate ..."
  sleep 10
fi
aws iam put-role-policy --role-name "$ROLE" --policy-name read-smtp-password --policy-document "{
  \"Version\": \"2012-10-17\",
  \"Statement\": [
    {\"Effect\": \"Allow\", \"Action\": \"ssm:GetParameter\", \"Resource\": \"arn:aws:ssm:$REGION:$ACCOUNT:parameter/qsoftwares/contact/*\"},
    {\"Effect\": \"Allow\", \"Action\": \"kms:Decrypt\", \"Resource\": \"*\", \"Condition\": {\"StringEquals\": {\"kms:ViaService\": \"ssm.$REGION.amazonaws.com\"}}}
  ]
}"
ROLE_ARN="arn:aws:iam::$ACCOUNT:role/$ROLE"

# Package: the two source files plus nodemailer (the AWS SDK comes with the runtime).
BUILD="$(mktemp -d)"
cp core.js lambda.js "$BUILD/"
NODEMAILER_VERSION="$(node -p "require('./package.json').dependencies.nodemailer")"
npm install --prefix "$BUILD" --no-save --no-audit --no-fund "nodemailer@$NODEMAILER_VERSION" >/dev/null
(cd "$BUILD" && rm -f package.json package-lock.json && zip -qr function.zip .)

ENV="SMTP_USER=$SMTP_USER,SMTP_HOST=${SMTP_HOST:-smtp.zoho.com},MAIL_TO=${MAIL_TO:-info@qsoftwares.org},SMTP_PASSWORD_PARAM=$PARAM"
# Turnstile is enforced only once its secret exists.
if aws ssm get-parameter --name "$TURNSTILE_PARAM" >/dev/null 2>&1; then
  ENV="$ENV,TURNSTILE_SECRET_PARAM=$TURNSTILE_PARAM"
  echo "Turnstile check: on"
else
  echo "Turnstile check: off (run with SET_TURNSTILE=1 to turn it on)"
fi
ENV="Variables={$ENV}"
if aws lambda get-function --function-name "$FUNCTION" >/dev/null 2>&1; then
  aws lambda update-function-code --function-name "$FUNCTION" --zip-file "fileb://$BUILD/function.zip" >/dev/null
  aws lambda wait function-updated --function-name "$FUNCTION"
  aws lambda update-function-configuration --function-name "$FUNCTION" --environment "$ENV" >/dev/null
else
  aws lambda create-function --function-name "$FUNCTION" \
    --runtime nodejs20.x --handler lambda.handler --role "$ROLE_ARN" \
    --zip-file "fileb://$BUILD/function.zip" \
    --memory-size 256 --timeout 15 --environment "$ENV" >/dev/null
fi
aws lambda wait function-updated --function-name "$FUNCTION"
rm -rf "$BUILD"

# Cap concurrency to limit cost if the URL is flooded. Accounts with a low concurrency
# quota refuse reservations, so this is best effort.
aws lambda put-function-concurrency --function-name "$FUNCTION" \
  --reserved-concurrent-executions 2 >/dev/null 2>&1 \
  || echo "Note: could not reserve concurrency (account quota); continuing."

# Public HTTPS address. CORS is handled in the code, so the URL has none of its own.
if ! aws lambda get-function-url-config --function-name "$FUNCTION" >/dev/null 2>&1; then
  aws lambda create-function-url-config --function-name "$FUNCTION" --auth-type NONE >/dev/null
fi
aws lambda add-permission --function-name "$FUNCTION" --statement-id public-url \
  --action lambda:InvokeFunctionUrl --principal "*" --function-url-auth-type NONE >/dev/null 2>&1 || true
# Newer accounts also require lambda:InvokeFunction for public function URLs.
aws lambda add-permission --function-name "$FUNCTION" --statement-id public-url-invoke \
  --action lambda:InvokeFunction --principal "*" --invoked-via-function-url >/dev/null 2>&1 || true

# Usage alarm: email when the function runs more than ALERT_DAILY times in a day, which
# means someone is flooding the form. Alarms and email notifications are free at this size.
ALERT_EMAIL="${ALERT_EMAIL:-info@qsoftwares.org}"
TOPIC_ARN="$(aws sns create-topic --name "$FUNCTION-alerts" --query TopicArn --output text)"
if [ "$(aws sns list-subscriptions-by-topic --topic-arn "$TOPIC_ARN" \
    --query "length(Subscriptions[?Endpoint=='$ALERT_EMAIL'])" --output text)" = 0 ]; then
  aws sns subscribe --topic-arn "$TOPIC_ARN" --protocol email --notification-endpoint "$ALERT_EMAIL" >/dev/null
  echo "AWS will email $ALERT_EMAIL a link to confirm the usage alarm; click it once."
fi
aws cloudwatch put-metric-alarm --alarm-name "$FUNCTION-high-usage" \
  --alarm-description "Contact form function ran more than ${ALERT_DAILY:-500} times in a day" \
  --namespace AWS/Lambda --metric-name Invocations --dimensions "Name=FunctionName,Value=$FUNCTION" \
  --statistic Sum --period 86400 --evaluation-periods 1 --threshold "${ALERT_DAILY:-500}" \
  --comparison-operator GreaterThanThreshold --treat-missing-data notBreaching \
  --alarm-actions "$TOPIC_ARN"

URL="$(aws lambda get-function-url-config --function-name "$FUNCTION" --query FunctionUrl --output text)"
echo "CONTACT_ENDPOINT=${URL%/}"
SITEKEY="$(aws ssm get-parameter --name /qsoftwares/contact/turnstile-sitekey --query Parameter.Value --output text 2>/dev/null || true)"
[ -n "$SITEKEY" ] && echo "TURNSTILE_SITEKEY=$SITEKEY (goes in js/contact-endpoint.js)"
