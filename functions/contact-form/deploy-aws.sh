#!/usr/bin/env bash
# Deploys the contact form mailer to AWS Lambda with a public function URL. Safe to re-run.
# Uses the AWS CLI's current profile (set AWS_PROFILE to choose another).
#
# The first run asks for the Zoho app password (typing is hidden) and stores it in SSM
# Parameter Store as a SecureString; later runs reuse it unless RESET_PASSWORD=1.
# Prints CONTACT_ENDPOINT=<url> on success.
#
# Environment (all optional):
#   AWS_REGION   default eu-central-1
#   SMTP_USER    default info@qsoftwares.org
#   SMTP_HOST    default smtp.zoho.com (smtppro.zoho.com for paid Zoho Mail)
#   MAIL_TO      default info@qsoftwares.org
set -euo pipefail
cd "$(dirname "$0")"

REGION="${AWS_REGION:-eu-central-1}"
FUNCTION="qsoftwares-contact-form"
ROLE="qsoftwares-contact-form"
PARAM="/qsoftwares/contact-form/smtp-password"
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
    {\"Effect\": \"Allow\", \"Action\": \"ssm:GetParameter\", \"Resource\": \"arn:aws:ssm:$REGION:$ACCOUNT:parameter$PARAM\"},
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

ENV="Variables={SMTP_USER=$SMTP_USER,SMTP_HOST=${SMTP_HOST:-smtp.zoho.com},MAIL_TO=${MAIL_TO:-info@qsoftwares.org},SMTP_PASSWORD_PARAM=$PARAM}"
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

URL="$(aws lambda get-function-url-config --function-name "$FUNCTION" --query FunctionUrl --output text)"
echo "CONTACT_ENDPOINT=${URL%/}"
