#!/usr/bin/env bash
# Deploys website payments (KCB Buni M-Pesa) to AWS Lambda with a public function URL. Safe to re-run.
# Uses the AWS CLI's current profile (set AWS_PROFILE to choose another).
#
# The first run asks for the Buni consumer key and secret (typing hidden) and the KCB account
# number, and stores them in SSM Parameter Store. Re-run with RESET_BUNI=1 to change them,
# e.g. when KCB issues production keys. The callback secret is generated here; nobody types it.
# Reuses the Zoho password and Turnstile secret already stored for the contact form.
#
# Environment (all optional):
#   AWS_REGION     default eu-central-1
#   BUNI_ENV       sandbox (default) or production
#   SMTP_USER      default info@qsoftwares.org
#   MAIL_TO        default info@qsoftwares.org
set -euo pipefail
cd "$(dirname "$0")"

REGION="${AWS_REGION:-eu-central-1}"
FUNCTION="qsoftwares-payments"
ROLE="qsoftwares-payments"
TABLE="qsoftwares-payments"
P="/qsoftwares/payments"
export AWS_REGION="$REGION" AWS_PAGER=""

case "${BUNI_ENV:-sandbox}" in
  sandbox)    BUNI_BASE_URL="https://uat.buni.kcbgroup.com" ;;
  production) BUNI_BASE_URL="https://buni.kcbgroup.com" ;;
  *) echo "BUNI_ENV must be sandbox or production"; exit 1 ;;
esac

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
echo "Deploying payments to AWS account $ACCOUNT in $REGION (Buni ${BUNI_ENV:-sandbox})"

put_secret() {  # name, prompt
  local value
  read -rsp "$2 (typing is hidden): " value; echo
  printf '%s' "$value" | aws ssm put-parameter --name "$1" --type SecureString --overwrite \
    --value file:///dev/stdin >/dev/null
}
if [ "${RESET_BUNI:-0}" = 1 ] || ! aws ssm get-parameter --name "$P/buni-key" >/dev/null 2>&1; then
  put_secret "$P/buni-key" "Buni consumer key"
  put_secret "$P/buni-secret" "Buni consumer secret"
  read -rp "KCB account number that receives the payments: " KCB_ACCOUNT
  aws ssm put-parameter --name "$P/kcb-account" --type String --overwrite --value "$KCB_ACCOUNT" >/dev/null
  echo "Stored the Buni keys and KCB account in Parameter Store ($P/...)."
fi
if ! aws ssm get-parameter --name "$P/callback-secret" >/dev/null 2>&1; then
  openssl rand -hex 24 | tr -d '\n' | aws ssm put-parameter --name "$P/callback-secret" --type SecureString \
    --value file:///dev/stdin >/dev/null
fi
KCB_ACCOUNT="$(aws ssm get-parameter --name "$P/kcb-account" --query Parameter.Value --output text)"

# Orders table. 1 read/1 write unit each stays inside DynamoDB's always-free 25 units.
if ! aws dynamodb describe-table --table-name "$TABLE" >/dev/null 2>&1; then
  aws dynamodb create-table --table-name "$TABLE" \
    --attribute-definitions AttributeName=orderId,AttributeType=S AttributeName=checkoutId,AttributeType=S \
    --key-schema AttributeName=orderId,KeyType=HASH \
    --provisioned-throughput ReadCapacityUnits=1,WriteCapacityUnits=1 \
    --global-secondary-indexes '[{"IndexName":"checkout","KeySchema":[{"AttributeName":"checkoutId","KeyType":"HASH"}],"Projection":{"ProjectionType":"ALL"},"ProvisionedThroughput":{"ReadCapacityUnits":1,"WriteCapacityUnits":1}}]' >/dev/null
  aws dynamodb wait table-exists --table-name "$TABLE"
  echo "Created table $TABLE."
fi

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
aws iam put-role-policy --role-name "$ROLE" --policy-name payments --policy-document "{
  \"Version\": \"2012-10-17\",
  \"Statement\": [
    {\"Effect\": \"Allow\", \"Action\": \"ssm:GetParameter\", \"Resource\": [
      \"arn:aws:ssm:$REGION:$ACCOUNT:parameter/qsoftwares/payments/*\",
      \"arn:aws:ssm:$REGION:$ACCOUNT:parameter/qsoftwares/contact/smtp-password\",
      \"arn:aws:ssm:$REGION:$ACCOUNT:parameter/qsoftwares/contact/turnstile-secret\"]},
    {\"Effect\": \"Allow\", \"Action\": \"kms:Decrypt\", \"Resource\": \"*\", \"Condition\": {\"StringEquals\": {\"kms:ViaService\": \"ssm.$REGION.amazonaws.com\"}}},
    {\"Effect\": \"Allow\", \"Action\": [\"dynamodb:PutItem\", \"dynamodb:GetItem\", \"dynamodb:UpdateItem\", \"dynamodb:Query\"],
     \"Resource\": [\"arn:aws:dynamodb:$REGION:$ACCOUNT:table/$TABLE\", \"arn:aws:dynamodb:$REGION:$ACCOUNT:table/$TABLE/index/*\"]}
  ]
}"
ROLE_ARN="arn:aws:iam::$ACCOUNT:role/$ROLE"

BUILD="$(mktemp -d)"
cp core.js lambda.js plans.json "$BUILD/"
NODEMAILER_VERSION="$(node -p "require('./package.json').dependencies.nodemailer")"
npm install --prefix "$BUILD" --no-save --no-audit --no-fund "nodemailer@$NODEMAILER_VERSION" >/dev/null
(cd "$BUILD" && rm -f package.json package-lock.json && zip -qr function.zip .)

if aws lambda get-function --function-name "$FUNCTION" >/dev/null 2>&1; then
  aws lambda update-function-code --function-name "$FUNCTION" --zip-file "fileb://$BUILD/function.zip" >/dev/null
else
  aws lambda create-function --function-name "$FUNCTION" \
    --runtime nodejs20.x --handler lambda.handler --role "$ROLE_ARN" \
    --zip-file "fileb://$BUILD/function.zip" --memory-size 256 --timeout 30 >/dev/null
fi
aws lambda wait function-updated --function-name "$FUNCTION"
rm -rf "$BUILD"

if ! aws lambda get-function-url-config --function-name "$FUNCTION" >/dev/null 2>&1; then
  aws lambda create-function-url-config --function-name "$FUNCTION" --auth-type NONE >/dev/null
fi
aws lambda add-permission --function-name "$FUNCTION" --statement-id public-url \
  --action lambda:InvokeFunctionUrl --principal "*" --function-url-auth-type NONE >/dev/null 2>&1 || true
aws lambda add-permission --function-name "$FUNCTION" --statement-id public-url-invoke \
  --action lambda:InvokeFunction --principal "*" --invoked-via-function-url >/dev/null 2>&1 || true
URL="$(aws lambda get-function-url-config --function-name "$FUNCTION" --query FunctionUrl --output text)"
URL="${URL%/}"

ENV="PAYMENTS_TABLE=$TABLE,BUNI_BASE_URL=$BUNI_BASE_URL,KCB_ACCOUNT=$KCB_ACCOUNT,CALLBACK_BASE_URL=$URL"
ENV="$ENV,BUNI_KEY_PARAM=$P/buni-key,BUNI_SECRET_PARAM=$P/buni-secret,CALLBACK_SECRET_PARAM=$P/callback-secret"
ENV="$ENV,SMTP_USER=${SMTP_USER:-info@qsoftwares.org},MAIL_TO=${MAIL_TO:-info@qsoftwares.org}"
ENV="$ENV,SMTP_PASSWORD_PARAM=/qsoftwares/contact/smtp-password"
if aws ssm get-parameter --name /qsoftwares/contact/turnstile-secret >/dev/null 2>&1; then
  ENV="$ENV,TURNSTILE_SECRET_PARAM=/qsoftwares/contact/turnstile-secret"
fi
aws lambda update-function-configuration --function-name "$FUNCTION" --environment "Variables={$ENV}" >/dev/null
aws lambda wait function-updated --function-name "$FUNCTION"

echo "PAYMENTS_ENDPOINT=$URL"
