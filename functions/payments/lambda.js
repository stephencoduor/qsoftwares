// AWS Lambda entry point, called through a Lambda function URL.
// Orders live in DynamoDB (table PAYMENTS_TABLE, key orderId, GSI "checkout" on checkoutId).
// Secrets come from SSM Parameter Store, read once per cold start:
//   SMTP_PASSWORD_PARAM, BUNI_KEY_PARAM, BUNI_SECRET_PARAM, CALLBACK_SECRET_PARAM, TURNSTILE_SECRET_PARAM
const { createHandler } = require('./core');

let secretsLoaded = false;
async function loadSecrets() {
  if (secretsLoaded) return;
  const wanted = [
    ['SMTP_PASSWORD_PARAM', 'SMTP_PASSWORD'], ['BUNI_KEY_PARAM', 'BUNI_CONSUMER_KEY'],
    ['BUNI_SECRET_PARAM', 'BUNI_CONSUMER_SECRET'], ['CALLBACK_SECRET_PARAM', 'CALLBACK_SECRET'],
    ['TURNSTILE_SECRET_PARAM', 'TURNSTILE_SECRET'],
  ].filter(([param, target]) => process.env[param] && !process.env[target]);
  if (wanted.length) {
    const { SSMClient, GetParameterCommand } = require('@aws-sdk/client-ssm');
    const ssm = new SSMClient({});
    for (const [param, target] of wanted) {
      const out = await ssm.send(new GetParameterCommand({ Name: process.env[param], WithDecryption: true }));
      process.env[target] = out.Parameter.Value;
    }
  }
  secretsLoaded = true;
}

function dynamoStore(table) {
  const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
  const { DynamoDBDocumentClient, PutCommand, GetCommand, QueryCommand, UpdateCommand } = require('@aws-sdk/lib-dynamodb');
  const db = DynamoDBDocumentClient.from(new DynamoDBClient({}));
  return {
    async put(order) { await db.send(new PutCommand({ TableName: table, Item: order })); },
    async get(orderId) {
      if (!orderId) return null;
      return (await db.send(new GetCommand({ TableName: table, Key: { orderId } }))).Item || null;
    },
    async byCheckout(checkoutId) {
      const out = await db.send(new QueryCommand({
        TableName: table, IndexName: 'checkout', KeyConditionExpression: 'checkoutId = :c',
        ExpressionAttributeValues: { ':c': checkoutId }, Limit: 1,
      }));
      return (out.Items && out.Items[0]) || null;
    },
    // Only a pending order changes, so a repeated callback can't send receipts twice.
    async settle(orderId, fields) {
      const names = {}, values = { ':pending': 'pending' };
      const sets = Object.keys(fields).map((k, i) => {
        names[`#f${i}`] = k; values[`:v${i}`] = fields[k];
        return `#f${i} = :v${i}`;
      });
      try {
        await db.send(new UpdateCommand({
          TableName: table, Key: { orderId }, UpdateExpression: `SET ${sets.join(', ')}`,
          ConditionExpression: '#s = :pending', ExpressionAttributeNames: { ...names, '#s': 'status' },
          ExpressionAttributeValues: values,
        }));
        return true;
      } catch (err) {
        if (err.name === 'ConditionalCheckFailedException') return false;
        throw err;
      }
    },
  };
}

function parseBody(event) {
  let raw = event.body || '';
  if (event.isBase64Encoded) raw = Buffer.from(raw, 'base64').toString('utf8');
  const type = (event.headers && event.headers['content-type']) || '';
  if (type.includes('application/x-www-form-urlencoded')) return Object.fromEntries(new URLSearchParams(raw));
  try { return JSON.parse(raw); } catch { return {}; }
}

let handle;
exports.handler = async (event, _ctx, store) => {
  handle = handle || createHandler(store || dynamoStore(process.env.PAYMENTS_TABLE));
  const headers = event.headers || {};
  const http = (event.requestContext && event.requestContext.http) || {};
  const req = {
    method: http.method || 'GET',
    path: event.rawPath || http.path || '/',
    query: event.queryStringParameters || {},
    body: parseBody(event),
    ip: http.sourceIp || 'unknown',   // set by AWS from the connection, can't be forged
    get(name) { return headers[name.toLowerCase()]; },
  };
  const result = { statusCode: 200, headers: {}, body: '' };
  const res = {
    status(code) { result.statusCode = code; return res; },
    set(name, value) { result.headers[name] = value; return res; },
    json(obj) {
      result.headers['Content-Type'] = 'application/json; charset=utf-8';
      result.body = JSON.stringify(obj);
      return res;
    },
    send(text) { result.body = String(text); return res; },
  };
  if (req.method === 'POST') await loadSecrets();
  await handle(req, res);
  return result;
};
