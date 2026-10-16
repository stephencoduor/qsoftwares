// AWS Lambda entry point, called through a Lambda function URL.
// Adapts the function-URL event to the small req/res surface core.js uses.
//
// Extra config (environment):
//   SMTP_PASSWORD_PARAM  SSM Parameter Store SecureString holding the Zoho app password,
//                        read once per cold start (the AWS SDK ships with the Node runtime).
const { contactForm } = require('./core');

let passwordLoaded = false;
async function loadPassword() {
  if (passwordLoaded || process.env.SMTP_PASSWORD || !process.env.SMTP_PASSWORD_PARAM) return;
  const { SSMClient, GetParameterCommand } = require('@aws-sdk/client-ssm');
  const out = await new SSMClient({}).send(new GetParameterCommand({
    Name: process.env.SMTP_PASSWORD_PARAM, WithDecryption: true,
  }));
  process.env.SMTP_PASSWORD = out.Parameter.Value;
  passwordLoaded = true;
}

function parseBody(event) {
  let raw = event.body || '';
  if (event.isBase64Encoded) raw = Buffer.from(raw, 'base64').toString('utf8');
  const type = (event.headers && event.headers['content-type']) || '';
  if (type.includes('application/json')) {
    try { return JSON.parse(raw); } catch { return {}; }
  }
  return Object.fromEntries(new URLSearchParams(raw));
}

exports.handler = async (event) => {
  const headers = event.headers || {};
  const http = (event.requestContext && event.requestContext.http) || {};
  // sourceIp is set by AWS from the connection, so it can't be forged by the client.
  const ip = http.sourceIp || 'unknown';

  const req = {
    method: http.method || 'GET',
    body: parseBody(event),
    ip,
    get(name) {
      const key = name.toLowerCase();
      return key === 'x-forwarded-for' ? ip : headers[key];
    },
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

  if (req.method === 'POST') await loadPassword();
  await contactForm(req, res);
  return result;
};
