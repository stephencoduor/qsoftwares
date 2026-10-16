const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { SMTPServer } = require('smtp-server');

const received = [];
let smtp, server, base;

before(async () => {
  smtp = new SMTPServer({
    secure: false, authOptional: false, allowInsecureAuth: true, disabledCommands: ['STARTTLS'],
    onAuth(auth, _s, cb) { cb(null, { user: auth.username }); },
    onData(stream, _s, cb) { let d = ''; stream.on('data', (c) => (d += c)); stream.on('end', () => { received.push(d); cb(); }); },
  });
  await new Promise((r) => smtp.listen(0, '127.0.0.1', r));
  Object.assign(process.env, {
    SMTP_HOST: '127.0.0.1', SMTP_PORT: String(smtp.server.address().port), SMTP_SECURE: 'false',
    SMTP_USER: 'info@qsoftwares.org', SMTP_PASSWORD: 'x', MAIL_TO: 'info@qsoftwares.org',
  });
  const { getTestServer } = require('@google-cloud/functions-framework/testing');
  require('../index.js');
  server = getTestServer('contactForm');
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}/`;
});
after(() => { server.close(); smtp.close(); });

const post = (fields, origin = 'https://qsoftwares.org') => fetch(base, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', Origin: origin },
  body: new URLSearchParams(fields),
});
const good = { contactName: 'Jane Wanjiru', contactEmail: 'jane@example.org', contactMessage: '[KoboToolbox Support Request]\nServer down <b>now</b>' };

test('sends a valid form through SMTP', async () => {
  const r = await post(good);
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.headers.get('access-control-allow-origin'), 'https://qsoftwares.org');
  assert.deepStrictEqual(await r.json(), ['success', 'Thank you. Your message has been sent.']);
  const mail = received.at(-1);
  assert.match(mail, /Subject: KoboToolbox Support Request from Jane Wanjiru/);
  assert.match(mail, /Reply-To: Jane Wanjiru <jane@example.org>/);
  assert.doesNotMatch(mail, /<b>now<\/b>/);
});

test('answers the CORS preflight', async () => {
  const r = await fetch(base, { method: 'OPTIONS', headers: { Origin: 'https://www.qsoftwares.org' } });
  assert.strictEqual(r.status, 204);
  assert.strictEqual(r.headers.get('access-control-allow-origin'), 'https://www.qsoftwares.org');
});

test('rejects other origins', async () => {
  const r = await post(good, 'https://evil.example');
  assert.strictEqual(r.status, 403);
});

test('rejects bad input', async () => {
  const r = await post({ ...good, contactEmail: 'nope' });
  assert.strictEqual(r.status, 422);
});

test('honeypot looks like success but sends nothing', async () => {
  const before = received.length;
  const r = await post({ ...good, website_url: 'http://spam' });
  assert.deepStrictEqual(await r.json(), ['success', 'Thank you. Your message has been sent.']);
  assert.strictEqual(received.length, before);
});

test('rate limits after 5 per hour', async () => {
  const statuses = [];
  for (let i = 0; i < 6; i++) statuses.push((await post({ ...good, contactName: 'Rate Test' }, 'https://qsoftwares.org')).status);
  assert.ok(statuses.includes(429));
});

test('lambda handler sends via a function URL event', async () => {
  const { handler } = require('../lambda.js');
  const event = {
    requestContext: { http: { method: 'POST', sourceIp: '203.0.113.9' } },
    headers: { origin: 'https://qsoftwares.org', 'content-type': 'application/x-www-form-urlencoded' },
    body: Buffer.from(new URLSearchParams({ ...good, contactName: 'Lambda Test' }).toString()).toString('base64'),
    isBase64Encoded: true,
  };
  const before = received.length;
  const r = await handler(event);
  assert.strictEqual(r.statusCode, 200);
  assert.strictEqual(r.headers['Access-Control-Allow-Origin'], 'https://qsoftwares.org');
  assert.deepStrictEqual(JSON.parse(r.body), ['success', 'Thank you. Your message has been sent.']);
  assert.strictEqual(received.length, before + 1);
});

test('lambda handler answers preflight and rejects foreign origins', async () => {
  const { handler } = require('../lambda.js');
  const pre = await handler({ requestContext: { http: { method: 'OPTIONS', sourceIp: '203.0.113.10' } }, headers: { origin: 'https://www.qsoftwares.org' } });
  assert.strictEqual(pre.statusCode, 204);
  const bad = await handler({ requestContext: { http: { method: 'POST', sourceIp: '203.0.113.11' } }, headers: { origin: 'https://evil.example' }, body: '' });
  assert.strictEqual(bad.statusCode, 403);
});
