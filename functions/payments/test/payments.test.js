const { test, before, after } = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { SMTPServer } = require('smtp-server');

const mails = [];
const pushes = [];
let smtp, buni, handler, store;

before(async () => {
  smtp = new SMTPServer({
    secure: false, authOptional: false, allowInsecureAuth: true, disabledCommands: ['STARTTLS'],
    onAuth(a, _s, cb) { cb(null, { user: a.username }); },
    onData(stream, _s, cb) { let d = ''; stream.on('data', (c) => (d += c)); stream.on('end', () => { mails.push(d); cb(); }); },
  });
  await new Promise((r) => smtp.listen(0, '127.0.0.1', r));

  // Stand-in for KCB Buni: token and STK push.
  buni = http.createServer((q, s) => {
    let d = ''; q.on('data', (c) => (d += c)); q.on('end', () => {
      s.setHeader('Content-Type', 'application/json');
      if (q.url.startsWith('/token')) {
        const ok = q.headers.authorization === `Basic ${Buffer.from('key:secret').toString('base64')}`;
        s.statusCode = ok ? 200 : 401;
        return s.end(JSON.stringify(ok ? { access_token: 'tok', expires_in: 3600 } : {}));
      }
      if (q.url === '/mm/api/request/1.0.0/stkpush' && q.headers.authorization === 'Bearer tok') {
        const body = JSON.parse(d);
        pushes.push(body);
        return s.end(JSON.stringify({
          header: { statusCode: '0' },
          response: { ResponseCode: '0', CheckoutRequestID: `ws_CO_${pushes.length}`, MerchantRequestID: 'm' },
        }));
      }
      s.statusCode = 404; s.end('{}');
    });
  });
  await new Promise((r) => buni.listen(0, '127.0.0.1', r));

  Object.assign(process.env, {
    SMTP_HOST: '127.0.0.1', SMTP_PORT: String(smtp.server.address().port), SMTP_SECURE: 'false',
    SMTP_USER: 'info@qsoftwares.org', SMTP_PASSWORD: 'x', MAIL_TO: 'info@qsoftwares.org',
    BUNI_BASE_URL: `http://127.0.0.1:${buni.address().port}`, BUNI_CONSUMER_KEY: 'key', BUNI_CONSUMER_SECRET: 'secret',
    KCB_ACCOUNT: '1234567890', CALLBACK_BASE_URL: 'https://pay.example', CALLBACK_SECRET: 'cb-secret-0123456789',
  });
  store = require('../core').memoryStore();
  handler = require('../lambda').handler;
});
after(() => { smtp.close(); buni.close(); });

const call = (method, path, body, { ip = '198.51.100.1', origin = 'https://qsoftwares.org', query } = {}) => handler({
  rawPath: path, queryStringParameters: query,
  requestContext: { http: { method, sourceIp: ip } },
  headers: { origin, 'content-type': 'application/json' },
  body: body ? JSON.stringify(body) : '',
}, {}, store);

const invoice = { plan: 'invoice', invoice: 'INV-001', amount: '2500', name: 'Jane Wanjiru',
  email: 'jane@example.org', phone: '0712 345 678', form_elapsed_ms: '9000' };
const callback = (cid, amount, code = 0) => ({ Body: { stkCallback: {
  MerchantRequestID: 'm', CheckoutRequestID: cid, ResultCode: code, ResultDesc: code ? 'Request cancelled by user' : 'ok',
  CallbackMetadata: code ? undefined : { Item: [{ Name: 'Amount', Value: amount }, { Name: 'MpesaReceiptNumber', Value: 'SJK1AB2CD3' }] },
} } });

test('pay sends an STK push for an invoice and the callback marks it paid with receipts', async () => {
  const r = await call('POST', '/pay', invoice);
  assert.strictEqual(r.statusCode, 200);
  const { orderId } = JSON.parse(r.body);
  const push = pushes.at(-1);
  assert.deepStrictEqual(
    [push.phoneNumber, push.amount, push.invoiceNumber, push.orgShortCode, push.sharedShortCode],
    ['254712345678', '2500', '1234567890', '522522', true]);
  assert.strictEqual(push.callbackUrl, 'https://pay.example/callback/cb-secret-0123456789');

  let s = JSON.parse((await call('GET', '/status', null, { query: { id: orderId } })).body);
  assert.strictEqual(s.status, 'pending');

  const before = mails.length;
  const cb = await call('POST', '/callback/cb-secret-0123456789', callback(`ws_CO_${pushes.length}`, 2500), { origin: '' });
  assert.strictEqual(cb.statusCode, 200);
  s = JSON.parse((await call('GET', '/status', null, { query: { id: orderId } })).body);
  assert.deepStrictEqual(s, { status: 'paid', receipt: 'SJK1AB2CD3' });
  assert.strictEqual(mails.length, before + 2);
  assert.match(mails.at(-2), /Subject: Payment received: KES 2500 from Jane Wanjiru/);
  assert.match(mails.at(-1), /To: Jane Wanjiru <jane@example.org>/);

  // A repeated notice sends nothing more.
  await call('POST', '/callback/cb-secret-0123456789', callback(`ws_CO_${pushes.length}`, 2500), { origin: '' });
  assert.strictEqual(mails.length, before + 2);
});

test('callbacks on the wrong path, for other amounts, or cancelled do not mark orders paid', async () => {
  const { orderId } = JSON.parse((await call('POST', '/pay', invoice, { ip: '198.51.100.2' })).body);
  const cid = `ws_CO_${pushes.length}`;
  assert.strictEqual((await call('POST', '/callback/wrong-secret-0000000', callback(cid, 2500))).statusCode, 404);
  const before = mails.length;
  await call('POST', '/callback/cb-secret-0123456789', callback(cid, 1));
  const s = JSON.parse((await call('GET', '/status', null, { query: { id: orderId } })).body);
  assert.strictEqual(s.status, 'review');
  assert.match(mails.at(-1), /KES 1 received, KES 2500\s+expected/);
  assert.strictEqual(mails.length, before + 1);

  const { orderId: id2 } = JSON.parse((await call('POST', '/pay', invoice, { ip: '198.51.100.3' })).body);
  await call('POST', '/callback/cb-secret-0123456789', callback(`ws_CO_${pushes.length}`, 0, 1032));
  assert.strictEqual(JSON.parse((await call('GET', '/status', null, { query: { id: id2 } })).body).status, 'failed');
});

test('pay rejects bad input, other origins, bots and floods', async () => {
  const n = pushes.length;
  assert.strictEqual((await call('POST', '/pay', { ...invoice, phone: '12345' }, { ip: '198.51.100.4' })).statusCode, 422);
  assert.strictEqual((await call('POST', '/pay', { ...invoice, amount: '5' }, { ip: '198.51.100.4' })).statusCode, 422);
  assert.strictEqual((await call('POST', '/pay', { ...invoice, plan: 'nope' }, { ip: '198.51.100.4' })).statusCode, 422);
  assert.strictEqual((await call('POST', '/pay', { ...invoice, form_elapsed_ms: '500' }, { ip: '198.51.100.4' })).statusCode, 400);
  assert.strictEqual((await call('POST', '/pay', invoice, { ip: '198.51.100.4', origin: 'https://evil.example' })).statusCode, 403);
  assert.strictEqual(pushes.length, n);

  const statuses = [];
  for (let i = 0; i < 6; i++) {
    statuses.push((await call('POST', '/pay', { ...invoice, phone: '0799000111' }, { ip: `203.0.113.${i}` })).statusCode);
  }
  assert.deepStrictEqual(statuses, [200, 200, 200, 200, 200, 429]);
});

test('lists plans and answers the CORS preflight', async () => {
  assert.deepStrictEqual(JSON.parse((await call('GET', '/plans')).body), []);
  const pre = await call('OPTIONS', '/pay');
  assert.strictEqual(pre.statusCode, 204);
  assert.strictEqual(pre.headers['Access-Control-Allow-Origin'], 'https://qsoftwares.org');
});

test('normalises Kenyan phone numbers', () => {
  const { normalisePhone } = require('../core');
  assert.strictEqual(normalisePhone('+254 712-345-678'), '254712345678');
  assert.strictEqual(normalisePhone('0110123456'), '254110123456');
  assert.strictEqual(normalisePhone('0812345678'), null);
});
