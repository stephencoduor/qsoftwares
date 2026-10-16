/**
 * QSOFTWARES website payments through KCB Buni (M-Pesa STK push). Platform-neutral core;
 * lambda.js wraps it for an AWS Lambda function URL.
 *
 * Routes:
 *   GET  /plans                 fixed-price items from plans.json
 *   POST /pay                   start a payment: sends an M-Pesa prompt to the payer's phone
 *   GET  /status?id=<orderId>   pending | paid | failed | review, for the page to poll
 *   POST /callback/<secret>     KCB's result notice (unsigned, so the path carries a secret)
 *
 * Buni callbacks are not signed. A notice only counts when it arrives on the secret path,
 * names a CheckoutRequestID this function created, and reports the amount that was asked for.
 *
 * Config (environment):
 *   BUNI_BASE_URL        default https://uat.buni.kcbgroup.com (sandbox); production https://buni.kcbgroup.com
 *   BUNI_TOKEN_URL       default <BUNI_BASE_URL>/token?grant_type=client_credentials
 *   BUNI_CONSUMER_KEY, BUNI_CONSUMER_SECRET
 *   KCB_ACCOUNT          KCB account the paybill credits (sent as invoiceNumber)
 *   KCB_SHORTCODE        default 522522 (KCB's shared M-Pesa paybill)
 *   CALLBACK_BASE_URL    this function's public URL; CALLBACK_SECRET  random path segment
 *   SMTP_*, MAIL_TO      as in the contact form; receipts go to MAIL_TO and the payer
 *   ALLOWED_ORIGINS, TURNSTILE_SECRET   as in the contact form
 *   INVOICE_MIN, INVOICE_MAX            bounds for paying an invoice, default 100 and 500000 KES
 */
const crypto = require('node:crypto');
const nodemailer = require('nodemailer');
const { plans } = require('./plans.json');

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS ||
  'https://qsoftwares.org,https://www.qsoftwares.org').split(',').map((s) => s.trim()).filter(Boolean);
const MIN_FILL_MS = 3000;
const RATE_LIMIT_MAX = 5;                  // payment prompts per hour per IP and per phone
const RATE_LIMIT_WINDOW_MS = 3600 * 1000;

const env = (k, d) => process.env[k] || d;
const baseUrl = () => env('BUNI_BASE_URL', 'https://uat.buni.kcbgroup.com').replace(/\/$/, '');

// ── small helpers ───────────────────────────────────────────────────────────
const hits = new Map();
function withinRateLimit(key) {
  const now = Date.now();
  const recent = (hits.get(key) || []).filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
  const ok = recent.length < RATE_LIMIT_MAX;
  if (ok) recent.push(now);
  hits.set(key, recent);
  return ok;
}
const clean = (s, max = 200) => String(s || '').replace(/<[^>]*>/g, '').trim().slice(0, max);
const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// Accepts 07XXXXXXXX, 01XXXXXXXX, +2547..., 2547... and returns 2547XXXXXXXX / 2541XXXXXXXX.
function normalisePhone(raw) {
  const d = String(raw || '').replace(/[\s()+-]/g, '');
  const m = d.match(/^(?:254|0)?([17]\d{8})$/);
  return m ? `254${m[1]}` : null;
}

async function turnstileOk(token, ip) {
  if (!process.env.TURNSTILE_SECRET) return true;
  if (!token) return false;
  try {
    const r = await fetch(env('TURNSTILE_VERIFY_URL', 'https://challenges.cloudflare.com/turnstile/v0/siteverify'), {
      method: 'POST',
      body: new URLSearchParams({ secret: process.env.TURNSTILE_SECRET, response: token, remoteip: ip }),
      signal: AbortSignal.timeout(5000),
    });
    const out = await r.json();
    return out.success === true && ALLOWED_ORIGINS.map((o) => new URL(o).hostname).includes(out.hostname);
  } catch (err) {
    console.error('Turnstile check failed:', err.message);
    return false;
  }
}

// ── KCB Buni ────────────────────────────────────────────────────────────────
let token = null;
async function buniToken() {
  if (token && token.expires > Date.now()) return token.value;
  const basic = Buffer.from(`${process.env.BUNI_CONSUMER_KEY}:${process.env.BUNI_CONSUMER_SECRET}`).toString('base64');
  const r = await fetch(env('BUNI_TOKEN_URL', `${baseUrl()}/token?grant_type=client_credentials`), {
    method: 'POST',
    headers: { Authorization: `Basic ${basic}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=client_credentials',
    signal: AbortSignal.timeout(10000),
  });
  const out = await r.json().catch(() => ({}));
  if (!r.ok || !out.access_token) throw new Error(`Buni token request failed (${r.status})`);
  // Refresh a few minutes early.
  token = { value: out.access_token, expires: Date.now() + (Number(out.expires_in || 3600) - 300) * 1000 };
  return token.value;
}

async function stkPush({ phone, amount, description }) {
  const r = await fetch(`${baseUrl()}/mm/api/request/1.0.0/stkpush`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${await buniToken()}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      phoneNumber: phone,
      amount: String(amount),
      invoiceNumber: process.env.KCB_ACCOUNT,
      sharedShortCode: true,
      orgShortCode: env('KCB_SHORTCODE', '522522'),
      orgPassKey: '',
      callbackUrl: `${env('CALLBACK_BASE_URL', '').replace(/\/$/, '')}/callback/${process.env.CALLBACK_SECRET}`,
      transactionDescription: description.slice(0, 13),
    }),
    signal: AbortSignal.timeout(15000),
  });
  const out = await r.json().catch(() => ({}));
  const res = out.response || out;
  if (!r.ok || String(res.ResponseCode) !== '0' || !res.CheckoutRequestID) {
    throw new Error(`STK push refused (${r.status}): ${res.ResponseDescription || JSON.stringify(out).slice(0, 200)}`);
  }
  return res.CheckoutRequestID;
}

// KCB's notice may arrive as Daraja's {Body:{stkCallback}} or flat; read either.
function parseCallback(body) {
  const cb = (body && body.Body && body.Body.stkCallback) || body || {};
  const items = (cb.CallbackMetadata && cb.CallbackMetadata.Item) || [];
  const meta = Object.fromEntries(items.map((i) => [i.Name, i.Value]));
  return {
    checkoutId: cb.CheckoutRequestID,
    resultCode: String(cb.ResultCode),
    resultDesc: cb.ResultDesc || '',
    amount: Number(meta.Amount),
    receipt: meta.MpesaReceiptNumber || '',
  };
}

// ── mail ────────────────────────────────────────────────────────────────────
let transporter;
function mailer() {
  transporter = transporter || nodemailer.createTransport({
    host: env('SMTP_HOST', 'smtp.zoho.com'),
    port: Number(env('SMTP_PORT', 465)),
    secure: env('SMTP_SECURE', 'true') === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD },
  });
  return transporter;
}

async function sendReceipts(order) {
  const from = { name: 'QSOFTWARES', address: process.env.SMTP_USER };
  const lines = [
    `Item: ${order.item}`,
    `Amount: KES ${order.amount.toLocaleString('en-KE')}`,
    `M-Pesa receipt: ${order.receipt}`,
    `Reference: ${order.orderId}`,
    `Paid by: ${order.name} <${order.email}>, ${order.phone}`,
  ];
  const html = (intro) => `<div style="font-family:Arial,Helvetica,sans-serif;max-width:600px">` +
    `<p>${escapeHtml(intro)}</p><p>${lines.map(escapeHtml).join('<br>')}</p></div>`;
  const mail = mailer();
  await mail.sendMail({
    from, to: env('MAIL_TO', 'info@qsoftwares.org'), replyTo: { name: order.name, address: order.email },
    subject: `Payment received: KES ${order.amount} from ${order.name}`,
    text: lines.join('\n'), html: html('A website payment has been received.'),
  });
  await mail.sendMail({
    from, to: { name: order.name, address: order.email }, replyTo: env('MAIL_TO', 'info@qsoftwares.org'),
    subject: 'Your payment to QSOFTWARES',
    text: `Thank you, ${order.name}. We have received your payment.\n\n${lines.join('\n')}\n`,
    html: html(`Thank you, ${order.name}. We have received your payment.`),
  });
}

// ── handler ─────────────────────────────────────────────────────────────────
function respond(res, http, obj) { return res.status(http).json(obj); }

/** store: { put(order), get(orderId), byCheckout(checkoutId), settle(orderId, fields) -> bool (true once) } */
function createHandler(store) {
  return async function payments(req, res) {
    const origin = req.get('origin') || '';
    if (ALLOWED_ORIGINS.includes(origin)) {
      res.set('Access-Control-Allow-Origin', origin);
      res.set('Vary', 'Origin');
    }
    const path = (req.path || '/').replace(/\/+$/, '') || '/';
    const ip = req.ip || 'unknown';

    if (req.method === 'OPTIONS') {
      res.set('Access-Control-Allow-Methods', 'GET, POST');
      res.set('Access-Control-Allow-Headers', 'Content-Type');
      res.set('Access-Control-Max-Age', '3600');
      return res.status(204).send('');
    }

    // KCB's server calls this; no browser origin.
    if (req.method === 'POST' && path.startsWith('/callback/')) {
      const secret = path.slice('/callback/'.length);
      const expected = process.env.CALLBACK_SECRET || '';
      const okPath = expected && secret.length === expected.length &&
        crypto.timingSafeEqual(Buffer.from(secret), Buffer.from(expected));
      if (!okPath) return res.status(404).send('Not found');
      const cb = parseCallback(req.body);
      const order = cb.checkoutId && await store.byCheckout(cb.checkoutId);
      if (!order) {
        console.warn('Callback for unknown CheckoutRequestID', cb.checkoutId);
        return res.status(200).send('Callback received');
      }
      if (cb.resultCode === '0' && cb.amount === order.amount) {
        const paid = { ...order, status: 'paid', receipt: cb.receipt, paidAt: new Date().toISOString() };
        if (await store.settle(order.orderId, { status: 'paid', receipt: cb.receipt, paidAt: paid.paidAt })) {
          await sendReceipts(paid).catch((err) => console.error('Receipt mail failed:', err.message));
        }
      } else if (cb.resultCode === '0') {
        // Money moved but not the amount asked for: hold it for a person to check.
        console.error('Amount mismatch', order.orderId, cb.amount, order.amount);
        if (await store.settle(order.orderId, { status: 'review', receipt: cb.receipt, paidAmount: cb.amount })) {
          await mailer().sendMail({
            from: { name: 'QSOFTWARES', address: process.env.SMTP_USER }, to: env('MAIL_TO', 'info@qsoftwares.org'),
            subject: `Check payment ${order.orderId}: KES ${cb.amount} received, KES ${order.amount} expected`,
            text: `M-Pesa receipt ${cb.receipt} from ${order.name} <${order.email}>, ${order.phone}, for ${order.item}.\n`,
          }).catch((err) => console.error('Review mail failed:', err.message));
        }
      } else {
        await store.settle(order.orderId, { status: 'failed', reason: cb.resultDesc.slice(0, 200) });
      }
      return res.status(200).send('Callback received');
    }

    if (req.method === 'GET' && path === '/plans') {
      return respond(res, 200, plans.map(({ id, name, amount, description }) => ({ id, name, amount, description })));
    }

    if (req.method === 'GET' && path === '/status') {
      const order = await store.get(clean(req.query && req.query.id, 64));
      if (!order) return respond(res, 404, { status: 'unknown' });
      return respond(res, 200, { status: order.status, receipt: order.status === 'paid' ? order.receipt : undefined });
    }

    if (req.method === 'POST' && path === '/pay') {
      if (!ALLOWED_ORIGINS.includes(origin)) return respond(res, 403, { error: 'Unauthorized origin.' });
      const b = req.body || {};
      if (b.website_url || !(Number(b.form_elapsed_ms) >= MIN_FILL_MS)) {
        return respond(res, 400, { error: 'Please try again.' });
      }
      const name = clean(b.name, 100);
      const email = clean(b.email, 254);
      const phone = normalisePhone(b.phone);
      if (!/^[\p{L}\s'.-]{2,100}$/u.test(name)) return respond(res, 422, { error: 'Please enter your name.' });
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return respond(res, 422, { error: 'Please enter a valid email address.' });
      if (!phone) return respond(res, 422, { error: 'Please enter a Safaricom M-Pesa number, e.g. 0712 345 678.' });

      // The price comes from plans.json, never from the browser; invoices take the typed amount within bounds.
      let item, amount;
      const plan = plans.find((p) => p.id === b.plan);
      if (plan) {
        item = plan.name; amount = plan.amount;
      } else if (b.plan === 'invoice') {
        const invoice = clean(b.invoice, 40);
        amount = Math.round(Number(b.amount));
        const min = Number(env('INVOICE_MIN', 100)), max = Number(env('INVOICE_MAX', 500000));
        if (!/^[\w./-]{1,40}$/.test(invoice)) return respond(res, 422, { error: 'Please enter your invoice number.' });
        if (!(amount >= min && amount <= max)) {
          return respond(res, 422, { error: `Please enter an amount between KES ${min} and KES ${max}.` });
        }
        item = `Invoice ${invoice}`;
      } else {
        return respond(res, 422, { error: 'Please choose what you are paying for.' });
      }

      if (!withinRateLimit(`ip:${ip}`) || !withinRateLimit(`phone:${phone}`)) {
        return respond(res, 429, { error: 'Too many payment attempts. Please try again later.' });
      }
      if (!(await turnstileOk(b['cf-turnstile-response'], ip))) {
        return respond(res, 403, { error: 'Please complete the verification check and try again.' });
      }

      const orderId = crypto.randomBytes(12).toString('hex');
      let checkoutId;
      try {
        checkoutId = await stkPush({ phone, amount, description: 'QSOFTWARES' });
      } catch (err) {
        console.error('STK push failed:', err.message);
        return respond(res, 502, { error: 'We could not reach M-Pesa. Please try again in a moment.' });
      }
      await store.put({
        orderId, checkoutId, status: 'pending', item, amount, name, email, phone,
        createdAt: new Date().toISOString(),
      });
      return respond(res, 200, { orderId, message: 'Check your phone and enter your M-Pesa PIN to pay.' });
    }

    return respond(res, 404, { error: 'Not found.' });
  };
}

function memoryStore() {
  const orders = new Map();
  return {
    async put(o) { orders.set(o.orderId, { ...o }); },
    async get(id) { return orders.get(id) || null; },
    async byCheckout(cid) { return [...orders.values()].find((o) => o.checkoutId === cid) || null; },
    async settle(id, fields) {
      const o = orders.get(id);
      if (!o || o.status !== 'pending') return false;
      Object.assign(o, fields);
      return true;
    },
  };
}

module.exports = { createHandler, memoryStore, normalisePhone, parseCallback };
