/**
 * QSOFTWARES contact form mailer (Google Cloud Run function).
 *
 * The site stays on GitHub Pages; its forms POST here and this function sends
 * the message through Zoho SMTP. Replies use the same JSON shape the old PHP
 * handler did: ["success" | "error", "message"].
 *
 * Config (set by .github/workflows/deploy-contact-function.yml):
 *   SMTP_USER, SMTP_PASSWORD  from Secret Manager
 *   SMTP_HOST                 default smtp.zoho.com
 *   SMTP_PORT, SMTP_SECURE    default 465 / true
 *   MAIL_TO                   default info@qsoftwares.org
 *   ALLOWED_ORIGINS           comma-separated, default qsoftwares.org and www
 */
const functions = require('@google-cloud/functions-framework');
const nodemailer = require('nodemailer');

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS ||
  'https://qsoftwares.org,https://www.qsoftwares.org')
  .split(',').map((s) => s.trim()).filter(Boolean);
const MAIL_TO = process.env.MAIL_TO || 'info@qsoftwares.org';
const RATE_LIMIT_MAX = 5;               // submissions
const RATE_LIMIT_WINDOW_MS = 3600 * 1000; // per hour, per IP, per instance
const MAX_MESSAGE_LENGTH = 5000;

let transporter;
function getTransporter() {
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'smtp.zoho.com',
      port: Number(process.env.SMTP_PORT || 465),
      secure: (process.env.SMTP_SECURE || 'true') === 'true',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD },
    });
  }
  return transporter;
}

const hits = new Map();
function withinRateLimit(ip) {
  const now = Date.now();
  const recent = (hits.get(ip) || []).filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
  if (recent.length >= RATE_LIMIT_MAX) {
    hits.set(ip, recent);
    return false;
  }
  recent.push(now);
  hits.set(ip, recent);
  return true;
}

const escapeHtml = (s) => s.replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));
const stripTags = (s) => String(s || '').replace(/<[^>]*>/g, '').trim();

function respond(res, status, message, http = 200) {
  res.status(http).json([status, message]);
}

async function contactForm(req, res) {
  const origin = req.get('origin') || '';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') {
    res.set('Access-Control-Allow-Methods', 'POST');
    res.set('Access-Control-Allow-Headers', 'Content-Type');
    res.set('Access-Control-Max-Age', '3600');
    return res.status(204).send('');
  }
  if (req.method !== 'POST') return respond(res, 'error', 'Invalid request method.', 405);
  if (!ALLOWED_ORIGINS.includes(origin)) return respond(res, 'error', 'Unauthorized origin.', 403);

  const body = req.body || {};

  // Honeypot: bots fill the hidden field; pretend it worked.
  if (body.website_url) return respond(res, 'success', 'Thank you. Your message has been sent.');

  // Google's front end appends the real client address last; earlier entries can be forged.
  const ip = String(req.get('x-forwarded-for') || req.ip || 'unknown').split(',').pop().trim();
  if (!withinRateLimit(ip)) return respond(res, 'error', 'Too many requests. Please try again later.', 429);

  const name = stripTags(body.contactName);
  const email = stripTags(body.contactEmail);
  const message = stripTags(body.contactMessage);

  if (!name || !email || !message) return respond(res, 'error', 'Please fill in all required fields.', 422);
  if (!/^[\p{L}\s'.-]{2,100}$/u.test(name)) return respond(res, 'error', 'Please enter a valid name.', 422);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    return respond(res, 'error', 'Please enter a valid email address.', 422);
  }
  if (message.length > MAX_MESSAGE_LENGTH) {
    return respond(res, 'error', 'Message is too long (max 5 000 characters).', 422);
  }

  let subject = 'New Contact Form Submission';
  if (message.includes('[KoboToolbox Support Request]')) subject = `KoboToolbox Support Request from ${name}`;
  else if (message.includes('[Training Enquiry]')) subject = `Training Enquiry from ${name}`;

  const html =
    '<div style="font-family:Arial,Helvetica,sans-serif;max-width:640px;margin:0 auto;">' +
    '<div style="background:#015055;padding:20px 24px;border-radius:8px 8px 0 0;">' +
    '<h2 style="color:#fff;margin:0;">New Support Request</h2></div>' +
    '<div style="background:#f9f9f9;padding:24px;border:1px solid #e0e0e0;border-radius:0 0 8px 8px;">' +
    `<p><strong>Name:</strong> ${escapeHtml(name)}<br>` +
    `<strong>Email:</strong> <a href="mailto:${escapeHtml(email)}">${escapeHtml(email)}</a></p>` +
    '<hr style="border:none;border-top:1px solid #e0e0e0;margin:16px 0;">' +
    `<div style="white-space:pre-wrap;line-height:1.6;">${escapeHtml(message)}</div>` +
    '</div></div>';
  const text = `New Support Request\n\nName:  ${name}\nEmail: ${email}\n\nMessage:\n${message}\n`;

  try {
    // Zoho only accepts a From address that matches the mailbox it logs in with.
    await getTransporter().sendMail({
      from: { name: 'QSOFTWARES Website', address: process.env.SMTP_USER },
      to: MAIL_TO,
      replyTo: { name, address: email },
      subject,
      text,
      html,
    });
    return respond(res, 'success', 'Thank you. Your message has been sent.');
  } catch (err) {
    console.error('Mail send failed:', err.message);
    return respond(res, 'error', 'Message could not be sent. Please try again later.', 500);
  }
}

functions.http('contactForm', contactForm);
module.exports = { contactForm };
