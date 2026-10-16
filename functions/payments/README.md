# Website payments (KCB Buni, M-Pesa)

`qsoftwares.org/pay` lets clients pay for self-hosted KoboToolbox support plans, or pay an invoice, with M-Pesa. The page posts to this AWS Lambda function, which asks KCB Buni to send an M-Pesa STK push to the payer's phone. The money goes through KCB's shared paybill 522522 into the KCB account set at deploy time. Buni then calls the function back, which marks the order paid and emails a receipt to the payer and to info@qsoftwares.org.

## Safety

- Plan prices live in `plans.json` on the server. The browser only sends a plan id.
- Invoice payments accept amounts between `INVOICE_MIN` and `INVOICE_MAX` (KES 100 to 500,000 by default).
- Buni callbacks are not signed, so the function only accepts them on a secret path (`/callback/<secret>`, generated at deploy). A callback must also name a CheckoutRequestID this function created and report the amount that was asked for. A different amount is held as `review`, and info@ is emailed.
- Each order is settled once, so a repeated callback can't send a second receipt.
- `/pay` uses the contact form's protections: an origin check, a honeypot, the 3-second timer and Cloudflare Turnstile. It also allows 5 prompts per hour per IP and per phone number, so nobody can flood a stranger's phone with prompts.

## Deploy

```bash
./deploy-aws.sh                    # sandbox (uat.buni.kcbgroup.com)
BUNI_ENV=production RESET_BUNI=1 ./deploy-aws.sh   # after KCB approves go-live and issues production keys
```

The first run asks for the Buni consumer key and secret (typing is hidden) and the KCB account number. It then creates:

- the SSM parameters under `/qsoftwares/payments/`;
- a DynamoDB table (inside the always-free tier);
- the role, the function and its URL.

It prints `PAYMENTS_ENDPOINT=...`, which goes into `js/contact-endpoint.js` as `QS_PAYMENTS_ENDPOINT`. While that value is empty, the Pay page shows contact details instead of the form.

To add fixed-price plans, list them in `plans.json` as `{ "id": "basic", "name": "...", "amount": 15000, "description": "..." }` and redeploy.

## Open questions for KCB

The public Buni documentation covers M-Pesa STK push only. Ask buni@kcbgroup.com:

- whether the card and bank options under "Receive Payments" can be used from a website;
- whether callbacks can be authenticated;
- the exact production token URL. The function's default is `<base>/token?grant_type=client_credentials`, and `BUNI_TOKEN_URL` overrides it.

## Test

```bash
cd functions/payments && npm ci && npm test
```

The tests run against a stand-in Buni server and a local SMTP server.
