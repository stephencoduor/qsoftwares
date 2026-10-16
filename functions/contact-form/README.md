# Contact form mailer

The website stays on GitHub Pages. The Kobo support and training forms POST to this function, which sends the message to info@qsoftwares.org through Zoho SMTP on port 465. The shared logic is in `core.js`. `lambda.js` runs it on AWS Lambda, which is the live setup, and `index.js` runs it on Google Cloud Run functions.

## AWS Lambda (live)

Run `./deploy-aws.sh` on a machine where the AWS CLI is signed in. On the first run it asks for the Zoho app password; typing is hidden. It then:

- stores the password in SSM Parameter Store as a free SecureString;
- creates a role that can read only that parameter and write logs;
- deploys `qsoftwares-contact-form` (Node 20, eu-central-1) with a public function URL;
- prints `CONTACT_ENDPOINT=...`, which goes into `js/contact-endpoint.js`.

Lambda's always-free allowance is 1 million requests and 400,000 GB-seconds a month. Function URLs cost nothing extra. Reserved concurrency is capped at 2 where the account allows it. Run with `RESET_PASSWORD=1` to change the password.

It also sets up a free usage alarm that emails info@qsoftwares.org (`ALERT_EMAIL`) when the function runs more than 500 times in a day (`ALERT_DAILY`). AWS sends a confirmation email on the first run; click its link once.

To turn on Cloudflare Turnstile, create a widget for qsoftwares.org and www.qsoftwares.org in the Cloudflare dashboard, put its site key in `js/contact-endpoint.js`, and run `SET_TURNSTILE=1 ./deploy-aws.sh` to type the secret key. Until the secret exists the function skips the check, so the forms keep working.

# Google Cloud Run functions (alternative)

## Quickest setup: one link

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https%3A%2F%2Fgithub.com%2Fstephencoduor%2Fqsoftwares&cloudshell_git_branch=deploy%2Fgcp-e2-micro&cloudshell_tutorial=functions%2Fcontact-form%2FTUTORIAL.md&show=terminal)

The link opens Google Cloud Shell with this repo and a short guide. Click the copy button on the one command and press Enter, then type your Zoho mailbox and app password when asked. It creates a project, links billing, and deploys the function. Nothing goes into GitHub secrets.

## Alternative: deploy from GitHub Actions

1. **Google Cloud project.** In the [console](https://console.cloud.google.com), create a project (for example `qsoftwares-web`) and link a billing account. Note the project ID. Billing must be linked, but this stays inside the free tier.
2. **Deploy key.** Go to IAM & Admin → Service Accounts → Create service account. Name it `github-deployer` and give it the **Owner** role on this project. Then open it → Keys → Add key → JSON and download the file.
3. **Zoho app password.** In Zoho, go to My Account → Security → App Passwords and create one named "Website".
4. **GitHub secrets.** In this repo, go to Settings → Secrets and variables → Actions → New repository secret:

   | Secret | Value |
   | --- | --- |
   | `GCP_PROJECT_ID` | the project ID from step 1 |
   | `GCP_SA_KEY` | the whole contents of the JSON key file |
   | `SMTP_USER` | the Zoho mailbox, e.g. `info@qsoftwares.org` |
   | `SMTP_PASSWORD` | the Zoho app password |
   | `SMTP_HOST` | optional; `smtppro.zoho.com` for paid Zoho Mail (default `smtp.zoho.com`) |

5. **Deploy.** Go to Actions → Deploy contact form function → Run workflow. The workflow tests the function, deploys it, and commits the function address into `js/contact-endpoint.js`, so the live forms start using it once GitHub Pages republishes.
6. **Tidy up.** Delete the downloaded key file from your computer. Add a $5 budget in Billing → Budgets & alerts.

To change the Zoho password later, update `SMTP_PASSWORD` and run the workflow again.

## Free tier fit

| Item | Free each month | This form |
| --- | --- | --- |
| Cloud Run function requests | 2 million | A few hundred |
| Compute | 180,000 vCPU-seconds, 360,000 GB-seconds | Well under 1% |
| Secret Manager | 6 versions, 10,000 accesses | 2 secrets, read at cold starts |
| Cloud Build | 120 build-minutes a day | About 2 minutes per deploy |
| Artifact Registry | 0.5 GB | Each deploy stores a small image; delete old ones if a bill appears |

`--max-instances 2` caps spend if the endpoint is ever flooded.

## Protection

The function answers only requests from https://qsoftwares.org and https://www.qsoftwares.org. It rejects filled-in honeypot fields (`website_url`), ignores submissions sent less than 3 seconds after the page loaded (`form_elapsed_ms`, set by `js/form-guard.js`), allows 5 submissions per IP per hour, validates name and email, strips HTML, and caps messages at 5,000 characters. With a Turnstile secret configured, it also checks every submission's Turnstile token with Cloudflare before sending.

## Local test

```bash
cd functions/contact-form && npm ci && npm test
```

The tests run the function against a local SMTP server and check sending, CORS, origin rejection, validation, the honeypot, the timing check, Turnstile and the rate limit.
