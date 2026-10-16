# Hosting qsoftwares.org on a free Google Cloud e2-micro

The site runs on one free-tier e2-micro VM (us-central1) with Caddy for automatic HTTPS and PHP-FPM for the contact form. The form sends through Zoho SMTP on port 465. Google Cloud blocks outbound port 25 but allows 465 and 587. The Zoho login is kept in Google Secret Manager and copied to the server at boot and every hour, so it is never in git. The server pulls `main` from GitHub every 5 minutes, so you deploy with a normal merge.

## One-time setup (clicks only, no commands)

1. **Google Cloud project.** In the [console](https://console.cloud.google.com), create a project (for example `qsoftwares-web`) and link a billing account. Note the project ID.
2. **Deploy key.** Go to IAM & Admin → Service Accounts → Create service account, name it `github-deployer`, and give it the **Owner** role on this project. Then open it → Keys → Add key → JSON and download the file.
3. **Zoho app password.** In Zoho, go to My Account → Security → App Passwords and create one for "Website".
4. **GitHub secrets.** In this repo, go to Settings → Secrets and variables → Actions and add:

   | Secret | Value |
   | --- | --- |
   | `GCP_PROJECT_ID` | the project ID from step 1 |
   | `GCP_SA_KEY` | the whole contents of the JSON key file |
   | `SMTP_USER` | the Zoho mailbox, e.g. `info@qsoftwares.org` |
   | `SMTP_PASSWORD` | the Zoho app password |
   | `SMTP_HOST` | optional; `smtppro.zoho.com` for paid Zoho Mail (default `smtp.zoho.com`) |

5. **Run it.** Go to Actions → Provision GCP server → Run workflow. The run summary shows the server IP and the two DNS records to set.
6. **DNS.** At your DNS provider, replace the GitHub Pages records for `qsoftwares.org` and `www` with A records pointing to that IP. Caddy issues the HTTPS certificate on its own once DNS resolves.
7. **Tidy up.** Delete the downloaded JSON key file from your computer. To create a $5 budget alert, go to Billing → Budgets & alerts; the workflow adds one automatically only if its key has billing access.

To change the Zoho password later, update `SMTP_PASSWORD` and run the workflow again. The server picks up the change within an hour.

Prefer Cloud Shell? `export SMTP_USER=... SMTP_PASSWORD=...` and then run `./create-vm.sh` from this folder. It does the same work.

## What stays free

| Item | Free tier allowance | This site |
| --- | --- | --- |
| e2-micro VM in us-central1 | 1 per month | 1 |
| Standard persistent disk | 30 GB-months | 30 GB |
| Outbound traffic | 1 GB per month (excludes China and Australia) | Roughly 500 page views with images; beyond that about $0.12 per GB |
| Secret Manager | 6 secret versions, 10,000 accesses | 1 secret, about 720 reads a month |
| External IPv4 address | Not covered | Expect a small hourly IPv4 charge; check the first invoice |

## Day-to-day

- **Deploy:** merge to `main`. Changes go live within 5 minutes.
- **Logs:** Compute Engine → VM instances → `qsoftwares-web` → Logs, or `gcloud compute ssh qsoftwares-web --zone us-central1-a -- sudo journalctl -u caddy -u 'php*-fpm' --since today`.
- **Form errors:** PHPMailer errors are written to the PHP-FPM log via `error_log`.
- **Rollback to GitHub Pages:** point DNS back to GitHub's Pages IPs. The `CNAME` file is still in the repo.
