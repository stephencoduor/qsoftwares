# Hosting qsoftwares.org on a free Google Cloud e2-micro

The site runs on one free-tier e2-micro VM (us-central1) with Caddy for automatic HTTPS and PHP-FPM for the contact form. The form sends through Zoho SMTP on port 465. Google Cloud blocks outbound port 25 but allows 465 and 587. The server pulls `main` from GitHub every 5 minutes, so you deploy with a normal merge.

## One-time setup (about 15 minutes)

1. Open [Cloud Shell](https://shell.cloud.google.com) and select or create a project that has billing linked.
2. Run:
   ```bash
   git clone https://github.com/stephencoduor/qsoftwares.git
   cd qsoftwares/deploy/gcp
   ./create-vm.sh
   ```
   This creates the VM, a static IP, the HTTP/HTTPS firewall rule and a $5 budget alert. At the end it prints the IP address.
3. In Zoho Mail, create an app-specific password (My Account → Security → App Passwords). Then run `./set-smtp.sh` and enter it when prompted. The password is stored only on the server at `/etc/qsoftwares/smtp.ini`, never in git.
4. At your DNS provider, replace the GitHub Pages records for `qsoftwares.org` and `www` with A records pointing to the printed IP. Caddy issues the certificate on its own once DNS resolves.
5. Test the forms on `/kobo-support.html` and `/training.html`.

## What stays free

| Item | Free tier allowance | This site |
| --- | --- | --- |
| e2-micro VM in us-central1 | 1 per month | 1 |
| Standard persistent disk | 30 GB-months | 30 GB |
| Outbound traffic | 1 GB per month (excludes China and Australia) | Roughly 500 page views with images; beyond that about $0.12 per GB |
| External IPv4 address | Not covered | Expect a small hourly IPv4 charge; check the first invoice |

The budget alert emails you at 50%, 90% and 100% of $5.

## Day-to-day

- **Deploy:** merge to `main`. Changes go live within 5 minutes.
- **Logs:** `gcloud compute ssh qsoftwares-web --zone us-central1-a -- sudo journalctl -u caddy -u 'php*-fpm' --since today`
- **Form errors:** PHPMailer errors are written to the PHP-FPM log via `error_log`.
- **Rollback to GitHub Pages:** point DNS back to GitHub's Pages IPs. The `CNAME` file is still in the repo.
