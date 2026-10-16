#!/usr/bin/env bash
# Startup script for the qsoftwares-web e2-micro (Debian 12).
# GCP runs it on every boot; each step is safe to repeat.
set -euo pipefail

REPO_URL="https://github.com/stephencoduor/qsoftwares.git"
BRANCH="main"
WEB_ROOT="/var/www/qsoftwares"
CONF_DIR="/etc/qsoftwares"

export DEBIAN_FRONTEND=noninteractive

# 1 GB swap: the e2-micro has about 1 GB RAM and apt/PHP can spike past it.
if [ ! -f /swapfile ]; then
  fallocate -l 1G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
swapon -a

# Packages: Caddy (HTTPS), PHP-FPM for the contact form, git for deploys.
if ! command -v caddy >/dev/null; then
  apt-get update
  apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl gnupg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update
  apt-get install -y caddy php-fpm php-mbstring git unattended-upgrades
fi

# Caddy talks to PHP-FPM over /run/php/php-fpm.sock (Debian's php-fpm unit maintains that link);
# the socket is owned by www-data, so Caddy joins that group.
usermod -aG www-data caddy

# Site checkout (public repo, no credentials needed).
if [ ! -d "$WEB_ROOT/.git" ]; then
  git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$WEB_ROOT"
fi

# Mail settings live outside the web root and outside git.
mkdir -p "$CONF_DIR" /var/lib/qsoftwares/rate_limits
chown www-data:www-data /var/lib/qsoftwares/rate_limits
if [ ! -f "$CONF_DIR/smtp.ini" ]; then
  cat > "$CONF_DIR/smtp.ini" <<'INI'
; Filled in by deploy/gcp/set-smtp.sh. Until then the form falls back to PHP mail(), which will not deliver.
host = "smtp.zoho.com"
port = 465
secure = "ssl"
username = ""
password = ""
from = "info@qsoftwares.org"
from_name = "QSOFTWARES Website"
rate_limit_dir = "/var/lib/qsoftwares/rate_limits"
INI
fi
chown root:www-data "$CONF_DIR/smtp.ini"
chmod 640 "$CONF_DIR/smtp.ini"

# Web server config comes from the repo, so changes ship with a normal commit.
cp "$WEB_ROOT/deploy/gcp/Caddyfile" /etc/caddy/Caddyfile
PHP_FPM_UNIT="$(systemctl list-unit-files 'php*-fpm.service' --no-legend | awk '{print $1}' | head -n1)"
systemctl enable --now "$PHP_FPM_UNIT" caddy
systemctl restart caddy

# Pull new commits from main every 5 minutes.
cat > /etc/systemd/system/qsoftwares-pull.service <<UNIT
[Unit]
Description=Pull qsoftwares.org from GitHub

[Service]
Type=oneshot
ExecStart=/usr/bin/git -C $WEB_ROOT pull --ff-only --depth 1 origin $BRANCH
ExecStartPost=/bin/sh -c 'cmp -s $WEB_ROOT/deploy/gcp/Caddyfile /etc/caddy/Caddyfile || (cp $WEB_ROOT/deploy/gcp/Caddyfile /etc/caddy/Caddyfile && systemctl reload caddy)'
UNIT
cat > /etc/systemd/system/qsoftwares-pull.timer <<'UNIT'
[Unit]
Description=Pull qsoftwares.org every 5 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now qsoftwares-pull.timer
