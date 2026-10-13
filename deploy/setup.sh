#!/usr/bin/env bash
# One-time setup of a fresh Ubuntu 24.04 server for DCTA. Run ON THE SERVER,
# after deploy/push.sh has copied the code to /opt/dcta:
#   sudo bash /opt/dcta/deploy/setup.sh 43-156-1-2.sslip.io
# Safe to run again: it never overwrites /opt/dcta/.env or the database.
set -euo pipefail

DOMAIN="${1:?usage: setup.sh <domain>, e.g. 43-156-1-2.sslip.io}"
[[ "$DOMAIN" =~ ^[a-z0-9.-]+$ ]] || { echo "not a domain: $DOMAIN" >&2; exit 1; }
APP=/opt/dcta
[ -f "$APP/backend/main.py" ] || { echo "no code in $APP: run deploy/push.sh first" >&2; exit 1; }

apt-get update -q
apt-get install -y -q python3-venv python3-pip caddy rsync

id dcta >/dev/null 2>&1 || useradd --system --home-dir "$APP" --shell /usr/sbin/nologin dcta

python3 -m venv "$APP/.venv"
"$APP/.venv/bin/pip" install -q --upgrade pip
"$APP/.venv/bin/pip" install -q -r "$APP/requirements.txt"

if [ ! -f "$APP/.env" ]; then
  sed "s/__DOMAIN__/$DOMAIN/g" "$APP/deploy/server.env.example" > "$APP/.env"
  NEW_ENV=1
fi
chown -R dcta:dcta "$APP"
chmod 600 "$APP/.env"

# Seed the mock ledger once. Later resets keep the passkeys: reset_demo, below.
if [ ! -f "$APP/backend/data/dcta.db" ]; then
  (cd "$APP" && sudo -u dcta .venv/bin/python -m backend.data.seed)
fi

install -m 644 "$APP/deploy/dcta.service" /etc/systemd/system/dcta.service
sed "s/__DOMAIN__/$DOMAIN/g" "$APP/deploy/Caddyfile" > /etc/caddy/Caddyfile
systemctl daemon-reload
systemctl enable dcta caddy
systemctl restart dcta caddy

echo
echo "DCTA is up at https://$DOMAIN"
if [ "${NEW_ENV:-0}" = 1 ]; then
  echo "Next: put the OpenAI key in $APP/.env, then restart:"
  echo "  sudo nano $APP/.env"
  echo "  sudo systemctl restart dcta"
fi
