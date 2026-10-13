#!/usr/bin/env bash
# Copy the code to the server and restart it. Run ON YOUR LAPTOP from the repo:
#   deploy/push.sh ubuntu@43.156.1.2
# Sends code only: never .env, the local database, .venv or git history. The
# server's own database (and its passkeys) is left alone.
set -euo pipefail

HOST="${1:?usage: deploy/push.sh user@server-ip}"
KEY="${DCTA_SSH_KEY:-$HOME/.ssh/dcta_tencent}"
SSH="ssh -i $KEY -o StrictHostKeyChecking=accept-new"
cd "$(dirname "$0")/.."

$SSH "$HOST" 'sudo mkdir -p /opt/dcta && { command -v rsync >/dev/null || sudo apt-get install -y -q rsync; }'
rsync -az --delete -e "$SSH" --rsync-path="sudo rsync" \
  --exclude '__pycache__/' --exclude 'backend/data/dcta.db*' \
  backend frontend deploy requirements.txt "$HOST:/opt/dcta/"

$SSH "$HOST" 'if [ -x /opt/dcta/.venv/bin/pip ]; then
  sudo /opt/dcta/.venv/bin/pip install -q -r /opt/dcta/requirements.txt
  sudo chown -R dcta:dcta /opt/dcta && sudo systemctl restart dcta && echo "deployed and restarted"
else
  echo "code copied; first time, now run on the server:  sudo bash /opt/dcta/deploy/setup.sh <domain>"
fi'
