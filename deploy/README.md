# Putting DCTA on Tencent Cloud

One small Tencent Cloud Lighthouse server in Singapore runs the app. Caddy in
front of it handles HTTPS, which passkeys need on any address but localhost.

## 1. Make an SSH key (laptop, once)

```bash
ssh-keygen -t ed25519 -f ~/.ssh/dcta_tencent
cat ~/.ssh/dcta_tencent.pub        # this public half goes into Tencent Cloud
```

## 2. Rent the server (Tencent Cloud console)

1. **Lighthouse → Create instance.**
2. **Region:** Singapore. **Image:** Ubuntu 24.04 LTS (a plain system image, not an app template).
3. **Plan:** 2 cores / 2 GB RAM is enough.
4. **SSH key:** Lighthouse → SSH keys → import `~/.ssh/dcta_tencent.pub`, then bind it to the instance.
5. **Firewall** (instance → Firewall): allow TCP 22, 80 and 443. Port 80 is
   needed for the HTTPS certificate, not just 443.
6. Note the **public IP**, e.g. `43.156.1.2`. The login user on Ubuntu images is `ubuntu`.

## 3. Pick the address

Free and instant: `<ip with dashes>.sslip.io`, e.g. `43-156-1-2.sslip.io`.
It already points at your IP, so there's nothing to set up. If you own a
domain, add an A record to the IP and use that instead. If Caddy's log shows a
Let's Encrypt rate limit on sslip.io, switch to your own domain.

## 4. Deploy

```bash
# laptop, from the repo
deploy/push.sh ubuntu@43.156.1.2

# then on the server
ssh -i ~/.ssh/dcta_tencent ubuntu@43.156.1.2
sudo bash /opt/dcta/deploy/setup.sh 43-156-1-2.sslip.io
sudo nano /opt/dcta/.env           # paste OPENAI_API_KEY=...
sudo systemctl restart dcta
```

Open `https://43-156-1-2.sslip.io`. Register a passkey there: one made on
localhost doesn't work on another address. Try it from a phone too.

## Every update after that

```bash
deploy/push.sh ubuntu@43.156.1.2   # copies the code and restarts; keeps the server's database
```

## Day to day

| What | Command (on the server) |
|---|---|
| Reset the demo money (keeps passkeys) | `cd /opt/dcta && sudo -u dcta .venv/bin/python -m backend.data.reset_demo` |
| App log | `sudo journalctl -u dcta -f` |
| HTTPS log | `sudo journalctl -u caddy -f` |
| Restart | `sudo systemctl restart dcta` |

## Before sharing the link

- Anyone with the link can make AI calls on our OpenAI key. Use a separate key
  for the server and set a monthly spending limit on it in the OpenAI dashboard.
- `MOCK_SIGNING` stays unset. `/api/auth/mock-sign` must answer 404.
- The app keeps drafts in memory, so it runs as one process. A restart drops
  drafts in progress, nothing else.
