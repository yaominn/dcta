# Putting DCTA on Render

A free Render web service builds `deploy/render/Dockerfile` from this repo.
The free plan sleeps after 15 minutes idle (the next visit waits about a
minute) and wipes its disk on every restart; the mock ledger is reseeded at
start, so registered passkeys are lost too.

1. Sign in at https://dashboard.render.com with GitHub.
2. **New → Blueprint**, pick this repo. Render reads `render.yaml`.
3. When it asks for `OPENAI_API_KEY`, paste the key, then **Apply**.
4. Open `https://<service>.onrender.com` once the deploy is live.

Each push to `main` redeploys.
