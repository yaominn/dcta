# DCTA on Render (free Docker web service). render.yaml at the repo root points
# here, with the repo root as the build context.
FROM python:3.12-slim

RUN useradd -m -u 1000 user
WORKDIR /app

COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=user backend backend
COPY --chown=user frontend frontend

USER user

# OPENAI_API_KEY is set in the Render dashboard (render.yaml asks for it on
# first deploy). MOCK_SIGNING stays unset.
ENV LLM_PROVIDER=openai \
    OPENAI_MODEL=gpt-4.1-mini \
    ASR_PROVIDER=openai

# The free plan's disk is wiped on every restart and deploy, so the mock ledger
# is seeded at start. Render sets PORT and RENDER_EXTERNAL_HOSTNAME (e.g.
# dcta.onrender.com); a passkey only works on the domain it was made on. One
# worker: drafts and nonces live in this process's memory.
CMD ["sh", "-c", "export WEBAUTHN_RP_ID=\"${WEBAUTHN_RP_ID:-$RENDER_EXTERNAL_HOSTNAME}\" WEBAUTHN_EXPECTED_ORIGIN=\"${WEBAUTHN_EXPECTED_ORIGIN:-https://$RENDER_EXTERNAL_HOSTNAME}\" && python -m backend.data.seed && exec uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-10000} --workers 1 --proxy-headers --forwarded-allow-ips='*'"]
