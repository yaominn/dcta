# Things to note

## Scam-risk scoring: how it works

**File:** `backend/policy/scam.py`. The full rulebook is in `docs/SCAM_SCORING.md`.

### The flow (two thresholds)

1. **The LLM turns your words into a draft.** That's all the LLM does.
2. **Never rules** ("safe account", OTP, "for an investigation"…) in your words
   mean **BLOCK**: nothing to sign, call the bank.
3. **Threshold 1, the facts score:** amount, payee, time, account changes and
   earlier attempts.
   - Under 3: sign as normal.
   - 10+: BLOCK.
   - 3 to 9.9: the app asks a question picked by the riskiest fact.
4. **Threshold 2, the words score:** your request plus your answer, in 10 scam
   categories (strongest 100%, next 80%, 64%…, max 8).
   - Under 2, and facts under 7: sign as normal.
   - 2–5.9, or facts 7+: DELAY, a 60-second wait after you sign, which you can
     cancel. Words 4+ or facts 7+ also need a phone code and a 30-second hold
     first (HOLD_STEP_UP).
   - 6+: BLOCK.
5. **You sign with your passkey.** The score is checked again when you sign
   and right before the money moves.

It never asks the LLM, so a prompt injection can't lower the score. Earlier
attempts are remembered: trying again after a stopped payment, a smaller amount,
split payments and growing amounts all add fact points.

**Example:** a first payment of $1,500 to someone new is 2 + 3 = **5** facts, so
you're asked. "october rent" passes; "he has a new number" (2.5) gets the
60-second wait.

Full details: `docs/SCAM_DECISION_FLOW.md`, `docs/SCAM_SCORING.md` and
`docs/SCAM_WORD_WEIGHTS.md`.

### Seeing it

- Open the browser console (Cmd+Option+J). Each payment prints a table of
  every rule and the points it gave.
- Set `CONSOLE_DEBUG=0` in `.env` before a public demo.

## Running the server

```bash
source .venv/bin/activate
uvicorn backend.main:app --reload
```

- Open http://localhost:8000. Use `localhost`, never `127.0.0.1`, or passkeys
  break.
- `/phone` opens the simulated phone.
- Before a demo, run `python -m backend.data.reset_demo`. It resets the money
  but keeps your passkey.
- Don't run `python -m backend.data.seed` before a demo. It wipes your passkey.
- **Running tests wipes your passkey.** Run them through `./guard.sh pytest -q`
  instead: it backs up the database and restores it afterwards.
