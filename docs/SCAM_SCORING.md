# Scam-risk scoring (current system)

Before a payment can be signed, the server scores it in two thresholds: first
the payment's **facts**, then, if those are risky enough, the user's **words**
(the request and their answer to a question). The result is one of five
outcomes, from no friction to "call the bank".

The scoring is fixed rules over the account's history and the user's words.
The AI model plays no part in it, so a prompt injection can't switch a rule off.
Rules only add friction: nothing in the score approves a payment or removes a
safeguard.

| Doc | What's in it |
|---|---|
| [`SCAM_DECISION_FLOW.md`](SCAM_DECISION_FLOW.md) | **How it decides:** the flow, every fact and its points, the questions, worked examples |
| [`SCAM_WORD_WEIGHTS.md`](SCAM_WORD_WEIGHTS.md) | The 10 word categories and their points |
| [`SCAM_SCORING_PROPOSAL.md`](SCAM_SCORING_PROPOSAL.md) | What to build next |

Code: [`backend/policy/scam.py`](../backend/policy/scam.py), with earlier
attempts in [`backend/policy/attempts.py`](../backend/policy/attempts.py).

## In one minute

1. The AI turns the user's words into a draft payment. That's all it does.
2. **Never rules** (a "safe account", an OTP, "for an investigation"…) in the
   user's words mean **call the bank**, whatever else.
3. **Threshold 1, the facts:** amount, payee, time, account changes and earlier
   attempts.
   - Under the ask line: authorised, no questions. The line is 4; 5 for a
     small payment (under $500, no amount fact); 3 when the request's words
     already look like a scam.
   - 10 or more: call the bank.
   - The ask line to 9.9: the app asks a question picked by the riskiest fact.
4. **Threshold 2, the words** of the request and the answer, in 10 categories:
   - under 2 (and facts under 7): authorised;
   - 2–5.9, or facts 7+: a fail (a 60-second wait after signing);
   - 6+: call the bank.

## What the user sees

| Outcome | When | What the user must do |
|---|---|---|
| `ALLOW` | A pass with nothing to say | Sign with a passkey as normal. |
| `WARN` | A pass with a warning | Read the warning on the card, then sign. |
| `DELAY` | A fail | Sign. The payment then waits **60 seconds** before the money moves, with a **Cancel this payment** button. |
| `HOLD_STEP_UP` | A fail with words 4+ or facts 7+ | A 30-second wait before Confirm, a code sent to the phone (`/phone`), typing the payee's name, then the same 60-second wait after signing. |
| `BLOCK` | A never rule, words 6+, or facts 10+ | Nothing to sign. "If you still need to make it, call your bank on the number on the back of your card", plus the ScamShield Helpline (1799). |

### The question

Asked when the facts are 3 to 9.9, before anything is held or signable. It is
picked by the highest-scoring fact, for example *"Mom's number changed 1 hour
ago. Did you check the new number by calling them on their old one?"*, and
always ends *"Is anyone on a call or chat with you about it right now?"*

- The answer's words are weighed with the request's, in the same 10 categories.
- It can only add points, and it is **never sent to the AI**.
- It's asked once per payment.

### The 60-second wait

After a fail is signed, the money waits 60 seconds. The page counts down with a
Cancel button. Cancelling sends nothing, and freezing payments also stops it.
When the minute is up the server sends it, after checking the freeze and the
spending limits again.

### Earlier attempts

Every scored payment is recorded: who it was for, how much, the outcome, and
whether it was sent or stopped. Later payments use this. Trying the same payee
again after a stopped payment, trying a smaller amount, several stopped
attempts in a day, split payments and growing amounts all add fact points.
The full list is in [`SCAM_DECISION_FLOW.md`](SCAM_DECISION_FLOW.md#earlier-attempts-the-score-remembers).

### Safeguards around the score

- **The hold is enforced by the server, not the page.** When it ends nothing
  happens by itself: the user still confirms and signs. Cancelling needs no
  signature.
- **A draft's outcome never goes down.** If a later answer lowers the score,
  the draft keeps its stricter outcome.
- **The score is checked again at signing and at the gateway.** If the payment
  now needs a hold, a code or a block the user was never shown, or now reaches
  threshold 1 without having been asked, it's refused and the user asks again.

## Trying it

Start the server and open http://localhost:8000 (see below). Mom has been paid
before; the Landlord and Uncle Bob haven't. Savings holds $3,420.50.

These outcomes come from the code, at midday. Between midnight and 5am every
payment gets 1 more fact point.

| Type this | Then answer | Facts | Words | Outcome |
|---|---|---|---|---|
| pay mom 50 now | – | 0 | – | `ALLOW` |
| SEND 50 to mom NOW NOW NOW | – | 0 | – | `ALLOW` |
| pay mom 50, she has a new number | – | 0 | – | `WARN` |
| pay mom 50 into a safe account | – | 0 | ⛔ | `BLOCK` |
| pay mom 50, it's for an investigation | – | 0 | ⛔ | `BLOCK` |
| pay landlord 50 | – | 2 | – | `WARN` |
| pay landlord 1500 | october rent | 5 | 0 | `WARN` |
| pay landlord 1500 | he has a new number | 5 | 2.5 | `DELAY` |
| pay landlord 1500 NOW NOW NOW | october rent | 5 | 2.7 | `DELAY` |
| pay mom 2000 | her share of the bills | 4 | 0 | `WARN` |
| pay mom 2000 | my online friend needs it for a customs fee | 4 | 4.1 | `HOLD_STEP_UP` |
| pay landlord 3000 | rent deposit | 7 | 0 | `HOLD_STEP_UP` |
| pay landlord 3000 | the officer said it's for an investigation | 7 | ⛔ | `BLOCK` |
| pay mom back 200 for the hospital bill | – | 0 | – | `ALLOW` |

**To see the score remember:** type `pay landlord 1500 NOW NOW NOW`, answer, and
cancel during the 60-second wait. Then type `pay landlord 900`: the retry (3) and
the smaller amount (3) push it to `HOLD_STEP_UP`.

Every request's scoring is printed in the browser console (Cmd+Option+J):

```
▼ DCTA scam check: facts 5, words 2.7 → FAIL → DELAY
  (table: every rule and the points it gave)
  word score: pressure 2.73 = 2.73  (adds 2.7 of at most 8)
```

## Running it

```bash
source .venv/bin/activate
uvicorn backend.main:app --reload
```

- Use http://localhost:8000, never `127.0.0.1`, or passkeys break.
- `/phone` shows the simulated phone, where codes arrive.
- `python -m backend.data.reset_demo` resets balances, history and earlier
  attempts, but keeps the passkey. Don't run `backend.data.seed`: it wipes the
  passkey.
- Run the tests with `./guard.sh pytest -q`. It backs up the database first,
  because the tests reset it. In tests the question and the 60-second wait are
  off unless a test turns them on.

## Settings

| Setting (`.env`) | Default | Controls |
|---|---|---|
| `RECENT_CHANGE_HOURS` | 24 | How recent a number change (5 points) or a new contact (3) must be |
| `CREDENTIAL_COOLING_HOURS` | 12 | How recent a new passkey must be to add 4 points |
| `SCAM_HOLD_SECONDS` | 30 | How long the hold before Confirm lasts on `HOLD_STEP_UP` (capped at 4 minutes) |
| `CONSOLE_DEBUG` | on | Print each score and every AI prompt to the browser console. Turn off before a public deploy. |

The thresholds, fact points and limits are in `scam.py`, listed in
[`SCAM_DECISION_FLOW.md`](SCAM_DECISION_FLOW.md#settings); the word settings
in [`SCAM_WORD_WEIGHTS.md`](SCAM_WORD_WEIGHTS.md).

## The audit log

Every score is written to the audit log as a `SCAM_ASSESSMENT` entry: the
facts, the words, the decision, the outcome and each rule's points, but never
the user's words, names or amounts. Points are stored in tenths (4.1 is stored
as 41), because the log's hashing refuses decimal numbers. Earlier attempts
(payees and amounts) are kept in the ledger's `scam_attempts` table, not the
audit log.
