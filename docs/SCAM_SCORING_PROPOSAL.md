# Scam-risk scoring: proposal

> **Status: proposals, not yet built.** The current system is in
> [`SCAM_SCORING.md`](SCAM_SCORING.md) and
> [`SCAM_DECISION_FLOW.md`](SCAM_DECISION_FLOW.md).
>
> **Built since the first version of this proposal:** the two-threshold flow
> (facts, then words), a block on any never rule, the questions picked by the
> riskiest fact, the 60-second wait after signing on a fail, and the score
> remembering earlier attempts (retries, smaller amounts after a stopped
> payment, several stopped attempts, split payments, escalating amounts, the
> freeze turned off, a dormant account, warnings gone past).

The proposals draw on a research summary of how Singapore's banks, SPF and
ScamShield describe scams, plus UK and Australian studies of what stops them.
The ground rules stay: **the AI never scores**, and **signals can only add
friction**.

## Where the current system falls short

| Gap | Example |
|---|---|
| **Warnings are mostly text.** | Warning text alone cut fraud by only 4 points (22% → 18%) in a UK experiment. Easy "stop" buttons cut 12. |
| **Nothing checks who is actually being paid.** | Fake-friend victims pay a stranger's PayNow account. PayNow now shows part of the registered name, but the app never asks about it. |
| **A coached victim with a tidy answer gets through mid-risk payments.** | A first $1,500 payment (facts 5) answered "october rent" passes. The research found coached victims gave a false reason in 42% of UK romance-fraud cases reviewed. |
| **Honest large first payments get heavy friction.** | "pay landlord 3000" for a rent deposit (facts 7) needs a phone code, the name typed, and a wait, whatever the answer. |
| **Cancelling and starting again on another payee resets nothing.** | The outcome of a stopped draft is remembered only as facts for the same payee (or as "several stopped attempts"), not carried over. |
| **The words are English only.** | ScamShield publishes Mandarin and Malay versions of key phrases; the app doesn't know them. |

## Proposals, in order

### 1. Easy ways to stop

On every `WARN` and above, show three buttons above Confirm: **Cancel**, **Save
for later**, and **Call my bank**. Make stopping the easiest action.

**Why:** in the UK experiment, warnings plus easy exits on risky payments took
fraud from 22% to 4%, while ordinary payments completed fell only from 57% to
50%. This is the largest measured effect in the research.

### 2. A check the scammer can't pass: the payee's name

For a first payment, show the masked registered name from PayNow (for example
"J*** T**") and ask: *"Is this the person you mean to pay?"* "No" or "I'm not
sure" adds 4 fact points and shows the fake-friend warning.

**Why:** PayNow nicknames were removed in June 2026 because scammers copied
trusted names. A mismatch between who the user thinks they're paying and the
registered name is one of the clearest signs in fake-friend scams, and unlike a
reason, a coached victim can't make it up.

### 3. Carry the outcome across drafts

A new payment within 24 hours of a stopped one starts at least at the stopped
one's outcome, whoever it's to. Today the history only adds fact points.

**Why:** the published Singapore cases show a second attempt from another
account or branch after a block.

### 4. Shifting stories

Compare the request with the answer. If they name different purposes ("rent",
then "an investment"), add 2 points. Keep every answer the user gives on that
payee for 7 days and compare those too.

**Why:** bank staff in the Singapore cases noticed victims who "provided
inconsistent versions" of why they needed the money.

### 5. A longer wait for real use

**Built:** a fail waits 60 seconds after signing and can be cancelled in that
time. **Proposed:**

- In a real deployment, make the wait **24 hours** for fails with facts 7+,
  with reminders during the wait. Keep 60 seconds for the demo.
- Use the industry "rapid draining" rule as an extra fact: a transfer that,
  with the last 24 hours' withdrawals, moves more than half of a S$50,000+
  balance.

**Why:** Singapore's banks already hold some risky transfers for up to 24
hours. A day breaks a scammer's momentum on the phone; a minute mostly gives
the user a last chance to change their mind.

### 6. Measure it

Build a fixed test set and run it on every change:

- **Scam requests**, written the way victims phrase them, from the patterns in
  published Singapore cases: "for an investigation", "an online friend", "a
  loan to a friend" for an overseas account, a purpose that changes.
- **Ordinary requests that look risky**: a contractor deposit, the first rent
  payment, a real loan to a friend, an urgent hospital bill.

Report two numbers: how many scam requests reach `HOLD` or stricter, and how
many ordinary ones get more than a `WARN`. The research warns that detectors
"over-flag legitimate urgent payments", so the second number matters as much
as the first.

### 7. Better word data

| Source | What it gives | Access |
|---|---|---|
| ScamAlert.sg stories (National Crime Prevention Council) | Victims' own accounts, Singapore-specific | No API: ask the council |
| PreScam (BBB Scam Tracker reports) | 11,573 real scam cases | Ask the authors; license unknown |
| ScamShield bulletins | Mandarin and Malay versions of key phrases ("安全"的银行账户, "akaun bank keselamatan") | Public PDFs |

Use them to check and extend the word lists by hand, not to set weights
automatically.

## Later

| Phase | What | Needs |
|---|---|---|
| Payee data | Payee is a company or crypto exchange; overseas account; a payment-service account (Liquid Pay, YouTrip) | Bank data, or simulated from `payees.legal_name` |
| Behaviour | The account number was pasted, typing unlike the user's own, warnings dismissed too fast, switching to other apps | Browser events and a per-user baseline. Cap: 4 points at most, never a `BLOCK` alone. |
| Device | Screen-sharing or remote control running, a call in progress | A native app |
| Bank-wide | The payee recently received first payments from many unrelated customers (a likely mule account) | Bank data |

## Left out, on purpose

| Idea | Why not |
|---|---|
| Letting the AI judge whether a request "sounds like a scam" | A prompt injection could switch it off, and AI detectors over-flag urgent but honest payments. |
| Negative points for trusted payees | Scammers build trust with small payments first. |
| Age-based rules | Unfair, and 64% of 1H 2026 victims were under 50. |
| Round amounts, spelling mistakes | No evidence either indicates a scam. |
| Trusting "no one told me to do this" | Coached victims deny being coached (in 42% of UK romance-fraud cases reviewed, victims gave a false reason). |
| Voice stress detection | The science is weak, and it would flag anxious but honest users. |
