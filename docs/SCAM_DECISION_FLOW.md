# Scam decision flow

How a payment request is decided, in two thresholds:

1. **Threshold 1 scores the payment's facts:** amount, payee, time, account
   changes and earlier attempts. Only if that score is high enough does the app
   ask questions.
2. **Threshold 2 weighs the words** of the request and the user's answers, and
   decides: authorise, delay by a minute, or call the bank.

**Status: built.** Code: [`backend/policy/scam.py`](../backend/policy/scam.py)
(`assess()`, `decide()`), with earlier attempts in
[`backend/policy/attempts.py`](../backend/policy/attempts.py). The word
categories are in [`SCAM_WORD_WEIGHTS.md`](SCAM_WORD_WEIGHTS.md); what the
user sees and how to try it is in [`SCAM_SCORING.md`](SCAM_SCORING.md).

## The flow

```
 User: "pay landlord 3000"
            │
            ▼
 ┌─────────────────────────────────────────────┐
 │ AI turns the words into a draft payment     │
 │ (it never scores anything)                  │
 └─────────────────────────────────────────────┘
            │
            ▼
 ┌─────────────────────────────────────────────┐
 │ ALWAYS-ON CHECK: never rules ⛔              │
 │ safe account, OTP, "for an investigation",  │──── found ───▶ CALL THE BANK
 │ "don't tell the bank", pass money on …      │
 └─────────────────────────────────────────────┘
            │ none
            ▼
 ╔═════════════════════════════════════════════╗
 ║ THRESHOLD 1: FACTS SCORE (no words)         ║
 ║ amount, payee, time, account, earlier       ║
 ║ attempts (tables below)                     ║
 ╚═════════════════════════════════════════════╝
            │
            ├──── facts 0–2.9 ───────────────────────▶ AUTHORISE
            │                                          (a warning may show)
            ├──── facts 10+ ─────────────────────────▶ CALL THE BANK
            │                                          (too risky to ask)
            ▼ facts 3–9.9
 ┌─────────────────────────────────────────────┐
 │ ASK: the question for the highest-scoring   │
 │ fact (two if a different kind ties), plus   │
 │ "Is anyone on a call or chat with you about │
 │ it right now?"                              │
 └─────────────────────────────────────────────┘
            │
            ▼
 ╔═════════════════════════════════════════════╗
 ║ THRESHOLD 2: WORDS SCORE                    ║
 ║ request + answer, in the 10 categories      ║
 ║ (strongest 100%, next 80%, 64%…, max 8)     ║
 ╚═════════════════════════════════════════════╝
            │
     ┌──────┴─────────────────┬────────────────────────┐
     ▼                        ▼                        ▼
 ┌───────────────┐   ┌───────────────────┐   ┌──────────────────────┐
 │ PASS          │   │ FAIL              │   │ FAIL BADLY           │
 │ words < 2     │   │ words 2–5.9, or   │   │ words 6+, or a       │
 │ and facts < 7 │   │ facts 7+          │   │ never rule ⛔ in the  │
 │               │   │                   │   │ answer               │
 │ AUTHORISE     │   │ DELAY             │   │ BLOCK                │
 │ sign, sent at │   │ sign, then a      │   │ nothing to sign;     │
 │ once (WARN if │   │ 60-second wait    │   │ call the bank to     │
 │ there's a     │   │ before it's sent; │   │ make it (1799 if     │
 │ warning)      │   │ can cancel        │   │ someone is pushing)  │
 │               │   │                   │   │                      │
 │               │   │ words 4+ or facts │   │                      │
 │               │   │ 7+: HOLD_STEP_UP  │   │                      │
 │               │   │ — also a 30s hold,│   │                      │
 │               │   │ a phone code and  │   │                      │
 │               │   │ typing the name   │   │                      │
 └───────────────┘   └───────────────────┘   └──────────────────────┘
```

- **Below threshold 1 the words add nothing.** "SEND 50 to mom NOW NOW NOW"
  goes straight through. A fixed warning sentence can still show ("pay mom 50,
  she has a new number" gets the new-number warning, with no other friction).
- **Facts 7+ fail even with a calm answer.** In an account takeover, the person
  typing *is* the scammer and gives a tidy reason. Very risky facts aren't
  undone by words.
- **The score is checked again when signing and at the gateway.** If it has
  risen to a hold, a code or a block, or now reaches threshold 1 when the user
  was never asked (a new passkey since drafting, say), the payment is refused
  and the user asks again.

## Threshold 1: the facts score

Each fact counts once per payment.

### Amount (together at most 5)

| Fact | Points |
|---|---|
| A first payment to this payee of $1,000+ | 3 |
| 80%+ of the account's balance | 3 |
| 50–79% of the account's balance | 2 |
| $5,000 or more | 2 |
| More than 3× the user's largest transfer in 90 days | 2 |
| More than 3× the most ever sent to this payee | 2 |

### Payee

| Fact | Points |
|---|---|
| Never paid this person at this number | 2 |
| Their number changed < 24 h ago (the "Hi Mum, new number" scam) | 5 |
| Contact added < 24 h ago | 3 |
| 3+ new people paid within 30 minutes | 4 |

A changed number (5) plus a first payment to it (2) is 7, so it always fails,
however calm the answer.

### Time and account

| Fact | Points |
|---|---|
| Between midnight and 5am Singapore time | 1 |
| A new passkey added < 12 h ago | 4 |
| The freeze turned off < 24 h ago | 4 |
| No transfers for 90+ days, then one to someone new | 2 |

### Earlier attempts (the score remembers)

Every scored payment is recorded with its outcome and how it ended: sent, or
stopped (blocked, declined, cancelled or frozen). A **stopped attempt** is one
that met friction first: it was asked, delayed, held or blocked.

| Fact | Points |
|---|---|
| A payment to this payee was stopped < 24 h ago | 3 |
| …and this amount is smaller than the stopped one (trying to get under a check) | +3 |
| 2 stopped attempts (to anyone) < 24 h ago | 2 |
| 3 or more | 3 |
| Payments to a payee first paid < 24 h ago, adding up to $1,000+ (split payments) | 3 |
| 3+ payments to one payee in 7 days, each bigger than the last | 2 |
| 2+ warned or delayed payments sent in the last 7 days | 2 |

Example: a $1,500 first payment to the landlord is delayed and the user cancels
it. Then "$900 to the landlord" scores first payment 2 + retry 3 + smaller 3 = 8
facts: a fail with the phone code, whatever the answer.

## The questions

The question for the **highest-scoring fact**, plus a second if a different
kind of fact ties, and always: *"Is anyone on a call or chat with you about it
right now?"* `{…}` is filled in from the payment.

| Highest-scoring fact | Question |
|---|---|
| Number changed | "{name}'s number changed {when}. Did you check the new number by calling them on their old one?" |
| Contact added | "You added {name} {when}. How did you meet them?" |
| Never paid this person | "How do you know {name}, and how did you get their number?" |
| First payment of $1,000+ | "This is your first payment to {name}, and it's {amount}. What is it for?" |
| 50%+ of the balance | "This is {percent}% of your {account} balance. What is it for?" |
| $5,000+, or 3× the usual largest | "This is more than you usually send. What is it for?" |
| More than ever sent to this payee | "This is more than you've ever sent {name}. What's it for this time?" |
| Midnight to 5am | "It's {time}. Is someone asking you to do this right now?" |
| 3+ new payees in 30 minutes | "You've paid {n} new people in the last half hour. Is someone telling you who to pay?" |
| A new passkey | "A new device was added to your account {when}. Was that you?" |
| The freeze turned off | "You turned off your freeze {when}. Did anyone ask you to?" |
| A stopped payment to this payee | "You stopped a payment to {name} {when}. What's changed since then?" |
| Smaller than the stopped one | "This is less than the payment to {name} that was stopped. Has someone asked you to try a smaller amount?" |
| Several stopped attempts | "Several payments were stopped in the last day. Is someone asking you to keep trying?" |
| Split payments | "You've sent {name} {total} today in parts. Has someone asked you to split it?" |
| Escalating amounts | "You've paid {name} {n} times this week, each more than before. Are you being asked to pay more to get money back?" |
| No transfers for 90+ days | "You haven't sent money in a while. What is this payment for?" |

## Worked through

Demo data: Savings holds $3,420.50. Mom has been paid before (most ever $500).
Scores at midday; between midnight and 5am every payment gets 1 more fact point.

| Request | Answer | Facts | Asked | Words | Result |
|---|---|---|---|---|---|
| pay mom 50 now | – | 0 | | – | **ALLOW** |
| SEND 50 to mom NOW NOW NOW | – | 0 | | – | **ALLOW** |
| pay mom 50, she has a new number | – | 0 | | – | **WARN** (warning only) |
| pay mom 50 into a safe account | – | 0 | | ⛔ | **BLOCK** |
| pay landlord 50 | – | 2 | | – | **WARN** |
| pay landlord 1500 | october rent | 5 | yes | 0 | **WARN** |
| pay landlord 1500 | he has a new number | 5 | yes | 2.5 | **DELAY** |
| pay landlord 1500 NOW NOW NOW | october rent | 5 | yes | 2.7 | **DELAY** |
| pay mom 2000 | her share of the bills | 4 | yes | 0 | **WARN** |
| pay mom 2000 | my online friend needs it for a customs fee | 4 | yes | 4.1 | **HOLD_STEP_UP** |
| pay landlord 3000 | rent deposit | 7 | yes | 0 | **HOLD_STEP_UP** (facts 7+) |
| pay landlord 3000 | the officer said it's for an investigation | 7 | yes | ⛔ | **BLOCK** |
| pay mom back 200 for the hospital bill | – | 0 | | – | **ALLOW** |

## Settings

All in [`scam.py`](../backend/policy/scam.py):

| What | Setting |
|---|---|
| The thresholds | `FACTS_ASK_FROM` (3), `FACTS_FAIL_FROM` (7), `FACTS_CALL_BANK_FROM` (10), `WORDS_FAIL_FROM` (2), `WORDS_SERIOUS_FROM` (4), `WORDS_CALL_BANK_FROM` (6) |
| Fact points | `WEIGHTS`, `NEW_CONTACT_POINTS`, `AMOUNT_MAX` (5) |
| Amount limits | `LARGE_FIRST_CENTS` ($1,000), `DRAIN_PERCENT` (80), `LARGE_SHARE_PERCENT` (50), `LARGE_AMOUNT_CENTS` ($5,000), `USUAL_MAX_FACTOR` and `PAYEE_MAX_FACTOR` (3) |
| Time windows | `ATTEMPT_WINDOW_S` (24 h), `WEEK_S`, `FREEZE_RECENT_S`, `DORMANT_S` (90 days) |
| The wait after signing on a fail | `RELEASE_DELAY_SECONDS` (60; 0 turns it off) |
| Asking at all | `ASK_QUESTIONS` (off in tests) |
