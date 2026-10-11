# Recurring bill payments, with a supervised start

"Pay SP Group S$85 from savings every month, starting 1 November, for six
months." DCTA sets this up as a **recurring mandate**: terms the user reviews
and signs once with their passkey. The first three payments still need their
own approval. After that, and only if the user chose it, the server pays the
rest on their due dates.

This is the one place in DCTA where money moves without a biometric prompt for
that payment. This document says exactly what authorizes it and what stops it.

> **Prototype, not banking compliance.** This is a mock-ledger demo. Before
> any real-money use, the payment provider and qualified reviewers must
> validate recurring-payment authorization, notifications and dispute handling
> against Singapore requirements, including the MAS E-Payments User Protection
> Guidelines.

## The flow

```
"…every month…"  ──rules (no model)──►  setup form  ──user confirms every field──►
  RecurringBillMandate (terms)  ──passkey──►  Gateway.submit_mandate()  ──►  mandates + occurrences
                                                                               (SQLite, durable)
run_due(now), on each due date:
  payments 1-3   SCHEDULED → PENDING_APPROVAL + notification
                 user opens it → a fresh one-payment draft built from the mandate
                 → passkey → Gateway.submit() (unchanged) → executor
  payment 4+     only if the signed terms say auto_after_supervised AND three
                 individually signed payments succeeded:
                 Gateway.run_mandate_occurrence() → re-check everything → executor
                 → receipt notification. Anything off → HELD / NEEDS_REVIEW, not paid.
```

| Step | Where |
|---|---|
| Recognise recurring wording; ask about a bare "pay my bill" | `backend/agent/router.py` (`recurring_bill`, `bill_ambiguous`) |
| Read biller, account, amount, frequency, start, end — rules only | `backend/recurring/parse.py` |
| Validate the form; build the terms | `backend/recurring/terms.py` |
| The signed payload | `backend/models/mandates.py` (`RecurringBillMandate`) |
| Enrol (signature checks, setup checks, store) | `Gateway.submit_mandate()`, `MockExecutor.create_mandate()` |
| Fall due, expire, complete | `backend/recurring/scheduler.py` (`run_due(now)`) |
| A supervised payment's draft | `backend/recurring/approve.py` |
| The automatic payment | `Gateway.run_mandate_occurrence()` |
| Checks under the write lock, counters, notifications | `backend/recurring/store.py` (`execution_refusal`, `record_execution`) |
| Biller reference versions | `backend/data/billers.py` |

## What the user signs

`RecurringBillMandate`, canonicalised and hashed like every other payload
(`challenge = sha256(payload_hash + nonce)`), binds:

- `mandate_id` (server-issued), `version`, `draft_id`, `user_id`
- the source account, the biller id, the biller reference **version and
  SHA-256** (`biller_ref_version`, `biller_ref_hash`) and its masked form
- `amount_cents` (fixed), `currency` SGD, `per_payment_cap_cents` (= amount),
  `total_cap_cents` (= amount × count)
- `frequency` (WEEKLY / MONTHLY), `start_date`, `end_date` (the last due date),
  `occurrence_count` (≤ 60), `timezone` (IANA; `Asia/Singapore`),
  `due_local_time` (09:00), `short_month_rule`
- `supervised_approvals` (3) and `auto_after_supervised` (the user's choice:
  true, false, or no terms at all)
- `valid_until`: no payment of any kind after the last payment's approval window
- `transcript_hash`, and a ≤ 5-minute **signing** window (`created_at` /
  `expires_at`)

The model refuses terms that contradict themselves, such as caps that don't
match the amount, an end date that isn't the last due date, or a `valid_until`
that doesn't match. Terms like that can't be signed.

`Gateway.submit_mandate()` checks, in order:

1. expiry, nonce, signature
2. not already used
3. exactly the terms the server drafted
4. the passkey belongs to the `user_id` in the terms (an unknown owner fails
   closed)
5. kill switch, KYC, account ownership, current biller version, the
   per-transaction limit, and a first payment that is still in the future

The executor stores the terms (canonical JSON plus their hash) and all their
occurrences in the transaction that claims the enrollment draft. Audit entry:
`MANDATE_CREATED`.

**No model output has payment authority.** Setup never calls the model.
`backend/recurring/` may not import `backend/agent/`, and
`tests/test_import_boundary.py` enforces that.

## Payments 1–3: supervised

When one falls due, `run_due` marks it `PENDING_APPROVAL` and writes a
notification. The notification is stored durably and copied to the demo phone
banner. It is text only and has no link that approves anything. The payment
waits under **Bills**, even if the app was closed. Nothing is paid.

Opening it builds an ordinary `ResolvedPlan` from the mandate: exactly its
biller, account and amount, under the occurrence's own execution key. It runs
the policy engine and the scam rules like any payment, and the user signs it
through the unchanged `Gateway.submit()`. Under the executor's write lock,
`execution_refusal` checks:

- the mandate is ACTIVE and its terms still match their hash
- the plan matches the terms
- the caps hold
- the biller version is the same
- the account owner hasn't changed
- the payment is inside its approval window (due date + 3 days)

A payment that would need more than a signature (a hold, a phone code, the
scam questions) isn't offered from here. The user is told to make it as a
one-time payment instead.

**Only a successful payment the user signed counts towards the three.** None
of these count: the enrollment signature, a declined prompt (final, never
offered again), an expired one (not paid later), or one that failed (for
example, not enough money).

After the third success, `record_execution` switches the mandate to AUTO,
**only if** `auto_after_supervised` is true in the signed terms. It does this
in the same transaction as the debit and tells the user.

## Payment 4+: automatic

`Gateway.run_mandate_occurrence()` is the only unattended debit. Before paying,
it checks:

| Check | If it fails |
|---|---|
| The stored terms re-hash to what was signed | HELD; mandate SUSPENDED |
| Mandate ACTIVE, occurrence SCHEDULED in the AUTO phase | not run |
| AUTO mode, set by the server (never by the browser), and terms that allow it | NEEDS_REVIEW |
| Its due date, local time: from 09:00 to midnight | MISSED (no catch-up) |
| Count and total cap | HELD |
| Biller reference version and hash unchanged | HELD; mandate SUSPENDED |
| The account still belongs to the user | HELD; mandate SUSPENDED |
| KYC verified | HELD |
| Kill switch off | HELD |
| Policy engine (limits, velocity…) | BLOCK → HELD; escalation → NEEDS_REVIEW |
| Scam rules: **any** signal (new passkey, freeze just lifted, stopped attempts) | NEEDS_REVIEW |
| Enough money | FAILED (not retried) |

Before the debit, it appends an audit entry; if the audit log is unavailable,
the payment fails closed. Then the executor claims the occurrence's execution
key, re-checks the mandate under the lock, debits the account, and records the
outcome, counters and receipt notification in that same transaction. Audit
entries: `MANDATE_OCCURRENCE` and then `EXECUTION` with `authority: mandate`.

A HELD or NEEDS_REVIEW payment can still be approved by the user, with their
passkey, within its approval window. A SUSPENDED mandate can't be resumed:
the user has to set up new terms and sign them.

## At most once

Every occurrence has an unguessable execution key (`occ_…`) in the existing
`executions` table, claimed in the same transaction as the debit, whichever
path pays it. Duplicate `run_due` calls, concurrent workers, retries and a
restart after an uncertain result all find the key taken and get the recorded
result back. Scheduler transitions are conditional `UPDATE`s under
`BEGIN IMMEDIATE`. The tests cover six concurrent workers and a pause racing
a payment.

## Pause, resume, cancel, change

- **Pause** takes effect immediately and needs no signature. It takes the
  write lock, so a payment in flight either committed first (and is reported)
  or finds the mandate paused. Payments that fall due while paused are
  SKIPPED; resuming doesn't catch them up.
- **Resume** needs a code sent to the user's phone, like unfreezing.
- **Cancel** is final and needs no signature. Every unpaid occurrence is
  cancelled.
- **Material changes** (amount, biller or reference, account, caps, schedule,
  end date) can't be edited in. They need a new mandate, signed again, and its
  three-approval count starts at zero. A changed biller reference suspends the
  old mandate.

## Dates

- **Weekly:** every 7 days.
- **Monthly:** on the start date's day. A month without that day pays on its
  last day, and the next month goes back to the start day
  (31 Jan → 28 Feb → 31 Mar). See `backend/recurring/schedule.py`.
- **Due time:** 09:00 in the mandate's time zone.
- **Automatic payments** run only on their due date. A run that comes later
  marks them MISSED.
- **Approvals** can be given until the end of the third day after the due
  date. After that the payment is EXPIRED.

## Running it

- **The server:** runs `run_due` every 10 seconds in its background loop.
  `POST /api/recurring/run-due` runs it on demand. It can't be run early,
  because there is no `now` parameter.
- **A worker or cron job:**
  - `python -m backend.recurring run-due` runs once.
  - `python -m backend.recurring loop 30` keeps running.
  - `python -m backend.recurring status` shows the arrangements.

  The worker's gateway can verify no signature, so the only thing it can do
  is mark payments due and run automatic ones.
- **Demo clock:** with `RECURRING_DEMO_CLOCK=1`, the Bills panel shows
  "⏭ Jump to the next due date" (`POST /api/recurring/clock/advance`). This
  moves only the recurring clock. With the flag off, that route returns 404
  and any stored offset is ignored.

**Endpoints:**

- `POST /api/drafts`: recurring wording → `status: recurring_setup`; a bare
  "pay my bill" → a once-or-recurring question
- `POST /api/recurring/setup/{draft_id}`
- `POST /api/recurring/mandates/enroll-webauthn`
- `GET /api/recurring/mandates[/{id}]`
- `GET /api/recurring/pending`
- `POST /api/recurring/occurrences/{mandate_id}/{seq}/review`, then the normal
  nonce + `/api/gateway/execute-webauthn`
- `POST /api/recurring/mandates/{id}/pause`, `/cancel`, `/resume/begin`,
  `/resume`
- `GET /api/recurring/notifications`

## Demo-only limitations

- **Fixed amounts only.** There is no trusted bill feed, so a variable invoice
  can't be paid automatically. A changing amount needs new terms.
- **Weekly or monthly only.** Every 30 days or less, at most 60 payments, at
  most five years.
- **Recurring transfers to people aren't offered.** A bill goes to a registered
  biller; a person's number can change under you.
- **Notifications** are a durable in-app inbox plus the simulated phone. There
  is no real SMS or push.
- **No login.** Like the rest of the demo, routes take a `user_id`. Pause and
  cancel only make things safer; resume needs a phone code.
- **The scheduler** is the server's background loop or the CLI. A deployment
  would run one supervised worker.
