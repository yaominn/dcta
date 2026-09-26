# Plan: prevent duplicate execution

> WorkPlan item: *"Prevent duplicate execution: the same draft currently executes twice with fresh nonces/signatures."*
> Owner: Person A (authorization / draft states / duplicate protection).
> Written 2026-09-25.

## 1. The problem

A nonce is single-use, but nothing stopped the **draft** from running again.
`/api/auth/nonce` issued a new nonce on every request, and a new signature took one more Touch ID.
Nothing recorded that a draft had already executed.
One $50 draft debited $100.

No attacker is needed. The user approves, the response times out, the button re-enables, and they tap again.

## 2. Status: the core fix is merged (`b99afca`)

The guarantee is **one draft → at most one outcome**, and it is enforced in the ledger, not the UI.

| Layer | What it does | Where |
|---|---|---|
| Ledger (the real guarantee) | `executions` table, `draft_id PRIMARY KEY`. The executor *claims* the draft as the first write of the same transaction as the debit. A second claim fails, and a racing request's debit rolls back. | [executor.py](../backend/gateway/executor.py), [db.py](../backend/data/db.py) |
| Gateway (early answer) | After the signature is verified, `prior_execution()` refuses a repeat as `DUPLICATE` and returns the original result and time. An `AlreadyExecuted` from a lost race maps to the same answer. | [gateway.py](../backend/gateway/gateway.py) |
| One attempt, any outcome | A `FAILED` execution also uses up the draft. `DECLINED`/`CANCELLED` claim the same row, so a decline racing a signature is settled by whichever write lands first. | executor `close()` |
| Nonce endpoint | Returns `409` for an executed or closed draft, so the page never asks for a second fingerprint. | [main.py](../backend/main.py) `issue_nonce` |
| UI | Shows "ALREADY SENT at HH:MM — nothing was sent twice" with the original legs. | [app.js](../frontend/app.js) `showAlreadySent` |
| Persistence | Stored in SQLite, so it survives a restart. `migrate()` adds the table to existing DBs without a re-seed, so passkeys are kept. | `db.py` |

Tests: [tests/test_execute_once.py](../tests/test_execute_once.py) has 12 tests: fresh nonce + signature refused, original result replayed, audited, four racing threads pay once, survives restart, failed attempt is final, no nonce after execution, contact edits run once, and migration.

Verified today: `419 passed, 10 skipped`. The skips are Node-only JS tests, and CI installs Node.

**Recommendation: mark the WorkPlan item done.** What follows is hardening and proof, not the fix itself.

## 3. Remaining work

### 3.1 Close the audit gap after a crash (small, do it)

The executor commits the debit and its `executions` row in one transaction.
The gateway then writes the `EXECUTION` audit entry in a **separate** write.
A crash between the two leaves money moved with no audit entry.
The ledger stays correct, but the audit chain is incomplete.

Options, preferred first:
1. **Reconcile at startup.** For every `executions` row with no matching audit entry, append a `RECOVERED_EXECUTION` entry built from the stored result. This is small and doesn't change the transaction code.
2. Write the audit entry inside the executor's transaction by passing the connection to `AuditLog.append`. It is stronger, but it couples the audit chain's hashing to the executor's transaction.

Test: execute, delete the audit entry (simulating the crash), restart, and assert that the entry is recovered and the chain still verifies.

### 3.2 Give duplicates their own audit type (small, optional)

`DUPLICATE` refusals are currently logged as `AuditEntryType.SIGNATURE` with `rejection: "DUPLICATE"`.
A separate type (or at least a filter in `data.html`) makes "retry attempted, nothing sent twice" easy to show during judging.

### 3.3 Same payment, *different* draft (follow-up, out of scope here)

The guarantee is per `draft_id`.
If the response is lost and the user **says it again** ("send Mom $50"), the pipeline creates a new draft, and that draft can legitimately run.
This is not a bug in this item, but judges may see it as a double payment.

- Add an **advisory** rule: if an identical payee + amount + source executed in the last N minutes, show "You sent $50 to Mom at 14:02, send again?" and require extra confirmation.
- Put it in the policy engine next to the velocity rule. It fits the scam-rules work in the WorkPlan (rapid repeat payments).
- It must not block outright: paying the same bill twice can be intended.

### 3.4 Limit checks race across two drafts (note only)

Policy runs *before* the executor's claim, so two **different** drafts submitted at the same moment can both pass the daily-limit check before either one debits.
Duplicate protection doesn't cause or fix this.
Record it as a known limitation, or move the limit check inside the executor transaction if time allows.

### 3.5 UX after a failed attempt (decide)

A `FAILED` execution (for example, insufficient funds) uses up the draft by design.
Check that the failure screen offers **"Start a new request"** rather than a dead Approve button.
The user decides whether that button prefills the transcript.

## 4. Proof for submission

- [ ] Keep `test_execute_once.py` in CI (it already runs, and the Node/Playwright steps cover the e2e path).
- [ ] Screen-record the double-tap scenario: approve, simulate a lost response, tap again, and "ALREADY SENT", with the balance debited once.
- [ ] Show the audit chain entry for the refused retry.
- [ ] One-line before/after for the write-up: **before $100 debited, after $50 + DUPLICATE**.
- [ ] Tick the item in `WorkPlan.md`.

## 5. Order of work

1. §3.1 audit reconcile with a test (about 1 hour).
2. §4 recording and WorkPlan tick.
3. §3.5 check the failure-screen UX.
4. §3.2 only if there is time.
5. §3.3 alongside the scam-rules work; §3.4 stays documented only.
