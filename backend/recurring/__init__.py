"""
Recurring bill payments, with a supervised start. (docs/RECURRING_BILLS.md)

The rest of DCTA says "drafts, never debits": every payment is one signed
ResolvedPlan, valid for minutes. A recurring bill keeps that for its first
payments and adds ONE new, narrow authority for the rest:

  1. Setup. Rules (parse.py — never the model) read what the user said; the
     user confirms every field in a form; terms.py builds a
     RecurringBillMandate (backend/models/mandates.py) and the user signs it
     with their passkey. Gateway.submit_mandate() stores it, durably, with the
     occurrences it allows.
  2. The first SUPERVISED_APPROVALS payments. When one falls due, scheduler.py
     makes it PENDING_APPROVAL and notifies the user. Nothing is paid: the
     user opens it, approve.py builds an ordinary one-payment draft from the
     mandate, and the user signs THAT with their passkey, through the
     unchanged Gateway.submit(). Only a successful, individually signed
     payment counts towards the three.
  3. After that — and only if the signed mandate says the user chose it —
     Gateway.run_mandate_occurrence() pays each later occurrence on its due
     date with no new prompt, after re-checking the mandate and today's safety
     rules. Anything it cannot clear is HELD or NEEDS_REVIEW, never paid.

store.py is the durable state (SQLite), and the at-most-once guarantee is the
existing `executions` table: every occurrence has its own execution key, claimed
in the same transaction as the debit.

TRUST BOUNDARY (tests/test_import_boundary.py): nothing under backend/recurring/
may import backend/agent/. A recurring payment's terms come from rules and the
user's own confirmations, never from model output.
"""
