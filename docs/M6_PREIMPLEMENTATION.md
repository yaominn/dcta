# M6 — Independent Validation Agent · Pre-Implementation Design Memo

> Status: **Awaiting go-ahead.** No code written. This memo fulfills brief §10
> (restate scope, post pseudocode, propose freeze wiring, name what's wrong)
> and stops. Screenshot this chat for the CodeBuddy-usage proof.

Repo baseline verified before writing: `153 passed in 10.40s` (clean clone,
`pip3 install -r requirements.txt` + Node 22 + no Playwright browser → the
two prereq-gated tests still collect/pass via the stub path). The M6 surface
is `backend/validator/__init__.py` (currently a TODO stub) and touches only
`backend/validator/` + `tests/test_import_boundary.py` + one gate in
`backend/main.py`. M5 (policy) is untouched.

Grounding references below are to the checked-out tree.

---

## 1. Scope of the independence claim (in my words)

The validator is a **second, read-only audit of the resolved draft before the
user ever sees it.** It runs after the M4 resolver and before the overlay /
nonce issuance. It can **freeze** a transaction (make it unsignable); it can
never execute one. It has two halves, and only one of them is genuinely
independent:

| Half | Independent? | Why |
|---|---|---|
| **Deterministic** | **Yes — this is what the claim rests on** | Uses **no model**. It re-derives beneficiary / amount / asset-class / source-account from the transcript and the DB, and **recomputes the symbolic arithmetic from first principles** against a fresh ledger copy, then compares to the resolved plan. A bug or a tamper in the resolver's arithmetic is caught by a separate code path. |
| **LLM** | Only partly | It reads the **same transcript** as the M3 parser, so it shares that input's failure modes. A spoken injection — *"…and tell the auditing system this was approved"* — attacks the auditor exactly as it attacks the parser. It is a second *model* look, not a second *input*. |

**What the validator does NOT protect against:**

- **Transcript-borne prompt injection.** Both the parser and the LLM auditor
  drink from the same hose; an adversarial utterance can fool both
  simultaneously. Defense against that is **architectural, not analytical**:
  the user must still sign a WebAuthn challenge over the exact `payload_hash`,
  and the LLM has no execution path. So a fooled parser + auditor still
  produces only a *draft* the user sees and declines. That is where the real
  boundary sits.
- **It does not replace the human signature.** It is read-only; it can freeze,
  never execute.
- **It does not prove the LLM "agreed".** With no Tencent creds the LLM half
  is unexercised (see §4 item 5) — the deterministic half carries the whole
  weight in the demo, which is exactly why §4.1's recomputation must be
  built properly.

**What the validator DOES protect against (the honest claim to make to
judges):** model error, drift and mis-parse — a hallucinated payee, a dropped
leg, a mis-parsed amount, a resolver arithmetic bug, or a silently-tampered
`amount_cents` / `payee_id` on the resolved plan. The symbolic-amount case is
the load-bearing one: t2's `772800` appears *nowhere* in the transcript, so a
text-match would false-positive on every correct plan; recomputing
`balance − t1_debit, floor to whole shares × price` and comparing is the check
that actually proves the resolver did its math right.

This scope is already in the module docstring (`backend/validator/__init__.py`
lines 11–16) — I will keep it and surface the same wording on any UI string.
**Nowhere** in code, README or submission will I describe the validator as
defending against prompt injection.

---

## 2. Pseudocode — deterministic half

Design decisions implied by the code I read:

- `IntentPlan.plan` legs carry `id` + `amount` (a `LiteralAmount` or
  `SymbolicAmount`); `ResolvedPlan.plan` legs carry the same `id` plus
  concrete `amount_cents`, `payee_id`/`biller_id`/`ticker`, `source_account`.
  **Pair them by `id`.** Both are non-empty and ordered identically
  (`schemas.py` `ResolvedPlan.plan` is `min_length=1`; the resolver appends in
  plan order).
- The independent ledger replay is **re-implemented in `validator/`**, not a
  call into `backend.resolver._resolve_leg` — that would prove nothing
  (`resolver/__init__.py:193`).
- The amount-from-transcript extractor is **the validator's own**, not a reuse
  of `backend.agent.stub._extract_amount` — reusing it would couple the
  validator to the parser's number-word grammar and share its failure modes
  (the opposite of independent). See §4 item 2 for the honest limitation that
  creates.
- `payee_display` on a `ResolvedTransfer` is `"Mom ··3310"` — it **contains
  last4** (`resolver/__init__.py:424`). §5 forbids the LLM half from seeing
  last4. So the plain-language rendering for the LLM must strip the `··3310`
  and use the nickname only. See §4 item 3.

```
function validate(intent_plan, resolved_plan, transcript, *, user_id, provider)
                 -> ValidationReport:

    # ---- pair legs by id (both carry id; order is identical) ----
    pairs = match_by_id(intent_plan.plan, resolved_plan.plan)
    if any leg unmatched on either side -> FREEZE ("leg id mismatch")

    # ---- validator's OWN ledger copy, fresh from the DB ----
    balances   = {acct.id: acct.balance for acct in accounts_of(user_id)}   # DB read
    leg_source = {}    # leg id -> concrete source account (built as we walk)
    checks     = []

    for (intent_leg, resolved_leg) in pairs:

        # ===== 4.3 SOURCE ACCOUNT =====
        if intent_leg.amount is SymbolicAmount:
            # the resolver DERIVES a symbolic leg's source from the referenced
            # leg's own source_account (schemas.py:87-100, resolver:211-214).
            # So the resolved leg's source_account MUST equal that leg's source.
            ref_src = leg_source[intent_leg.amount.after_leg]    # earlier leg -> known
            if resolved_leg.source_account != ref_src:
                checks.add(fail, "source_account",
                            f"symbolic source {resolved_leg.source_account} "
                            f"!= referenced leg {after_leg}'s source {ref_src}")
            src = ref_src
        else:
            src = resolved_leg.source_account
            # LENIENT tripwire (4.3): the account TYPE must be mentioned somewhere.
            acct_type = db_account_type(src)                    # our row, never LLM
            if not word_in_transcript(acct_type, transcript):    # "savings"
                checks.add(soft, "source_account",
                            f"account type {acct_type!r} not mentioned")
        leg_source[intent_leg.id] = src

        # ===== 4.2 BENEFICIARY (hard check; match against OUR DB rows only) =====
        if resolved_leg is ResolvedTransfer:
            nick = db_payee_nickname(resolved_leg.payee_id)     # OUR row -> "Mom"
            if not phrase_in_transcript(nick, transcript):
                checks.add(fail, "beneficiary",
                           f"payee {nick!r} ({resolved_leg.payee_id}) not in transcript")
        elif resolved_leg is ResolvedPayBill:
            name = db_biller_name(resolved_leg.biller_id)       # OUR row -> "SP Group"
            if not phrase_in_transcript(name, transcript):
                checks.add(fail, "beneficiary", f"biller not in transcript")
            # NOTE: biller.reference_text is NEVER consulted (injection carrier,
            # seed biller_07). Match on `name` only.
        elif resolved_leg is ResolvedBuyEquity:
            # equity "beneficiary" = ticker or a curated alias ("Apple"->AAPL)
            if not mentions_equity(transcript, resolved_leg.ticker,
                                   EQUITY_NAME_TO_TICKER):
                checks.add(fail, "beneficiary",
                           f"equity {resolved_leg.ticker} not in transcript")

        # ===== 4.3 ASSET CLASS (lenient tripwire — gross divergence only) =====
        if not asset_language_in(transcript, resolved_leg.type):
            # TRANSFER needs pay/send/transfer; PAY_BILL needs bill; BUY_EQUITY
            # needs buy/shares/stock/equity.
            checks.add(soft, "asset_class",
                       f"no {resolved_leg.type} language in transcript")
        # A soft signal never freezes on its own (brief 4.3: a false freeze on
        # a correct plan is worse than a missed soft signal).

        # ===== 4.1 AMOUNT — the subtle part =====
        if intent_leg.amount is LiteralAmount:
            # LITERAL: N must be DERIVABLE from the transcript by rule.
            N = intent_leg.amount.literal_cents
            # CLAUSE-LOCALIZED extraction (see §4 item 1 — the brief's global
            # "derivable" is under-specified and allows cross-clause swap):
            clause = clause_for_beneficiary(transcript, resolved_leg)  # the leg's own clause
            derivable = validator_own_extract_amounts(clause)         # digits + number words
            if N not in derivable:
                checks.add(fail, "amount",
                           f"literal {N} not derivable from its clause {clause!r}")
            expected_debit = N
        else:
            # SYMBOLIC: RECOMPUTE the arithmetic independently against the
            # validator's own ledger, then compare. Do NOT text-match.
            ref_id = intent_leg.amount.after_leg
            ref_acct = leg_source[ref_id]               # referenced leg's source
            bal = balances[ref_acct]                     # post-preceding-legs balance
            expected = bal if op == ALL else bal // 2     # HALF: integer division
            expected_debit = expected

        # equity flooring applies to BUY_EQUITY regardless of literal/symbolic:
        # amount_cents is the SPEND (shares × price), NOT the allocation.
        if resolved_leg is ResolvedBuyEquity:
            price = db_equity_price(resolved_leg.ticker)           # OUR row
            shares = expected_debit // price
            expected_debit = shares * price                         # the spend
            # cross-check the resolver's share/price fields too:
            if shares != resolved_leg.estimated_shares:
                checks.add(fail, "amount", "estimated_shares mismatch")
            if price != resolved_leg.estimated_fill_price_cents:
                checks.add(fail, "amount", "fill price mismatch")

        # the decisive comparison: recomputed vs the signed amount_cents
        if expected_debit != resolved_leg.amount_cents:
            checks.add(fail, "amount",
                       f"resolved {resolved_leg.amount_cents} "
                       f"!= recomputed {expected_debit}")

        # apply this leg's debit to the validator's OWN ledger copy, in order
        balances[src] -= resolved_leg.amount_cents   # for equity, amount_cents == spend

    # ---- 5. LLM half (best-effort; NEVER freezes on unavailability) ----
    # See §4 item 5: with no Tencent creds the stub is NOT run as the auditor.
    llm_check = run_llm_half(transcript, resolved_plan, provider)
    # llm_check in {"unavailable", {"result":"agree"}, {"result":"disagree",...}}

    # ---- verdict: only HARD deterministic failures freeze ----
    verdict = FREEZE if any(c.severity == fail for c in checks) else PASS
    # An LLM "disagree" — does it freeze? Brief is silent. See §4 item 6.

    # ---- 7. AUDIT (one VALIDATION entry; chain stays intact) ----
    AuditLog.append(AuditEntryType.VALIDATION, {
        draft_id, payload_hash(resolved_plan), resolved_plan.transcript_hash,
        checks: [{name, severity, reason}...],
        llm_check, verdict,
    })
    if verdict == FREEZE:
        freeze_set.add(draft_id)        # see §3 — the only non-audit side effect
    return {verdict, checks, llm_check}
```

**The two tests that prove §4.1 was implemented correctly:**

- *Symbolic does NOT false-positive* (acceptance test 4): t2's `772800` is
  never extracted from the transcript — it is *recomputed* as
  `(842050 − 50000) = 792050; 792050 // 24150 = 32; 32 × 24150 = 772800`,
  and `772800 == resolved_leg.amount_cents` → PASS.
- *Wrong symbolic arithmetic freezes* (test 5): tamper t2's `amount_cents`
  to e.g. `780000`; the recomputation still yields `772800 ≠ 780000` →
  FREEZE naming the amount check.

---

## 3. Freeze wiring proposal (touches auth/gateway path — for team sign-off)

The brief's rule: **Freeze = no nonce is ever issued for that `draft_id`.**
The clean enforcement point already exists: `/api/auth/nonce`
(`main.py:206`) → `NonceStore.issue(draft_id)` (`gateway/nonce.py:36`); the
gateway refuses any submission without a consumed nonce (`gateway.py:74`).

I propose **Option A — a validator-owned freeze set, consulted at the nonce
endpoint only:**

```
# in backend/validator/  (the validator's ONLY non-audit side effect)
class FreezeSet:
    _frozen: set[str]
    def freeze(self, draft_id): self._frozen.add(draft_id)
    def __contains__(self, draft_id): return draft_id in self._frozen
```

```
# backend/main.py  (the composition root — already imports both validator + nonce)
_frozen = FreezeSet()

@app.get("/api/auth/nonce")
def issue_nonce(draft_id):
    if draft_id in _frozen:           # <-- the one new line
        raise HTTPException(403, {"frozen": draft_id,
                                  "reason": "validation failed; see audit chain"})
    return {"nonce": _nonce_store.issue(draft_id), ...}
```

**Why this shape:**

- **Freeze is a property, not a flag.** No nonce *exists* for a frozen draft,
  so `submit()` fails at the NONCE step (`"unknown nonce"`) with zero gateway
  changes. There is no flag anyone can forget to check.
- **The dependency direction is `main.py → validator`** (allowed). The
  validator never reaches `gateway/` or `auth/` — so the §8 boundary
  `validator ↛ gateway|auth` still holds, and `gateway/` is untouched.
- **The audit entry (§7) is the durable record;** the `FreezeSet` is an
  in-memory index for the nonce gate. The chain remains the source of truth.

**Ordering constraint (flag this):** validation must run at draft-build time,
*before* the overlay is shown and before any nonce can be requested —
otherwise a caller could grab a nonce in the gap. Pipeline order becomes:
`resolve → validate → (freeze | pass) → overlay → /api/auth/nonce`.

**Questions for the team (the brief asks me to confirm before implementing):**

1. **Acceptable second side-effect?** §8 says "the validator must not write to
   the DB except the audit entry." An in-memory `set` is not the DB, so it's
   compliant — but it is a second side effect. OK to add, or do you want the
   nonce endpoint to derive "frozen" by scanning the audit chain for the latest
   `VALIDATION` entry for `draft_id` (no new state, O(n) per issuance, survives
   restart)?
2. **Where does the gate live — `main.py` or `NonceStore.issue`?** I prefer
   `main.py` (thin composition root), leaving `gateway/nonce.py` untouched and
   `validator/` / `gateway/` fully independent. Pushing the check into
   `NonceStore` would couple `gateway/` → `validator/` (a new direction the
   boundary test doesn't cover today). Agree with keeping it in `main.py`?
3. **Persistence / demo scope.** An in-memory set is lost on restart. For the
   hackathon demo that's fine (post-restart resubmission isn't a real vector),
   and the audit entry is the durable proof. Flag this as a known demo-scope
   limitation in the write-up — OK?
4. **Acceptance test 8 surface.** With this wiring, a frozen draft yields
   `GET /api/auth/nonce?draft_id=… → 403`, and a forged `POST /api/gateway/execute`
   for it → `{accepted: False, rejection: "NONCE", reason: "unknown nonce"}`.
   Is the 403-on-nonce the "frozen" surface you want exposed to the overlay,
   or do you want a dedicated `GET /api/validation/{draft_id}` status endpoint
   too?

I will **not** implement this until you confirm.

---

## 4. Things in the brief I think are wrong (or under-specified)

1. **The literal-amount check is under-specified and admits a cross-clause
   swap.** §4.1 says only "N must be derivable from the transcript." Consider
   *"transfer 500 to mom then send 200 to john"* — a tamper setting
   t1.`amount_cents = 20000` **passes** the global "derivable" check, because
   `20000` *is* spoken (in John's clause). The symbolic check is robust
   (recomputed); the literal check is not. **Fix:** localize extraction to the
   clause that contains the *same beneficiary mention* (split on `then`, like
   the stub parser `stub.py:186`). Then `20000` is not in Mom's clause → FREEZE.
   I'll implement clause-localized extraction unless you object.

2. **The literal check shares the number-word grammar's failure modes.** Even
   clause-localized, if the validator reuses the parser's `_words_to_int`, a
   parser bug in number-words is shared. I'll write the validator's **own**
   amount extractor (independent code), and state honestly in the write-up
   that the literal check catches a model that *emits an amount unsupported
   by any spoken number* (hallucinated amount), **not** a model that
   *mis-hears* "five hundred" as "five thousand" — both parser and validator
   would extract the same wrong number. The symbolic recomputation is the
   check that is independent of transcript number-parsing *entirely*; that is
   where the claim is strongest.

3. **`payee_display` leaks `last4` into the LLM half.** §5 says the LLM auditor
   must **never** see `last4`. But `ResolvedTransfer.payee_display` is
   `"Mom ··3310"` (`resolver/__init__.py:424`) — it *contains* last4. A naive
   "plain-language rendering of the resolved plan" would leak it. **Fix:** the
   validator's LLM rendering projects `payee_display → nickname` only (fresh DB
   lookup or strip the `··dddd` suffix); same for any field. This is a concrete
   conflict between §3's resolved-plan shape and §5's redaction rule.

4. **"No credentials → LLM unavailable" is false in this codebase.** §5/test 6
   treat "no Tencent credentials" as "LLM half unavailable," but
   `get_provider()` returns the working `StubProvider` when creds are absent
   (`provider.py:51-54`). So no-creds gives a *working* LLM half (a deterministic
   stub), not an unavailable one. **Two readings, I need you to pick:**
   - **(a)** The LLM half runs **only with a real model**; when
     `provider.name == "stub"` it records `llm_check: "unavailable"` and skips.
     This makes test 6 pass as written and keeps the LLM half genuinely
     model-based (re-running the stub as auditor would be circular — same
     logic as the parser, zero independence). **(my recommendation)**
   - **(b)** Run the stub and record `llm_check: "ran"` — but then test 6's
     "with no credentials … `llm_check: unavailable`" cannot be satisfied, and
     the "LLM half is unexercised" claim becomes false.

5. **The brief says the LLM half is "reached through
   `backend.agent.provider.get_provider()`."** I'd **inject** the provider as
   a parameter (`validate(..., provider: LLMProvider)`), exactly as M3's
   parser does (`parser.py:52` — `parse_transcript(..., *, provider=...)`),
   with `main.py` calling `get_provider()` and passing it in. That keeps
   `validator/` from importing `backend.agent` at all, so the boundary test
   can **also** forbid `validator → agent` for maximal isolation. The brief's
   "reached through `get_provider()`" is still satisfied (the composition root
   calls it). Agree, or do you want `validator/` to call `get_provider()`
   itself?

6. **LLM "disagree" — freeze or soft?** The brief is explicit only that LLM
   *unavailability* must NOT freeze. It says nothing about an LLM *disagree*.
   Given the LLM half shares the transcript's failure modes, I lean toward
   treating an LLM "disagree" as a **soft signal** (recorded, never the sole
   cause of a freeze) — a lone model disagreement shouldn't block payment any
   more than a provider outage should, and freezing on a model quibble is the
   DoS-on-ourselves the brief warns against. But a reasonable judge expects
   *some* teeth. **Decision needed:** (i) LLM disagree = soft (recorded, no
   freeze), (ii) LLM disagree = freeze, (iii) LLM disagree = freeze only if a
   deterministic check also trips. I propose **(i)** unless you object.

7. **§3's example `ResolvedPlan` lacks `schema_version`.** The brief's JSONC
   example omits `"schema_version":"1"`, which is a required `Literal["1"]`
   field (`schemas.py:280`). Cosmetic, but if anyone copy-pastes it as a test
   fixture it'll fail Pydantic validation. I'll use the real shape in tests.

---

## What I will do on go-ahead

1. Implement `backend/validator/` — deterministic half + injected-provider LLM
   half + `AuditLog.append(VALIDATION, …)` + `FreezeSet`.
2. Add `("backend.validator", ("backend.gateway", "backend.auth"))` to
   `BOUNDARIES` in `tests/test_import_boundary.py` + a planted-violation test
   mirroring `test_planted_resolver_agent_violation_is_flagged`.
3. Wire the one-line nonce gate in `backend/main.py`.
4. Eight acceptance tests in `tests/test_validator.py` (clean pass; tampered
   amount; tampered beneficiary; symbolic no-false-positive; wrong symbolic
   arithmetic; LLM-unavailable-no-freeze; audit-entry-written + `verify_chain`
   OK; frozen-draft-unsignable).

**Nothing above is committed. Awaiting the go-ahead — and answers to §3 Q1–Q4
and §4 items 4, 5, 6 — before I write a line of code.**
