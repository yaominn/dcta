# Handoff: answer tables + silent autocorrect

Status as of 13 Oct 2026. **The code is in, but the test suite has not been
run on it yet.** See [Not done yet](#not-done-yet).

## What changed

### 1. Answers with several rows come back as a table

"who did I pay recently?" and "how much do I have?" now show a table card in
the chat instead of a run of text lines.

- `backend/answers.py`: `reply()` still returns `message` exactly as before
  (it is spoken aloud, and the existing tests check it). It now also returns
  a `table`:
  ```json
  {"title": "Recent payments",
   "columns": [{"label": "Date", "numeric": false},
               {"label": "Paid to", "numeric": false},
               {"label": "Amount", "numeric": true}],
   "rows": [["12 Oct", "John ··8892", "$50.00"]],
   "footer": ["Total", "$4,070.50"]}
  ```
  `footer` is set only for the balances table, and only when there is more
  than one account. Every cell is text the server wrote from the ledger. No
  model text is shown, so the original guarantee still holds.
- `frontend/app.js`: `buildTable()` draws it as a card. An `info` reply with a
  `table` shows the card; without one it shows the text bubble as before.
- `frontend/style.css`: `.data-table` styles. They use only the theme
  variables, so the table works in both light and dark themes.

One-line answers ("what can you do?", "why was that stopped?") have no table.

### 2. Typos are fixed silently before anything reads them

`backend/spelling.py` is new. It is deterministic and calls no model.
`/api/drafts` runs it first (`_autocorrect` in `backend/main.py`), so routing,
the parser, the scam scan, the validator and the transcript hash that the
signature binds all see the same corrected words. The user's chat bubble shows
what they typed.

| Typed | Read as |
|---|---|
| sned 50 to mom | send 50 to mom |
| whats my balence | whats my balance |
| tranfer fourty dollars to Landlord from savigns | transfer forty dollars to Landlord from savings ($40 to Landlord from Savings) |
| pay my citygass bill 120 | pay my CityGas bill 120 |
| buy 200 dollars of APPL | buy 200 dollars of AAPL |
| show my contcats | show my contacts |
| its urgnet, the polise said so | its urgent, the police said so (the scam check now sees it) |

The answer to "what is this payment for?" (`/purpose`) is corrected the same
way, so scam words in it are caught.

**Rules, and why:**

- **Contact names are never corrected silently.** "Tom" is one letter from
  "Tim", so a silent fix could pay the wrong person. If a name is near a
  contact, the app asks instead: *"Mon isn't in your contacts. Did you mean
  Mom ··3310? Or add Mon as a new contact."* If two contacts share the near
  name, both are named ("John ··4521 or John ··8892").
- Biller names and tickers *are* corrected. They are a fixed list, so a near
  miss can't be a real new biller or ticker the user meant instead.
- Words under 4 letters are never corrected. Words of 4 to 7 letters may be 1
  edit off, and words of 8 or more may be 2 off. A swap of two neighbouring
  letters counts as one edit. The first letter must match (or be swapped with
  the second).
- A tie between two words is never guessed. Words containing a digit
  (amounts, phone numbers) are never touched.
- `KNOWN` in `spelling.py` lists common real words that sit near a command
  word ("there"/"three", "tent"/"ten") and are never changed. **If a normal
  word gets "corrected" wrongly, add it to `KNOWN`.** If a typo isn't caught,
  add the intended word to `VOCAB`.
- Each correction is recorded on the trace as an `autocorrect` step (visible
  on `/data`).

## Files

| File | Change |
|---|---|
| `backend/spelling.py` | new: `correct()` and `closest()` |
| `backend/answers.py` | `balance_table()`, `recent_table()`, `table` in `reply()` |
| `backend/main.py` | `_autocorrect()` and `_trace_start()`; correction in `/purpose`; "did you mean?" for a near contact name |
| `frontend/app.js` | `buildTable()` and the table branch in `handleDraft` |
| `frontend/style.css` | `.data-table` |
| `tests/test_spelling.py` | new: corrector, "did you mean?", tables |

## Not done yet

1. **Run the tests.** Neither the suite nor `tests/test_spelling.py` has run on
   these changes. Use `./guard.sh .venv/bin/python -m pytest -q` (tests
   re-seed `dcta.db`; `guard.sh` puts the demo database back afterwards).
2. **`frontend/app.js` was not syntax-checked** (Node isn't installed on the
   machine this was written on). Load the page and ask "who did I pay
   recently?" to confirm the table card draws.
3. A failing test already on main, unrelated to these changes:
   `tests/test_reset_demo.py::test_reset_brings_an_old_ledger_up_to_date_first`
   (SQLite "error in table payees after drop column").
4. With a live model (`LLM_PROVIDER=tokenhub` or `openai`), the model already
   copes with typos. The corrector still helps the keyword rules that run
   before it (routing, scam phrase scan), but it is most useful on `stub`.

## Prompts to try

- `who did i pay recnetly` → recent payments table
- `whats my balence` → balances table with a Total row
- `sned 50 to Mom` → review sheet for $50.00 to Mom
- `send 50 to Mon` → "Did you mean Mom ··3310?"
- `send 50 to Jon` → asks which John
- `send 50 to Steve` → offers to add Steve (no near contact)
