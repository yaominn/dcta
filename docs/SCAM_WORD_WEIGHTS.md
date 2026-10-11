# Scam word weights

How the user's own words are scored: 10 scam categories, the words in each,
their points, and how they combine. The words come from how Singapore's banks,
the Singapore Police Force (SPF) and ScamShield describe scams.

The words are read from the payment request and from the user's answer to the
question the app asks. They are **threshold 2**: they're only weighed once the
payment's facts score 3 or more (threshold 1, see
[`SCAM_DECISION_FLOW.md`](SCAM_DECISION_FLOW.md)). Below that, a fixed warning
sentence can show, but the words add no friction. The never rules below are the
exception: they always count. The scoring is fixed rules: the AI never scores
anything and never sees the answer.

## The formula

1. **Each category scores its strongest match.** Several phrases in one
   category count once.
2. **Sort the categories that matched, strongest first.**
3. **Weigh them 100%, 80%, 64%, 51%…** Each one counts 0.8× the one before.
4. **Add them up, capped at 8.** Scores are rounded to one decimal place.

```
words = min(8,  c1 + 0.8·c2 + 0.64·c3 + 0.512·c4 + …)     c1 ≥ c2 ≥ c3 …
```

| Example | Categories | Points |
|---|---|---|
| "my son has a new number" | contact 2.5 | 2.5 |
| "guaranteed returns, he has a new number" | investment 2.5, contact 2.5 × 0.8 | 4.5 |
| "move it to a safe account, don't tell anyone" | safe account 4, secrecy 3 × 0.8 | 6.4 |
| "the police told me to move it to a safe account, don't tell anyone" | 4 + 4 × 0.8 + 3 × 0.64 = 9.1 | **8** (cap) |

## Never rules ⛔

Some phrases describe something no real bank, police officer or government
agency ever asks for. **If any one appears, in the request or the answer, the
payment is blocked (`BLOCK`) whatever the facts**: nothing to sign, a warning
naming the rule, and the user is told to call their bank, plus the ScamShield
Helpline (1799). No question is asked.

## The 10 categories

| # | Category | Points | ⛔ | Words that match (capitals don't matter) |
|---|---|---|---|---|
| 1 | **An official or the bank directing it** | 4 | ⛔ | An official (police, officer, MAS officer/staff, CPF board/officer, IRAS, ICA officer, Interpol, government, ministry, bank staff/officer, investigator, inspector, caller) + an instruction (said, told, asked, ordered, wants, needs) + a money word (pay, transfer, send, move, withdraw) in one sentence. Also: "for an investigation / investigation purposes / their investigation" (not "for the investigations": medical tests), "assist (with) the investigation", "under investigation", "my account is being investigated", "money laundering" (not "anti-money laundering"), "prove my innocence / I am innocent", "financial inspection", "call was transferred to the police / MAS / officer", "they transferred my call to the police / SPF", "I was transferred to a police officer" |
| | …the bank directing a transfer | 4 | | The bank as the one speaking: "the bank called me. They told me to transfer my savings…", "DBS said I must move my money…", "the bank told me my account was hacked and I must transfer…", "I was told to transfer it by the bank". Not a never rule (banks do sometimes ask you to move money, e.g. to a new account of your own), and not "pay jess 50 to her UOB" or "pay my card bill" |
| 2 | **Safe account** | 4 | ⛔ | "safe / safety / secure / holding / protected / verification account", "protect my money / savings / funds", "for safekeeping", "keep my money safe" |
| 3 | **Codes, apps and screen-sharing** | 4 | ⛔ | "OTP", "one-time password / PIN / code", "my PIN / password / login", "token approval", "approve the digital token", "AnyDesk", "TeamViewer", "screen share", "remote access", "remote-control app" (not "the aircon remote control"), "install an / the / this / their app", "the app from the link", "gave him the 6-digit code", "APK", "Play Protect" |
| 4 | **Secrecy** | 3 | | "don't / do not / never tell", "keep it secret", "between you and me", "nobody must know", "NDA", "non-disclosure" |
| | …from the bank | 4 | ⛔ | "don't tell the bank", "the bank is in on it", "keep it from the bank", "lie to the bank" |
| 5 | **Receiving money to pass on** | 3 | ⛔ | "receive the money and send / forward it", "forward the money", "use my account to receive", "rent / sell / lend my account", "pass it on" |
| 6 | **Investment** | 2.5 | | "guaranteed", "high / fixed / daily returns", "crypto", "bitcoin", "USDT", "trading platform", "double my money", "withdrawal fee", "tax to withdraw", "release my profits", "pay … to withdraw my money / funds", "pay … to unfreeze my account", "trading signals", "investment group / lessons / community" |
| 7 | **A job that makes you pay first** | 2.5 | | "part-time job", "task fee", "top up to earn", "unlock / release / withdraw my commission", "unlock my tasks", "upgrade my account", "rectify a mistake", "activation fee", "training fee" |
| 8 | **A new number, or someone met online** | 2.5 | | "new number", "changed his number", "lost my phone", "phone is broken", "guess who" (not "guess who won"), "online friend / boyfriend / girlfriend", "met her online", "we met on tinder / through wechat", "never met him", "haven't met him in person", "boyfriend overseas", "proof of my love", "dating app" |
| 9 | **A fee before you receive something** | 2 | | "processing / admin / release / clearance / handling fee", "customs fee / charge / duty", "re-delivery fee", "loan approval / activation", "claim my prize", "won a prize / the lottery / a lucky draw", "recover my money / losses", "fund recovery", paying "so they can release my loan" or "to get the loan", "upfront fee" |
| | …a parcel or refund alone | 0.5 | | "parcel", "customs", "delivery fee", "refund", "tax rebate" |
| 10 | **Being rushed, or directed live** | up to 3 | | See below |
| + | **Wording aimed at the app** | 2 | | "ignore previous instructions", "disregard previous", "system prompt", "you are now" |

Category 10 adds up word by word, up to 3:

| What | Points |
|---|---|
| Each urgency word: now, urgent, urgently, immediately, asap, hurry, quick, quickly, right away, as soon as possible, before it's too late | 0.75 |
| Each repeat of the same word | 0.75× the one before (so "hurry now hurry" 2.1 > "hurry hurry" 1.3) |
| An urgency word in CAPITALS (not ASAP) | +1 |
| `!!` | +0.5 |
| Someone directing live: "don't hang up", "they told me not to hang up", "he's still on the line", "the officer is on the line", "they're waiting for me", "told me what to say", a stranger on the call directing the payment ("the man on the phone said pay…", "There is a man on the phone. He said to pay…") | +2 |

A **"rushed"** warning appears once this category reaches 2.

## Not used, on purpose

| Idea | Why not |
|---|---|
| Round amounts | No source links them to scams. One study found scammers asking for odd amounts. |
| Spelling or grammar | Scam messages are now often well written, so good writing proves nothing. |
| "commission" alone (for payments) | Paying an agent's commission is routine. Only the job-scam forms count. |
| Weights learned from data | The only open dataset tried (AI-generated scammer calls) gave ordinary words like "need" and "account" top weight. |

## Changing the weights

| To change | Edit |
|---|---|
| A category's points, or which phrases are in it | `CATEGORIES` in [`scam.py`](../backend/policy/scam.py) |
| Which phrases are never rules | `NEVER_RULES` in `scam.py` |
| The 0.8 factor, or the cap of 8 | `CATEGORY_FACTOR`, `WORDS_MAX` |
| Urgency points | `URGENT_WORD_POINTS`, `REPEAT_FACTOR`, `CAPITALS_POINTS`, `EXCLAIM_POINTS`, `PRESSURE_MAX` |
| The words a phrase matches | `_WORDS` in [`new_contact.py`](../backend/policy/new_contact.py) (shared with adding a contact); for payments, `_PAYMENT_RULES` in `scam.py` (official orders, job, app wording) |

Add a test in [`tests/test_scam_protection.py`](../tests/test_scam_protection.py)
for each change, with a scam phrasing and an innocent one.
