"""
Silent spelling correction of what the user typed, before anything reads it:
"sned 50 to mom" is read as "send 50 to mom", "whats my balence" as "whats my
balance". The user's own bubble is never changed.

Deterministic, no model: the routing rules, the stub parser and the scam
phrase scan are all keyword rules, so a typo in a keyword is a request nobody
understands. Fixing it once, up front, lets every later step (route, parse,
scam scan, validator, the transcript hash the signature binds) see the same
corrected words.

What it will NOT do is guess a person. A contact's name is never corrected:
"Tom" is one letter from "Tim", and a silent fix there pays someone else. A
name the user got wrong goes to the resolver, which asks "did you mean?".
Billers and tickers ARE corrected (passed in as `names`): they are a closed
list, so a near miss cannot be a new, real target the user meant instead.
A word with a digit in it (an amount, a phone number) is never touched.
"""
from __future__ import annotations

import re

# The words the rules act on. A typo near one of these is corrected to it.
VOCAB = frozenset("""
send pay transfer give buy purchase move wire remit paid sent bill bills
balance balances money funds account accounts savings spending joint invest
investment investments shares share stock stocks equity
recent recently last history transactions transaction spent statement payments payment
contacts contact payees payee people rename change update number phone mobile
nickname name
remainder rest everything half whatever
every daily weekly monthly yearly quarterly recurring automatic
stopped stop blocked block declined cancelled canceled refused
help please
urgent urgently immediately hurry quickly secret police officer government
safe safety secure holding guaranteed returns crypto bitcoin commission
parcel customs refund delivery dating boyfriend girlfriend online
three seven eight eleven twelve thirteen fourteen fifteen sixteen seventeen
eighteen nineteen twenty thirty forty fifty sixty seventy eighty ninety
hundred thousand dollars cents bucks
""".split())

# Common words that are already right and sit one typo from a VOCAB word
# ("there" / "three", "says" / "pays", "tent" / "ten"). Never corrected.
KNOWN = frozenset("""
gave given bought brought transferred wired wiped moved remitted received receive owed owe owned
about after again all also always and another any anyone are aren around ask
asked back bank because been before being best better between both but bye
call called came can cannot card cash come could day days did didn does doesn
done dont down each else even ever few find first for from get gets getting
going gone good got had has have having hello her here hers him his home how
into isn its just keep kind know last late later least left less let like
little long look looking lost lot made make many may maybe mean meant mine
more most much must myself need never new next nice nothing now off okay old
once one only open other our out over own part past phone place plus put rather
really right said same saw say says see seen self sell sent set should show
side since some soon still such sure take tell than thank thanks that the their
them then there these they thing things think this those though through time
today told too took tree try two under until upon use used very want wanted
wants was way well went were what when where which while who whom whose why
will wish with without won wont work would yes yet you your yours
tent says lays days ways rays bays
sends spend spends paying pays stay stays
mobiles numbers names changes updates helps stops blocks
""".split())

_WORD = re.compile(r"[A-Za-z]+")


def _distance(a: str, b: str, limit: int) -> int:
    """Edit distance with adjacent swaps ("sned" -> "send" is 1), or limit+1
    once it is clearly over the limit."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def _limit(word: str) -> int:
    """How many typos a word of this length may have: none under 4 letters
    (too many real words are one letter apart), 1 up to 7, 2 from 8. Two in a
    shorter word reaches too far: "phoebe" is two from "phone"."""
    return 0 if len(word) < 4 else 1 if len(word) < 8 else 2


def _same_start(a: str, b: str) -> bool:
    """Typos rarely hit the first letter; a swap of the first two counts."""
    return a[0] == b[0] or (len(a) > 1 and len(b) > 1 and a[:2] == b[1::-1])


def _best(word: str, targets: dict[str, str]) -> str | None:
    """The one target within reach of `word`, or None if there is none or the
    nearest are a tie (then it is a guess, and nothing is guessed)."""
    limit = _limit(word)
    if not limit:
        return None
    found: dict[int, set[str]] = {}
    for low, canonical in targets.items():
        if len(low) < 3 or not _same_start(word, low):
            continue
        d = _distance(word, low, limit)
        if d <= limit:
            found.setdefault(d, set()).add(canonical)
    if not found:
        return None
    nearest = found[min(found)]
    return next(iter(nearest)) if len(nearest) == 1 else None


def _cased(original: str, fixed: str) -> str:
    if original.isupper() and len(original) > 1:
        return fixed.upper()
    if original[0].isupper():
        return fixed[0].upper() + fixed[1:]
    return fixed


def correct(text: str, *, names: list[str] = (), keep: list[str] = ()) -> tuple[str, list[tuple[str, str]]]:
    """(corrected text, [(typed, read as), ...]).

    `names`: closed-list names to correct towards, in their own casing (biller
    names, tickers). `keep`: words that are right as typed and must not be
    touched (every word of the user's contacts' names)."""
    name_words = {w.lower(): w for n in names for w in _WORD.findall(n)}
    vocab = {w: w for w in VOCAB}
    leave = KNOWN | VOCAB | set(name_words) | {w.lower() for k in keep for w in _WORD.findall(k)}
    changes: list[tuple[str, str]] = []

    def fix(m: re.Match) -> str:
        typed = m.group(0)
        low = typed.lower()
        if low in leave:
            return typed
        # A name word keeps its own casing ("citygass" -> "CityGas"); a
        # vocabulary word follows the user's.
        hit = _best(low, name_words)
        out = hit if hit else (_cased(typed, w) if (w := _best(low, vocab)) else None)
        if out is None:
            return typed
        changes.append((typed, out))
        return out

    # A token glued to a digit ("50dollars", "ab12") is left whole.
    fixed = re.sub(r"(?<![\w])[A-Za-z]+(?![\w])", fix, text)
    return fixed, changes


def closest(word: str, options: list[str]) -> str | None:
    """The one option `word` looks like a typo of ("Mon" -> "Mom"), for a
    "did you mean?" the user answers: a suggestion, never a silent fix, so a
    3-letter word may be one letter off. None if nothing is close, or two are."""
    low = " ".join(word.lower().split())
    limit = max(1, _limit(low))
    found: dict[int, set[str]] = {}
    for opt in options:
        o = " ".join(opt.lower().split())
        if o == low or not low or not o or not _same_start(low, o):
            continue
        d = _distance(low, o, limit)
        if d <= limit:
            found.setdefault(d, set()).add(opt)
    if not found:
        return None
    nearest = found[min(found)]
    return next(iter(nearest)) if len(nearest) == 1 else None
