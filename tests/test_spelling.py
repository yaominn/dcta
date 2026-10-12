"""
Typos in what the user typed are fixed before anything reads it
(backend/spelling.py), so "sned 50 to mom" is a payment and "whats my balence"
is a question. A contact's name is never corrected — a near miss is ASKED
("did you mean Mom?") — and a word with a digit in it is never touched.

Also: answers with several rows carry a table the app draws as a card.
"""
from __future__ import annotations

import contextlib
import io

import pytest
from fastapi.testclient import TestClient

from backend.data.seed import seed
from backend.spelling import closest, correct

BILLERS = ["SP Group", "CityGas", "AAPL", "D05", "O39"]
CONTACTS = ["Mom", "John", "Landlord", "Uncle Bob"]


@pytest.fixture
def client():
    with contextlib.redirect_stdout(io.StringIO()):
        seed()
    from backend.main import _phone, _stopped
    _phone.clear()
    _stopped.clear()
    yield TestClient(__import__("backend.main", fromlist=["app"]).app)
    with contextlib.redirect_stdout(io.StringIO()):
        seed()


def _ask(client, text):
    return client.post("/api/drafts", json={"transcript": text}).json()


def _fix(text):
    return correct(text, names=BILLERS, keep=CONTACTS)[0]


# --------------------------------------------------------------------------- the corrector
@pytest.mark.parametrize("typed, read_as", [
    ("sned 50 to mom", "send 50 to mom"),
    ("whats my balence", "whats my balance"),
    ("who did i pay recnetly", "who did i pay recently"),
    ("tranfer 50 to Mom from savigns", "transfer 50 to Mom from savings"),
    ("send fourty dollars to John", "send forty dollars to John"),
    ("send three hundered to Landlord", "send three hundred to Landlord"),
    ("pay my citygass bill 120", "pay my CityGas bill 120"),
    ("buy 200 dollars of APPL", "buy 200 dollars of AAPL"),
    ("Show my contcats", "Show my contacts"),
    ("its urgnet, the polise said so", "its urgent, the police said so"),
])
def test_typos_are_read_as_the_word_meant(typed, read_as):
    assert _fix(typed) == read_as


@pytest.mark.parametrize("text", [
    "send 50 to Tom",          # one letter from "Tim": a person is never guessed
    "send 50 to Phoebe",       # two from "phone"
    "send 50 to Mon",          # asked about instead (below)
    "add Steev as a contact 9123 4567",
    "there is a tent",         # real words one letter from "three" / "ten"
    "send 50abc to Mom",       # glued to a digit
    "who can i pay",
])
def test_names_real_words_and_digits_are_left_alone(text):
    assert _fix(text) == text


def test_a_tie_is_not_guessed():
    # One letter from both: picking either would be a guess.
    assert correct("cxst", names=["Cast", "Cost"])[0] == "cxst"


def test_closest_suggests_one_contact_or_none():
    assert closest("Mon", CONTACTS) == "Mom"
    assert closest("unlce bob", CONTACTS) == "Uncle Bob"
    assert closest("Steve", CONTACTS) is None
    assert closest("Mom", CONTACTS) is None          # not a typo: the name itself


# --------------------------------------------------------------------------- through the app
def test_a_typo_still_reaches_a_payment(client):
    d = _ask(client, "tranfer fourty dollars to Landlord from savigns")
    assert d["status"] == "ready"
    leg = d["resolved_plan"]["plan"][0]
    assert (leg["payee_display"].split(" ··")[0], leg["amount_cents"], leg["source_account"]) \
        == ("Landlord", 4000, "acct_savings")


def test_a_typo_still_reaches_a_question(client):
    d = _ask(client, "whats my balence")
    assert (d["status"], d["kind"]) == ("info", "answer")


def test_a_misspelled_contact_is_asked_about_never_assumed(client):
    d = _ask(client, "send 50 to Mon")
    assert d["status"] == "clarify"
    assert d["question"].startswith("Mon isn't in your contacts. Did you mean Mom ··")
    assert d["choices"][0]["display"].startswith("Mom ··")
    assert d["new_contact"]["name"] == "Mon"          # adding "Mon" is still offered


def test_two_contacts_with_the_near_name_are_both_offered(client):
    q = _ask(client, "send 50 to Jon")["question"]
    assert q.count("John ··") == 2


# --------------------------------------------------------------------------- tables
def test_recent_payments_come_with_a_table(client):
    d = _ask(client, "who did i pay recently")
    t = d["table"]
    assert [c["label"] for c in t["columns"]] == ["Date", "Paid to", "Amount"]
    assert [c["numeric"] for c in t["columns"]] == [False, False, True]
    assert len(t["rows"]) == len(d["message"].split("\n"))
    assert all(r[2].startswith("$") for r in t["rows"])


def test_balance_table_has_a_total(client):
    t = _ask(client, "how much do I have")["table"]
    assert [r[0] for r in t["rows"]] == ["Savings", "Spending"]
    cents = [int(r[1].strip("$").replace(",", "").replace(".", "")) for r in t["rows"]]
    total = sum(cents)
    assert t["footer"] == ["Total", f"${total // 100:,}.{total % 100:02d}"]


def test_a_one_line_answer_has_no_table(client):
    assert "table" not in _ask(client, "what can you do")


@pytest.mark.parametrize("word", ["gave", "given", "bought", "transferred", "wired", "moved",
                                  "received", "owed", "owe"])
def test_past_money_words_are_left_alone(word):
    """A real word is never "corrected" into another: "the officer gave me"
    became "give me", and "I bought" would become "I buy" (a new payment)."""
    from backend.spelling import correct
    text = f"I {word} mom 50"
    assert correct(text)[0] == text
