"""
H1 — the trusted overlay must not have an XSS sink.

`showResult()` renders the gateway's response on the confirmation overlay — the
ONE surface the client-integrity argument ("what you see is what you sign")
presumes renders faithfully. The rejection reason reaches it from the executor
(e.g. `unknown account <…>`), and `source_account` is LLM-supplied, so a markup
string can ride into that reason. The fix is the textContent-only rule the rest
of the file already follows; this test pins that the sink renders markup as
literal characters, never as a parsed element.

We drive the REAL showResult (loaded from the real app.js on the real server)
with the exact payload shape a rejection produces, then assert:
  1. the markup string is present in the DOM as text, and
  2. zero <img> elements exist inside #result (it was not parsed as HTML), and
  3. no element carries an inline event-handler attribute (onerror/etc).

Before the fix this test fails at (2): innerHTML + JSON.stringify (which escapes
quotes but not </>) parsed `<img src=x onerror=alert(1)>` into a real <img>
whose onerror fired on the overlay's origin.
"""
from __future__ import annotations

import pytest

pytest.importorskip("playwright")
from playwright.sync_api import sync_playwright  # noqa: E402

# A rejection whose reason carries markup, exactly as a failed executor would
# emit it for an LLM-supplied source_account like '<img src=x onerror=alert(1)>'.
_MARKUP = "<img src=x onerror=alert(1)>"


def test_rejection_reason_with_markup_is_text_not_an_element(server_url):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(server_url + "/")
            # #result is in the static HTML; app.js is a classic script so
            # top-level showResult is global on window. Drive the real sink.
            page.wait_for_selector("#result", state="attached", timeout=10000)
            page.evaluate(
                "([m]) => showResult({status: 200, json: {"
                "accepted: false, rejection: 'unknown account ' + m, nonce: 'n1'}})",
                [_MARKUP],
            )

            # 1. the markup string is in the DOM as literal text.
            body_text = page.inner_text("#result")
            assert _MARKUP in body_text, (
                f"markup must appear as literal text in #result; got: {body_text!r}"
            )

            # 2. zero <img> elements parsed inside #result (the sink used
            #    textContent, not innerHTML -> tags stay characters).
            img_count = page.eval_on_selector_all(
                "#result img", "els => els.length",
            )
            assert img_count == 0, (
                f"markup was parsed as HTML: {img_count} <img> in #result (XSS)"
            )

            # 3. no inline event handler attribute survived anywhere in #result
            #    (onerror/onload/onclick would mean a tag was parsed as HTML).
            has_handler = page.evaluate(
                "() => !!document.querySelector('#result *[onerror],"
                " #result *[onload], #result *[onclick], #result *[onmouseover]')"
            )
            assert not has_handler, (
                "an inline event-handler attribute exists in #result (XSS)"
            )

            # 4. the box is visible and marked bad (a normal rejected render).
            assert page.get_attribute("#result", "hidden") is None, (
                "#result should be un-hidden after showResult"
            )
            cls = page.get_attribute("#result", "class") or ""
            assert "bad" in cls, f"#result class should mark rejection 'bad': {cls!r}"
        finally:
            browser.close()
