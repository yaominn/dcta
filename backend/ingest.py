"""
What the user typed or said, cleaned once before anything reads it.
(brief 6.6, layer 1: normalise, strip invisible characters, cap the length)

  - Unicode NFKC: full-width "ｓｅｎｄ" is "send", so the router, the rules and
    the validator read the same letters the user sees.
  - Invisible characters removed: every format character (zero-width spaces
    and joiners, soft hyphens, the bidi controls that make text display in a
    different order from how it is stored, the "tag" characters that can spell
    out hidden text), plus variation selectors and fillers. "m<zero-width>om"
    was read as an unknown name and frozen with "you didn't say Mom".
  - Control characters become spaces, and runs of whitespace one space.

Length is checked by the caller against MAX_CHARS: a request is a sentence or
two, and anything sent to the model costs money on a public link.
"""
from __future__ import annotations

import re
import unicodedata

MAX_CHARS = 500

# Invisible, beyond the format characters (category Cf, which covers the zero-
# width ones, the bidi controls, U+061C and the tag block U+E0000-E007F): the
# combining grapheme joiner, the Mongolian and Unicode variation selectors, and
# the Hangul fillers. Escapes, never the characters themselves, in this file.
_INVISIBLE = re.compile("[\u034f\u115f\u1160\u180b-\u180f\u3164\ufe00-\ufe0f\uffa0"
                        "\U000e0100-\U000e01ef]")


def clean(text: str | None) -> str:
    """NFKC, invisible characters out, whitespace collapsed. Never raises."""
    text = unicodedata.normalize("NFKC", text or "")
    text = "".join(c for c in text if unicodedata.category(c) != "Cf")
    text = _INVISIBLE.sub("", text)
    text = "".join(" " if unicodedata.category(c) == "Cc" else c for c in text)
    return " ".join(text.split())
