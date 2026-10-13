"""
What the user typed or said, cleaned once before anything reads it.
(brief 6.6, layer 1: normalise, strip invisible characters, cap the length)

  - Unicode NFKC: full-width "ｓｅｎｄ" is "send", so the router, the rules and
    the validator read the same letters the user sees.
  - Invisible characters removed: zero-width spaces, joiners, soft hyphens and
    the bidi controls that make text display in a different order from how it
    is stored. "m<zero-width>om" was read as an unknown name and the draft was
    frozen with "you didn't say Mom".
  - Control characters become spaces, and runs of whitespace one space.

Length is checked by the caller against MAX_CHARS: a request is a sentence or
two, and anything sent to the model costs money on a public link.
"""
from __future__ import annotations

import re
import unicodedata

MAX_CHARS = 500

_INVISIBLE = re.compile("[­᠎​-‏‪-‮⁠-⁤⁦-⁩﻿]")


def clean(text: str | None) -> str:
    """NFKC, invisible characters out, whitespace collapsed. Never raises."""
    text = unicodedata.normalize("NFKC", text or "")
    text = _INVISIBLE.sub("", text)
    text = "".join(" " if unicodedata.category(c) == "Cc" else c for c in text)
    return " ".join(text.split())
