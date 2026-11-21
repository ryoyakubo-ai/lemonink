"""Text normalization and detection of hidden or obfuscated characters.

Rules are matched twice: on the raw text and on a normalized form. A rule that
matches only after normalization means the text was obfuscated (for example
with full-width letters or zero-width characters), which raises the severity.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# Characters that render as nothing but can split or hide words.
ZERO_WIDTH = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "⁡": "FUNCTION APPLICATION",
    "⁢": "INVISIBLE TIMES",
    "⁣": "INVISIBLE SEPARATOR",
    "⁤": "INVISIBLE PLUS",
    "﻿": "ZERO WIDTH NO-BREAK SPACE",
    "᠎": "MONGOLIAN VOWEL SEPARATOR",
    "­": "SOFT HYPHEN",
}

# Bidirectional controls can reorder what a human sees.
BIDI = {chr(c) for c in list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A))}

# Unicode "tag" characters (U+E0000..U+E007F) can carry invisible ASCII.
TAG_RANGE = range(0xE0000, 0xE0080)

FULLWIDTH_LATIN = re.compile(r"[！-～]{3,}")
HALFWIDTH_KATAKANA = re.compile(r"[ｦ-ﾟ]{3,}")


@dataclass
class HiddenChars:
    zero_width: list[str]
    bidi: int
    tag_text: str  # ASCII smuggled in tag characters, decoded
    fullwidth_runs: list[str]
    halfwidth_kana_runs: list[str]
    mixed_script_words: list[str]


def strip_invisible(text: str) -> str:
    out = []
    for ch in text:
        if ch in ZERO_WIDTH or ch in BIDI or ord(ch) in TAG_RANGE:
            continue
        out.append(ch)
    return "".join(out)


def decode_tags(text: str) -> str:
    return "".join(chr(ord(ch) - 0xE0000) for ch in text if ord(ch) in TAG_RANGE)


def normalize(text: str) -> str:
    """NFKC (full-width -> ASCII, half-width kana -> full-width), drop invisible
    characters, append any ASCII hidden in tag characters, lower-case."""
    tags = decode_tags(text)
    t = unicodedata.normalize("NFKC", strip_invisible(text))
    if tags:
        t = t + "\n" + tags
    return t.lower()


_LATIN_WORD = re.compile(r"[^\W\d_]{3,}", re.UNICODE)


def _script(ch: str) -> str:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "?"
    return name.split(" ")[0]


def mixed_script_words(text: str) -> list[str]:
    """Words mixing Latin with Cyrillic or Greek letters (homoglyph tricks)."""
    found = []
    for m in _LATIN_WORD.finditer(text):
        scripts = {_script(c) for c in m.group(0)}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
            found.append(m.group(0))
    return found


def find_hidden(text: str) -> HiddenChars:
    return HiddenChars(
        zero_width=sorted({ZERO_WIDTH[c] for c in text if c in ZERO_WIDTH}),
        bidi=sum(1 for c in text if c in BIDI),
        tag_text=decode_tags(text),
        fullwidth_runs=FULLWIDTH_LATIN.findall(text),
        halfwidth_kana_runs=HALFWIDTH_KATAKANA.findall(text),
        mixed_script_words=mixed_script_words(text),
    )
