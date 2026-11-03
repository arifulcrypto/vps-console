"""Two-language UI. English is the default and the fallback for any missing key."""

from __future__ import annotations

import json
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

LANGS = ("en", "zh")
DEFAULT = "en"
_DIR = Path(__file__).resolve().parent / "locales"


@lru_cache
def catalog(lang: str) -> dict[str, str]:
    return json.loads((_DIR / f"{lang}.json").read_text(encoding="utf-8"))


def translate(lang: str, key: str, **params) -> str:
    text = catalog(lang).get(key) or catalog(DEFAULT).get(key) or key
    if params:
        try:
            text = text.format_map(defaultdict(str, params))
        except (ValueError, IndexError):
            pass
    return text


def pick(lang: str | None) -> str:
    return lang if lang in LANGS else DEFAULT
