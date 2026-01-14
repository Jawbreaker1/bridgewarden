"""Unicode normalization and suspicious character stripping."""

from dataclasses import dataclass
import unicodedata

BIDI_CHARS = set("\u202A\u202B\u202D\u202E\u202C\u2066\u2067\u2068\u2069")
ZERO_WIDTH_CHARS = set("\u200B\u200C\u200D\u2060\uFEFF")


@dataclass(frozen=True)
class NormalizedText:
    """Normalized text plus unicode risk flag."""

    text: str
    unicode_suspicious: bool


def normalize_text(text: str) -> NormalizedText:
    """Normalize text to NFKC and strip bidi/zero-width characters."""

    normalized = unicodedata.normalize("NFKC", text)
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
    suspicious = False
    cleaned = []
    for ch in normalized:
        if ch in BIDI_CHARS or ch in ZERO_WIDTH_CHARS:
            suspicious = True
            continue
        cleaned.append(ch)
    return NormalizedText(text="".join(cleaned), unicode_suspicious=suspicious)
