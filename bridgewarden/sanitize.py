"""HTML/markdown sanitization helpers."""

import re

_TAG_RE = re.compile(r"<[^>]+>")


def sanitize_text(text: str) -> str:
    """Strip basic HTML tags from input text."""

    return _TAG_RE.sub("", text)
