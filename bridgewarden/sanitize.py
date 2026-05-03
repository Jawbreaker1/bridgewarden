"""HTML/markdown sanitization helpers."""

import re

_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_TAG_RE = re.compile(r"</?[A-Za-z][A-Za-z0-9:-]*(?:\s[^<>]*)?\s*/?>")


def sanitize_text(text: str) -> str:
    """Strip basic HTML tags from input text."""

    without_comments = _COMMENT_RE.sub("", text)
    return _TAG_RE.sub("", without_comments)
