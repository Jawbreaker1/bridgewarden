import unittest

from bridgewarden.normalize import normalize_text


class NormalizeTests(unittest.TestCase):
    def test_normalizes_newlines(self) -> None:
        text = "a\r\nb\rc"
        result = normalize_text(text)
        self.assertEqual(result.text, "a\nb\nc")

    def test_flags_bidi_controls(self) -> None:
        text = "safe \u202e text"
        result = normalize_text(text)
        self.assertTrue(result.unicode_suspicious)
        self.assertEqual(result.text, "safe  text")
