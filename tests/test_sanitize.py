import unittest

from bridgewarden.sanitize import sanitize_text


class SanitizeTests(unittest.TestCase):
    def test_strips_html_tags(self) -> None:
        text = "<script>alert(1)</script>ok"
        self.assertEqual(sanitize_text(text), "alert(1)ok")
