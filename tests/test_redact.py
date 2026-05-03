import unittest

from bridgewarden.redact import redact_secrets


class RedactTests(unittest.TestCase):
    def test_redacts_api_keys(self) -> None:
        text = "token sk-1234567890ABCDEF"
        redacted, redactions = redact_secrets(text)
        self.assertEqual(redacted, "token [REDACTED]")
        self.assertEqual(redactions, [{"kind": "API_KEY", "count": 1}])

    def test_redacts_private_key_blocks(self) -> None:
        text = (
            "before\n"
            "-----BEGIN TEST PRIVATE KEY-----\n"
            "placeholder-key-material\n"
            "-----END TEST PRIVATE KEY-----\n"
            "after"
        )
        redacted, redactions = redact_secrets(text)
        self.assertEqual(redacted, "before\n[REDACTED]\nafter")
        self.assertEqual(redactions, [{"kind": "PRIVATE_KEY", "count": 1}])

    def test_redacts_unterminated_private_key_blocks(self) -> None:
        text = "before\n-----BEGIN TEST PRIVATE KEY-----\nplaceholder-key-material"
        redacted, redactions = redact_secrets(text)
        self.assertEqual(redacted, "before\n[REDACTED]")
        self.assertEqual(redactions, [{"kind": "PRIVATE_KEY", "count": 1}])
