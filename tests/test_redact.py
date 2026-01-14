import unittest

from bridgewarden.redact import redact_secrets


class RedactTests(unittest.TestCase):
    def test_redacts_api_keys(self) -> None:
        text = "token sk-1234567890ABCDEF"
        redacted, redactions = redact_secrets(text)
        self.assertEqual(redacted, "token [REDACTED]")
        self.assertEqual(redactions, [{"kind": "API_KEY", "count": 1}])
