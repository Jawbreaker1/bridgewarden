import unittest

from bridgewarden.e2e import extract_guard_results


class E2EParserTests(unittest.TestCase):
    def test_extracts_guard_result(self) -> None:
        lines = [
            "{\"event\":\"start\"}",
            "{\"tool\":\"bw_read_file\",\"result\":{\"decision\":\"WARN\",\"risk_score\":0.4,"
            "\"reasons\":[\"ROLE_IMPERSONATION\"],\"content_hash\":\"abc\","
            "\"sanitized_text\":\"ok\",\"policy_version\":\"v1\"}}",
        ]
        results = extract_guard_results(lines)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["decision"], "WARN")

    def test_ignores_non_json(self) -> None:
        lines = ["WARNING: something", "{bad json}"]
        results = extract_guard_results(lines)
        self.assertEqual(results, [])
