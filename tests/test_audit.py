import json
import unittest

from bridgewarden.audit import audit_event_to_json, build_audit_event
from bridgewarden.pipeline import guard_text


class AuditLogTests(unittest.TestCase):
    def test_audit_event_schema(self) -> None:
        result = guard_text("hello", source={"kind": "fixture", "path": "demo"})
        event = build_audit_event(result, timestamp="2024-01-01T00:00:00+00:00")
        data = json.loads(audit_event_to_json(event))

        expected_keys = {
            "timestamp",
            "source",
            "content_hash",
            "risk_score",
            "decision",
            "policy_version",
            "cache_hit",
            "reasons",
            "redactions",
            "quarantine_id",
            "approval_id",
        }
        self.assertEqual(set(data.keys()), expected_keys)
        self.assertNotIn("sanitized_text", data)
        self.assertNotIn("original_text", data)
