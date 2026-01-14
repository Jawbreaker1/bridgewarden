import json
from pathlib import Path
import unittest

from bridgewarden.pipeline import guard_text

FIXTURES_DIR = Path("test-corpus/fixtures")


def _load_expected(fixture: Path) -> dict:
    expected_path = fixture.with_name(fixture.name + ".expected.json")
    if expected_path.exists():
        return json.loads(expected_path.read_text(encoding="utf-8"))

    name = fixture.name.lower()
    if "_allow_" in name:
        decision = "ALLOW"
    elif "_warn_" in name:
        decision = "WARN"
    elif "_block_" in name:
        decision = "BLOCK"
    else:
        decision = "ALLOW"
    return {"expected_decision": decision, "expected_reasons": []}


class CorpusRunnerTests(unittest.TestCase):
    def test_fixtures_match_expectations(self) -> None:
        fixtures = [path for path in sorted(FIXTURES_DIR.iterdir()) if path.is_file()]
        fixture_files = [path for path in fixtures if not path.name.endswith(".expected.json")]
        self.assertTrue(fixture_files, "No fixtures found under test-corpus/fixtures")

        for fixture in fixture_files:
            with self.subTest(fixture=fixture.name):
                expected = _load_expected(fixture)
                content = fixture.read_text(encoding="utf-8")
                result = guard_text(content, source={"kind": "fixture", "path": str(fixture)})

                self.assertEqual(result.decision, expected["expected_decision"])
                self.assertTrue(
                    set(expected.get("expected_reasons", [])).issubset(result.reasons)
                )
                if "expected_risk_score" in expected:
                    self.assertAlmostEqual(
                        result.risk_score, expected["expected_risk_score"], places=2
                    )
                if result.decision == "BLOCK":
                    self.assertEqual(result.sanitized_text, "")
                else:
                    self.assertNotEqual(result.sanitized_text, "")
