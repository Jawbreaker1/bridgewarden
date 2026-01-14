import unittest

from bridgewarden.decision import decide, get_profile


class DecisionTests(unittest.TestCase):
    def test_warn_decision(self) -> None:
        decision, score = decide(["ROLE_IMPERSONATION"], get_profile("balanced"))
        self.assertEqual(decision, "WARN")
        self.assertEqual(score, 0.4)

    def test_block_decision(self) -> None:
        decision, score = decide(["PROCESS_SABOTAGE"], get_profile("balanced"))
        self.assertEqual(decision, "BLOCK")
        self.assertEqual(score, 0.7)

    def test_allow_decision(self) -> None:
        decision, score = decide([], get_profile("balanced"))
        self.assertEqual(decision, "ALLOW")
        self.assertEqual(score, 0.0)

    def test_strict_profile_blocks(self) -> None:
        decision, score = decide(
            ["ROLE_IMPERSONATION", "STEALTH_INSTRUCTION"], get_profile("strict")
        )
        self.assertEqual(decision, "BLOCK")
        self.assertEqual(score, 0.7)
