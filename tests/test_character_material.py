"""Owned offline fixtures for the character material admission boundary."""
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from jev_decision_questions import DecisionQuestionError, build_questions
from test_decision_questions import make_context


class CharacterMaterialAdmissionTests(unittest.TestCase):
    def test_native_character_requires_material_provenance(self):
        for deterministic in ({}, {"sweep": {"materialCapture": "original-material-fixed-lighting-v1"}}):
            context = make_context("quality-review")
            context["subject"]["passId"] = "character-terminal-review"
            context["observations"]["nativeEvidence"] = {
                "provider": "character", "deterministic": deterministic}
            with self.subTest(deterministic=deterministic), self.assertRaises(DecisionQuestionError):
                build_questions(context)


if __name__ == "__main__":
    unittest.main()
