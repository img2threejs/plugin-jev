"""Placement reuses typed Choice/Noul, never arbitrary transform output."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from jev_decision_questions import build_questions, validate_answers, DecisionQuestionError


def context(question):
    values = [[.5, .5, .5], [1, 1, 1]] if question == "size" else list(range(8))
    return {"kind": "img2.build-strategy-context", "version": 1, "group": "build-strategy",
        "subject": {"runId": "run-placement", "objectId": "chair", "revision": 1, "passId": "placement-" + question},
        "bindings": [{"role": role, "sha256": "a" * 64} for role in
                     ("reference", "inventory", "artifact", "size-prior", "camera", "depth", "support")],
        "candidates": [{"id": "option-" + str(index), "value": value} for index, value in enumerate(values)],
        "observations": {"images": [{"role": "reference", "asset": "reference-image"}]},
        "requirements": {"criticalFeatures": [], "requiredViews": [], "placement": {"question": question}},
        "policyVersion": "placement-policy-v1", "questionSetVersion": "strategy-questions-v1", "requestedModel": "jev-1.14.0"}


class PlacementQuestionsTests(unittest.TestCase):
    def test_all_yaw_bins_and_size_options_survive_typed_answer_roundtrip(self):
        for question in ("size", "yaw"):
            original = context(question)
            questions = build_questions(original)
            for candidate in original["candidates"]:
                selected = candidate["id"]
                answer = {"model": "jev-1.14.0", "answers": {
                    "selection": {"type": "choice", "choice": selected, "confidence": 1,
                                  "probabilities": {row["id"]: float(row["id"] == selected) for row in original["candidates"]}},
                    "anyFits": {"type": "noul", "noul": 1}}, "usage": {"input_tokens": 10, "output_tokens": 2}}
                with self.subTest(question=question, selected=selected):
                    validated = validate_answers(original, answer)
                    self.assertEqual(validated["answers"]["selection"]["choice"], selected)
                    self.assertEqual(set(questions["selection"]["criteria"]), {row["id"] for row in original["candidates"]})
                    self.assertEqual(questions["anyFits"]["type"], "noul")

    def test_invalid_yaw_vector_and_missing_evidence_never_form_questions(self):
        bad_yaw = context("yaw")
        bad_yaw["candidates"][0]["value"] = 8
        bad_size = context("size")
        bad_size["candidates"][0]["value"] = [True, 1, 1]
        missing = context("size")
        missing["bindings"] = [row for row in missing["bindings"] if row["role"] != "depth"]
        wrong_group = deepcopy(missing)
        wrong_group["group"] = "repair"
        for value in (bad_yaw, bad_size, missing, wrong_group):
            with self.subTest(value=value), self.assertRaises(DecisionQuestionError):
                build_questions(value)


if __name__ == "__main__":
    unittest.main()
