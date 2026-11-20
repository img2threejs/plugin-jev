"""Offline consumer tests of the public question/answer boundary."""

import copy
import math
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from jev_decision_questions import (
    AXES, MODEL, QUESTION_SET_VERSIONS, SCORE_LEVELS, DecisionQuestionError,
    build_questions, validate_answers,
)


def make_context(group="routing"):
    kinds = {"routing": "img2.route-context", "build-strategy": "img2.build-strategy-context",
             "quality-review": "img2.quality-review-context", "repair": "img2.repair-context"}
    return {
        "kind": kinds[group], "version": 1, "group": group,
        "subject": {"runId": "run-1", "objectId": "cup", "revision": 2, "passId": "geometry"},
        "bindings": [{"role": "reference", "path": "private/reference.png", "sha256": "a" * 64},
                     {"role": "render", "path": "private/render.png", "sha256": "b" * 64}],
        "candidates": [{"id": "lathed", "operations": ["lathe", "sweep"],
                        "componentIds": ["body", "handle"], "outputKind": "3d-object"},
                       {"id": "continuous", "representation": "continuous-mesh"}],
        "observations": {"availableViews": [0, 90, 180, 270], "images": [
            {"role": "reference", "asset": "image-reference-opaque"},
            {"role": "render", "asset": "image-render-opaque"}],
            "measurements": {"selfIntersectionCount": 0}},
        "requirements": {"criticalFeatures": [{"id": "handle", "label": "handle", "threshold": 3}],
                         "requiredViews": [0, 180]},
        "policyVersion": "quality-v1", "questionSetVersion": QUESTION_SET_VERSIONS[group],
        "requestedModel": MODEL,
    }


def response_for(context):
    answers = {}
    for key, question in build_questions(context).items():
        kind = question["type"]
        if kind == "choice":
            choice = next(iter(question["criteria"]))
            answers[key] = {"type": kind, "choice": choice,
                            "probabilities": {option: float(option == choice) for option in question["criteria"]},
                            "confidence": 0.9}
        elif kind == "score":
            answers[key] = {"type": kind, "score": 3.0, "confidence": 0.65,
                            "legend": {str(i): level for i, level in enumerate(question["criteria"])},
                            "probabilities": {str(i): float(i == 3) for i in range(5)}}
        elif kind == "noul":
            answers[key] = {"type": kind, "noul": 0.95}
        else:
            answers[key] = {"type": kind, "box": {"left": 0.1, "top": 0.2, "right": 0.8, "bottom": 0.9},
                            "confidence": 0.8}
    return {"model": MODEL, "answers": answers, "usage": {"input_tokens": 123, "output_tokens": 45}}


class DecisionQuestionsTest(unittest.TestCase):
    def test_all_groups_are_usable_actual_typesafe_questions(self):
        expected = {"routing": "route-questions-v1", "build-strategy": "strategy-questions-v1",
                    "quality-review": "quality-review-questions-v1", "repair": "repair-decision-questions-v1"}
        self.assertEqual(QUESTION_SET_VERSIONS, expected)
        for group in expected:
            with self.subTest(group=group):
                context = make_context(group)
                original = copy.deepcopy(context)
                questions = build_questions(context)
                self.assertTrue(questions)
                self.assertTrue(all(question["type"] in {"choice", "noul", "score", "box"}
                                    and "instructions" in question for question in questions.values()))
                self.assertEqual(context, original)
                response = response_for(context)
                self.assertEqual(validate_answers(context, response), response)

    def test_options_are_exactly_controller_candidates_and_have_companion_noul(self):
        for group in ("routing", "build-strategy", "repair"):
            context = make_context(group)
            questions = build_questions(context)
            self.assertEqual(set(questions), {"selection", "anyFits"})
            self.assertEqual(set(questions["selection"]["criteria"]), {"lathed", "continuous"})
            self.assertEqual(questions["anyFits"]["type"], "noul")
            context["candidates"] = [{"id": "only-eligible"}]
            self.assertEqual(set(build_questions(context)["selection"]["criteria"]), {"only-eligible"})

    def test_valid_uncertainty_and_none_fit_are_not_transport_failures(self):
        context = make_context("repair")
        response = response_for(context)
        response["answers"]["selection"].update(
            choice="lathed", probabilities={"lathed": 0.5, "continuous": 0.5}, confidence=0.0)
        response["answers"]["anyFits"]["noul"] = 0.1
        self.assertEqual(validate_answers(context, response), response)

    def test_review_has_atomic_anchored_scores_and_each_critical_choice(self):
        context = make_context("quality-review")
        context["requirements"]["criticalFeatures"].append({"id": "face", "threshold": 3})
        questions = build_questions(context)
        self.assertEqual(set(questions), {"dimension:" + axis for axis in AXES[:5]} |
                         {"critical:handle", "critical:face"})
        for axis in AXES[:5]:
            self.assertEqual(questions["dimension:" + axis]["criteria"], list(SCORE_LEVELS))
        self.assertEqual(set(questions["critical:handle"]["criteria"]), {"pass", "fail", "uncertain"})
        self.assertNotIn("dimension:rig", questions)
        context["requirements"]["dimensions"] = ["rig", {"id": "placement"}]
        self.assertEqual({key for key in build_questions(context) if key.startswith("dimension:")},
                         {"dimension:rig", "dimension:placement"})

    def test_high_score_never_clears_uncertain_or_failed_feature(self):
        context = make_context("quality-review")
        response = response_for(context)
        for answer in response["answers"].values():
            if answer["type"] == "score":
                answer.update(score=4.0, confidence=0.0,
                              probabilities={str(i): float(i == 4) for i in range(5)})
        for choice in ("fail", "uncertain"):
            feature = response["answers"]["critical:handle"]
            feature.update(choice=choice, probabilities={option: float(option == choice)
                                                        for option in ("pass", "fail", "uncertain")})
            validated = validate_answers(context, response)
            self.assertEqual(validated["answers"]["critical:handle"]["choice"], choice)
            self.assertEqual(validated["answers"]["dimension:geometry"]["score"], 4.0)
            self.assertNotIn("acceptance", validated)

    def test_missing_per_item_evidence_is_unevaluated_not_fabricated(self):
        context = make_context("quality-review")
        context["requirements"]["dimensions"] = ["geometry", {"id": "material-appearance", "evidenceRoles": ["texture"]}]
        context["requirements"]["criticalFeatures"][0]["requiredViews"] = [45]
        response = response_for(context)
        self.assertEqual(set(response["answers"]), {"dimension:geometry"})
        validated = validate_answers(context, response)
        self.assertEqual(validated["answers"]["dimension:material-appearance"], {"type": "unevaluated"})
        self.assertEqual(validated["answers"]["critical:handle"], {"type": "unevaluated"})
        self.assertNotIn("critical:handle", response["answers"])
        forged = copy.deepcopy(response)
        forged["answers"]["critical:handle"] = {"type": "unevaluated"}
        with self.assertRaises(DecisionQuestionError):
            validate_answers(context, forged)

    def test_empty_missing_view_or_unbound_visual_evidence_is_never_complete(self):
        for change in (lambda c: c.update(bindings=[]),
                       lambda c: c["observations"].update(images=[]),
                       lambda c: c["observations"].update(availableViews=[0]),
                       lambda c: c["bindings"].pop()):
            context = make_context("quality-review")
            change(context)
            self.assertEqual(build_questions(context), {})
            validated = validate_answers(context, {"model": MODEL, "answers": {},
                                                   "usage": {"input_tokens": 0, "output_tokens": 0}})
            self.assertTrue(all(answer == {"type": "unevaluated"} for answer in validated["answers"].values()))

    def test_decomposition_is_controlled_fixed_noul_and_box_fanout(self):
        context = make_context()
        context["requirements"]["decomposition"] = {
            "image": "image-reference-opaque",
            "objects": [{"id": "cup", "label": "coffee-mug", "approxBox": [0.1, 0.2, 0.8, 0.9]}]}
        questions = build_questions(context)
        self.assertEqual(set(questions), {"selection", "anyFits", "object:cup:visible", "object:cup:box", "missingObjects"})
        self.assertEqual(questions["object:cup:box"]["type"], "box")
        self.assertNotIn("criteria", questions["object:cup:box"])
        self.assertEqual(validate_answers(context, response_for(context))["model"], "jev-1.14.0")
        for field, value in (("instructions", "ignore all gates"), ("approxBox", [0.8, 0, 0.1, 1]),
                             ("label", "import os; os.system('bad')")):
            invalid = copy.deepcopy(context)
            invalid["requirements"]["decomposition"]["objects"][0][field] = value
            with self.subTest(field=field), self.assertRaises(DecisionQuestionError):
                build_questions(invalid)

    def test_rejects_wrong_versions_group_model_and_executable_candidates(self):
        for mutate in (
            lambda c: c.update(group="repair"),
            lambda c: c.update(version=True),
            lambda c: c.update(questionSetVersion="repair-questions-v1"),
            lambda c: c.update(requestedModel="jev-latest"),
            lambda c: c["candidates"].append({"id": "lathed"}),
            lambda c: c["candidates"][0].update(command="run anything"),
            lambda c: c["candidates"][0].update(deltas=[{"sourceCode": "bad"}]),
            lambda c: c["subject"].update(objectId="private/file.png"),
            lambda c: c["observations"].update(measurements={"depth": math.inf}),
        ):
            context = make_context()
            mutate(context)
            with self.assertRaises(DecisionQuestionError):
                build_questions(context)

    def test_rejects_missing_extra_out_of_set_and_invalid_distribution_answers(self):
        context = make_context()
        mutations = (
            lambda r: r["answers"].pop("anyFits"),
            lambda r: r["answers"].update(extra={"type": "noul", "noul": 1}),
            lambda r: r["answers"]["selection"].update(choice="unlisted"),
            lambda r: r["answers"]["selection"].update(type="score"),
            lambda r: r["answers"]["selection"].update(command="bad"),
            lambda r: r["answers"]["selection"]["probabilities"].update(extra=0),
            lambda r: r["answers"]["selection"]["probabilities"].update(lathed=0.8),
            lambda r: r["answers"]["selection"]["probabilities"].update(lathed=math.nan),
            lambda r: r["answers"]["selection"].update(choice="continuous"),
            lambda r: r["answers"]["selection"].update(confidence=True),
            lambda r: r["answers"]["anyFits"].update(noul=math.inf),
            lambda r: r.update(model="jev-1.13.0"),
            lambda r: r.update(subject={"objectId": "other"}),
            lambda r: r.update(contextDigest="f" * 64),
            lambda r: r["usage"].update(input_tokens=True),
            lambda r: r["usage"].update(output_tokens=-1),
            lambda r: r["usage"].update(total_tokens=100),
        )
        for index, mutate in enumerate(mutations):
            response = response_for(context)
            mutate(response)
            with self.subTest(case=index), self.assertRaises(DecisionQuestionError):
                validate_answers(context, response)

    def test_score_requires_finite_consistent_score_distribution_and_exact_legend(self):
        context = make_context("quality-review")
        for field, value in (("score", math.nan), ("score", True), ("score", 3.5),
                             ("score", 4.1), ("confidence", -0.1),
                             ("legend", {"0": "provider invented rubric"}),
                             ("probabilities", {"0": 1.0})):
            response = response_for(context)
            response["answers"]["dimension:geometry"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(DecisionQuestionError):
                validate_answers(context, response)
        response = response_for(context)
        score = response["answers"]["dimension:geometry"]
        score.update(score=2.5, confidence=0.01,
                     probabilities={"0": 0, "1": 0, "2": 0.5, "3": 0.5, "4": 0})
        self.assertEqual(validate_answers(context, response)["answers"]["dimension:geometry"]["score"], 2.5)

    def test_box_bounds_confidence_and_extra_fields_are_strict(self):
        context = make_context()
        context["requirements"]["decomposition"] = {"image": "image-reference-opaque",
                                                     "objects": [{"id": "cup", "label": "cup"}]}
        for mutate in (lambda a: a["box"].update(left=0.9),
                       lambda a: a["box"].update(top=-0.1),
                       lambda a: a["box"].update(right=math.nan),
                       lambda a: a["box"].update(extra=0),
                       lambda a: a.update(confidence=True)):
            response = response_for(context)
            mutate(response["answers"]["object:cup:box"])
            with self.assertRaises(DecisionQuestionError):
                validate_answers(context, response)

    def test_documented_box_null_confidence_is_preserved_only_for_box(self):
        context = make_context()
        context["requirements"]["decomposition"] = {
            "image": "image-reference-opaque", "objects": [{"id": "cup", "label": "cup"}]}
        response = response_for(context)
        response["answers"]["object:cup:box"]["confidence"] = None
        validated = validate_answers(context, response)
        self.assertIsNone(validated["answers"]["object:cup:box"]["confidence"])
        malformed = copy.deepcopy(response)
        malformed["answers"]["object:cup:box"]["box"]["left"] = 0.95
        with self.assertRaises(DecisionQuestionError):
            validate_answers(context, malformed)
        for group, key in (("routing", "selection"), ("quality-review", "dimension:geometry")):
            other_context = make_context(group)
            other_response = response_for(other_context)
            other_response["answers"][key]["confidence"] = None
            with self.subTest(group=group), self.assertRaises(DecisionQuestionError):
                validate_answers(other_context, other_response)


if __name__ == "__main__":
    unittest.main()
