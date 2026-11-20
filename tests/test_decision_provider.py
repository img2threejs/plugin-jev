"""Offline tests exercising request construction, transport use and advisory binding."""

import base64
import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

TESTS = Path(__file__).resolve().parent
TOOLS = TESTS.parent / "tools"
for directory in (TESTS, TOOLS):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

import jev_decision_provider as provider
from jev_decision_questions import DecisionQuestionError, build_questions
from test_decision_questions import make_context, response_for

KEY = "offline-credential-not-a-live-secret"


def assets_for(context, prepared=False):
    # Transport is mocked; this fixture tests explicit asset handoff, not decoding.
    data = b"offline image bytes"
    result = {}
    for image in context["observations"].get("images", []):
        asset = {"format": "png", "data_base64": base64.b64encode(data).decode("ascii")}
        if prepared:
            asset.update(sha256=hashlib.sha256(data).hexdigest(), width=280, height=280,
                         transform={"sourceWidth": 280, "sourceHeight": 280,
                                    "crop": [0, 0, 280, 280], "scaleX": 1, "scaleY": 1,
                                    "padX": 0, "padY": 0})
        result[image["asset"]] = asset
    return result


def digest(context):
    return hashlib.sha256(json.dumps(context, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()


class DecisionProviderTest(unittest.TestCase):
    def test_each_group_calls_real_transport_boundary_and_returns_bound_advisory(self):
        for group in ("routing", "build-strategy", "quality-review", "repair"):
            context = make_context(group)
            assets = assets_for(context)
            response = response_for(context)
            with self.subTest(group=group), mock.patch.object(provider, "post_systemone", return_value=response) as post:
                result = provider.evaluate_context(context, api_key=KEY, assets=assets, timeout=4.5)
            post.assert_called_once()
            payload, passed_key = post.call_args.args
            self.assertEqual(passed_key, KEY)
            self.assertEqual(post.call_args.kwargs, {"timeout": 4.5})
            self.assertEqual(payload["questions"], build_questions(context))
            self.assertEqual(payload["model"], "jev-1.14.0")
            self.assertEqual(set(payload), {"model", "state", "questions", "assets"})
            self.assertEqual(result, {
                "kind": "img2.decision-advisory", "version": 1, "group": group,
                "subject": context["subject"], "contextDigest": digest(context),
                "model": response["model"], "answers": response["answers"], "usage": response["usage"],
            })
            self.assertNotIn("path", payload["state"]["bindings"][0])
            self.assertNotIn(KEY, json.dumps(result))

    def test_projection_strips_nested_paths_filenames_free_text_and_secrets(self):
        context = make_context("build-strategy")
        context["observations"].update(
            filename="customer-private.png", path="/Users/private/file.png", password="do-not-send",
            notes="look at C:\\private\\file.png, relative/private.png or secret.glb",
            measurements={"width": 1.2, "depth": 0.7, "filename": "also-private.jpg", "height": "/private/value"})
        context["candidates"][0].update(
            description="execute arbitrary Python; bearer hidden", apiKey="secret-credential",
            label="private-name.png", specDeltas=[{"field": "material.roughness", "value": 0.35,
                                                   "path": "secret-material.jpg", "token": "do-not-send"}])
        original = copy.deepcopy(context)
        with mock.patch.object(provider, "post_systemone", return_value=response_for(context)) as post:
            provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
        state = post.call_args.args[0]["state"]
        encoded = json.dumps(state)
        for private in ("private", "do-not-send", "secret-credential", "arbitrary Python", "bearer", "apiKey", "password"):
            self.assertNotIn(private, encoded)
        self.assertEqual(state["observations"]["measurements"], {"width": 1.2, "depth": 0.7})
        self.assertEqual(state["candidates"][0]["operations"], ["lathe", "sweep"])
        self.assertEqual(state["candidates"][0]["specDeltas"], [{"field": "material.roughness", "value": 0.35}])
        self.assertEqual(context, original)

    def test_prepared_assets_keep_keys_and_only_wire_image_properties(self):
        context = make_context()
        prepared = assets_for(context, prepared=True)
        with mock.patch.object(provider, "post_systemone", return_value=response_for(context)) as post:
            provider.evaluate_context(context, api_key=KEY, assets=prepared)
        payload = post.call_args.args[0]
        self.assertEqual(set(payload["assets"]), set(prepared))
        for key, image in payload["assets"].items():
            self.assertEqual(set(image), {"type", "format", "data_base64"})
            self.assertEqual(image["type"], "image")
            self.assertEqual(image["data_base64"], prepared[key]["data_base64"])
            self.assertEqual(json.dumps(payload["state"]).count(key), 1)
        self.assertNotIn("data_base64", json.dumps(context))

    def test_image_free_request_never_loads_or_discloses_files(self):
        context = make_context("repair")
        context["observations"]["images"] = []
        with mock.patch("builtins.open", side_effect=AssertionError("unexpected file read")), \
                mock.patch.object(provider, "post_systemone", return_value=response_for(context)) as post:
            result = provider.evaluate_context(context, api_key=KEY)
        self.assertNotIn("assets", post.call_args.args[0])
        self.assertEqual(result["contextDigest"], digest(context))

    def test_assets_must_be_explicit_complete_referenced_and_never_paths(self):
        context = make_context()
        cases = [None, {}, {"not-referenced": {"format": "png", "data_base64": "YWJj"}},
                 {key: "/private/image.png" for key in assets_for(context)}]
        bad = assets_for(context)
        bad["image-reference-opaque"]["path"] = "/private/image.png"
        cases.append(bad)
        bad = assets_for(context)
        bad["image-reference-opaque"]["data_base64"] = "Y WJj"
        cases.append(bad)
        bad = assets_for(context, prepared=True)
        bad["image-reference-opaque"]["sha256"] = "0" * 64
        cases.append(bad)
        with mock.patch.object(provider, "post_systemone") as post:
            for index, assets in enumerate(cases):
                with self.subTest(case=index), self.assertRaises(DecisionQuestionError):
                    provider.evaluate_context(context, api_key=KEY, assets=assets)
            post.assert_not_called()

    def test_decomposition_uses_one_copy_of_image_and_fixed_field_references(self):
        context = make_context()
        context["requirements"]["decomposition"] = {
            "image": "image-reference-opaque", "objects": [{"id": "cup", "label": "coffee-mug", "approxBox": [0, 0, 1, 1]}]}
        with mock.patch.object(provider, "post_systemone", return_value=response_for(context)) as post:
            result = provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
        payload = post.call_args.args[0]
        self.assertEqual(json.dumps(payload["state"]).count("image-reference-opaque"), 1)
        self.assertEqual(payload["state"]["requirements"]["decomposition"]["imageIndex"], 0)
        self.assertIn("`observations.images[0].asset`", payload["questions"]["object:cup:box"]["instructions"]["question"])
        self.assertEqual(result["answers"]["object:cup:box"]["type"], "box")

    def test_digest_is_exact_canonical_entire_incoming_context(self):
        context = make_context()
        context["observations"]["notes"] = "café admission data"
        incoming = dict(reversed(list(context.items())))
        with mock.patch.object(provider, "post_systemone", return_value=response_for(context)):
            first = provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
            reordered = provider.evaluate_context(incoming, api_key=KEY, assets=assets_for(incoming))
            changed = copy.deepcopy(context)
            changed["bindings"][0]["path"] = "another/reference.png"
            other = provider.evaluate_context(changed, api_key=KEY, assets=assets_for(changed))
        self.assertEqual(first["contextDigest"], digest(context))
        self.assertEqual(first["contextDigest"], reordered["contextDigest"])
        self.assertNotEqual(first["contextDigest"], other["contextDigest"])

    def test_input_mutation_during_transport_cannot_rebind_subject_or_digest(self):
        context = make_context()
        frozen = copy.deepcopy(context)
        def transport(_payload, _key, **_kwargs):
            context["subject"]["objectId"] = "foreign-object"
            context["observations"]["measurements"]["selfIntersectionCount"] = 12
            return response_for(frozen)
        with mock.patch.object(provider, "post_systemone", side_effect=transport):
            result = provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
        self.assertEqual(result["subject"], frozen["subject"])
        self.assertEqual(result["contextDigest"], digest(frozen))

    def test_uncertain_answer_remains_advisory_and_no_fallback_is_invented(self):
        context = make_context("repair")
        response = response_for(context)
        response["answers"]["selection"].update(
            probabilities={"lathed": 0.51, "continuous": 0.49}, confidence=0.01)
        response["answers"]["anyFits"]["noul"] = 0.5
        with mock.patch.object(provider, "post_systemone", return_value=response):
            result = provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
        self.assertEqual(result["answers"], response["answers"])
        self.assertNotIn("outcome", result)
        self.assertNotIn("unavailable", result)

    def test_missing_review_assessments_are_explicit_and_all_missing_stops_before_call(self):
        context = make_context("quality-review")
        context["requirements"]["criticalFeatures"][0]["requiredViews"] = [45]
        with mock.patch.object(provider, "post_systemone", return_value=response_for(context)):
            result = provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
        self.assertEqual(result["answers"]["critical:handle"], {"type": "unevaluated"})
        context["bindings"] = []
        with mock.patch.object(provider, "post_systemone") as post:
            with self.assertRaises(DecisionQuestionError) as error:
                provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
            self.assertEqual(error.exception.reason_code, "missing-evidence")
            missing_handle = next(item for item in error.exception.details
                                  if item["assessment"] == "critical:handle")
            self.assertEqual(missing_handle["missingViews"], [45])
            self.assertEqual(missing_handle["missingRoles"], ["reference", "render"])
            self.assertNotIn("private", json.dumps(error.exception.details))
            post.assert_not_called()

    def test_wrong_served_model_unbound_claims_and_provider_instructions_are_rejected(self):
        context = make_context()
        for field, value in (("model", "jev-latest"), ("subject", {"objectId": "foreign"}),
                             ("contextDigest", "0" * 64), ("group", "quality-review"),
                             ("command", "disable all checks")):
            response = response_for(context)
            response[field] = value
            with mock.patch.object(provider, "post_systemone", return_value=response), \
                    self.subTest(field=field), self.assertRaises(DecisionQuestionError):
                provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))

    def test_transport_failures_propagate_without_fake_fallback_or_credentials(self):
        context = make_context()
        failure = RuntimeError("credential-rejected")
        with mock.patch.object(provider, "post_systemone", side_effect=failure) as post:
            with self.assertRaises(RuntimeError) as error:
                provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
        self.assertIs(error.exception, failure)
        self.assertNotIn(KEY, str(error.exception))
        post.assert_called_once()

    def test_actual_credential_cannot_leak_through_an_opaque_candidate_id(self):
        context = make_context()
        context["candidates"][0]["id"] = KEY
        with mock.patch.object(provider, "post_systemone") as post:
            with self.assertRaises(DecisionQuestionError) as error:
                provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
            self.assertEqual(error.exception.reason_code, "credential-in-context")
            self.assertNotIn(KEY, str(error.exception))
            post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
