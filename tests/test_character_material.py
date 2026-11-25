"""Owned offline fixtures for the character material admission boundary."""
import sys
import copy
import importlib.util
import json
import math
import os
import tempfile
from unittest import mock
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from jev_decision_questions import DecisionQuestionError, build_questions
from test_decision_questions import make_context
from _character_material_fixture import material_fixture, rewrite_binding, sync_manifest, canonical
from test_decision_enrollment import _WorkspaceFixture, KEY
from test_decision_questions import response_for
import jev_decision_provider as provider
import test_decision_enrollment as enrollment


def _world(right, up, back):
    return [*right, 0, *up, 0, *back, 0, 11, 7, -3, 1]


DEGENERATE_WORLDS = [
    ("zero-right", _world((0,0,0), (0,1,0), (0,0,1))),
    ("zero-up", _world((1,0,0), (0,0,0), (0,0,1))),
    ("parallel", _world((1,0,0), (2,0,0), (0,0,1))),
    ("coplanar", _world((1,0,0), (1,0,1), (0,0,1))),
    ("nearly-parallel", _world((1,0,0), (1,1e-14,0), (0,0,1))),
    ("collapsed-right", _world((1e-14,0,0), (0,1,0), (0,0,1))),
]
VALID_WORLDS = [
    _world((1,0,0), (0,1,0), (0,0,1)),
    _world((0,2,0), (-3,0,0), (0,0,4)),
    _world((2,0,0), (0.5,3,0), (0,0,4)),
    _world((-2,0,0), (0,3,0), (0,0,4)),
    _world((1e-5,0,0), (0,1e-5,0), (0,0,1e-5)),
]


class CharacterMaterialAdmissionTests(unittest.TestCase):
    def test_native_character_requires_material_provenance(self):
        for deterministic in ({}, {"sweep": {"materialCapture": "original-material-fixed-lighting-v1"}}):
            context = make_context("quality-review")
            context["subject"]["passId"] = "character-terminal-review"
            context["observations"]["nativeEvidence"] = {
                "provider": "character", "deterministic": deterministic}
            with self.subTest(deterministic=deterministic), self.assertRaises(DecisionQuestionError):
                build_questions(context)

    def test_complete_material_questions_and_projection_preserve_typed_facts(self):
        with tempfile.TemporaryDirectory() as directory:
            context, _ = material_fixture(directory)
            questions = build_questions(context)
            self.assertEqual(set(questions), {
                "dimension:silhouette-proportions", "dimension:part-relationships", "dimension:geometry",
                "dimension:material-appearance", "dimension:identity-features",
                "critical:part:body", "critical:feature:identity"})
            projected = provider._project_state(context)
            self.assertEqual(projected["observations"]["characterMaterial"],
                             context["observations"]["characterMaterial"])
            self.assertNotIn("path", json.dumps(projected["observations"]["characterMaterial"]))

    def test_incomplete_or_contradictory_material_contexts_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            source, _ = material_fixture(directory)
            mutations = [
                lambda c: c.update(policyVersion="quality-v1"),
                lambda c: c.update(questionSetVersion="quality-review-questions-v1"),
                lambda c: c["observations"]["nativeEvidence"].update(provider="environment"),
                lambda c: c["observations"]["characterMaterial"].update(mode="normal-only"),
                lambda c: c["observations"]["characterMaterial"]["pixels"].update(alphaMode="premultiplied"),
                lambda c: c["observations"]["characterMaterial"].update(configurationSha256="0"*64),
                lambda c: c["observations"]["characterMaterial"].update(path="/private/fixture"),
                lambda c: c["requirements"].update(dimensions=["geometry"]),
                lambda c: c["requirements"]["criticalFeatures"].pop(),
                lambda c: c["observations"]["images"].pop(),
                lambda c: c["observations"]["characterMaterial"]["frames"].pop(),
                lambda c: c["observations"]["characterMaterial"]["frames"][1]["camera"].update(
                    matrixWorld=c["observations"]["characterMaterial"]["frames"][0]["camera"]["matrixWorld"]),
                lambda c: c["observations"]["characterMaterial"]["coverage"]["clipIds"].append("clip-"+"f"*64),
                lambda c: c["observations"]["characterMaterial"]["renderer"].update(toneMapping="aces"),
                lambda c: c["observations"]["characterMaterial"]["frames"][0]["camera"].update(projection="perspective"),
            ]
            for index, mutate in enumerate(mutations):
                context = copy.deepcopy(source)
                mutate(context)
                with self.subTest(index=index), self.assertRaises(DecisionQuestionError):
                    build_questions(context)

    def test_cardinal_tolerance_is_inclusive_and_not_automatically_relaxed(self):
        with tempfile.TemporaryDirectory() as directory:
            source, _ = material_fixture(directory)
            for delta, accepted in [(0, True), (0.0000999, True), (0.0001, True),
                                    (-0.0001, True), (0.0001001, False)]:
                context = copy.deepcopy(source)
                theta = math.radians(delta)
                matrix = context["observations"]["characterMaterial"]["frames"][0]["camera"]["matrixWorld"]
                matrix[8], matrix[10] = math.sin(theta), math.cos(theta)
                with self.subTest(delta=delta):
                    if accepted:
                        self.assertEqual(len(build_questions(context)), 7)
                    else:
                        with self.assertRaises(DecisionQuestionError):
                            build_questions(context)

    def test_cardinal_boundary_rejects_one_float_step_outside(self):
        with tempfile.TemporaryDirectory() as directory:
            source, _ = material_fixture(directory)
            limit = math.tan(math.radians(1e-4))
            for cross, accepted in [(limit, True), (math.nextafter(limit, math.inf), False)]:
                context = copy.deepcopy(source)
                matrix = context["observations"]["characterMaterial"]["frames"][0]["camera"]["matrixWorld"]
                matrix[8], matrix[10] = cross, 1
                if accepted:
                    self.assertEqual(len(build_questions(context)), 7)
                else:
                    with self.assertRaises(DecisionQuestionError):
                        build_questions(context)

    def test_degenerate_camera_bases_refuse_question_compilation(self):
        with tempfile.TemporaryDirectory() as directory:
            source, _ = material_fixture(directory)
            for name, matrix in DEGENERATE_WORLDS:
                context = copy.deepcopy(source)
                context["observations"]["characterMaterial"]["frames"][0]["camera"]["matrixWorld"] = matrix
                with self.subTest(name=name), self.assertRaises(DecisionQuestionError):
                    build_questions(context)

    def test_degenerate_camera_bases_refuse_before_provider_or_reservation(self):
        with tempfile.TemporaryDirectory() as directory:
            source, assets = material_fixture(directory)
            response = response_for(source)
            for name, matrix in DEGENERATE_WORLDS:
                context = copy.deepcopy(source)
                context["observations"]["characterMaterial"]["frames"][0]["camera"]["matrixWorld"] = matrix
                reserve = mock.Mock()
                with self.subTest(name=name), mock.patch.object(
                        provider, "post_systemone", return_value=response) as post:
                    with self.assertRaises(DecisionQuestionError):
                        provider.evaluate_context(context, api_key=KEY, assets=assets, before_send=reserve)
                    reserve.assert_not_called()
                    post.assert_not_called()


class CharacterMaterialFileTests(_WorkspaceFixture):
    def setUp(self):
        super().setUp()
        self.home.mkdir()
        harness = Path(os.environ["IMG2_HARNESS_DIR"])
        (self.home / "harness").symlink_to(harness, target_is_directory=True)
        spec = importlib.util.spec_from_file_location("jev_material_cli", TOOLS / "jev.py")
        self.cli = importlib.util.module_from_spec(spec)
        from _harness import linked_harness
        with linked_harness():
            spec.loader.exec_module(self.cli)
        self.context, self.assets = material_fixture(self.workspace)

    def _rewrite_world(self, context, matrix):
        frame = context["observations"]["characterMaterial"]["frames"][0]
        binding = next(item for item in context["bindings"] if item["role"] == frame["camera"]["role"])
        record = json.loads((self.workspace / binding["path"]).read_text())
        record["matrixWorld"] = matrix
        frame["camera"]["matrixWorld"] = matrix
        frame["camera"]["sha256"] = rewrite_binding(self.workspace, context, binding["role"], record)
        sync_manifest(self.workspace, context)

    def test_fresh_hash_degenerate_camera_refuses_file_preflight_and_cli(self):
        self.grant(128000)
        response = response_for(self.context)
        import jev_decision_transport as transport
        for name, matrix in DEGENERATE_WORLDS:
            context = copy.deepcopy(self.context)
            self._rewrite_world(context, matrix)
            with self.subTest(name=name):
                with self.assertRaises(DecisionQuestionError):
                    self.cli._decision_bindings(self.workspace, context, self.assets)
                (self.workspace / "context.json").write_bytes(canonical(context))
                (self.workspace / "assets.json").write_bytes(canonical(self.assets))
                with mock.patch.object(self.cli, "auth_status", return_value={"status": "present"}) as auth, \
                        mock.patch.object(self.cli, "resolve_api_key", return_value=KEY) as key, \
                        mock.patch.object(transport, "_run_worker", return_value=response) as worker:
                    code, result = enrollment.DecisionCliTests.invoke(self, "quality-review")
                    self.assertEqual(code, 2)
                    self.assertEqual(result["reasonCode"], "invalid-material-evidence")
                    self.assertEqual((result["sendState"], result["chargedTokens"]), ("not-sent", 0))
                    auth.assert_not_called()
                    key.assert_not_called()
                    worker.assert_not_called()

    def test_valid_scaled_rolled_and_translated_camera_bases_remain_usable(self):
        for index, matrix in enumerate(VALID_WORLDS):
            context = copy.deepcopy(self.context)
            self._rewrite_world(context, matrix)
            with self.subTest(index=index):
                self.assertEqual(len(build_questions(context)), 7)
                self.cli._decision_bindings(self.workspace, context, self.assets)
        self.grant(128000)
        (self.workspace / "context.json").write_bytes(canonical(context))
        (self.workspace / "assets.json").write_bytes(canonical(self.assets))
        import jev_decision_transport as transport
        with mock.patch.object(self.cli, "auth_status", return_value={"status": "present"}), \
                mock.patch.object(self.cli, "resolve_api_key", return_value=KEY), \
                mock.patch.object(transport, "_run_worker", return_value=response_for(context)) as worker:
            code, result = enrollment.DecisionCliTests.invoke(self, "quality-review")
            self.assertEqual(code, 0)
            self.assertEqual((result["status"], result["sendState"], result["chargedTokens"]),
                             ("answered", "charged", 168))
            worker.assert_called_once()

    def test_source_rgba_mismatch_refuses_even_with_fresh_hashes(self):
        frame = self.context["observations"]["characterMaterial"]["frames"][0]
        role = frame["rgbaRole"]
        binding = next(item for item in self.context["bindings"] if item["role"] == role)
        raw = bytearray((self.workspace / binding["path"]).read_bytes())
        raw[3] ^= 1
        frame["rgbaSha256"] = rewrite_binding(self.workspace, self.context, role, bytes(raw))
        sync_manifest(self.workspace, self.context)
        with self.assertRaises(DecisionQuestionError):
            self.cli._decision_bindings(self.workspace, self.context)

    def test_camera_metadata_cannot_disagree_with_bound_camera(self):
        frame = self.context["observations"]["characterMaterial"]["frames"][0]
        frame["azimuth"] = 90
        sync_manifest(self.workspace, self.context)
        with self.assertRaises(DecisionQuestionError):
            self.cli._decision_bindings(self.workspace, self.context)

    def test_real_decision_pipeline_and_cache_keep_original_charge(self):
        self.grant(128000)
        (self.workspace / "context.json").write_bytes(canonical(self.context))
        (self.workspace / "assets.json").write_bytes(canonical(self.assets))
        import jev_decision_transport as transport
        with mock.patch.object(self.cli, "auth_status", return_value={"status": "present"}), \
                mock.patch.object(self.cli, "resolve_api_key", return_value=KEY), \
                mock.patch.object(transport, "_run_worker", side_effect=lambda *a, **k: response_for(self.context)) as worker:
            code, first = enrollment.DecisionCliTests.invoke(
                self, "quality-review", ("--attempt-id", "a"*32))
            self.assertEqual(code, 0)
            self.assertEqual((first["sendState"], first["chargedTokens"]), ("charged", 168))
            code, second = enrollment.DecisionCliTests.invoke(
                self, "quality-review", ("--attempt-id", "b"*32))
            self.assertEqual(code, 0)
            self.assertTrue(second["cached"])
            self.assertEqual((second["sendState"], second["chargedTokens"]), ("not-sent", 0))
            self.assertEqual(second["advisory"]["usage"], first["advisory"]["usage"])
            worker.assert_called_once()

    def test_roi_must_be_nonempty_binary_and_hash_bound(self):
        for value in (b"\0"*15, b"\2"*15, b"\1"*14):
            with self.subTest(value=value):
                context = copy.deepcopy(self.context)
                frame = context["observations"]["characterMaterial"]["frames"][0]
                frame["roi"]["sha256"] = rewrite_binding(self.workspace, context, frame["roi"]["role"], value)
                sync_manifest(self.workspace, context)
                with self.assertRaises(DecisionQuestionError):
                    self.cli._decision_bindings(self.workspace, context)

    def test_manifest_cannot_disagree_with_context_even_with_fresh_hash(self):
        lane = copy.deepcopy(self.context["observations"]["characterMaterial"])
        lane["mode"] = "normal-only"
        rewrite_binding(self.workspace, self.context, "character-material-capture", lane)
        with self.assertRaises(DecisionQuestionError):
            self.cli._decision_bindings(self.workspace, self.context)

    def test_rgb_compression_bytes_are_not_used_as_pixel_provenance(self):
        import base64
        from PIL import Image
        import io
        assets = copy.deepcopy(self.assets)
        record = assets["image-render"]
        with Image.open(io.BytesIO(base64.b64decode(record["data_base64"]))) as image:
            output = io.BytesIO()
            image.save(output, format="PNG", compress_level=0)
        data = output.getvalue()
        import hashlib
        self.assertNotEqual(data, base64.b64decode(record["data_base64"]))
        record.update(data_base64=base64.b64encode(data).decode(), sha256=hashlib.sha256(data).hexdigest())
        self.cli._decision_assets(self.context, assets)
        self.cli._decision_bindings(self.workspace, self.context, assets)
        self.grant(128000)
        (self.workspace / "context.json").write_bytes(canonical(self.context))
        (self.workspace / "assets.json").write_bytes(canonical(assets))
        import jev_decision_transport as transport
        with mock.patch.object(self.cli, "auth_status", return_value={"status": "present"}), \
                mock.patch.object(self.cli, "resolve_api_key", return_value=KEY), \
                mock.patch.object(transport, "_run_worker", side_effect=lambda *a, **k: response_for(self.context)) as worker:
            code, result = enrollment.DecisionCliTests.invoke(self, "quality-review")
            self.assertEqual(code, 0)
            self.assertEqual((result["status"], result["sendState"], result["chargedTokens"]),
                             ("answered", "charged", 168))
            worker.assert_called_once()

    def test_prepared_visual_must_match_its_bound_source(self):
        with self.assertRaises(DecisionQuestionError):
            self.cli._decision_bindings(self.workspace, self.context,
                                       {**self.assets, "image-render": self.assets["image-reference"] | {
                                           "transform": {**self.assets["image-reference"]["transform"], "padX": 0}}})


if __name__ == "__main__":
    unittest.main()
