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
from test_decision_questions import localization_context, make_context, response_for

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

    def test_routing_descriptions_use_only_fixed_approved_route_semantics(self):
        context = make_context()
        routes = ["base-generic", "interior", "character", "cs2", "pixi2d"]
        context["candidates"] = [
            {"id": "option-" + str(index), "routeId": route, "outputKind": "3d-object",
             "display": {"appliesTo": "PRIVATE DISPLAY MUST NOT LEAK"},
             "description": "UNTRUSTED ROUTE INSTRUCTION", "label": "private-label.jpg"}
            for index, route in enumerate(routes)]
        original = copy.deepcopy(context)
        with mock.patch.object(provider, "post_systemone", return_value=response_for(context)) as post:
            result = provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
        payload = post.call_args.args[0]
        criteria = payload["questions"]["selection"]["criteria"]
        self.assertEqual(set(criteria), {item["id"] for item in original["candidates"]})
        descriptions = [criteria[item["id"]]["description"] for item in original["candidates"]]
        self.assertEqual(len(set(descriptions)), 5)
        for index, route in enumerate(routes):
            self.assertEqual(criteria["option-" + str(index)]["candidateIndex"], index)
            self.assertEqual(descriptions[index], provider._ROUTE_DESCRIPTIONS[route])
        self.assertIn("procedural Three.js", descriptions[0])
        self.assertIn("one enclosed room", descriptions[1])
        self.assertIn("explicit rig intent", descriptions[2])
        self.assertIn("classification may veto", descriptions[3])
        self.assertIn("explicitly requested 2D", descriptions[4])
        encoded = json.dumps(payload)
        for text in ("PRIVATE DISPLAY", "UNTRUSTED ROUTE", "private-label.jpg"):
            self.assertNotIn(text, encoded)
        self.assertEqual([item["routeId"] for item in payload["state"]["candidates"]], routes)
        self.assertEqual(context, original)
        self.assertEqual(result["contextDigest"], digest(original))

    def test_unknown_routes_and_other_decision_groups_keep_generic_criteria(self):
        for group in ("routing", "build-strategy", "repair"):
            context = make_context(group)
            context["candidates"][0]["routeId"] = "base" if group == "routing" else "base-generic"
            context["candidates"][1]["routeId"] = "not-an-approved-route"
            with self.subTest(group=group), mock.patch.object(
                    provider, "post_systemone", return_value=response_for(context)) as post:
                provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
            self.assertEqual(post.call_args.args[0]["questions"], build_questions(context))

    def test_strategy_preserves_controlled_operations_and_both_component_id_shapes(self):
        context = make_context("build-strategy")
        context["candidates"][0].update(
            components=["body", "handle", "/private/component", "arbitrary component prose"],
            operations=["lathe", "sweep"],
            description="PRIVATE STRATEGY DISPLAY")
        with mock.patch.object(provider, "post_systemone", return_value=response_for(context)) as post:
            provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
        candidate = post.call_args.args[0]["state"]["candidates"][0]
        self.assertEqual(candidate["operations"], ["lathe", "sweep"])
        self.assertEqual(candidate["components"], ["body", "handle"])
        self.assertEqual(candidate["componentIds"], ["body", "handle"])
        self.assertNotIn("description", candidate)
        self.assertNotIn("private", json.dumps(candidate))

    def test_native_strategy_allowlist_preserves_approved_scope_without_source_hashes(self):
        context = make_context("build-strategy")
        context["candidates"][0].update(
            operations=["lathe", "match-camera", "bind-pbr", "graphics"],
            fieldPaths=["geometry.parameters"], materialSources=["a" * 64], rigHandoff=True,
            specFields=["geometry.parameters"], expectedMeasurements=["silhouetteIoU"])
        with mock.patch.object(provider, "post_systemone", return_value=response_for(context)) as post:
            provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
        candidate = post.call_args.args[0]["state"]["candidates"][0]
        self.assertEqual(candidate["operations"], ["lathe", "match-camera", "bind-pbr"])
        self.assertEqual(candidate["fieldPaths"], ["geometry.parameters"])
        self.assertIs(candidate["rigHandoff"], True)
        self.assertIs(candidate["materialSourcesPresent"], True)
        for field in ("materialSources", "specFields", "expectedMeasurements"):
            self.assertNotIn(field, candidate)

    def test_native_strategy_candidates_keep_operation_field_and_rig_distinctions(self):
        context = make_context("build-strategy")
        source_hash = "1234567890abcdef" * 4
        context["candidates"] = [
            {"id": "camera-plan", "components": ["room"], "operations": ["match-camera"],
             "fieldPaths": ["authoring.cameraEstimate", "authoring.inspectionViews"],
             "rigHandoff": False, "materialSources": []},
            {"id": "material-plan", "components": ["room"], "operations": ["bind-pbr"],
             "fieldPaths": ["authoring.resourceManifest", "runtime.finishTarget"],
             "rigHandoff": True, "materialSources": [source_hash]},
        ]
        original = copy.deepcopy(context)
        with mock.patch.object(provider, "post_systemone", return_value=response_for(context)) as post:
            result = provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
        candidates = post.call_args.args[0]["state"]["candidates"]
        self.assertEqual(candidates[0], {
            "id": "camera-plan", "components": ["room"], "operations": ["match-camera"],
            "fieldPaths": ["authoring.cameraEstimate", "authoring.inspectionViews"],
            "rigHandoff": False, "materialSourcesPresent": False})
        self.assertEqual(candidates[1], {
            "id": "material-plan", "components": ["room"], "operations": ["bind-pbr"],
            "fieldPaths": ["authoring.resourceManifest", "runtime.finishTarget"],
            "rigHandoff": True, "materialSourcesPresent": True})
        self.assertNotIn(source_hash, json.dumps(post.call_args.args[0]))
        self.assertEqual(context, original)
        self.assertEqual(result["contextDigest"], digest(original))

    def test_all_approved_interior_operations_and_fields_survive_without_arbitrary_paths(self):
        context = make_context("build-strategy")
        operations = [
            "match-camera", "box", "mesh", "tube", "lathe", "cushion", "curtain", "import-model",
            "bind-pbr", "refresh-material", "calibrate", "bake", "probe", "configure-views", "configure-variants"]
        fields = [
            "authoring.cameraEstimate", "authoring.inspectionViews", "authoring.sceneBuilder",
            "authoring.resourceManifest", "authoring.probePosition", "runtime.glassTransmission",
            "runtime.variants", "runtime.finishTarget", "geometry.parameters", "material.roughness",
            "material.metalness", "camera.projection", "camera.fov", "transform.position",
            "transform.rotation", "transform.scale"]
        context["candidates"][0].update(
            operations=operations + ["PRIVATE OPERATION", "unsupported-operation"],
            fieldPaths=fields + ["/private/secret", "authoring.sceneBuilder; PRIVATE COMMAND",
                                 "authoring.sceneBuilder.secret", "rig", {"field": "authoring.sceneBuilder"}],
            materialSources=[], materialSourcesPresent=True, rigHandoff=False)
        with mock.patch.object(provider, "post_systemone", return_value=response_for(context)) as post:
            provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
        candidate = post.call_args.args[0]["state"]["candidates"][0]
        self.assertEqual(candidate["operations"], operations)
        self.assertEqual(candidate["fieldPaths"], fields)
        self.assertIs(candidate["materialSourcesPresent"], False)
        self.assertIs(candidate["rigHandoff"], False)
        self.assertNotIn("PRIVATE", json.dumps(post.call_args.args[0]))
        self.assertNotIn("/private/", json.dumps(post.call_args.args[0]))

    def test_material_presence_and_rig_handoff_are_derived_or_strict_booleans(self):
        cases = [
            ([], False, True), (["a" * 64], True, False),
            (["a" * 64, "PRIVATE SOURCE"], False, 1),
            ("a" * 64, False, "true"), (["G" * 64], False, None)]
        for sources, expected, rig in cases:
            context = make_context("build-strategy")
            context["candidates"][0].update(
                materialSources=sources, materialSourcesPresent=True, rigHandoff=rig,
                fieldPaths={"field": "authoring.sceneBuilder"})
            with self.subTest(sources=sources, rig=rig), mock.patch.object(
                    provider, "post_systemone", return_value=response_for(context)) as post:
                provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
            candidate = post.call_args.args[0]["state"]["candidates"][0]
            self.assertIs(candidate["materialSourcesPresent"], expected)
            self.assertNotIn("materialSources", candidate)
            self.assertNotIn("fieldPaths", candidate)
            if type(rig) is bool:
                self.assertIs(candidate["rigHandoff"], rig)
            else:
                self.assertNotIn("rigHandoff", candidate)

    def test_routing_request_room_and_instance_facts_survive_without_free_text(self):
        context = make_context()
        context["requirements"]["request"] = {
            "expectedOutput": "3d", "intent": ["rig", "PRIVATE INTENT", "delete-everything"],
            "explicitRoute": "character", "notes": "PRIVATE REQUEST", "apiKey": "PRIVATE SECRET",
            "command": "PRIVATE COMMAND"}
        context["observations"].update(
            role="scene-container", box=[0, 0, 1, 1], enclosure="enclosed-room", roomCount=1,
            stylization="unknown", notes="PRIVATE OBSERVATION",
            instances=[{
                "id": "chair-2", "role": "prop", "box": [0.1, 0.2, 0.5, 0.8], "instanceOf": "chair-1",
                "label": "PRIVATE LABEL", "source": "/private/source.png",
                "observations": {"enclosure": "enclosed-room", "roomCount": 1, "stylization": "unknown",
                                 "notes": "PRIVATE INSTANCE", "apiKey": "PRIVATE SECRET"},
            }])
        original = copy.deepcopy(context)
        with mock.patch.object(provider, "post_systemone", return_value=response_for(context)) as post:
            result = provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
        state = post.call_args.args[0]["state"]
        self.assertEqual(state["requirements"]["request"], {
            "expectedOutput": "3d", "intent": ["rig"], "explicitRoute": "character"})
        self.assertEqual(state["observations"]["role"], "scene-container")
        self.assertEqual(state["observations"]["box"], [0, 0, 1, 1])
        self.assertEqual(state["observations"]["enclosure"], "enclosed-room")
        self.assertEqual(state["observations"]["roomCount"], 1)
        self.assertEqual(state["observations"]["stylization"], "unknown")
        self.assertEqual(state["observations"]["instances"], [{
            "id": "chair-2", "role": "prop", "box": [0.1, 0.2, 0.5, 0.8], "instanceOf": "chair-1",
            "observations": {"enclosure": "enclosed-room", "roomCount": 1, "stylization": "unknown"}}])
        self.assertNotIn("PRIVATE", json.dumps(post.call_args.args[0]))
        self.assertNotIn("/private/", json.dumps(post.call_args.args[0]))
        self.assertEqual(context, original)
        self.assertEqual(result["contextDigest"], digest(original))

    def test_routing_unknown_values_do_not_expand_disclosure_vocabulary(self):
        context = make_context()
        context["requirements"]["request"] = {
            "expectedOutput": "PRIVATE OUTPUT", "intent": ["PRIVATE INTENT"], "explicitRoute": "base"}
        context["observations"].update(
            role="PRIVATE ROLE", enclosure="PRIVATE ENCLOSURE", roomCount="PRIVATE COUNT",
            stylization="photorealistic", box=[-0.1, 0, 1, 1],
            instances=[{"id": "chair", "role": "PRIVATE ROLE", "box": [0, 0, 1, 1]},
                       {"id": "lamp", "role": "prop", "box": [0, 0, 2, 1]}])
        with mock.patch.object(provider, "post_systemone", return_value=response_for(context)) as post:
            provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
        state = post.call_args.args[0]["state"]
        self.assertEqual(state["requirements"]["request"], {"intent": []})
        for field in ("role", "enclosure", "roomCount", "stylization", "box"):
            self.assertNotIn(field, state["observations"])
        self.assertEqual(state["observations"]["instances"], [])
        self.assertNotIn("PRIVATE", json.dumps(post.call_args.args[0]))
        self.assertNotIn("photorealistic", json.dumps(post.call_args.args[0]))

    def test_explicit_2d_request_and_approved_route_are_not_lost(self):
        context = make_context()
        context["requirements"]["request"] = {"expectedOutput": "2d", "intent": [], "explicitRoute": "pixi2d"}
        context["observations"].update(enclosure="unknown", roomCount=0, stylization="unknown")
        with mock.patch.object(provider, "post_systemone", return_value=response_for(context)) as post:
            provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
        state = post.call_args.args[0]["state"]
        self.assertEqual(state["requirements"]["request"], {
            "expectedOutput": "2d", "intent": [], "explicitRoute": "pixi2d"})
        self.assertEqual(state["observations"]["enclosure"], "unknown")
        self.assertEqual(state["observations"]["roomCount"], 0)

    def test_prepared_assets_map_to_single_use_wire_references_and_only_wire_properties(self):
        context = make_context()
        prepared = assets_for(context, prepared=True)
        with mock.patch.object(provider, "post_systemone", return_value=response_for(context)) as post:
            provider.evaluate_context(context, api_key=KEY, assets=prepared)
        payload = post.call_args.args[0]
        references = {original["asset"]: wire["asset"] for original, wire in zip(
            context["observations"]["images"], payload["state"]["observations"]["images"])}
        self.assertEqual(set(payload["assets"]), set(references.values()))
        for key, reference in references.items():
            self.assertRegex(reference, r"^imgref-[0-9a-f]{64}$")
            image = payload["assets"][reference]
            self.assertEqual(set(image), {"type", "format", "data_base64"})
            self.assertEqual(image["type"], "image")
            self.assertEqual(image["data_base64"], prepared[key]["data_base64"])
            self.assertEqual(json.dumps(payload["state"]).count(reference), 1)
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

    def test_localization_discloses_complete_inventory_as_data_without_route_candidates(self):
        context = localization_context()
        context["observations"].update(
            expectedOwner="PRIVATE OWNER", expert="PRIVATE EXPERT",
            groundTruthBox=[0, 0, 1, 1], filename="private-image.png")
        context["requirements"]["expectedOwner"] = "PRIVATE OWNER"
        original = copy.deepcopy(context)
        response = {
            "model": "jev-1.14.0",
            "answers": {
                "missingObjects": {"type": "noul", "noul": 0.0},
                "object:cup:visible": {"type": "noul", "noul": 0.0},
                "object:cup:box": {"type": "box",
                                   "box": {"left": 0.1, "top": 0.2, "right": 0.4, "bottom": 0.9},
                                   "confidence": None},
            },
            "usage": {"input_tokens": 123, "output_tokens": 45},
        }
        with mock.patch.object(provider, "post_systemone", return_value=response) as post:
            result = provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
        payload = post.call_args.args[0]
        state = payload["state"]
        self.assertNotIn("candidates", state)
        self.assertEqual(state["questionSetVersion"], "route-questions-v3")
        decomposition = state["requirements"]["decomposition"]
        self.assertEqual(decomposition, {
            "imageIndex": 0,
            "objects": original["requirements"]["decomposition"]["objects"],
            "inventory": original["requirements"]["decomposition"]["inventory"],
        })
        self.assertEqual({key: question["type"] for key, question in payload["questions"].items()}, {
            "missingObjects": "noul", "object:cup:visible": "noul", "object:cup:box": "box",
        })
        reference = state["observations"]["images"][0]["asset"]
        self.assertEqual(json.dumps(state).count(reference), 1)
        encoded = json.dumps(payload)
        for private in ("expectedOwner", "expert", "groundTruthBox", "PRIVATE", "private-image.png",
                        "image-reference-opaque", "private/reference.png", "private/render.png"):
            self.assertNotIn(private, encoded)
        self.assertEqual(result["answers"], response["answers"])
        self.assertEqual(result["contextDigest"], digest(original))
        self.assertEqual(context, original)

    def test_localization_inventory_includes_other_targets_and_scene_container_roles(self):
        for role in ("subject", "prop", "set-dressing", "scene-container"):
            context = localization_context()
            context["requirements"]["decomposition"]["inventory"][1]["role"] = role
            with self.subTest(role=role), mock.patch.object(
                    provider, "post_systemone", return_value=response_for(context)) as post:
                provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
            inventory = post.call_args.args[0]["state"]["requirements"]["decomposition"]["inventory"]
            self.assertEqual([item["id"] for item in inventory], ["cup", "plate"])
            self.assertEqual(inventory[1]["role"], role)

    def test_invalid_localization_inventory_is_rejected_before_disclosure(self):
        context = localization_context()
        context["requirements"]["decomposition"]["inventory"][1]["expert"] = "private-owner"
        with mock.patch.object(provider, "post_systemone") as post:
            with self.assertRaises(DecisionQuestionError):
                provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
        post.assert_not_called()

    def test_localization_rejects_private_or_nonsemantic_labels_before_transport(self):
        for label in ("private-name.png", "Coffee-Mug", "coffee:mug", "coffee_mug",
                      "9mug", "a" * 97):
            for location in ("target", "inventory"):
                context = localization_context()
                decomposition = context["requirements"]["decomposition"]
                if location == "target":
                    decomposition["objects"][0]["label"] = label
                    decomposition["inventory"][0]["label"] = label
                else:
                    decomposition["inventory"][1]["label"] = label
                with self.subTest(label=label, location=location), \
                        mock.patch.object(provider, "post_systemone") as post:
                    with self.assertRaises(DecisionQuestionError):
                        provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
                    post.assert_not_called()
        for label in ("coffee-mug", "chair2", "a" * 96):
            context = localization_context()
            decomposition = context["requirements"]["decomposition"]
            for item in (decomposition["objects"][0], decomposition["inventory"][0]):
                item.update(id="Cup.v1:main", label=label)
            with self.subTest(valid_label=label), mock.patch.object(
                    provider, "post_systemone", return_value=response_for(context)) as post:
                provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
            post.assert_called_once()
            disclosed = post.call_args.args[0]["state"]["requirements"]["decomposition"]
            self.assertEqual(disclosed["objects"][0]["label"], label)
            self.assertEqual(disclosed["inventory"][0]["label"], label)
            self.assertEqual(disclosed["objects"][0]["id"], "Cup.v1:main")

    def test_short_asset_ids_never_replace_roles_instructions_or_criteria(self):
        context = make_context("quality-review")
        for image in context["observations"]["images"]:
            image["asset"] = image["role"]
        original = copy.deepcopy(context)
        assets = assets_for(context, prepared=True)
        original_assets = copy.deepcopy(assets)
        with mock.patch.object(provider, "post_systemone", return_value=response_for(context)) as post:
            first = provider.evaluate_context(context, api_key=KEY, assets=assets)
            first_payload = copy.deepcopy(post.call_args.args[0])
            second = provider.evaluate_context(context, api_key=KEY, assets=dict(reversed(list(assets.items()))))
            second_payload = post.call_args.args[0]
        self.assertEqual(first_payload, second_payload)
        self.assertEqual(first["contextDigest"], digest(original))
        self.assertEqual(second["contextDigest"], digest(original))
        self.assertEqual(context, original)
        self.assertEqual(assets, original_assets)
        self.assertEqual(first_payload["questions"], build_questions(original))
        wire_images = first_payload["state"]["observations"]["images"]
        self.assertEqual([image["role"] for image in wire_images], ["reference", "render"])
        references = set(first_payload["assets"])
        self.assertEqual(references, {image["asset"] for image in wire_images})
        self.assertTrue(references.isdisjoint({"reference", "render"}))

        def values(value):
            if type(value) is str:
                yield value
            elif type(value) is dict:
                for item in value.values():
                    yield from values(item)
            elif type(value) is list:
                for item in value:
                    yield from values(item)

        def substitute(value):
            if type(value) is str:
                for reference in references:
                    value = value.replace(reference, "[IMAGE]")
                return value
            if type(value) is dict:
                return {key: substitute(item) for key, item in value.items()}
            if type(value) is list:
                return [substitute(item) for item in value]
            return value

        strings = list(values({"state": first_payload["state"], "questions": first_payload["questions"]}))
        for reference in references:
            self.assertRegex(reference, r"^imgref-[0-9a-f]{64}$")
            self.assertEqual(sum(text.count(reference) for text in strings), 1)
        expanded = substitute({"state": first_payload["state"], "questions": first_payload["questions"]})
        self.assertEqual(expanded["questions"], build_questions(original))
        self.assertEqual(expanded["state"]["observations"]["images"], [
            {"role": "reference", "asset": "[IMAGE]"}, {"role": "render", "asset": "[IMAGE]"}])

    def test_duplicate_wire_references_fail_before_transport(self):
        context = make_context()
        with mock.patch.object(provider, "_wire_reference", return_value="imgref-" + "a" * 64), \
                mock.patch.object(provider, "post_systemone") as post:
            with self.assertRaises(DecisionQuestionError) as error:
                provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
        self.assertEqual(error.exception.reason_code, "asset-reference-collision")
        post.assert_not_called()

    def test_wire_reference_in_other_state_instructions_or_criteria_fails_closed(self):
        reference = "imgref-" + "a" * 64
        other = "imgref-" + "b" * 64
        for location in ("state", "instructions", "criteria"):
            context = make_context()
            if location == "state":
                context["subject"]["objectId"] = reference
            questions = build_questions(context)
            if location == "instructions":
                questions["selection"]["instructions"] += " " + reference + " twice " + reference
            elif location == "criteria":
                questions["selection"]["criteria"]["lathed"]["description"] = "embedded-" + reference
            original = copy.deepcopy(context)
            with self.subTest(location=location), \
                    mock.patch.object(provider, "_wire_reference", side_effect=[reference, other]), \
                    mock.patch.object(provider, "build_questions", return_value=questions), \
                    mock.patch.object(provider, "post_systemone") as post:
                with self.assertRaises(DecisionQuestionError) as error:
                    provider.evaluate_context(context, api_key=KEY, assets=assets_for(context))
            self.assertEqual(error.exception.reason_code, "asset-reference-collision")
            self.assertEqual(context, original)
            post.assert_not_called()

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
