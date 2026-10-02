import argparse
import errno
import fcntl
import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

PLUGIN = Path(__file__).resolve().parent.parent
HARNESS = Path(os.environ.get("IMG2_HARNESS_DIR", PLUGIN.parent / "img2")).resolve()


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="jev integration ")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.home = self.base / "img2home"
        self.home.mkdir()
        (self.home / "harness").symlink_to(HARNESS, target_is_directory=True)
        self.workspace = self.base / "workspace with spaces"
        self.workspace.mkdir()
        self.test_support = self.base / "test-support"
        self.test_support.mkdir()
        self.security_log = self.base / "fake-security.log"
        self.network_log = self.base / "blocked-network.log"
        self.provider_calls = self.base / "provider-calls.log"
        fake_security = self.test_support / "fake-security"
        fake_security.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$*\" >> \"$JEV_TEST_SECURITY_LOG\"\n"
            "case \"$1\" in find-generic-password) exit 44 ;; add-generic-password) exit 1 ;; *) exit 2 ;; esac\n",
            encoding="utf-8",
        )
        fake_security.chmod(0o700)
        (self.test_support / "sitecustomize.py").write_text(
            "import os, urllib.request\n"
            "def _deny_external_transport(self, fullurl, *args, **kwargs):\n"
            "    with open(os.environ['JEV_TEST_NETWORK_LOG'], 'a', encoding='utf-8') as log:\n"
            "        log.write(str(fullurl) + '\\n')\n"
            "    raise RuntimeError('external transport disabled in offline integration tests')\n"
            "urllib.request.OpenerDirector.open = _deny_external_transport\n",
            encoding="utf-8",
        )
        (self.test_support / "jev_cli_bootstrap.py").write_text(
            "import importlib, json, os, runpy, sys\n"
            "from pathlib import Path\n"
            f"plugin = Path({str(PLUGIN)!r})\n"
            "sys.path.insert(0, str(plugin / 'tools'))\n"
            "auth = importlib.import_module('jev_auth')\n"
            "auth._security_path = lambda: os.environ['JEV_TEST_SECURITY']\n"
            "transport = importlib.import_module('jev_transport')\n"
            "client = importlib.import_module('jev_client')\n"
            "def deny_transport(*args, **kwargs):\n"
            "    with open(os.environ['JEV_TEST_NETWORK_LOG'], 'a', encoding='utf-8') as log:\n"
            "        log.write('external transport blocked\\n')\n"
            "    raise transport.ProviderError('external transport disabled in offline integration tests')\n"
            "def fake_transport(state, api_key, timeout=15.0):\n"
            "    with open(os.environ['JEV_TEST_PROVIDER_CALLS_LOG'], 'a', encoding='utf-8') as log:\n"
            "        log.write('dispatch\\n')\n"
            "    raw = os.environ.get('JEV_TEST_PROVIDER_RESPONSE')\n"
            "    if raw is None: return deny_transport()\n"
            "    try: return client.validate_response(json.loads(raw))\n"
            "    except Exception: raise transport.ProviderError('invalid synthetic response') from None\n"
            "transport.evaluate_bounded = fake_transport\n"
            "sys.argv = [str(plugin / 'tools' / 'jev.py'), *sys.argv[1:]]\n"
            "runpy.run_path(sys.argv[0], run_name='__main__')\n",
            encoding="utf-8",
        )
        self.env = {
            **os.environ,
            "IMG2_HOME": str(self.home),
            "PYTHONPATH": os.pathsep.join((str(self.test_support), str(HARNESS))),
            "PYTHONDONTWRITEBYTECODE": "1",
            "JEV_TEST_SECURITY": str(fake_security),
            "JEV_TEST_SECURITY_LOG": str(self.security_log),
            "JEV_TEST_NETWORK_LOG": str(self.network_log),
            "JEV_TEST_PROVIDER_CALLS_LOG": str(self.provider_calls),
        }
        self.env.pop("TYPESAFE_API_KEY", None)
        self.env.pop("IMG2THREEJS_HOME", None)
        self._test_consent_authorized = False
        self.observation = json.loads((PLUGIN / "examples" / "observation.json").read_text())
        for binding in self.observation["bindings"]:
            path = self.workspace / binding["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic bound evidence for " + binding["role"])
        self.seed_environment_files(0.5)
        gate_path, gate = self.synthetic_gate(failed_row="12-ip-provenance-hygiene")
        self.bind_gate(gate_path, gate)
        self.write("observation.json", self.observation)

    def write(self, relative, data):
        target = self.workspace / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(data), encoding="utf-8")

    def load(self, relative):
        return json.loads((self.workspace / relative).read_text())

    def command(self, *args, expected=0, env=None):
        proc = subprocess.run([sys.executable, "-m", "jev_cli_bootstrap", *args, "--workspace", str(self.workspace)], cwd=self.workspace, env={**self.env, **(env or {})}, capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, expected, proc.stdout + proc.stderr)
        if args[:2] == ("consent", "authorize"):
            self._test_consent_authorized = True
        elif args[:2] == ("consent", "revoke"):
            self._test_consent_authorized = False
        return json.loads(proc.stdout)
    def live_response(self):
        options = {
            "evidence": ("sufficient", "need_capture", "need_reference", "conflicting", "unknown"),
            "domain": ("capture", "hierarchy", "geometry", "material", "rigging", "animation", "vfx", "mixed", "unknown"),
            "specRelation": ("supported", "contradicted", "underspecified", "unknown"),
            "scope": ("parameter_patch", "component_rebuild", "cross_component", "unknown"),
        }
        selected = {"evidence": "sufficient", "domain": "material", "specRelation": "supported", "scope": "parameter_patch"}
        answers = {}
        for question, values in options.items():
            choice = selected[question]
            answers[question] = {
                "type": "choice", "choice": choice,
                "probabilities": {value: float(value == choice) for value in values},
                "confidence": 1.0,
            }
        return {"model": "jev-1.13.0", "answers": answers, "usage": {"input_tokens": 12, "output_tokens": 8}}

    def command_live(self, *args, expected=0, response=None, env=None):
        self.provider_calls.unlink(missing_ok=True)
        fake_env = {
            "TYPESAFE_API_KEY": "synthetic-test-only-key",
            "JEV_TEST_PROVIDER_RESPONSE": json.dumps(response if response is not None else self.live_response()),
        }
        return self.command(*args, expected=expected, env={**fake_env, **(env or {})})
    def load_jev_module(self):
        tools_path = str(PLUGIN / "tools")
        harness_path = str(HARNESS)
        sys.path[:0] = [tools_path, harness_path]
        stale_core = {name: sys.modules.pop(name) for name in list(sys.modules) if name == "img2_core" or name.startswith("img2_core.")}
        try:
            with mock.patch.dict(os.environ, {"IMG2_HOME": str(self.home)}):
                spec = importlib.util.spec_from_file_location("jev_t2_transaction_test", PLUGIN / "tools" / "jev.py")
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            return module
        finally:
            for name in list(sys.modules):
                if name == "img2_core" or name.startswith("img2_core."):
                    sys.modules.pop(name)
            sys.modules.update(stale_core)
            del sys.path[:2]

    def prepare(self):
        return self.command("prepare", "--input", "observation.json")

    def gate(self, expected):
        proc = subprocess.run([sys.executable, "-m", "img2_core.gate_runner", "--plugin-dir", str(PLUGIN), "--workspace", str(self.workspace)], cwd=self.workspace, env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, expected, proc.stdout + proc.stderr)
        return json.loads(proc.stdout)

    CHECKS = ("01-scene-classify", "02-subject-inventory", "03-placement-consistency", "04-scale-anchors", "05-occlusion", "06-terrain-grounding", "07-material-independence", "08-multi-angle-legality", "09-llm-vs-forge-agreement", "10-code-only-contract", "11-screenshot-gate", "12-ip-provenance-hygiene")

    def seed_environment_files(self, quality_value, phase="before", quality_measurements=None):
        reference_path = self.workspace / "synthetic/reference.png"
        reference_path.parent.mkdir(parents=True, exist_ok=True)
        reference_path.write_bytes(b"synthetic reference view")
        source_hash = hashlib.sha256(reference_path.read_bytes()).hexdigest()
        intake = {"sceneClassification": {"kind": "room"}, "sourceViews": [{"id": "reference", "path": "synthetic/reference.png", "sha256": source_hash, "width": 640, "height": 480}], "syntheticFixturePhase": phase}
        spec = {"reviewViewpoints": ["reference", "orbit-a"], "syntheticFixturePhase": phase}
        screenshots = {name: "synthetic/review/" + name + ".png" for name in ("reference", "fixed", "orbit-a")}
        review = {
            "screenshots": screenshots, "sideBySide": "synthetic/review/side-by-side.png",
            "subjectPasses": {"subject-a": "synthetic/review/subjects/subject-a.png"},
            "regionPasses": {"region-a": "synthetic/review/regions/region-a.png"},
            "camera": {"projection": "orthographic", "position": [0, 0, 8]},
            "renderer": "synthetic-renderer", "resolution": [128, 96], "exposure": 1.0,
            "toneMapping": "linear", "background": "neutral-gray", "environment": "synthetic-studio",
            "iblContribution": 0.25, "qualityMeasurementMethod": "synthetic pixel fixture readback",
            "syntheticFixturePhase": phase,
            "qualityMeasurements": quality_measurements if quality_measurements is not None else [{"featureId": "quality", "value": quality_value, "unit": "score", "direction": "higher-is-better"}],
        }
        self.write(".img2/artifacts/environment/scene-intake.json", intake)
        self.write(".img2/artifacts/environment/scene-spec.json", spec)
        self.write(".img2/artifacts/environment/scene-review.json", review)
        self.write(".img2/artifacts/environment/reference-provenance.json", {"syntheticOnly": True})
        source = self.workspace / ".img2/artifacts/environment/createEnvironmentRoomsModel.ts"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("// synthetic T2 room adapter evidence", encoding="utf-8")
        for path in [*screenshots.values(), review["sideBySide"], *review["subjectPasses"].values(), *review["regionPasses"].values()]:
            target = self.workspace / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(("synthetic PNG fixture " + path).encode())

    def current_dependency_paths(self):
        review = self.load(".img2/artifacts/environment/scene-review.json")
        return [
            ".img2/artifacts/environment/scene-intake.json",
            ".img2/artifacts/environment/scene-spec.json",
            ".img2/artifacts/environment/scene-review.json",
            ".img2/artifacts/environment/reference-provenance.json",
            ".img2/artifacts/environment/createEnvironmentRoomsModel.ts",
            *review["screenshots"].values(), review["sideBySide"],
            *review["subjectPasses"].values(), *review["regionPasses"].values(),
        ]

    def synthetic_gate(self, status="pass", failed_row=None, dependency="before", adapter="room"):
        evaluator = {"id": "environment-gate", "plugin": "environment", "version": 2, "adapter": adapter, "checks": list(self.CHECKS), "checkDigest": "c" * 64}
        rows = [{"id": cid, "status": "unevaluated" if cid == failed_row == "incomplete" else "fail" if cid == failed_row else "pass", "reasons": ["synthetic failure"] if cid == failed_row else [], "evidence": {}} for cid in self.CHECKS]
        actual_status = "fail" if failed_row else status
        reasons = ["synthetic failure"] if failed_row else []
        evidence = {"gates": rows, "unevaluated": [failed_row] if failed_row == "incomplete" else []}
        files = []
        for dep_path in self.current_dependency_paths():
            data = (self.workspace / dep_path).read_bytes()
            files.append({"path": dep_path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        core = {"evaluator": evaluator, "files": files, "status": actual_status, "reasons": reasons, "evidence": evidence}
        snapshot_id = hashlib.sha256(json.dumps(core, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        result_path = ".img2/artifacts/environment/gate-results/" + snapshot_id + ".json"
        gate = {"kind": "img2.gate-verdict", "version": 1, "gate": "environment", "plugin": "environment", "status": actual_status, "reasons": reasons, "evidence": evidence, "evaluator": evaluator, "snapshot": {"id": snapshot_id, "path": result_path, "evaluator": evaluator, "files": files}, "snapshotId": snapshot_id, "snapshotPath": result_path, "resultPath": result_path}
        target = self.workspace / result_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(gate, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        return result_path, gate
    def bind_gate(self, path, gate):
        self.observation["state"]["sceneKind"] = gate["evaluator"]["adapter"]
        self.observation["state"]["gates"] = [
            {
                "id": row["id"],
                "status": "not_run" if row["status"] == "unevaluated" else row["status"],
                "blocking": True,
                "coverage": "none" if row["status"] == "unevaluated" else "complete",
                "reasonCodes": ["provenance-missing"] if row["status"] == "fail" and row["id"] == "12-ip-provenance-hygiene" else ["gate-failed"] if row["status"] == "fail" else ["gate-unevaluated"] if row["status"] == "unevaluated" else [],
                "evidenceIds": ["build"],
            }
            for row in gate["evidence"]["gates"]
        ]
        self.observation["bindings"] = [
            dict(binding, path=path) if binding["role"] == "evaluation" else binding
            for binding in self.observation["bindings"]
        ]

    def context_hash(self):
        intake = self.load(".img2/artifacts/environment/scene-intake.json")
        spec = self.load(".img2/artifacts/environment/scene-spec.json")
        review = self.load(".img2/artifacts/environment/scene-review.json")
        projection = {
            "adapter": "room", "sourceViews": [{"id": view["id"], "sha256": view["sha256"]} for view in intake["sourceViews"]],
            "reviewViewpoints": spec["reviewViewpoints"],
            **{key: review[key] for key in ("camera", "renderer", "resolution", "exposure", "toneMapping", "background", "environment", "iblContribution", "qualityMeasurementMethod")},
        }
        return hashlib.sha256(json.dumps(projection, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def v2_outcome(self, label="improved", *, bad_rows=False, bind_before=True, identical_context=False, metric_count=1, metric_digits=None):
        evaluator = {"id": "environment-gate", "version": "2", "adapter": "room", "checksDigest": "c" * 64}
        if metric_digits is None:
            feature_ids = ["quality"]
            before_values = {"quality": 0.5}
            after_values = {"quality": {"unchanged": 0.5, "regressed": 0.1}.get(label, 0.9)}
        else:
            feature_ids = ["quality_" + format(index, "02d") for index in range(metric_count)]
            base = 10 ** metric_digits
            before_values = {feature: base + index for index, feature in enumerate(feature_ids)}
            after_values = {
                feature: before_values[feature] if label == "unchanged" else before_values[feature] - 1 if label == "regressed" else before_values[feature] + 1
                for feature in feature_ids
            }
        before_metrics = [{"featureId": feature, "value": before_values[feature], "unit": "score", "direction": "higher-is-better"} for feature in feature_ids]
        before_review_rows = [{key: row[key] for key in ("featureId", "value", "unit", "direction")} for row in before_metrics]
        self.seed_environment_files(before_metrics[0]["value"], quality_measurements=before_review_rows)
        before_path, before = self.synthetic_gate(failed_row="12-ip-provenance-hygiene", dependency="before")
        historical_paths = []
        for name in ("scene-intake.json", "scene-spec.json", "scene-review.json"):
            original = ".img2/artifacts/environment/" + name
            archived = "synthetic/historical/" + name
            target = self.workspace / archived
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((self.workspace / original).read_bytes())
            historical_paths.append(archived)
        if bind_before:
            request_gate_path, request_gate = before_path, before
        else:
            request_gate_path, request_gate = self.synthetic_gate(failed_row="11-screenshot-gate", dependency="request")
        self.bind_gate(request_gate_path, request_gate)
        self.write("observation.json", self.observation)
        self.prepare()
        if not self._test_consent_authorized:
            self.command("consent", "authorize")
        recommendation = self.command_live("route")
        report = self.load(recommendation["artifact"])
        evidence = [before_path, *historical_paths]
        after = None
        after_metrics = [{"featureId": feature, "value": after_values[feature], "unit": "score", "direction": "higher-is-better"} for feature in feature_ids]
        after_review_rows = [{key: row[key] for key in ("featureId", "value", "unit", "direction")} for row in after_metrics]
        if label != "build_failed":
            self.seed_environment_files(after_metrics[0]["value"], phase="before" if identical_context else "after", quality_measurements=after_review_rows)
            failed_row = "incomplete" if bad_rows else "12-ip-provenance-hygiene" if label == "regressed" else None
            after_path, after_gate = self.synthetic_gate(failed_row=failed_row, dependency="after")
            after = after_gate["snapshot"]
            evidence.extend([after_path, ".img2/artifacts/environment/scene-intake.json", ".img2/artifacts/environment/scene-spec.json", ".img2/artifacts/environment/scene-review.json"])
        self.write("failure/build.log", {"syntheticOnly": True, "result": "fixture failure"})
        if label == "build_failed": evidence.append("failure/build.log")
        measurement_context_hash = self.context_hash()
        outcome = {
            "kind": "img2.repair-outcome", "version": 2, "recommendationId": report["id"],
            "attemptId": "attempt-" + label, "outcome": label,
            "recommendationHash": hashlib.sha256(json.dumps(report, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "approvedAction": {"action": "refine-code", "tactic": "parameter-patch"},
            "actualAction": {"action": "refine-code", "tactic": "parameter-patch"},
            "recommendationFollowed": True, "assetAdapter": "room",
            "beforeSnapshot": {"id": before["snapshotId"], "evaluator": evaluator, "measurementContextHash": measurement_context_hash, "metrics": before_metrics},
            "afterSnapshot": None if after is None else {"id": after["id"], "evaluator": evaluator, "measurementContextHash": measurement_context_hash, "metrics": after_metrics},
            "measurements": {"rows": [] if after is None else [{"featureId": feature, "beforeValue": before_values[feature], "afterValue": after_values[feature], "unit": "score", "direction": "higher-is-better"} for feature in feature_ids]},
            "adjudication": {"status": "independent", "adjudicatorId": "synthetic-reviewer", "method": "test-fixture", "recordedAt": "2026-09-28T12:00:00Z"},
            "evidencePaths": evidence, "buildFailureEvidencePaths": ["failure/build.log"] if label == "build_failed" else [],
            "evidenceClass": "synthetic",
        }
        self.write("outcome-v2.json", outcome)
        return recommendation, outcome

    def record_v2(self, label="improved", **kwargs):
        recommendation, outcome = self.v2_outcome(label, **kwargs)
        result = self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation["artifact"])
        return result, outcome

    def test_v2_rejects_stale_after_dependency_and_incomplete_gate(self):
        recommendation, outcome = self.v2_outcome()
        dependency = outcome["evidencePaths"][-1]
        (self.workspace / dependency).write_text("stale synthetic dependency", encoding="utf-8")
        self.write("outcome-v2.json", outcome)
        self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation["artifact"], expected=2)
        self.assertFalse(list((self.workspace / ".img2/artifacts/jev/outcomes/archive/records").glob("*.json")))
        self.assertFalse(list((self.workspace / ".img2/artifacts/jev/outcomes/archive/pairs").glob("*/*.json")))
        recommendation, outcome = self.v2_outcome(bad_rows=True)
        self.write("outcome-v2.json", outcome)
        self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation["artifact"], expected=2)
        self.assertFalse(list((self.workspace / ".img2/artifacts/jev/outcomes/archive/records").glob("*.json")))

    def test_v2_rejects_metric_and_measurement_context_mismatches(self):
        recommendation, outcome = self.v2_outcome()
        outcome["beforeSnapshot"]["measurementContextHash"] = "f" * 64
        outcome["afterSnapshot"]["measurementContextHash"] = "f" * 64
        self.write("outcome-v2.json", outcome)
        self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation["artifact"], expected=2)
        recommendation, outcome = self.v2_outcome()
        outcome["beforeSnapshot"]["metrics"][0]["value"] = 0.4
        outcome["measurements"]["rows"][0]["beforeValue"] = 0.4
        self.write("outcome-v2.json", outcome)
        self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation["artifact"], expected=2)

    def test_v2_rejects_missing_current_after_gate_dependency(self):
        recommendation, outcome = self.v2_outcome()
        missing = outcome["evidencePaths"][-1]
        (self.workspace / missing).unlink()
        self.write("outcome-v2.json", outcome)
        self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation["artifact"], expected=2)
        self.assertFalse(list((self.workspace / ".img2/artifacts/jev/outcomes/archive/records").glob("*.json")))
        self.assertFalse(list((self.workspace / ".img2/artifacts/jev/outcomes/archive/pairs").glob("*/*.json")))
    def test_v2_rejects_incomplete_extra_and_reordered_after_manifests(self):
        for mutation in ("omission", "extra", "reorder"):
            with self.subTest(mutation=mutation):
                recommendation, outcome = self.v2_outcome()
                gate_path = next(path for path in outcome["evidencePaths"] if self.load(path).get("snapshotId") == outcome["afterSnapshot"]["id"])
                gate = self.load(gate_path)
                files = list(gate["snapshot"]["files"])
                if mutation == "omission":
                    files.pop()
                elif mutation == "extra":
                    extra_path = "synthetic/review/unexpected.png"
                    extra = self.workspace / extra_path
                    extra.parent.mkdir(parents=True, exist_ok=True)
                    extra.write_bytes(b"synthetic unexpected dependency")
                    data = extra.read_bytes()
                    files.append({"path": extra_path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
                else:
                    files[-1], files[-2] = files[-2], files[-1]
                gate["snapshot"]["files"] = files
                core = {"evaluator": gate["evaluator"], "files": files, "status": gate["status"], "reasons": gate["reasons"], "evidence": gate["evidence"]}
                snapshot_id = hashlib.sha256(json.dumps(core, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                new_path = ".img2/artifacts/environment/gate-results/" + snapshot_id + ".json"
                gate["snapshot"]["id"] = snapshot_id
                gate["snapshot"]["path"] = new_path
                gate["snapshotId"] = snapshot_id
                gate["snapshotPath"] = new_path
                gate["resultPath"] = new_path
                target = self.workspace / new_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(json.dumps(gate, sort_keys=True, separators=(",", ":")), encoding="utf-8")
                outcome["evidencePaths"][outcome["evidencePaths"].index(gate_path)] = new_path
                outcome["afterSnapshot"]["id"] = snapshot_id
                self.write("outcome-v2.json", outcome)
                self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation["artifact"], expected=2)
                self.assertFalse(list((self.workspace / ".img2/artifacts/jev/outcomes/archive/records").glob("*.json")))
                self.assertFalse(list((self.workspace / ".img2/artifacts/jev/outcomes/archive/pairs").glob("*/*.json")))

    def test_v2_historical_before_context_uses_matching_archived_copies(self):
        result, _ = self.record_v2()
        record = self.load(result["artifact"])
        archived_sources = {entry["originalPath"] for entry in record["archivedEvidence"]}
        self.assertTrue({"synthetic/historical/scene-intake.json", "synthetic/historical/scene-spec.json", "synthetic/historical/scene-review.json"} <= archived_sources)
    def test_v2_prefers_canonical_copy_when_historical_hash_also_matches(self):
        result, outcome = self.record_v2(identical_context=True)
        for name in ("scene-intake.json", "scene-spec.json"):
            canonical = ".img2/artifacts/environment/" + name
            historical = "synthetic/historical/" + name
            self.assertIn(canonical, outcome["evidencePaths"])
            self.assertIn(historical, outcome["evidencePaths"])
            self.assertEqual((self.workspace / canonical).read_bytes(), (self.workspace / historical).read_bytes())
        self.assertEqual(self.load(result["artifact"])["evidenceClass"], "synthetic")

    def test_v2_rechecks_historical_context_hash_after_archive_copy(self):
        recommendation, outcome = self.v2_outcome()
        jev = self.load_jev_module()
        archive = jev._archive_outcome_files

        def mutate_before_copy(workspace, paths):
            (workspace / "synthetic/historical/scene-review.json").write_bytes(b"mutated synthetic historical review")
            return archive(workspace, paths)

        with mock.patch.dict(os.environ, {"IMG2_HOME": str(self.home)}):
            with mock.patch.object(jev, "_archive_outcome_files", mutate_before_copy):
                with self.assertRaises(jev.ContractError):
                    jev.run_outcome_v2(self.workspace, SimpleNamespace(recommendation=recommendation["artifact"]), outcome)
        self.assertFalse(list((self.workspace / ".img2/artifacts/jev/outcomes/archive/records").glob("*.json")))
        self.assertFalse(list((self.workspace / ".img2/artifacts/jev/outcomes/archive/pairs").glob("*/*.json")))
        self.assertFalse(list((self.workspace / ".img2/artifacts/jev/outcomes/archive").glob("*/*.blob")))
    def test_v2_decodes_the_hash_verified_context_buffer_during_replacement(self):
        recommendation, outcome = self.v2_outcome()
        jev = self.load_jev_module()
        contract_module = sys.modules["jev_contracts"]
        review_path = self.workspace / "synthetic/historical/scene-review.json"
        original_bytes = review_path.read_bytes()
        replacement_value = json.loads(original_bytes)
        replacement_value["qualityMeasurementMethod"] = "interleaved replacement must not be parsed"
        replacement_bytes = json.dumps(replacement_value, sort_keys=True, separators=(",", ":")).encode()
        read_context = jev._read_outcome_context_bytes
        decode_context = jev.decode
        decode_contract = contract_module.decode
        archive = jev._archive_outcome_files
        read_observed, verified_buffer_decoded, mutated_file_decoded, restored_for_archive = [], [], [], []

        def replace_after_read(workspace, path, manifest):
            data = read_context(workspace, path, manifest)
            if path == "synthetic/historical/scene-review.json" and data == original_bytes:
                review_path.write_bytes(replacement_bytes)
                read_observed.append(path)
            return data

        def decode_verified_buffer(data):
            if data == original_bytes:
                self.assertEqual(review_path.read_bytes(), replacement_bytes)
                verified_buffer_decoded.append(True)
            return decode_context(data)

        def detect_path_reload(data):
            if data == replacement_bytes:
                mutated_file_decoded.append(True)
            return decode_contract(data)

        def restore_before_archive(workspace, paths):
            self.assertEqual(review_path.read_bytes(), replacement_bytes)
            review_path.write_bytes(original_bytes)
            restored_for_archive.append(True)
            return archive(workspace, paths)

        try:
            with mock.patch.dict(os.environ, {"IMG2_HOME": str(self.home)}):
                with mock.patch.object(jev, "_read_outcome_context_bytes", replace_after_read), mock.patch.object(jev, "decode", decode_verified_buffer):
                    with mock.patch.object(contract_module, "decode", detect_path_reload), mock.patch.object(jev, "_archive_outcome_files", restore_before_archive):
                        result = jev.run_outcome_v2(self.workspace, SimpleNamespace(recommendation=recommendation["artifact"]), outcome)
        finally:
            if review_path.read_bytes() != original_bytes:
                review_path.write_bytes(original_bytes)
        self.assertEqual(read_observed, ["synthetic/historical/scene-review.json"])
        self.assertEqual(verified_buffer_decoded, [True])
        self.assertFalse(mutated_file_decoded)
        self.assertEqual(restored_for_archive, [True])
        record = self.load(result["artifact"])
        archived = next(item for item in record["archivedEvidence"] if item["originalPath"] == "synthetic/historical/scene-review.json")
        self.assertEqual(archived["sha256"], hashlib.sha256(original_bytes).hexdigest())

    def test_v2_archive_rollback_is_serialized_against_shared_blob_commit(self):
        recommendation, first = self.v2_outcome()
        second = copy.deepcopy(first)
        second["attemptId"] = "attempt-concurrent-b"
        jev = self.load_jev_module()
        original_commit = jev._commit_outcome_pair_index
        original_flock = fcntl.flock
        first_at_commit = threading.Event()
        release_first = threading.Event()
        second_lock_attempted = threading.Event()
        second_lock_contended = threading.Event()
        second_lock_bypassed = threading.Event()
        results = {}

        def injected_commit(path, outcome, artifact):
            if outcome["attemptId"] == first["attemptId"]:
                first_at_commit.set()
                if not release_first.wait(10):
                    raise RuntimeError("test barrier timed out")
                raise RuntimeError("injected first-attempt commit failure")
            return original_commit(path, outcome, artifact)

        def observe_lock(fd, operation):
            if threading.current_thread().name == "outcome-second" and operation == fcntl.LOCK_EX:
                second_lock_attempted.set()
                try:
                    original_flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as error:
                    if error.errno not in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                        raise
                    second_lock_contended.set()
                else:
                    second_lock_bypassed.set()
            return original_flock(fd, operation)

        def record(label, outcome):
            try:
                results[label] = jev.run_outcome_v2(self.workspace, SimpleNamespace(recommendation=recommendation["artifact"]), outcome)
            except Exception as error:
                results[label] = error

        first_thread = threading.Thread(target=record, name="outcome-first", args=("first", first))
        second_thread = threading.Thread(target=record, name="outcome-second", args=("second", second))
        with mock.patch.dict(os.environ, {"IMG2_HOME": str(self.home)}), mock.patch.object(jev, "_commit_outcome_pair_index", injected_commit), mock.patch.object(jev.fcntl, "flock", observe_lock):
            first_thread.start()
            self.assertTrue(first_at_commit.wait(10), "first attempt did not reach injected commit barrier")
            second_thread.start()
            try:
                self.assertTrue(second_lock_attempted.wait(10), "second attempt did not attempt the archive lock")
                self.assertTrue(second_lock_contended.wait(10), "second attempt did not observe nonblocking lock contention")
                self.assertFalse(second_lock_bypassed.is_set(), "second attempt acquired the archive lock before rollback")
            finally:
                release_first.set()
            first_thread.join(10)
            second_thread.join(10)
        self.assertFalse(first_thread.is_alive())
        self.assertFalse(second_thread.is_alive())
        self.assertIsInstance(results["first"], RuntimeError)
        self.assertEqual(results["second"]["status"], "recorded")
        record = self.load(results["second"]["artifact"])
        self.assertEqual(record["attemptId"], second["attemptId"])
        for entry in record["archivedEvidence"]:
            blob = self.workspace / entry["archivedPath"]
            self.assertTrue(blob.is_file())
            self.assertEqual(hashlib.sha256(blob.read_bytes()).hexdigest(), entry["sha256"])

    def test_v2_archives_twelve_evidence_files(self):
        recommendation, outcome = self.v2_outcome()
        for index in range(4):
            relative = "selected/synthetic-evidence-" + str(index) + ".bin"
            target = self.workspace / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(("synthetic selected evidence " + str(index)).encode())
            outcome["evidencePaths"].append(relative)
        self.assertEqual(len(outcome["evidencePaths"]), 12)
        self.write("outcome-v2.json", outcome)
        result = self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation["artifact"])
        self.assertEqual(len(self.load(result["artifact"])["archivedEvidence"]), 12)
    def test_v2_rejects_expanded_oversize_record_before_record_publish(self):
        input_limit = 128 * 1024

        def make_case(digits):
            recommendation, outcome = self.v2_outcome(metric_count=32, metric_digits=digits)
            for index in range(4):
                relative = "selected/boundary-evidence-" + str(index) + ".bin"
                target = self.workspace / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(("synthetic boundary evidence " + str(index)).encode())
                outcome["evidencePaths"].append(relative)
            self.write("outcome-v2.json", outcome)
            input_size = (self.workspace / "outcome-v2.json").stat().st_size
            gate_paths = {}
            archived_evidence = []
            for relative in outcome["evidencePaths"]:
                source = self.workspace / relative
                data = source.read_bytes()
                sha = hashlib.sha256(data).hexdigest()
                archived_evidence.append({
                    "originalPath": relative,
                    "archivedPath": ".img2/artifacts/jev/outcomes/archive/" + sha[:2] + "/" + sha + ".blob",
                    "size": len(data), "sha256": sha,
                })
                if relative.endswith(".json"):
                    candidate = json.loads(data)
                    if isinstance(candidate, dict) and candidate.get("kind") == "img2.gate-verdict":
                        gate_paths[candidate["snapshotId"]] = relative
            expanded = {
                **outcome, "verification": "environment-gate-and-archived-evidence",
                "archivedEvidence": archived_evidence,
                "beforeGatePath": gate_paths[outcome["beforeSnapshot"]["id"]],
                "afterGatePath": gate_paths[outcome["afterSnapshot"]["id"]],
                "advisoryOnly": True,
            }
            expanded_size = len(json.dumps(expanded, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()) + 1
            return recommendation, input_size, expanded_size

        digits = 700
        for _ in range(8):
            recommendation, input_size, expanded_size = make_case(digits)
            if input_size <= input_limit < expanded_size:
                break
            if input_size > input_limit:
                digits -= max(1, (input_size - input_limit + 127) // 128)
            else:
                digits += max(1, (input_limit - expanded_size) // 128 + 1)
        else:
            self.fail("could not construct a bounded input with an oversized expanded record")
        self.assertEqual(len(self.load("outcome-v2.json")["evidencePaths"]), 12)
        self.assertLessEqual(input_size, input_limit)
        self.assertGreater(expanded_size, input_limit)
        result = self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation["artifact"], expected=2)
        self.assertIn("128KiB", result["reason"])
        self.assertFalse(list((self.workspace / ".img2/artifacts/jev/outcomes/archive/records").glob("*.json")))
        self.assertFalse(list((self.workspace / ".img2/artifacts/jev/outcomes/archive/pairs").glob("*/*.json")))
        self.assertFalse(list((self.workspace / ".img2/artifacts/jev/outcomes/archive").glob("*/*.blob")))

    def test_v2_duplicate_pair_refuses_exact_and_altered_payload_without_partial_publish(self):
        recorded, outcome = self.record_v2()
        records_dir = self.workspace / ".img2/artifacts/jev/outcomes/archive/records"
        archive_dir = self.workspace / ".img2/artifacts/jev/outcomes/archive"
        index_dir = self.workspace / ".img2/artifacts/jev/outcomes/archive/pairs"
        before_records = {path.name for path in records_dir.glob("*.json")}
        before_blobs = {path.name for path in archive_dir.glob("*/*.blob")}
        before_indexes = {path.name for path in index_dir.glob("*/*.json")}
        self.assertTrue(before_indexes)
        recommendation_path = next((self.workspace / ".img2/artifacts/jev/records").glob("*.json"))
        for changed in (outcome, copy.deepcopy(outcome)):
            if changed is not outcome:
                changed["adjudication"]["method"] = "different-synthetic-review-method"
            self.write("outcome-v2.json", changed)
            self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation_path.relative_to(self.workspace).as_posix(), expected=2)
            self.assertEqual({path.name for path in records_dir.glob("*.json")}, before_records)
            self.assertEqual({path.name for path in archive_dir.glob("*/*.blob")}, before_blobs)
            self.assertEqual({path.name for path in index_dir.glob("*/*.json")}, before_indexes)
        self.assertEqual(recorded["status"], "recorded")



    def test_v2_records_valid_quality_labels_and_build_failure(self):
        for label in ("improved", "unchanged", "regressed", "build_failed"):
            with self.subTest(label=label):
                recommendation, outcome = self.v2_outcome(label)
                state_path = self.workspace / ".img2/state.json"
                state_before = state_path.read_bytes()
                result = self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation["artifact"])
                self.assertEqual(state_path.read_bytes(), state_before)
                archived = self.load(result["artifact"])
                self.assertEqual(archived["outcome"], label)
                self.assertEqual(archived["evidenceClass"], "synthetic")
                self.assertEqual(len(archived["archivedEvidence"]), len(outcome["evidencePaths"]))
                for source, entry in zip(outcome["evidencePaths"], archived["archivedEvidence"]):
                    stored = self.workspace / entry["archivedPath"]
                    self.assertEqual(entry["originalPath"], source)
                    self.assertEqual(entry["size"], stored.stat().st_size)
                    self.assertEqual(entry["sha256"], hashlib.sha256(stored.read_bytes()).hexdigest())
                record_digest = hashlib.sha256(json.dumps(archived, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                self.assertEqual(result["artifact"], ".img2/artifacts/jev/outcomes/archive/records/" + record_digest + ".json")
                if label == "build_failed":
                    self.assertIsNone(archived["afterGatePath"])
                    self.assertEqual(archived["buildFailureEvidencePaths"], ["failure/build.log"])

    def test_v2_rejects_recommendation_hash_mismatch(self):
        recommendation, outcome = self.v2_outcome()
        outcome["recommendationHash"] = "0" * 64
        self.write("outcome-v2.json", outcome)
        self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation["artifact"], expected=2)

    def test_v2_archives_evidence_and_survives_later_workspace_changes(self):
        result, outcome = self.record_v2()
        record = self.load(result["artifact"])
        for item in outcome["evidencePaths"]: (self.workspace / item).write_text("later workspace change", encoding="utf-8")
        for item in record["archivedEvidence"]:
            archived = self.workspace / item["archivedPath"]
            self.assertEqual(hashlib.sha256(archived.read_bytes()).hexdigest(), item["sha256"])

    def test_v2_rejects_unbound_before_gate_and_wrong_snapshot_id(self):
        recommendation, outcome = self.v2_outcome(bind_before=False)
        self.write("outcome-v2.json", outcome)
        self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation["artifact"], expected=2)
        recommendation, outcome = self.v2_outcome()
        outcome["afterSnapshot"]["id"] = "f" * 64
        self.write("outcome-v2.json", outcome)
        self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation["artifact"], expected=2)

    def test_v2_rejects_unsafe_symlink_and_oversized_evidence_without_partial_archive(self):
        recommendation, outcome = self.v2_outcome()
        outcome["evidencePaths"].append("../unsafe.bin")
        self.write("outcome-v2.json", outcome)
        self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation["artifact"], expected=2)
        recommendation, outcome = self.v2_outcome()
        (self.workspace / "outside.bin").write_bytes(b"outside")
        (self.workspace / "symlink.bin").symlink_to(self.workspace / "outside.bin")
        outcome["evidencePaths"].append("symlink.bin")
        self.write("outcome-v2.json", outcome)
        self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation["artifact"], expected=2)
        self.assertFalse(list((self.workspace / ".img2/artifacts/jev/outcomes/archive/.tmp").glob("*")))
        recommendation, outcome = self.v2_outcome()
        oversized = self.workspace / "oversized.bin"
        with oversized.open("wb") as stream: stream.truncate(64 * 1024 * 1024 + 1)
        outcome["evidencePaths"].append("oversized.bin")
        self.write("outcome-v2.json", outcome)
        self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation["artifact"], expected=2)
        self.assertFalse(list((self.workspace / ".img2/artifacts/jev/outcomes/archive/records").glob("*.json")))
        self.assertFalse(list((self.workspace / ".img2/artifacts/jev/outcomes/archive/pairs").glob("*/*.json")))
        self.assertFalse(list((self.workspace / ".img2/artifacts/jev/outcomes/archive").glob("*/*.blob")))
        self.assertFalse(list((self.workspace / ".img2/artifacts/jev/outcomes/archive/.tmp").glob("*")))
    def test_v2_rejects_committed_pair_without_reservation_index(self):
        recorded, _ = self.record_v2()
        records_dir = self.workspace / ".img2/artifacts/jev/outcomes/archive/records"
        archive_dir = self.workspace / ".img2/artifacts/jev/outcomes/archive"
        index_dir = self.workspace / ".img2/artifacts/jev/outcomes/archive/pairs"
        indexes = list(index_dir.glob("*/*.json"))
        self.assertTrue(indexes)
        for path in indexes:
            path.unlink()
        self.assertFalse(list(index_dir.glob("*/*.json")))
        before_records = {path.name for path in records_dir.glob("*.json")}
        before_blobs = {path.name for path in archive_dir.glob("*/*.blob")}
        report_path = next((self.workspace / ".img2/artifacts/jev/records").glob("*.json"))
        rejection = self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", report_path.relative_to(self.workspace).as_posix(), expected=2)
        self.assertIn("duplicate recommendationId+attemptId", rejection["reason"])
        self.assertEqual({path.name for path in records_dir.glob("*.json")}, before_records)
        self.assertEqual({path.name for path in archive_dir.glob("*/*.blob")}, before_blobs)
        self.assertFalse(list(index_dir.glob("*/*.json")))
    def test_v2_fails_closed_on_oversized_indexless_committed_record(self):
        recorded, _ = self.record_v2()
        index_dir = self.workspace / ".img2/artifacts/jev/outcomes/archive/pairs"
        indexes = list(index_dir.glob("*/*.json"))
        self.assertTrue(indexes)
        for path in indexes:
            path.unlink()
        self.assertFalse(list(index_dir.glob("*/*.json")))
        archive_dir = self.workspace / ".img2/artifacts/jev/outcomes/archive"
        before_blobs = {path.name for path in archive_dir.glob("*/*.blob")}
        (self.workspace / recorded["artifact"]).write_bytes(b" " * (128 * 1024 + 1))
        recommendation_path = next((self.workspace / ".img2/artifacts/jev/records").glob("*.json"))
        rejection = self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation_path.relative_to(self.workspace).as_posix(), expected=2)
        self.assertIn("unreadable", rejection["reason"])
        self.assertFalse(list(index_dir.glob("*/*.json")))
        self.assertEqual({path.name for path in archive_dir.glob("*/*.blob")}, before_blobs)

    def test_v2_fails_closed_on_hash_named_incomplete_record_without_index(self):
        recorded, outcome = self.record_v2()
        records_dir = self.workspace / ".img2/artifacts/jev/outcomes/archive/records"
        archive_dir = self.workspace / ".img2/artifacts/jev/outcomes/archive"
        index_dir = self.workspace / ".img2/artifacts/jev/outcomes/archive/pairs"
        indexes = list(index_dir.glob("*/*.json"))
        self.assertTrue(indexes)
        for index in indexes:
            index.unlink()
        self.assertFalse(list(index_dir.glob("*/*.json")))
        (self.workspace / recorded["artifact"]).unlink()
        incomplete = {
            "kind": "img2.repair-outcome", "version": 2,
            "recommendationId": outcome["recommendationId"], "attemptId": outcome["attemptId"],
            "verification": "environment-gate-and-archived-evidence", "archivedEvidence": [],
        }
        serialized = json.dumps(incomplete, sort_keys=True, separators=(",", ":")).encode()
        malformed_path = records_dir / (hashlib.sha256(serialized).hexdigest() + ".json")
        malformed_path.write_bytes(serialized + bytes((10,)))
        before_records = {path.name for path in records_dir.glob("*.json")}
        before_blobs = {path.name for path in archive_dir.glob("*/*.blob")}
        recommendation_path = next((self.workspace / ".img2/artifacts/jev/records").glob("*.json"))
        rejection = self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation_path.relative_to(self.workspace).as_posix(), expected=2)
        self.assertIn("malformed", rejection["reason"])
        self.assertEqual({path.name for path in records_dir.glob("*.json")}, before_records)
        self.assertEqual({path.name for path in archive_dir.glob("*/*.blob")}, before_blobs)
        self.assertFalse(list(index_dir.glob("*/*.json")))

    def test_v2_fails_closed_when_record_directory_scan_is_denied(self):
        recorded, outcome = self.record_v2()
        records_dir = self.workspace / ".img2/artifacts/jev/outcomes/archive/records"
        archive_dir = self.workspace / ".img2/artifacts/jev/outcomes/archive"
        index_dir = self.workspace / ".img2/artifacts/jev/outcomes/archive/pairs"
        indexes = list(index_dir.glob("*/*.json"))
        self.assertTrue(indexes)
        for index in indexes:
            index.unlink()
        self.assertFalse(list(index_dir.glob("*/*.json")))
        before_records = {path.name for path in records_dir.glob("*.json")}
        before_blobs = {path.relative_to(archive_dir).as_posix(): (path.stat().st_size, path.stat().st_mtime_ns) for path in archive_dir.glob("*/*.blob")}
        outcome["adjudication"]["method"] = "altered same-pair synthetic adjudication"
        recommendation_path = next((self.workspace / ".img2/artifacts/jev/records").glob("*.json")).relative_to(self.workspace).as_posix()
        jev = self.load_jev_module()
        original_scandir = jev.os.scandir

        def denied_scan(path):
            if Path(path) == records_dir:
                raise PermissionError("synthetic outcome-record directory denial")
            return original_scandir(path)

        with mock.patch.object(jev.os, "scandir", denied_scan):
            with self.assertRaises(jev.ContractError) as error:
                jev.run_outcome_v2(self.workspace, SimpleNamespace(recommendation=recommendation_path), outcome)
        self.assertIn("cannot enumerate outcome record directory", str(error.exception))
        self.assertEqual({path.name for path in records_dir.glob("*.json")}, before_records)
        self.assertFalse(list(index_dir.glob("*/*.json")))
        self.assertEqual({path.relative_to(archive_dir).as_posix(): (path.stat().st_size, path.stat().st_mtime_ns) for path in archive_dir.glob("*/*.blob")}, before_blobs)

    def test_v2_indexless_scan_decodes_bounded_record_buffer_without_reopen(self):
        recorded, _ = self.record_v2()
        records_dir = self.workspace / ".img2/artifacts/jev/outcomes/archive/records"
        archive_dir = self.workspace / ".img2/artifacts/jev/outcomes/archive"
        index_dir = self.workspace / ".img2/artifacts/jev/outcomes/archive/pairs"
        record_path = self.workspace / recorded["artifact"]
        original_bytes = record_path.read_bytes()
        indexes = list(index_dir.glob("*/*.json"))
        self.assertTrue(indexes)
        for index in indexes:
            index.unlink()
        self.assertFalse(list(index_dir.glob("*/*.json")))
        outcome = self.load("outcome-v2.json")
        jev = self.load_jev_module()
        read_record = jev._read_persisted_outcome_record_bytes
        original_path_read = Path.read_bytes
        read_buffers = []
        replacement_size = 8 * 1024 * 1024

        def replace_after_bounded_read(workspace, relative):
            buffer = read_record(workspace, relative)
            if relative == recorded["artifact"]:
                read_buffers.append(buffer)
                with record_path.open("wb") as stream:
                    stream.truncate(replacement_size)
            return buffer

        def reject_record_reopen(path):
            if Path(path) == record_path:
                raise AssertionError("committed record path was reopened after bounded read")
            return original_path_read(path)

        before_records = {path.name for path in records_dir.glob("*.json")}
        before_blobs = {path.relative_to(archive_dir).as_posix(): (path.stat().st_size, path.stat().st_mtime_ns) for path in archive_dir.glob("*/*.blob")}
        try:
            with mock.patch.object(jev, "_read_persisted_outcome_record_bytes", replace_after_bounded_read), mock.patch.object(Path, "read_bytes", reject_record_reopen):
                with self.assertRaises(jev.ContractError) as error:
                    jev.run_outcome_v2(self.workspace, SimpleNamespace(recommendation=next((self.workspace / ".img2/artifacts/jev/records").glob("*.json")).relative_to(self.workspace).as_posix()), outcome)
        finally:
            record_path.write_bytes(original_bytes)
        self.assertIn("duplicate recommendationId+attemptId", str(error.exception))
        self.assertEqual(read_buffers, [original_bytes])
        self.assertLessEqual(len(read_buffers[0]), 128 * 1024)
        self.assertEqual(record_path.read_bytes(), original_bytes)
        self.assertEqual({path.name for path in records_dir.glob("*.json")}, before_records)
        self.assertFalse(list(index_dir.glob("*/*.json")))
        self.assertEqual({path.relative_to(archive_dir).as_posix(): (path.stat().st_size, path.stat().st_mtime_ns) for path in archive_dir.glob("*/*.blob")}, before_blobs)

    def test_v2_indexless_record_recovery_enforces_aggregate_even_for_shared_blob_hashes(self):
        recommendation, outcome = self.v2_outcome()
        for index in range(4):
            relative = "selected/small-evidence-" + str(index) + ".bin"
            path = self.workspace / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(bytes((index,)))
            outcome["evidencePaths"].append(relative)
        self.write("outcome-v2.json", outcome)
        result = self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation["artifact"])
        record_path = self.workspace / result["artifact"]
        record = json.loads(record_path.read_text())
        records_dir = self.workspace / ".img2/artifacts/jev/outcomes/archive/records"
        archive_dir = self.workspace / ".img2/artifacts/jev/outcomes/archive"
        index_dir = self.workspace / ".img2/artifacts/jev/outcomes/archive/pairs"
        indexes = list(index_dir.glob("*/*.json"))
        self.assertTrue(indexes)
        for index in indexes:
            index.unlink()
        record_path.unlink()
        size = 40 * 1024 * 1024
        zeros = bytes(65536)
        digest = hashlib.sha256()
        for _ in range(size // len(zeros)):
            digest.update(zeros)
        sha = digest.hexdigest()
        shared_relative = ".img2/artifacts/jev/outcomes/archive/" + sha[:2] + "/" + sha + ".blob"
        shared_blob = self.workspace / shared_relative
        shared_blob.parent.mkdir(parents=True, exist_ok=True)
        with shared_blob.open("wb") as stream:
            stream.truncate(size)
        for entry in record["archivedEvidence"][:2]:
            entry.update(size=size, sha256=sha, archivedPath=shared_relative)
        serialized = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        malformed_path = records_dir / (hashlib.sha256(serialized).hexdigest() + ".json")
        malformed_path.write_bytes(serialized + bytes((10,)))
        before_records = {path.name for path in records_dir.glob("*.json")}
        before_blobs = {path.relative_to(archive_dir).as_posix(): (path.stat().st_size, path.stat().st_mtime_ns) for path in archive_dir.glob("*/*.blob")}
        outcome["attemptId"] = "attempt-fresh-recovery"
        jev = self.load_jev_module()
        with mock.patch.object(jev, "file_hash", side_effect=AssertionError("blob hashing occurred before aggregate preflight")) as blob_hash:
            with self.assertRaises(jev.ContractError) as error:
                jev.run_outcome_v2(self.workspace, SimpleNamespace(recommendation=recommendation["artifact"]), outcome)
        blob_hash.assert_not_called()
        self.assertIn("malformed", str(error.exception))
        self.assertFalse(list(index_dir.glob("*/*.json")))
        self.assertIn("64MiB", str(error.exception.__cause__))
        self.assertEqual({path.name for path in records_dir.glob("*.json")}, before_records)
        self.assertTrue(before_records)
        self.assertEqual({path.relative_to(archive_dir).as_posix(): (path.stat().st_size, path.stat().st_mtime_ns) for path in archive_dir.glob("*/*.blob")}, before_blobs)

    def test_v2_allows_historical_before_dependencies_but_build_failure_rejects_after_gate(self):
        recommendation, outcome = self.v2_outcome()
        (self.workspace / "synthetic/before.json").write_text("old before dependency", encoding="utf-8")
        self.write("outcome-v2.json", outcome)
        self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation["artifact"])
        recommendation, outcome = self.v2_outcome("build_failed")
        extra_path, _ = self.synthetic_gate(dependency="unexpected-after")
        outcome["evidencePaths"].append(extra_path)
        self.write("outcome-v2.json", outcome)
        self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation["artifact"], expected=2)
    def test_repeated_phone_extensions_stop_before_provider_or_publication(self):
        self.command("consent", "authorize")
        cases = (
            "415-555-0123 x123 ext 456",
            "415-555-0123 ext 123 #456",
            "07700 900123 ext 123 x456",
            "+44 20 7946 0958 ext 123 #456",
            "+44 20 7946 0958 x123 x456",
            "415-555-0123 x123_456",
            "415-555-0123 ext:ABC_def",
            "415-555-0123 ext 123_456",
            "+44 20 7946 0958x123-456",
            "+44 20 7946 0958 ext:123-456",
            "415-555-0123-456",
            "415-555-0123 x123 456",
            "+44 20 7946 0958--123",
            "415-555-0123ABC",
            "415-555-0123_ABC",
        )
        for contact in cases:
            with self.subTest(contact=contact):
                self.observation["state"]["focus"]["symptom"] = "Contact " + contact + " for assistance"
                self.write("observation.json", self.observation)
                self.prepare()
                self.network_log.unlink(missing_ok=True)
                result = self.command("route", expected=2, env={"TYPESAFE_API_KEY": "synthetic-offline-test-key"})
                self.assertEqual(result["status"], "error")
                self.assertFalse(self.network_log.exists(), "unconsumed contact extensions must stop before provider transport")
                self.assertFalse((self.workspace / ".img2/artifacts/jev/recommendation.json").exists())
                records = self.workspace / ".img2/artifacts/jev/records"
                self.assertFalse(list(records.glob("*.json")) if records.exists() else [])
                self.assertFalse(list(records.glob("*.state.json")) if records.exists() else [])
    def test_missing_keychain_credential_fails_closed_without_recommendation(self):
        self.write(".img2/state.json", {"version": 1, "workspace": str(self.workspace), "plugins": {"other": {"sentinel": 7}}})
        before = {item["path"]: (self.workspace / item["path"]).read_bytes() for item in self.observation["bindings"]}
        self.prepare()
        self.command("consent", "authorize")
        result = self.command("route", expected=2)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["reason"], "macOS Keychain credential is missing or could not be read")
        self.assertTrue(self.security_log.read_text(encoding="utf-8").strip().endswith("find-generic-password -a jev -s ai.typesafe.api-key -w"))
        self.assertFalse(self.network_log.exists(), "unavailable credentials must stop before external transport")
        self.assertFalse((self.workspace / ".img2/artifacts/jev/recommendation.json").exists())
        for relative, data in before.items():
            self.assertEqual((self.workspace / relative).read_bytes(), data)
        self.assertEqual(self.load(".img2/state.json")["plugins"]["other"], {"sentinel": 7})


    def test_archive_binding_rotates_with_grant_and_rejects_v1_history(self):
        self.prepare()
        self.command("consent", "authorize")
        first = self.command_live("route")
        first_report = self.load(first["artifact"])
        first_archive = self.load(first_report["requestPath"])
        self.assertEqual(first_archive["version"], 2)
        first_hash = first_archive["consentHash"]
        self.assertEqual(first_hash, first_report["consentHash"])
        self.command("consent", "revoke")
        self.command("consent", "authorize")
        second = self.command_live("route")
        second_report = self.load(second["artifact"])
        second_archive = self.load(second_report["requestPath"])
        self.assertEqual(second_archive["version"], 2)
        self.assertNotEqual(first_hash, second_archive["consentHash"])
        self.assertEqual(second_archive["consentHash"], second_report["consentHash"])
        jev = self.load_jev_module()
        with mock.patch.dict(os.environ, {"IMG2_HOME": str(self.home)}):
            with self.assertRaisesRegex(ValueError, "disclosure binding mismatch|consent changed"):
                jev.validate_report(self.workspace, first_report)
            paired = dict(second_report, requestPath=first_report["requestPath"])
            with self.assertRaisesRegex(ValueError, "disclosure binding mismatch"):
                jev.validate_report(self.workspace, paired)
        # Consent metadata remains local; provider bytes contain only the approved projection.
        from jev_projection import project_state
        from jev_client import _serialize_request
        serialized = _serialize_request(project_state(self.observation["state"]))
        self.assertNotIn(b"consentHash", serialized)
        self.assertNotIn(b"generation", serialized)
        self.assertNotIn(first_hash.encode(), serialized)
        self.assertNotIn(second_archive["consentHash"].encode(), serialized)
        old_archive = dict(second_archive, version=1)
        old_archive.pop("consentHash")
        self.write(second_report["requestPath"], old_archive)
        with mock.patch.dict(os.environ, {"IMG2_HOME": str(self.home)}):
            with self.assertRaisesRegex(ValueError, "unsupported archived request|unexpected or missing fields"):
                jev.validate_report(self.workspace, second_report)

    def test_controller_stop_refuses_live_route_without_provider(self):
        self.observation["control"]["controllerStopped"] = True
        self.write("observation.json", self.observation)
        self.prepare()
        self.command("consent", "authorize")
        result = self.command_live("route", "--mode", "assist", expected=2)
        self.assertEqual(result["status"], "error")
        self.assertFalse(self.provider_calls.exists(), "controller stops must not dispatch a provider request")
        self.assertFalse((self.workspace / ".img2/artifacts/jev/recommendation.json").exists())
        self.assertTrue(self.gate(1)["stopped"])

    def test_stale_source_prevents_route_and_invalidates_gate(self):
        self.prepare()
        self.command("consent", "authorize")
        self.command_live("route")
        (self.workspace / "src/createCharacter.ts").write_text("changed source")
        result = self.command_live("route", expected=2)
        self.assertEqual(result["status"], "error")
        self.assertFalse((self.workspace / ".img2/artifacts/jev/recommendation.json").exists())
        self.assertFalse(self.provider_calls.exists(), "stale source must stop before provider dispatch")
        self.assertTrue(self.gate(1)["stopped"])

    def test_gate_rejects_forged_acceptance_and_missing_record(self):
        self.assertTrue(self.gate(1)["stopped"])
        self.prepare()
        self.command("consent", "authorize")
        self.command_live("route")
        report = self.load(".img2/artifacts/jev/recommendation.json")
        report["proposal"]["action"] = "continue"
        self.write(".img2/artifacts/jev/recommendation.json", report)
        self.assertTrue(self.gate(1)["stopped"])

    def test_new_prepare_does_not_erase_recorded_request(self):
        self.prepare()
        self.command("consent", "authorize")
        first = self.command_live("route")
        report = self.load(first["artifact"])
        self.observation["state"]["focus"]["symptom"] = "a different observed symptom"
        self.write("observation.json", self.observation)
        self.prepare()
        archive = self.load(report["requestPath"])
        self.assertNotEqual(archive["request"]["state"]["focus"]["symptom"], self.observation["state"]["focus"]["symptom"])
        self.assertTrue(self.gate(1)["stopped"])

    def test_archived_request_cannot_override_current_preparation(self):
        self.prepare()
        self.command("consent", "authorize")
        first = self.command_live("route")
        archived = self.load(first["artifact"])["requestPath"]
        self.observation["control"]["controllerStopped"] = True
        self.write("observation.json", self.observation)
        self.prepare()
        module = self.load_jev_module()
        args = SimpleNamespace(input=archived, timeout=10, mode="assist")
        with mock.patch.dict(os.environ, {"IMG2_HOME": str(self.home)}):
            with mock.patch.object(module, "resolve_api_key") as resolve_key:
                with mock.patch.object(module, "evaluate_bounded") as dispatch:
                    with self.assertRaisesRegex(module.ContractError, "active prepared request"):
                        module.run_route(self.workspace, args)
                resolve_key.assert_not_called()
                dispatch.assert_not_called()
        self.assertFalse((self.workspace / ".img2/artifacts/jev/recommendation.json").exists())
        self.assertTrue(self.gate(1)["stopped"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes unavailable")
    def test_nonregular_input_is_refused_without_blocking(self):
        os.mkfifo(self.workspace / "input-pipe")
        proc = subprocess.run(
            [sys.executable, str(PLUGIN / "tools/jev.py"), "prepare", "--workspace", str(self.workspace),
             "--input", "input-pipe"],
            env=self.env, capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(proc.returncode, 2)

    def test_escape_symlink_and_unknown_evidence_are_refused(self):
        escaped = copy.deepcopy(self.observation)
        escaped["bindings"][0]["path"] = "../outside.png"
        self.write("bad.json", escaped)
        self.command("prepare", "--input", "bad.json", expected=2)
        linked = self.workspace / "reference/front.png"
        linked.unlink()
        outside = self.base / "outside.png"
        outside.write_bytes(b"external")
        linked.symlink_to(outside)
        self.command("prepare", "--input", "observation.json", expected=2)
        linked.unlink()
        linked.write_bytes(b"local")
        self.observation["state"]["gates"][0]["evidenceIds"] = ["invented"]
        self.write("bad.json", self.observation)
        self.command("prepare", "--input", "bad.json", expected=2)

    def test_output_namespace_symlink_does_not_write_outside(self):
        outside = self.base / "external-artifacts"
        outside.mkdir()
        artifacts = self.workspace / ".img2/artifacts"
        shutil.rmtree(artifacts)
        artifacts.symlink_to(outside, target_is_directory=True)
        self.command("prepare", "--input", "observation.json", expected=2)
        self.assertEqual(list(outside.iterdir()), [])

    def test_malformed_and_nonfinite_input_produce_json_error(self):
        for raw in ('{"kind":1,"kind":2}', '{"bad":NaN}', '[]'):
            with self.subTest(raw=raw):
                (self.workspace / "bad.json").write_text(raw)
                result = self.command("prepare", "--input", "bad.json", expected=2)
                self.assertEqual(result["status"], "error")

    def test_outcome_requires_matching_record_and_measured_files(self):
        self.prepare()
        self.command("consent", "authorize")
        result = self.command_live("route")
        report = self.load(result["artifact"])
        (self.workspace / "src/createCharacter.ts").write_text("repaired source")
        self.write("evaluation/after.json", {"measured": "synthetic outcome fixture"})
        outcome = {"kind": "img2.repair-outcome", "version": 1, "recommendationId": report["id"], "outcome": "improved", "improvedFeatureIds": ["finish"], "regressedFeatureIds": [], "evidencePaths": ["evaluation/after.json"]}
        self.write("outcome.json", outcome)
        recorded = self.command("record-outcome", "--input", "outcome.json", "--recommendation", result["artifact"])
        self.assertEqual(recorded["verification"], "file-integrity-only")
        provenance = self.load(recorded["artifact"])
        before_sources = {item["path"]: item["sha256"] for item in provenance["beforeSnapshot"]["files"] if item["role"] == "source"}
        after_sources = {item["path"]: item["sha256"] for item in provenance["afterSnapshot"]["files"] if item["role"] == "source"}
        self.assertNotEqual(before_sources["src/createCharacter.ts"], after_sources["src/createCharacter.ts"])
        outcome["recommendationId"] = "wrong"
        self.write("outcome.json", outcome)
        self.command("record-outcome", "--input", "outcome.json", "--recommendation", result["artifact"], expected=2)

    def test_outcome_rejects_forged_active_path_and_self_evidence(self):
        self.prepare()
        self.command("consent", "authorize")
        result = self.command_live("route")
        report = self.load(result["artifact"])
        self.write("evaluation/after.json", {"measured": "after repair"})
        outcome = {"kind": "img2.repair-outcome", "version": 1, "recommendationId": report["id"], "outcome": "unchanged",
                   "improvedFeatureIds": [], "regressedFeatureIds": [], "evidencePaths": ["evaluation/after.json"]}
        self.write("outcome.json", outcome)
        report["activeRequestPath"] = "../outside.json"
        self.write(result["artifact"], report)
        self.command("record-outcome", "--input", "outcome.json", "--recommendation", result["artifact"], expected=2)
        report["activeRequestPath"] = ".img2/artifacts/jev/repair-state.json"
        self.write(result["artifact"], report)
        outcome["evidencePaths"] = [result["artifact"]]
        self.write("outcome.json", outcome)
        self.command("record-outcome", "--input", "outcome.json", "--recommendation", result["artifact"], expected=2)

    def test_outcome_refuses_unmeasured_change_and_contradictory_features(self):
        self.prepare()
        self.command("consent", "authorize")
        result = self.command_live("route")
        report = self.load(result["artifact"])
        prior_evaluation = next(item["path"] for item in self.observation["bindings"] if item["role"] == "evaluation")
        outcome = {"kind": "img2.repair-outcome", "version": 1, "recommendationId": report["id"], "outcome": "improved",
                   "improvedFeatureIds": ["finish"], "regressedFeatureIds": [], "evidencePaths": [prior_evaluation]}
        self.write("outcome.json", outcome)
        self.command("record-outcome", "--input", "outcome.json", "--recommendation", result["artifact"], expected=2)
        self.write("evaluation/new.json", {"measured": "new synthetic evaluation"})
        outcome["evidencePaths"] = ["evaluation/new.json"]
        for label, improved, regressed in (("regressed", [], []), ("unchanged", ["finish"], []),
                                           ("inconclusive", [], ["finish"]), ("build_failed", ["finish"], [])):
            with self.subTest(outcome=label):
                outcome.update(outcome=label, improvedFeatureIds=improved, regressedFeatureIds=regressed)
                self.write("outcome.json", outcome)
                self.command("record-outcome", "--input", "outcome.json", "--recommendation", result["artifact"], expected=2)

    def test_replay_accepts_multiple_labels_without_live_calls(self):
        state = copy.deepcopy(self.observation["state"])
        for gate in state["gates"]:
            gate["status"] = "pass"
            gate["reasonCodes"] = []
        case = {"caseId": "synthetic-case", "state": state, "control": self.observation["control"], "response": None, "acceptable": [{"action": "defer", "tactic": "fallback"}, {"action": "request-input", "tactic": "re-analyze"}]}
        (self.workspace / "cases.jsonl").write_text(json.dumps(case) + "\n")
        result = self.command("replay", "--input", "cases.jsonl")
        self.assertEqual(result["liveCalls"], 0)
        self.assertEqual(result["arms"]["rules"]["acceptable"], 1)
        self.assertEqual(result["arms"]["rules"]["actionableCoverage"], 0)
        self.assertIsNone(result["arms"]["rules"]["actionablePrecision"])


    def test_offline_diagnostics_preserve_live_advice_and_environment_authority(self):
        self.command("consent", "authorize")
        self.prepare()
        self.command_live("route")
        recommendation_path = self.workspace / ".img2/artifacts/jev/recommendation.json"
        recommendation_before = recommendation_path.read_bytes()
        jev_state_before = copy.deepcopy(self.load(".img2/state.json")["plugins"]["jev"])
        state = copy.deepcopy(self.observation["state"])
        for gate in state["gates"]:
            gate["status"] = "pass"
            gate["reasonCodes"] = []
        case = {"caseId": "offline-diagnostic", "state": state, "control": self.observation["control"],
                "response": None, "acceptable": [{"action": "defer", "tactic": "fallback"}]}
        (self.workspace / "diagnostic-cases.jsonl").write_text(json.dumps(case) + chr(10))
        replay = self.command("replay", "--input", "diagnostic-cases.jsonl")
        self.assertEqual(replay["liveCalls"], 0)
        self._write_report_corpus("diagnostic-outcomes.jsonl", [])
        report = self._run_outcome_report("diagnostic-outcomes.jsonl")
        self.assertEqual(report["liveCalls"], 0)
        self.assertEqual(recommendation_path.read_bytes(), recommendation_before)
        self.assertEqual(self.load(".img2/state.json")["plugins"]["jev"], jev_state_before)
        gate_result = subprocess.run(
            [sys.executable, str(PLUGIN / "tools" / "gate_jev.py"), "--workspace", str(self.workspace)],
            cwd=self.workspace, env=self.env, capture_output=True, text=True, timeout=10, check=False,
        )
        self.assertEqual(gate_result.returncode, 0, gate_result.stdout + gate_result.stderr)
        envelope = json.loads(gate_result.stdout)
        self.assertIs(envelope["evidence"]["acceptanceAuthority"], False)
        self.assertFalse(self.network_log.exists())

    def _report_record(self, label, *, evidence_class="synthetic", adjudication="independent", match_proposal=False, override_proposal=False):
        recommendation, outcome = self.v2_outcome(label)
        # Synthetic temporary-workspace schema exercise only; never release evidence.
        outcome["evidenceClass"] = evidence_class
        outcome["adjudication"]["status"] = adjudication
        if adjudication != "independent":
            outcome["adjudication"]["adjudicatorId"] = None
            outcome["adjudication"]["method"] = None
        if match_proposal or override_proposal:
            proposal = self.load(recommendation["artifact"])["proposal"]
            action = {key: proposal[key] for key in ("action", "tactic")}
            if override_proposal:
                alternatives = ({"action": "refine-code", "tactic": "parameter-patch"}, {"action": "defer", "tactic": "fallback"})
                action = next(candidate for candidate in alternatives if candidate != action)
            outcome["approvedAction"] = action
            outcome["actualAction"] = action
            outcome["recommendationFollowed"] = True
        self.write("outcome-v2.json", outcome)
        result = self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation["artifact"])
        return self.load(result["artifact"])


    def _write_report_corpus(self, relative, records):
        path = self.workspace / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"".join(json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n" for row in records))

    def _run_outcome_report(self, relative, *, expected=0):
        return self.command("report-outcomes", "--input", relative, expected=expected)

    def test_report_outcomes_reads_only_explicit_workspace_corpus(self):
        self._write_report_corpus("chosen.jsonl", [])
        # Other workspace JSONL data must not be discovered or merged.
        self._write_report_corpus("elsewhere/outcomes.jsonl", [{"kind": "img2.repair-outcome", "version": 1}])
        before_files = {p.relative_to(self.workspace): p.read_bytes() for p in self.workspace.rglob("*") if p.is_file()}
        result = self._run_outcome_report("chosen.jsonl")
        unchanged = {p.relative_to(self.workspace): p.read_bytes() for p in self.workspace.rglob("*") if p.is_file() and p.relative_to(self.workspace) in before_files}
        self.assertEqual(unchanged, before_files)
        after_files = {p.relative_to(self.workspace) for p in self.workspace.rglob("*") if p.is_file()}
        self.assertEqual(after_files - set(before_files), {Path(result["artifact"])})
        report = self.load(result["artifact"])
        self.assertEqual(report["corpusPath"], "chosen.jsonl")
        self.assertEqual(report["eligibleCount"], 0)
        self.assertEqual(result["liveCalls"], 0)
        self.assertEqual(result["calibrationStatus"], "uncalibrated")
        expected_digest = hashlib.sha256(json.dumps(report, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(result["artifact"], ".img2/artifacts/jev/reports/" + expected_digest + ".json")

    def test_report_outcomes_empty_and_synthetic_or_legacy_are_ineligible(self):
        self._write_report_corpus("empty.jsonl", [])
        self.env["TYPESAFE_API_KEY"] = "synthetic-test-credential-must-not-be-used"
        empty_result = self._run_outcome_report("empty.jsonl")
        empty = self.load(empty_result["artifact"])
        self.assertEqual((empty["status"], empty["calibrationStatus"], empty["liveCalls"]), ("insufficient-data", "uncalibrated", 0))
        synthetic = self._report_record("improved")
        unadjudicated = self._report_record("unchanged", evidence_class="observed", adjudication="none")
        self._write_report_corpus("ineligible.jsonl", [{"kind": "img2.repair-outcome", "version": 1}, synthetic, unadjudicated])
        result = self._run_outcome_report("ineligible.jsonl")
        report = self.load(result["artifact"])
        self.assertEqual(report["status"], "insufficient-data")
        self.assertEqual({item["reason"] for item in report["exclusions"]}, {"legacy-v1", "synthetic", "unadjudicated"}, report["exclusions"])
        self.assertEqual(result["liveCalls"], 0)

    def test_report_outcomes_positive_denominators_wilson_and_strata(self):
        # `observed` exercises the persisted eligibility schema only: every input/evidence file
        # is generated in this synthetic temp workspace and is not release evidence.
        records = [self._report_record(label, evidence_class="observed") for label in ("improved", "unchanged", "regressed", "build_failed", "inconclusive")]
        self.assertTrue(all(row["adjudication"]["adjudicatorId"] == "synthetic-reviewer" for row in records))
        self._write_report_corpus("eligible.jsonl", records)
        result = self._run_outcome_report("eligible.jsonl")
        report = self.load(result["artifact"])
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["quality"]["denominator"], 3)
        self.assertEqual(report["attempt"]["denominator"], 4)
        self.assertAlmostEqual(report["quality"]["statuses"]["improved"]["rate"], 1 / 3)
        improved = report["quality"]["statuses"]["improved"]["wilson95"]
        self.assertLess(improved["lower"], 1 / 3)
        self.assertGreater(improved["upper"], 1 / 3)
        self.assertEqual(report["attempt"]["statuses"]["build_failed"]["count"], 1)
        self.assertEqual(report["attempt"]["statuses"]["build_failed"]["rate"], 0.25)
        self.assertGreaterEqual(len(report["strata"]), 1)
        stratum = report["strata"][0]
        self.assertEqual(stratum["adapter"], "room")
        self.assertEqual(stratum["evaluatorVersion"], "2")
        self.assertEqual(stratum["policyVersion"], "repair-policy-v1")
        self.assertIn("actualAction", stratum)
        self.assertIn("recommendationFollowed", stratum)
        self.assertEqual(report["liveCalls"], 0)
        self.assertEqual(report["calibrationStatus"], "uncalibrated")
        self.assertIn("no causal-success inference", report["wording"])

    def test_report_outcomes_rejects_duplicate_pair_through_cli(self):
        record = self._report_record("improved")
        self._write_report_corpus("duplicates.jsonl", [record, record])
        result = self._run_outcome_report("duplicates.jsonl", expected=2)
        self.assertIn("duplicate recommendationId+attemptId", result["reason"])

    def test_report_recomputes_followed_against_archived_proposal(self):
        # Both records are synthetic schema exercises in this temporary workspace, not release evidence.
        overridden = self._report_record("improved", evidence_class="observed", override_proposal=True)
        recommendation_path = ".img2/artifacts/jev/records/" + overridden["recommendationId"] + ".json"
        proposal = self.load(recommendation_path)["proposal"]
        proposal_action = {key: proposal[key] for key in ("action", "tactic")}
        self.assertNotEqual(overridden["actualAction"], proposal_action)
        self.assertTrue(overridden["recommendationFollowed"])
        self.assertEqual(overridden["actualAction"], overridden["approvedAction"])

        followed = self._report_record("unchanged", evidence_class="observed", match_proposal=True)
        self.assertEqual(followed["actualAction"], proposal_action)
        self.assertTrue(followed["recommendationFollowed"])
        self._write_report_corpus("routing-agreement.jsonl", [overridden, followed])

        result = self._run_outcome_report("routing-agreement.jsonl")
        report = self.load(result["artifact"])
        self.assertEqual(report["eligibleCount"], 2)
        self.assertEqual(report["routingAgreement"]["count"], 1)
        self.assertEqual(report["routingAgreement"]["denominator"], 2)
        self.assertEqual(report["routingAgreement"]["rate"], 0.5)
        strata = {item["recommendationFollowed"]: item for item in report["strata"]}
        self.assertEqual(set(strata), {False, True})
        self.assertEqual(strata[False]["actualAction"], overridden["actualAction"])
        self.assertEqual(strata[True]["actualAction"], proposal_action)
        self.assertEqual(result["liveCalls"], 0)

    def test_report_outcomes_excludes_persisted_unknown_after_gate(self):
        record = self._report_record("improved", evidence_class="observed")
        old_gate_path = record["afterGatePath"]
        entry = next(item for item in record["archivedEvidence"] if item["originalPath"] == old_gate_path)
        gate_blob = self.workspace / entry["archivedPath"]
        gate = json.loads(gate_blob.read_text(encoding="utf-8"))
        gate["status"] = "unknown"
        gate_core = {
            "evaluator": gate["evaluator"], "files": gate["snapshot"]["files"],
            "status": gate["status"], "reasons": gate["reasons"], "evidence": gate["evidence"],
        }
        snapshot_id = hashlib.sha256(json.dumps(gate_core, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        new_gate_path = ".img2/artifacts/environment/gate-results/" + snapshot_id + ".json"
        gate["snapshotId"] = snapshot_id
        gate["snapshotPath"] = new_gate_path
        gate["resultPath"] = new_gate_path
        gate["snapshot"]["id"] = snapshot_id
        gate["snapshot"]["path"] = new_gate_path
        gate_bytes = json.dumps(gate, sort_keys=True, separators=(",", ":")).encode()
        gate_hash = hashlib.sha256(gate_bytes).hexdigest()
        new_blob_path = ".img2/artifacts/jev/outcomes/archive/" + gate_hash[:2] + "/" + gate_hash + ".blob"
        blob_path = self.workspace / new_blob_path
        blob_path.parent.mkdir(parents=True, exist_ok=True)
        blob_path.write_bytes(gate_bytes)
        entry.update(originalPath=new_gate_path, archivedPath=new_blob_path, size=len(gate_bytes), sha256=gate_hash)
        record["afterGatePath"] = new_gate_path
        record["afterSnapshot"]["id"] = snapshot_id
        record["evidencePaths"] = [new_gate_path if path == old_gate_path else path for path in record["evidencePaths"]]
        record_bytes = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        record_hash = hashlib.sha256(record_bytes).hexdigest()
        record_path = ".img2/artifacts/jev/outcomes/archive/records/" + record_hash + ".json"
        persisted_record_path = self.workspace / record_path
        persisted_record_path.parent.mkdir(parents=True, exist_ok=True)
        persisted_record_path.write_bytes(record_bytes + b"\n")
        self._write_report_corpus("unknown-gate.jsonl", [record])

        result = self._run_outcome_report("unknown-gate.jsonl")
        report = self.load(result["artifact"])
        self.assertEqual(report["status"], "insufficient-data")
        self.assertEqual(report["eligibleCount"], 0)
        self.assertEqual([item["reason"] for item in report["exclusions"]], ["invalid-record"])

    def test_report_outcomes_oversized_artifact_fails_without_partial_report(self):
        # Synthetic invalid rows deliberately produce many explicit exclusion details.
        self._write_report_corpus("oversized.jsonl", [{"version": 2, "recommendationId": "synthetic-r-" + str(index), "attemptId": "synthetic-a-" + str(index)} for index in range(3000)])
        result = self._run_outcome_report("oversized.jsonl", expected=2)
        self.assertEqual(result["status"], "error")
        self.assertIn("128KiB", result["reason"])
        self.assertFalse((self.workspace / ".img2/artifacts/jev/reports").exists())

    def test_report_outcomes_invalid_record_output_is_hashseed_stable(self):
        # Synthetic temporary-workspace record; malformed request fields exercise deterministic exclusions only.
        record = self._report_record("improved", evidence_class="observed")
        recommendation_path = ".img2/artifacts/jev/records/" + record["recommendationId"] + ".json"
        recommendation_file = self.workspace / recommendation_path
        recommendation = json.loads(recommendation_file.read_text(encoding="utf-8"))
        request_path = recommendation["requestPath"]
        request_file = self.workspace / request_path
        archive = json.loads(request_file.read_text(encoding="utf-8"))
        request = archive["request"]
        request["control"]["remainingBudgetUsd"] = "synthetic-invalid-number"
        request["control"]["remainingDeadlineMs"] = "synthetic-invalid-number"
        request_bytes = json.dumps(request, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        archive["requestHash"] = hashlib.sha256(request_bytes).hexdigest()
        archive_bytes = json.dumps(archive, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        request_file.write_bytes(archive_bytes + b"\n")
        recommendation["requestHash"] = archive["requestHash"]
        recommendation_bytes = json.dumps(recommendation, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        recommendation_file.write_bytes(recommendation_bytes + b"\n")
        record["recommendationHash"] = hashlib.sha256(recommendation_bytes).hexdigest()
        record_bytes = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        record_hash = hashlib.sha256(record_bytes).hexdigest()
        persisted_record = ".img2/artifacts/jev/outcomes/archive/records/" + record_hash + ".json"
        persisted_path = self.workspace / persisted_record
        persisted_path.parent.mkdir(parents=True, exist_ok=True)
        persisted_path.write_bytes(record_bytes + b"\n")
        self._write_report_corpus("unstable-validator.jsonl", [record])
        self.env["TYPESAFE_API_KEY"] = "synthetic-test-credential-must-not-be-used"

        first = self.command("report-outcomes", "--input", "unstable-validator.jsonl", env={"PYTHONHASHSEED": "1"})
        first_bytes = (self.workspace / first["artifact"]).read_bytes()
        second = self.command("report-outcomes", "--input", "unstable-validator.jsonl", env={"PYTHONHASHSEED": "2"})
        second_bytes = (self.workspace / second["artifact"]).read_bytes()
        self.assertEqual(first["artifact"], second["artifact"])
        self.assertEqual(first_bytes, second_bytes)
        report = json.loads(first_bytes)
        self.assertEqual(report["exclusions"][0]["reason"], "invalid-record")
        self.assertNotIn("detail", report["exclusions"][0])
        self.assertEqual(first["liveCalls"], 0)
        self.assertEqual(second["liveCalls"], 0)
    def test_live_dispatch_requires_workspace_consent_and_refusal_writes_no_advice(self):
        self.prepare()
        result = self.command("route", expected=2, env={"TYPESAFE_API_KEY": "synthetic-test-only-key"})
        self.assertEqual(result["status"], "error")
        self.assertFalse(self.network_log.exists(), "refused consent must stop before provider dispatch")
        self.assertFalse(self.provider_calls.exists(), "missing consent must stop before the synthetic provider")
        self.assertFalse(self.security_log.exists(), "test key override must avoid Keychain access")
        self.assertFalse((self.workspace / ".img2/artifacts/jev/recommendation.json").exists())
        self.assertFalse(list((self.workspace / ".img2/artifacts/jev/records").glob("*.json")))

    def test_revoked_then_reauthorized_consent_invalidates_advice_consumers(self):
        self.prepare()
        self.command("consent", "authorize")
        result = self.command_live("route")
        report = self.load(result["artifact"])
        self.assertEqual(report["provider"]["status"], "evaluated")
        self.assertIsNotNone(report["consentHash"])
        self.assertEqual(self.gate(0)["results"][0]["status"], "pass")
        calls_before_revoke = self.provider_calls.read_text(encoding="utf-8").splitlines()
        self.command("consent", "revoke")
        self.command("consent", "authorize")
        gate_result = self.gate(1)
        self.assertTrue(gate_result["stopped"])
        verdict = gate_result["results"][0]
        self.assertEqual(verdict["status"], "fail")
        self.assertIn("stale", verdict["reasons"][0])
        self.assertEqual(self.provider_calls.read_text(encoding="utf-8").splitlines(), calls_before_revoke)
        self.assertEqual(self.load(result["artifact"])["id"], report["id"])
        self.write("outcome-v1.json", {"kind": "img2.repair-outcome", "version": 1})
        consumption = self.command("record-outcome", "--input", "outcome-v1.json", "--recommendation", result["artifact"], expected=2)
        self.assertIn("consent changed or was revoked", consumption["reason"])
        self.assertFalse(list((self.workspace / ".img2/artifacts/jev/outcomes").glob("*.json")))
    def test_unsafe_projection_content_blocks_route_before_provider_dispatch(self):
        self.command("consent", "authorize")
        self.observation["state"]["evidence"]["facts"][0]["statement"] = "credential reference nested/sourceFile.ts cannot be safely disclosed"
        self.write("observation.json", self.observation)
        self.prepare()
        result = self.command("route", expected=2, env={"TYPESAFE_API_KEY": "synthetic-test-only-key"})
        self.assertEqual(result["status"], "error")
        self.assertIn("unsafe text", result["reason"])
        self.assertFalse(self.network_log.exists())
        self.assertFalse(self.provider_calls.exists(), "unsafe projection must stop before the synthetic provider")
        self.assertFalse(self.security_log.exists())
        self.assertFalse((self.workspace / ".img2/artifacts/jev/recommendation.json").exists())

    def test_malformed_international_phone_candidates_refuse_before_provider_and_publication(self):
        self.command("consent", "authorize")
        for symptom in (
            "Contact +44 20 7946 0958xABC for assistance",
            "Contact +44 20 7946 0958ext:ABC for assistance",
            "Contact +44 20 7946 0958ABC for assistance",
            "Contact +44 20 7946 0958 123ABC for assistance",
            "Contact +44 20 7946 0958_123 for assistance",
        ):
            with self.subTest(symptom=symptom):
                self.observation["state"]["focus"]["symptom"] = symptom
                self.write("observation.json", self.observation)
                self.prepare()
                result = self.command("route", expected=2, env={"TYPESAFE_API_KEY": "synthetic-test-only-key"})
                self.assertEqual(result["status"], "error")
                self.assertFalse(self.network_log.exists(), "malformed phone candidate reached external transport")
                self.assertFalse(self.provider_calls.exists(), "malformed phone candidate reached the synthetic provider")
                self.assertFalse((self.workspace / ".img2/artifacts/jev/recommendation.json").exists())
                self.assertFalse(list((self.workspace / ".img2/artifacts/jev/records").glob("*.json")))
    def test_route_report_projection_hash_is_recomputed_before_gate_display(self):
        self.prepare()
        self.command("consent", "authorize")
        result = self.command_live("route")
        report = self.load(result["artifact"])
        archive_path = report["requestPath"]
        archive = self.load(archive_path)
        request = archive["request"]
        jev = self.load_jev_module()
        projected = jev.project_state(request["state"])
        encoded = jev.canonical(projected).decode("utf-8")
        self.assertRegex(projected["focus"]["componentIds"][0], r"c[1-9][0-9]*")
        self.assertRegex(projected["evidence"]["facts"][0]["id"], r"e[1-9][0-9]*")
        self.assertEqual(projected["sceneKind"], request["state"]["sceneKind"])
        self.assertEqual(projected["gates"][0]["id"], request["state"]["gates"][0]["id"])
        self.assertEqual(projected["gates"][0]["status"], request["state"]["gates"][0]["status"])
        self.assertEqual(projected["gates"][0]["reasonCodes"], request["state"]["gates"][0]["reasonCodes"])
        self.assertIn("controlled comparison shows c1 gloss unlike reference", encoded)
        expected_hash = jev.digest(jev.canonical(projected))
        self.assertEqual(report["projectionHash"], expected_hash)
        self.assertFalse(self.gate(0)["stopped"])
        report["projectionHash"] = "0" * 64
        self.write(".img2/artifacts/jev/recommendation.json", report)
        self.assertTrue(self.gate(1)["stopped"])
        report["projectionHash"] = expected_hash
        self.write(".img2/artifacts/jev/recommendation.json", report)
        archive["projectionHash"] = "0" * 64
        self.write(archive_path, archive)
        gate_result = self.gate(1)
        self.assertTrue(gate_result["stopped"])
        self.assertEqual(gate_result["results"][0]["status"], "fail")
        self.assertIn("stale", gate_result["results"][0]["reasons"][0])
    def test_reauthorize_during_successful_mock_response_prevents_publication(self):
        self.prepare()
        module = self.load_jev_module()
        client = sys.modules["jev_client"]
        answers = {}
        for name, question in client.QUESTIONS.items():
            choice = next(iter(question["criteria"]))
            answers[name] = {
                "type": "choice", "choice": choice,
                "probabilities": {option: float(option == choice) for option in question["criteria"]},
                "confidence": 1.0,
            }
        response = {"model": client.MODEL, "answers": answers, "usage": {"input_tokens": 12, "output_tokens": 8}}
        with mock.patch.dict(os.environ, {"IMG2_HOME": str(self.home)}):
            module.set_consent(self.workspace, True)
        args = SimpleNamespace(input=module.REQUEST_PATH, timeout=10, mode="assist")

        def successful_response_then_consent_cycle(_projection, _key, timeout):
            self.assertGreater(timeout, 0)
            generation = module.require_consent(self.workspace)["generation"]
            module.set_consent(self.workspace, False)
            module.set_consent(self.workspace, True)
            serialized = module._serialize_request(_projection)
            self.assertNotIn(generation.encode("ascii"), serialized)
            return response

        with mock.patch.dict(os.environ, {"IMG2_HOME": str(self.home)}):
            with mock.patch.object(module, "resolve_api_key", return_value="synthetic-test-only-key"):
                with mock.patch.object(module, "evaluate_bounded", side_effect=successful_response_then_consent_cycle):
                    with self.assertRaisesRegex(module.ContractError, "consent changed before advice consumption"):
                        module.run_route(self.workspace, args)
        self.assertFalse((self.workspace / ".img2/artifacts/jev/recommendation.json").exists())
        self.assertFalse(list((self.workspace / ".img2/artifacts/jev/records").glob("*.json")))
    def test_malformed_international_phone_is_refused_before_provider_or_publication(self):
        self.prepare()
        module = self.load_jev_module()
        request_path = self.workspace / module.REQUEST_PATH
        request = json.loads(request_path.read_text(encoding="utf-8"))
        request["state"]["focus"]["symptom"] = "Contact +44 20 7946 0958 x123_456 for assistance"
        request_path.write_text(json.dumps(request), encoding="utf-8")
        with mock.patch.dict(os.environ, {"IMG2_HOME": str(self.home)}):
            module.set_consent(self.workspace, True)
        args = SimpleNamespace(input=module.REQUEST_PATH, timeout=10, mode="assist")
        with mock.patch.dict(os.environ, {"IMG2_HOME": str(self.home)}):
            with mock.patch.object(module, "resolve_api_key", return_value="synthetic-test-only-key"):
                with mock.patch.object(module, "evaluate_bounded") as dispatch:
                    with self.assertRaises(module.ContractError):
                        module.run_route(self.workspace, args)
                    dispatch.assert_not_called()
        self.assertFalse((self.workspace / ".img2/artifacts/jev/recommendation.json").exists())
        self.assertFalse(list((self.workspace / ".img2/artifacts/jev/records").glob("*.json")))
    def test_malformed_domestic_phone_extensions_are_refused_before_provider_or_publication(self):
        self.prepare()
        module = self.load_jev_module()
        request_path = self.workspace / module.REQUEST_PATH
        request = json.loads(request_path.read_text(encoding="utf-8"))
        malformed = (
            "Contact 415-555-0123x123-456 for assistance",
            "Contact 415-555-0123 ext 123.456 for assistance",
            "Contact 07700 900123 ext:123/456 for assistance",
            "Contact 4155550123_ABC for assistance",
            "Contact 07700900123x123ABC for assistance",
            "Contact 4155550123x123_456 for assistance",
            "Contact 07700900123x123_456 for assistance",
            "Contact 415-555-0123 x123\next 456 for assistance",
            "Contact +44 20 7946 0958 x123\next 456 for assistance",
            "Contact 415-555-0123 x123)456 for assistance",
            "Contact +44 20 7946 0958 x123)456 for assistance",
        )
        with mock.patch.dict(os.environ, {"IMG2_HOME": str(self.home)}):
            module.set_consent(self.workspace, True)
            for symptom in malformed:
                with self.subTest(symptom=symptom):
                    request["state"]["focus"]["symptom"] = symptom
                    request_path.write_text(json.dumps(request), encoding="utf-8")
                    args = SimpleNamespace(input=module.REQUEST_PATH, provider="jev", timeout=10, mode="assist")
                    with mock.patch.object(module, "resolve_api_key", side_effect=AssertionError("credential resolution occurred before local projection")) as resolve_key:
                        with mock.patch.object(module, "evaluate_bounded") as dispatch:
                            with self.assertRaises(module.ContractError):
                                module.run_route(self.workspace, args)
                            resolve_key.assert_not_called()
                            dispatch.assert_not_called()
                    self.assertFalse((self.workspace / ".img2/artifacts/jev/recommendation.json").exists())
                    self.assertFalse(list((self.workspace / ".img2/artifacts/jev/records").glob("*.json")))

    def test_four_phone_suffix_boundary_candidates_stop_before_credentials_provider_and_archives(self):
        self.prepare()
        module = self.load_jev_module()
        request_path = self.workspace / module.REQUEST_PATH
        request = json.loads(request_path.read_text(encoding="utf-8"))
        candidates = (
            "Contact 4155550123x123é for assistance",
            "Contact 07700900123x123α123 for assistance",
            "Contact 415-555-0123x123é for assistance",
            "Contact 07700 900123x123α123 for assistance",
            "Contact 4155550123x123e\u0301 for assistance",
            "Contact 415-555-0123 x123--456 for assistance",
            "Contact 415-555-0123 x123 -456 for assistance",
            "Contact 415-555-0123\u0301123 for assistance",
            "Contact +44 20 7946 0958 x123-ABC456 for assistance",
            "Contact 415-555-0123é for assistance",
            "Contact 415-555-0123α123 for assistance",
            "Contact 415-555-0123 x123:456 for assistance",
            "Contact +44 20 7946 0958 x123:456 for assistance",
            "Contact +44 20 7946 0958 x123 (456) for assistance",
            "Contact +44 20 7946 0958 x123(456) for assistance",
            "Contact +44 20 7946 0958 x123\t(456) for assistance",
            "Contact 415-555-0123 x123 (456) for assistance",
            "Contact 415-555-0123 x123(456) for assistance",
            "Contact 415-555-0123 x123\t(456) for assistance",
            "Contact 415-555-0123 x123:456.789 for assistance",
            "Contact +44 20 7946 0958 x123:456.789 for assistance",
            "Contact 415-555-0123 x123:456.789m for assistance",
            "Contact +44 20 7946 0958 x123:456.789m for assistance",
            "Contact +44 20 7946 0958 x123(456.789m) for assistance",
            "Contact +44 20 7946 0958 x123-456.789m for assistance",
            "Contact 415-555-0123 x123+456 for assistance",
            "Contact 415-555-0123 x123 +456 for assistance",
            "Contact +44 20 7946 0958 x123+456 for assistance",
            "Contact +44 20 7946 0958 x123 +456 for assistance",
            "Contact 4155550123x123,ext 456 for assistance",
            "Contact 07700900123x123;456 for assistance",
            "Contact +44 20 7946 0958 x123;ext 456 for assistance",
            "Contact 4155550123x123,,ext 456 for assistance",
            "Contact +44 20 7946 0958 x123;;ext 456 for assistance",
            "Contact 07700900123x123,;456 for assistance",
            "Contact 415-555-0123 x123) ext 456 for assistance",
            "Contact +44 20 7946 0958 x123 — ext 456 for assistance",
            "Contact +44 20 7946 0958 x123: ext 456 for assistance",
            "Contact +44 20 7946 0958 x123, ) ext 456 for assistance",
            "Contact 415-555-0123 x123) ; ext 456 for assistance",
            "Contact 415-555-0123 x123, ) -ABC456 for assistance",
            "Contact 415-555-0123 x123) ; 456 for assistance",
            "Contact 415-555-0123 x123=456 for assistance",
            "Contact +44 20 7946 0958 x123|ABC456 for assistance",
            "Contact 415-555-0123 x123=ext456 for assistance",
        )
        args = SimpleNamespace(input=module.REQUEST_PATH, provider="jev", timeout=10, mode="assist")
        with mock.patch.dict(os.environ, {"IMG2_HOME": str(self.home)}):
            module.set_consent(self.workspace, True)
            for symptom in candidates:
                with self.subTest(symptom=symptom):
                    request["state"]["focus"]["symptom"] = symptom
                    request_path.write_text(json.dumps(request), encoding="utf-8")
                    with mock.patch.object(module, "resolve_api_key", side_effect=AssertionError("credential resolution occurred before local projection")) as resolve_key:
                        with mock.patch.object(module, "evaluate_bounded") as dispatch:
                            with self.assertRaises(module.ContractError):
                                module.run_route(self.workspace, args)
                            resolve_key.assert_not_called()
                            dispatch.assert_not_called()
                    self.assertFalse((self.workspace / ".img2/artifacts/jev/recommendation.json").exists())
                    records = self.workspace / ".img2/artifacts/jev/records"
                    self.assertFalse(list(records.glob("*.json")))
                    self.assertFalse(list(records.glob("*.state.json")))
    def test_live_route_publishes_only_evaluated_v2_advice_for_one_failed_snapshot(self):
        self.prepare()
        self.command("consent", "authorize")
        result = self.command_live("route", "--mode", "assist")
        self.assertEqual(result["status"], "recommended")
        self.assertEqual(result["providerStatus"], "evaluated")
        self.assertEqual(self.provider_calls.read_text(encoding="utf-8").splitlines(), ["dispatch"])
        self.assertFalse(self.network_log.exists(), "synthetic provider fixture must not make a network request")
        report = self.load(result["artifact"])
        self.assertEqual(report["provider"]["status"], "evaluated")
        self.assertEqual(report["versions"]["normalizer"], "repair-state-v2")
        self.assertIsNotNone(report["consentHash"])
        archive = self.load(report["requestPath"])
        self.assertEqual(archive["version"], 2)
        self.assertEqual(archive["request"]["version"], 2)
        self.assertEqual(archive["request"]["state"]["schemaVersion"], "repair-state-v2")
        module = self.load_jev_module()
        projection = module.project_state(archive["request"]["state"])
        self.assertEqual(module.digest(module.canonical(projection)), report["projectionHash"])
        self.assertEqual(projection["sceneKind"], "room")
        self.assertEqual(projection["gates"][-1]["id"], "12-ip-provenance-hygiene")
        self.assertEqual(projection["gates"][-1]["status"], "fail")

    def test_provider_failure_invalidates_the_previous_current_recommendation(self):
        self.prepare()
        self.command("consent", "authorize")
        first = self.command_live("route")
        self.assertTrue((self.workspace / ".img2/artifacts/jev/recommendation.json").exists())
        records = self.workspace / ".img2/artifacts/jev/records"
        archived_before = sorted(path.name for path in records.glob("*.json"))
        self.provider_calls.unlink(missing_ok=True)
        failed = self.command("route", expected=2, env={"TYPESAFE_API_KEY": "synthetic-test-only-key"})
        self.assertEqual(failed["status"], "error")
        self.assertFalse((self.workspace / ".img2/artifacts/jev/recommendation.json").exists())
        self.assertIsNone(self.load(".img2/state.json")["plugins"]["jev"].get("lastRecommendation"))
        self.assertEqual(sorted(path.name for path in records.glob("*.json")), archived_before)
        self.assertEqual(self.provider_calls.read_text(encoding="utf-8").splitlines(), ["dispatch"])

    def test_malformed_provider_response_invalidates_the_previous_current_recommendation(self):
        self.prepare()
        self.command("consent", "authorize")
        self.command_live("route")
        records = self.workspace / ".img2/artifacts/jev/records"
        archived_before = sorted(path.name for path in records.glob("*.json"))
        malformed = self.live_response()
        del malformed["answers"]["scope"]
        result = self.command_live("route", response=malformed, expected=2)
        self.assertEqual(result["status"], "error")
        self.assertFalse((self.workspace / ".img2/artifacts/jev/recommendation.json").exists())
        self.assertIsNone(self.load(".img2/state.json")["plugins"]["jev"].get("lastRecommendation"))
        self.assertEqual(sorted(path.name for path in records.glob("*.json")), archived_before)
        self.assertEqual(self.provider_calls.read_text(encoding="utf-8").splitlines(), ["dispatch"])
        self.assertFalse(self.network_log.exists())

    def test_changed_request_during_provider_evaluation_never_publishes_the_response(self):
        self.prepare()
        self.command("consent", "authorize")
        module = self.load_jev_module()
        args = SimpleNamespace(input=module.REQUEST_PATH, mode="assist", timeout=10)

        def change_request_then_respond(_projection, _key, **_kwargs):
            request = self.load(module.REQUEST_PATH)
            request["state"]["focus"]["symptom"] += " changed during provider evaluation"
            self.write(module.REQUEST_PATH, request)
            return self.live_response()

        with mock.patch.dict(os.environ, {"IMG2_HOME": str(self.home), "TYPESAFE_API_KEY": "synthetic-test-only-key"}):
            with mock.patch.object(module, "resolve_api_key", return_value="synthetic-test-only-key"):
                with mock.patch.object(module, "evaluate_bounded", side_effect=change_request_then_respond) as dispatch:
                    with self.assertRaises(module.ContractError):
                        module.run_route(self.workspace, args)
                    dispatch.assert_called_once()
        self.assertFalse((self.workspace / ".img2/artifacts/jev/recommendation.json").exists())
        records = self.workspace / ".img2/artifacts/jev/records"
        self.assertFalse(list(records.glob("*.json")))
        self.assertFalse(list(records.glob("*.state.json")))

    def test_live_route_rejects_pass_incomplete_and_unknown_snapshots_before_dispatch(self):
        self.command("consent", "authorize")
        for scenario in ("pass", "incomplete", "unknown"):
            with self.subTest(snapshot=scenario):
                if scenario == "pass":
                    gate_path, gate = self.synthetic_gate(status="pass", dependency="pass-snapshot")
                elif scenario == "incomplete":
                    gate_path, gate = self.synthetic_gate(failed_row="incomplete", dependency="incomplete-snapshot")
                else:
                    gate_path, gate = self.synthetic_gate(failed_row="12-ip-provenance-hygiene", dependency="unknown-snapshot")
                self.bind_gate(gate_path, gate)
                if scenario == "unknown":
                    self.observation["state"]["gates"][0].update(status="unknown", coverage="none", reasonCodes=["gate-unknown"])
                self.write("observation.json", self.observation)
                self.prepare()
                result = self.command_live("route", expected=2)
                self.assertEqual(result["status"], "error")
                self.assertFalse(self.provider_calls.exists(), "ineligible Environment state must stop before provider dispatch")
                self.assertFalse((self.workspace / ".img2/artifacts/jev/recommendation.json").exists())
                records = self.workspace / ".img2/artifacts/jev/records"
                self.assertFalse(list(records.glob("*.json")))
                self.assertFalse(list(records.glob("*.state.json")))

    def test_live_route_control_budget_deadline_and_correction_limits_stop_before_dispatch(self):
        self.command("consent", "authorize")
        base_control = copy.deepcopy(self.observation["control"])
        stops = (
            ({"controllerStopped": True}, "controller-stopped"),
            ({"remainingBudgetUsd": 0}, "budget-exhausted"),
            ({"remainingDeadlineMs": 0}, "deadline-exhausted"),
            ({"passCorrectionsUsed": 3, "totalCorrectionsUsed": 3}, "pass-correction-ceiling"),
            ({"totalCorrectionsUsed": 6}, "total-correction-ceiling"),
        )
        for overrides, reason_code in stops:
            with self.subTest(reason=reason_code):
                self.observation["control"] = copy.deepcopy(base_control)
                self.observation["control"].update(overrides)
                self.write("observation.json", self.observation)
                self.prepare()
                result = self.command_live("route", expected=2)
                self.assertEqual(result["status"], "error")
                self.assertIn(reason_code, result["reason"])
                self.assertFalse(self.provider_calls.exists(), "control limit must stop before provider dispatch")
                self.assertFalse((self.workspace / ".img2/artifacts/jev/recommendation.json").exists())

    def test_v1_request_and_report_are_not_accepted_as_current(self):
        self.prepare()
        self.command("consent", "authorize")
        module = self.load_jev_module()
        request = self.load(module.REQUEST_PATH)
        request["state"]["schemaVersion"] = "repair-state-v1"
        self.write(module.REQUEST_PATH, request)
        refused = self.command_live("route", expected=2)
        self.assertEqual(refused["status"], "error")
        self.assertFalse(self.provider_calls.exists(), "v1 state must not reach the provider")
        self.assertFalse((self.workspace / ".img2/artifacts/jev/recommendation.json").exists())

        self.prepare()
        self.command_live("route")
        report = self.load(".img2/artifacts/jev/recommendation.json")
        report["versions"]["normalizer"] = "repair-state-v1"
        self.write(".img2/artifacts/jev/recommendation.json", report)
        module = self.load_jev_module()
        with mock.patch.dict(os.environ, {"IMG2_HOME": str(self.home)}):
            with self.assertRaisesRegex(module.ContractError, "recommendation version mismatch"):
                module.validate_report(self.workspace, report)
        provider_calls = self.provider_calls.read_text(encoding="utf-8").splitlines()
        self.assertEqual(provider_calls, ["dispatch"])
        self.assertTrue(self.gate(1)["stopped"])
        self.assertEqual(self.provider_calls.read_text(encoding="utf-8").splitlines(), provider_calls)

    def test_rules_provider_option_is_not_available_to_the_route_cli(self):
        proc = subprocess.run(
            [sys.executable, "-m", "jev_cli_bootstrap", "route", "--provider", "rules", "--workspace", str(self.workspace)],
            cwd=self.workspace, env=self.env, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("unrecognized arguments", proc.stderr)
        self.assertFalse((self.workspace / ".img2/artifacts/jev/recommendation.json").exists())
        self.assertFalse(self.provider_calls.exists())
    def test_route_selects_single_canonical_gate_with_multiple_evaluation_bindings(self):
        extra = "synthetic/extra-evaluation.json"
        target = self.workspace / extra
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("synthetic evaluation context", encoding="utf-8")
        self.observation["state"]["evidence"]["facts"][0]["source"] = "measurement"
        self.observation["bindings"].append({"role": "evaluation", "path": extra})
        self.write("observation.json", self.observation)
        self.prepare()
        self.command("consent", "authorize")
        result = self.command_live("route")
        self.assertEqual(result["providerStatus"], "evaluated")
        self.assertEqual(self.provider_calls.read_text(encoding="utf-8").splitlines(), ["dispatch"])

    def test_route_refuses_unqualified_adapter_before_provider_dispatch(self):
        path, gate = self.synthetic_gate(failed_row="12-ip-provenance-hygiene", adapter="street")
        self.bind_gate(path, gate)
        self.write("observation.json", self.observation)
        self.prepare()
        self.command("consent", "authorize")
        result = self.command("route", expected=2, env={"TYPESAFE_API_KEY": "synthetic-test-only-key"})
        self.assertEqual(result["status"], "error")
        self.assertIn("not fixture-qualified", result["reason"])
        self.assertFalse(self.provider_calls.exists())

    def test_prepare_requires_implementation_source_for_implementation_facts(self):
        self.observation["state"]["specification"]["implementationFacts"][0]["source"] = "measurement"
        self.write("observation.json", self.observation)
        result = self.command("prepare", "--input", "observation.json", expected=2)
        self.assertEqual(result["status"], "error")
        self.assertIn("implementation source", result["reason"])
    def test_record_outcome_refuses_unqualified_adapter(self):
        recommendation, outcome = self.v2_outcome()
        outcome["assetAdapter"] = "street"
        outcome["beforeSnapshot"]["evaluator"]["adapter"] = "street"
        outcome["afterSnapshot"]["evaluator"]["adapter"] = "street"
        self.write("outcome-v2.json", outcome)
        result = self.command("record-outcome", "--input", "outcome-v2.json", "--recommendation", recommendation["artifact"], expected=2)
        self.assertEqual(result["status"], "error")
        self.assertIn("not fixture-qualified", result["reason"])
        self.assertFalse(list((self.workspace / ".img2/artifacts/jev/outcomes/archive/records").glob("*.json")))
    def test_report_refuses_unqualified_adapter_in_archived_record(self):
        record = self._report_record("improved", evidence_class="observed")
        record["assetAdapter"] = "street"
        record["beforeSnapshot"]["evaluator"]["adapter"] = "street"
        record["afterSnapshot"]["evaluator"]["adapter"] = "street"
        serialized = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        record_hash = hashlib.sha256(serialized).hexdigest()
        persisted = self.workspace / ".img2/artifacts/jev/outcomes/archive/records" / (record_hash + ".json")
        persisted.parent.mkdir(parents=True, exist_ok=True)
        persisted.write_bytes(serialized + b"\n")
        self._write_report_corpus("unqualified.jsonl", [record])
        result = self._run_outcome_report("unqualified.jsonl")
        report = self.load(result["artifact"])
        self.assertEqual(report["eligibleCount"], 0)
        self.assertIn("invalid-record", {item["reason"] for item in report["exclusions"]})
        module = self.load_jev_module()
        core = {key: record[key] for key in "kind version recommendationId attemptId outcome recommendationHash approvedAction actualAction recommendationFollowed assetAdapter beforeSnapshot afterSnapshot measurements adjudication evidencePaths buildFailureEvidencePaths evidenceClass".split()}
        with self.assertRaisesRegex(module.ContractError, "not fixture-qualified"):
            module.validate_outcome(core)

if __name__ == "__main__":
    unittest.main()
