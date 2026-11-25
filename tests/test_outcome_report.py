import hashlib
import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from _harness import linked_harness

PLUGIN_DIR = Path(__file__).resolve().parents[1]


def setUpModule():
    with linked_harness():
        for name in ("jev_policy", "jev_contracts", "jev_outcome_report"):
            importlib.import_module(name)


reporter = None
contracts = None


class OutcomeReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global reporter, contracts
        reporter = sys.modules["jev_outcome_report"]
        contracts = sys.modules["jev_contracts"]

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def corpus(self, entries):
        p = self.root / "chosen.jsonl"
        p.write_bytes(b"".join(json.dumps(v, sort_keys=True, separators=(",", ":")).encode() + b"\n" for v in entries))
        return "chosen.jsonl"

    def fake_core(self, item, outcome="improved", evidence="observed", adjudication="independent"):
        return {
            "kind": "img2.repair-outcome", "version": 2,
            "recommendationId": item["recommendationId"], "attemptId": item["attemptId"],
            "outcome": outcome, "recommendationHash": "a" * 64,
            "approvedAction": {"action": "refine", "tactic": "local-edit"},
            "actualAction": {"action": "refine", "tactic": "local-edit"},
            "recommendationFollowed": True, "assetAdapter": "room",
            "beforeSnapshot": {"evaluator": {"version": "3", "checksDigest": "b" * 64}, "measurementContextHash": "c" * 64},
            "afterSnapshot": {"evaluator": {"version": "3", "checksDigest": "b" * 64}, "measurementContextHash": "c" * 64},
            "adjudication": {"status": adjudication}, "evidenceClass": evidence,
        }

    def fake_validate(self, workspace, item, raw):
        core = self.fake_core(item, item.get("outcome", "improved"), item.get("evidenceClass", "observed"), item.get("adjudicationStatus", "independent"))
        if item["attemptId"] == "a1":
            core["actualAction"] = {"action": "inspect", "tactic": "local-edit"}
        if item.get("incomparable"):
            core["afterSnapshot"]["measurementContextHash"] = "d" * 64
        mismatched = core["beforeSnapshot"]["measurementContextHash"] != core["afterSnapshot"]["measurementContextHash"]
        return core, {"policyVersion": "policy-7", "incomparable": mismatched, "recommendationProposal": {"action": "refine", "tactic": "local-edit"}}

    def test_empty_and_ineligible_only_are_insufficient_and_uncalibrated(self):
        empty = self.root / "empty.jsonl"
        empty.write_bytes(b"")
        r = reporter.build_report(self.root, "empty.jsonl")
        self.assertEqual(r["status"], "insufficient-data")
        self.assertEqual((r["liveCalls"], r["calibrationStatus"], r["eligibleCount"]), (0, "uncalibrated", 0))
        corpus = self.corpus([{"version": 1}, {"version": 2, "recommendationId": "r1", "attemptId": "a1", "evidenceClass": "synthetic"}, {"version": 2, "recommendationId": "r2", "attemptId": "a2", "adjudicationStatus": "none"}])
        with mock.patch.object(reporter, "_validate_record", side_effect=self.fake_validate):
            r = reporter.build_report(self.root, corpus)
        self.assertEqual(r["status"], "insufficient-data")
        self.assertEqual([x["reason"] for x in r["exclusions"]], ["legacy-v1", "synthetic", "unadjudicated"])

    def test_invalid_record_exclusion_omits_unstable_exception_text(self):
        corpus = self.corpus([{"version": 2}])
        first = reporter.build_report(self.root, corpus)
        second = reporter.build_report(self.root, corpus)
        expected = {"line": 1, "reason": "invalid-record"}
        self.assertEqual(first["exclusions"], [expected])
        self.assertEqual(first, second)
    def test_positive_aggregation_wilson_and_strata(self):
        entries = [
            {"version": 2, "recommendationId": f"r{i}", "attemptId": f"a{i}", "outcome": label}
            for i, label in enumerate(["improved", "unchanged", "regressed", "build_failed", "inconclusive"])
        ]
        corpus = self.corpus(entries)
        with mock.patch.object(reporter, "_validate_record", side_effect=self.fake_validate):
            r = reporter.build_report(self.root, corpus)
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["quality"]["denominator"], 3)
        self.assertEqual(r["attempt"]["denominator"], 4)
        self.assertEqual(r["quality"]["statuses"]["improved"]["rate"], 1 / 3)
        # Exact Wilson score interval for x=1,n=3,z=1.96.
        p, z, n = 1 / 3, 1.96, 3
        den = 1 + z*z/n
        center = (p + z*z/(2*n))/den
        margin = z*((p*(1-p)/n + z*z/(4*n*n))**0.5)/den
        self.assertAlmostEqual(r["quality"]["statuses"]["improved"]["wilson95"]["lower"], center-margin, places=14)
        self.assertAlmostEqual(r["quality"]["statuses"]["improved"]["wilson95"]["upper"], center+margin, places=14)
        self.assertEqual(r["inconclusive"], {"count": 1, "outsideDenominators": True})
        self.assertEqual(len(r["strata"]), 2)
        self.assertIn("actualAction", r["strata"][0])
        self.assertIn("recommendationFollowed", r["strata"][0])
        self.assertEqual(r["routingAgreement"]["denominator"], 5)
        self.assertEqual(r["liveCalls"], 0)
        self.assertIn("no causal-success inference", r["wording"])
        self.assertEqual(r["routingAgreement"]["count"], 4)
        self.assertEqual(r["routingAgreement"]["rate"], 4 / 5)
    def test_duplicate_pair_is_rejected_even_if_record_invalid(self):
        item = {"version": 2, "recommendationId": "same", "attemptId": "attempt"}
        with self.assertRaisesRegex(contracts.ContractError, r"duplicate recommendationId\+attemptId"):
            reporter.build_report(self.root, self.corpus([item, item]))

    def test_only_explicit_corpus_is_read(self):
        with mock.patch.object(reporter, "_validate_record", side_effect=self.fake_validate):
            self.corpus([{"version": 1}])
            (self.root / "elsewhere.jsonl").write_text('{"version":2}\n')
            r = reporter.build_report(self.root, "chosen.jsonl")
        self.assertEqual(r["excludedCount"], 1)
        self.assertEqual(r["corpusPath"], "chosen.jsonl")
        self.assertNotIn("elsewhere", r["corpusPath"])
    def test_corpus_symlink_swaps_before_and_after_open_are_rejected(self):
        target = self.root / "race.jsonl"
        outside_dir = tempfile.TemporaryDirectory(dir=self.root.parent)
        self.addCleanup(outside_dir.cleanup)
        outside = Path(outside_dir.name) / "outside.jsonl"
        outside.write_text("{\"version\":1}\n")
        original_read = reporter.os.read
        target.write_text("{\"version\":1}\n")
        swapped = False
        original_contained = contracts.contained
        def swap_after_contained(workspace, relative):
            nonlocal swapped
            path = original_contained(workspace, relative)
            if relative == "race.jsonl" and not swapped:
                swapped = True
                target.unlink()
                target.symlink_to(outside)
            return path
        with mock.patch.object(contracts, "contained", side_effect=swap_after_contained):
            with self.assertRaisesRegex(contracts.ContractError, "safely read"):
                reporter.build_report(self.root, "race.jsonl")
        self.assertTrue(swapped)
        target.unlink()
        target.write_text("{\"version\":1}\n")
        swapped = False
        def swap_after_open(descriptor, size):
            nonlocal swapped
            data = original_read(descriptor, size)
            if not swapped:
                swapped = True
                target.unlink()
                target.symlink_to(outside)
            return data
        with mock.patch.object(reporter.os, "read", side_effect=swap_after_open):
            with self.assertRaisesRegex(contracts.ContractError, "changed"): 
                reporter.build_report(self.root, "race.jsonl")
        self.assertTrue(swapped)
    def test_parent_directory_symlink_swap_after_containment_is_rejected(self):
        selected = self.root / "selected"
        selected.mkdir()
        (selected / "data.json").write_bytes(b"in-workspace")
        outside_dir = tempfile.TemporaryDirectory(dir=self.root.parent)
        self.addCleanup(outside_dir.cleanup)
        outside = Path(outside_dir.name)
        (outside / "data.json").write_bytes(b"outside-secret")
        moved = self.root / "selected-original"
        original_contained = contracts.contained
        swapped = False
        def swap_parent_after_containment(workspace, relative):
            nonlocal swapped
            path = original_contained(workspace, relative)
            if relative == "selected/data.json" and not swapped:
                swapped = True
                selected.rename(moved)
                selected.symlink_to(outside, target_is_directory=True)
            return path
        with mock.patch.object(contracts, "contained", side_effect=swap_parent_after_containment):
            with self.assertRaisesRegex(contracts.ContractError, "safely read"):
                reporter._safe_file(self.root, "selected/data.json", 1024)
        self.assertTrue(swapped)
    def test_workspace_root_symlink_swap_after_containment_is_rejected(self):
        workspace = self.root / "workspace"
        workspace.mkdir()
        (workspace / "data.json").write_bytes(b"in-workspace")
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "data.json").write_bytes(b"outside-secret")
        moved = self.root / "workspace-moved"
        original_contained = contracts.contained
        swapped = False
        def swap_root_after_containment(root, relative):
            nonlocal swapped
            path = original_contained(root, relative)
            if relative == "data.json" and not swapped:
                swapped = True
                workspace.rename(moved)
                workspace.symlink_to(outside, target_is_directory=True)
            return path
        try:
            with mock.patch.object(contracts, "contained", side_effect=swap_root_after_containment):
                with self.assertRaisesRegex(contracts.ContractError, "safely read"):
                    reporter._safe_file(workspace, "data.json", 1024)
        finally:
            if workspace.is_symlink():
                workspace.unlink()
            if moved.exists():
                moved.rename(workspace)
        self.assertTrue(swapped)

    def test_v2_contract_shape_normalizes_only_comparison_identity(self):
        metric_before = {"featureId": "quality", "value": 0.5, "unit": "score", "direction": "higher-is-better"}
        metric_after = {"featureId": "quality", "value": 0.7, "unit": "score", "direction": "higher-is-better"}
        evaluator = {"id": "env-checks", "version": "1.2", "adapter": "room", "checksDigest": "c" * 64}
        core = {"kind": "img2.repair-outcome", "version": 2, "recommendationId": "rec-1", "attemptId": "attempt-1", "outcome": "improved", "recommendationHash": "a" * 64, "approvedAction": {"action": "refine-code", "tactic": "parameter-patch"}, "actualAction": {"action": "refine-code", "tactic": "parameter-patch"}, "recommendationFollowed": True, "assetAdapter": "room", "beforeSnapshot": {"id": "b" * 64, "measurementContextHash": "e" * 64, "evaluator": evaluator, "metrics": [metric_before]}, "afterSnapshot": {"id": "d" * 64, "measurementContextHash": "f" * 64, "evaluator": evaluator, "metrics": [metric_after]}, "measurements": {"rows": [{"featureId": "quality", "beforeValue": 0.5, "afterValue": 0.7, "unit": "score", "direction": "higher-is-better"}]}, "adjudication": {"status": "independent", "adjudicatorId": "reviewer-1", "method": "blind-review", "recordedAt": "2026-09-28T12:00:00Z"}, "evidencePaths": ["reports/before.json", "reports/after.json"], "buildFailureEvidencePaths": [], "evidenceClass": "observed"}
        comparable = json.loads(json.dumps(core))
        comparable["afterSnapshot"]["measurementContextHash"] = comparable["beforeSnapshot"]["measurementContextHash"]
        invalid_label = json.loads(json.dumps(core))
        invalid_label["outcome"] = "unknown"
        with self.assertRaisesRegex(contracts.ContractError, "invalid value"):
            reporter._validate_outcome_shape(invalid_label)
        self.assertFalse(reporter._validate_outcome_shape(comparable))
        for changed_metric in ("feature", "unit", "direction", "adapter"):
            candidate = json.loads(json.dumps(comparable))
            if changed_metric == "feature":
                candidate["afterSnapshot"]["metrics"][0]["featureId"] = "other-feature"
                other_row = dict(candidate["measurements"]["rows"][0])
                other_row["featureId"] = "other-feature"
                candidate["measurements"]["rows"].append(other_row)
            elif changed_metric == "unit":
                candidate["afterSnapshot"]["metrics"][0]["unit"] = "ratio"
                candidate["measurements"]["rows"][0]["unit"] = "ratio"
            elif changed_metric == "direction":
                candidate["afterSnapshot"]["metrics"][0]["direction"] = "lower-is-better"
                candidate["measurements"]["rows"][0]["direction"] = "lower-is-better"
            else:
                candidate["afterSnapshot"]["evaluator"]["adapter"] = "street"
            self.assertTrue(reporter._validate_outcome_shape(candidate), changed_metric)
        reordered = json.loads(json.dumps(comparable))
        second_before = {"featureId": "second", "value": 0.2, "unit": "ratio", "direction": "higher-is-better"}
        second_after = {"featureId": "second", "value": 0.4, "unit": "ratio", "direction": "higher-is-better"}
        reordered["beforeSnapshot"]["metrics"].append(second_before)
        reordered["afterSnapshot"]["metrics"].append(second_after)
        reordered["afterSnapshot"]["metrics"].reverse()
        reordered["measurements"]["rows"].append({"featureId": "second", "beforeValue": 0.2, "afterValue": 0.4, "unit": "ratio", "direction": "higher-is-better"})
        incomplete = json.loads(json.dumps(reordered))
        incomplete["afterSnapshot"]["measurementContextHash"] = "a" * 64
        incomplete["measurements"]["rows"].pop()
        with self.assertRaisesRegex(contracts.ContractError, "do not cover all feature IDs"):
            reporter._validate_outcome_shape(incomplete)

    def test_routing_agreement_uses_archived_proposal_not_record_flag(self):
        recommendation_proposal = {"action": "defer", "tactic": "fallback"}
        record = {"actualAction": {"action": "refine-code", "tactic": "parameter-patch"}, "recommendationFollowed": True}
        self.assertFalse(reporter._follows_proposal(record, recommendation_proposal))
        record["actualAction"] = dict(recommendation_proposal)
        record["recommendationFollowed"] = False
        self.assertTrue(reporter._follows_proposal(record, recommendation_proposal))

    def test_valid_shape_context_mismatch_is_reported_as_incomparable(self):
        entry = {"version": 2, "recommendationId": "incomp", "attemptId": "a1", "incomparable": True}
        with mock.patch.object(reporter, "_validate_record", side_effect=self.fake_validate):
            report = reporter.build_report(self.root, self.corpus([entry]))
        self.assertEqual(report["eligibleCount"], 0)
        self.assertEqual(report["exclusions"][0]["reason"], "incomparable")

    def test_unparseable_selected_json_evidence_is_only_hash_checked(self):
        data = b"{"
        sha = hashlib.sha256(data).hexdigest()
        relative = f".img2/artifacts/jev/outcomes/archive/{sha[:2]}/{sha}.blob"
        path = self.root / relative
        path.parent.mkdir(parents=True)
        path.write_bytes(data)
        record = {"evidencePaths": ["failure/build.json"], "archivedEvidence": [{"originalPath": "failure/build.json", "archivedPath": relative, "size": len(data), "sha256": sha}]}
        self.assertEqual(reporter._archive_map(self.root, record)["failure/build.json"], data)

    def test_gate_snapshot_semantics_status_and_digest_are_enforced(self):
        evaluator = {"id": "environment-gate", "plugin": "environment", "version": 3, "adapter": "room", "checks": reporter.GATE_IDS, "checkDigest": "f" * 64}
        rows = [{"id": check_id, "status": "pass", "reasons": [], "evidence": {}} for check_id in reporter.GATE_IDS]
        evidence = {"gates": rows, "unevaluated": []}
        files = [{"path": ".img2/artifacts/environment/scene-intake.json", "size": 1, "sha256": "a" * 64}]
        status, reasons = "pass", []
        core = {"evaluator": evaluator, "files": files, "status": status, "reasons": reasons, "evidence": evidence}
        snapshot_id = reporter._hash(contracts.canonical(core))
        path = ".img2/artifacts/environment/gate-results/" + snapshot_id + ".json"
        gate_snapshot = {"id": snapshot_id, "path": path, "evaluator": evaluator, "files": files}
        gate = {"kind": "img2.gate-verdict", "version": 1, "gate": "environment", "plugin": "environment", "status": status, "reasons": reasons, "evidence": evidence, "evaluator": evaluator, "snapshot": gate_snapshot, "snapshotId": snapshot_id, "snapshotPath": path, "resultPath": path}
        record = {"archivedEvidence": [{"originalPath": path}], "assetAdapter": "room"}
        snapshot = {"id": snapshot_id, "evaluator": {"id": evaluator["id"], "version": "3", "adapter": "room", "checksDigest": evaluator["checkDigest"]}}
        self.assertEqual(reporter._gate(self.root, {path: contracts.canonical(gate)}, path, snapshot, record), gate)
        for mutate, message in ((lambda value: value.update(status="unknown"), "invalid value"), (lambda value: value.update(status="fail"), "status contradicts rows"), (lambda value: value.update(reasons=["wrong"]), "reasons differ")):
            bad = json.loads(json.dumps(gate))
            mutate(bad)
            with self.subTest(status=bad["status"], reasons=bad["reasons"]), self.assertRaisesRegex(contracts.ContractError, message):
                reporter._gate(self.root, {path: contracts.canonical(bad)}, path, snapshot, record)

    def test_context_metric_order_is_irrelevant_but_semantics_are_strict(self):
        metrics = [{"featureId": "q1", "value": 1, "unit": "score", "direction": "higher-is-better"}, {"featureId": "q2", "value": 2, "unit": "score", "direction": "higher-is-better"}]
        intake = {"sceneClassification": {"kind": "room"}, "sourceViews": [{"id": "view", "path": "ref.png", "sha256": "e" * 64}]}
        spec = {"reviewViewpoints": ["front"]}
        review = {"qualityMeasurements": metrics, "camera": {}, "renderer": "r", "resolution": {}, "exposure": 1, "toneMapping": "t", "background": {}, "environment": {}, "iblContribution": 0, "qualityMeasurementMethod": "method"}
        evaluator = {"id": "environment-gate", "version": "3", "adapter": "room", "checksDigest": "f" * 64}
        def check(objects):
            archive, archived, files = {}, [], []
            for path, value in zip(reporter.CONTEXT_PATHS, objects):
                data = contracts.canonical(value)
                sha = reporter._hash(data)
                archive[path] = data
                archived.append({"originalPath": path, "sha256": sha, "size": len(data)})
                files.append({"path": path, "sha256": sha, "size": len(data)})
            projection = {"adapter": objects[0]["sceneClassification"]["kind"], "sourceViews": [{"id": v["id"], "sha256": v["sha256"]} for v in objects[0]["sourceViews"]], "reviewViewpoints": objects[1]["reviewViewpoints"], **{key: objects[2][key] for key in ("camera", "renderer", "resolution", "exposure", "toneMapping", "background", "environment", "iblContribution")}, "qualityMeasurementMethod": objects[2]["qualityMeasurementMethod"]}
            files.extend([{"path": ".img2/artifacts/environment/reference-provenance.json", "size": 0, "sha256": "a" * 64}, {"path": reporter.ENVIRONMENT_SOURCE_FILES["room"], "size": 0, "sha256": "b" * 64}])
            gate = {"evaluator": {"adapter": "room"}, "snapshot": {"files": files}}
            record = {"archivedEvidence": archived}
            snapshot = {"id": "a" * 64, "evaluator": evaluator, "metrics": list(reversed(objects[2]["qualityMeasurements"])), "measurementContextHash": reporter._hash(contracts.canonical(projection))}
            reporter._verify_context(gate, snapshot, archive, record)
        check((intake, spec, review))
        for mutate in (lambda i, s, r: r.update(qualityMeasurementMethod=" "), lambda i, s, r: r.update(camera=None), lambda i, s, r: r["qualityMeasurements"][0].update(extra=True), lambda i, s, r: i["sceneClassification"].update(kind="street")):
            bad = json.loads(json.dumps([intake, spec, review]))
            mutate(*bad)
            with self.assertRaises(contracts.ContractError):
                check(tuple(bad))
        duplicate = json.loads(json.dumps([intake, spec, review]))
        duplicate[2]["qualityMeasurements"][1]["featureId"] = "q1"
        with self.assertRaisesRegex(contracts.ContractError, "duplicate scene-review quality measurement"):
            check(tuple(duplicate))

    def test_multiple_evaluation_roles_still_bind_the_before_gate(self):
        recommendation_id = "rec-multi"
        request_path = f".img2/artifacts/jev/records/{recommendation_id}.state.json"
        recommendation_path = f".img2/artifacts/jev/records/{recommendation_id}.json"
        before_path, extra_path = "gates/before.json", "gates/other.json"
        before_hash, extra_hash = "a" * 64, "b" * 64
        state = json.loads((PLUGIN_DIR / "examples" / "observation.json").read_text(encoding="utf-8"))["state"]
        request = {"state": state, "snapshot": {"files": [{"role": "evaluation", "path": before_path, "sha256": before_hash}, {"role": "evaluation", "path": extra_path, "sha256": extra_hash}]}}
        request_hash = reporter._hash(contracts.canonical(request))
        projection_hash = reporter._hash(contracts.canonical(reporter.project_state(state)))
        archive = {"kind": "img2.jev-outbound-request-archive", "version": 2, "request": request, "requestHash": request_hash, "projectionHash": projection_hash, "consentHash": None, "consentPolicyVersion": reporter.CONSENT_POLICY_VERSION}
        recommendation = {"id": recommendation_id, "requestPath": request_path, "requestHash": request_hash, "projectionHash": projection_hash, "consentHash": None, "consentPolicyVersion": reporter.CONSENT_POLICY_VERSION, "versions": {"projection": reporter.PROJECTION_POLICY_VERSION}, "provider": {"status": "rules"}}
        recommendation_hash = reporter._hash(contracts.canonical(recommendation))
        for relative, value in ((request_path, archive), (recommendation_path, recommendation)):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(contracts.canonical(value) + b"\n")
        record = {"recommendationId": recommendation_id, "recommendationHash": recommendation_hash, "beforeGatePath": before_path, "archivedEvidence": [{"originalPath": before_path, "sha256": before_hash}]}
        with mock.patch.object(contracts, "validate_request", return_value=request):
            got_recommendation, got_request = reporter._recommendation(self.root, record)
        self.assertEqual(got_recommendation, recommendation)
        self.assertEqual(got_request, request)
        archive["consentHash"] = "a" * 64
        target = self.root / request_path
        target.write_bytes(contracts.canonical(archive) + b"\n")
        with mock.patch.object(contracts, "validate_request", return_value=request):
            with self.assertRaisesRegex(contracts.ContractError, "disclosure binding mismatch"):
                reporter._recommendation(self.root, record)
        archive["consentHash"] = None
        archive["version"] = 1
        target.write_bytes(contracts.canonical(archive) + b"\n")
        with mock.patch.object(contracts, "validate_request", return_value=request):
            with self.assertRaisesRegex(contracts.ContractError, "unsupported archived outbound request"):
                reporter._recommendation(self.root, record)
    def _archive_case(self, corrupt=False, missing=False):
        data = b'{"x":1}\n'
        sha = hashlib.sha256(data).hexdigest()
        blob = f".img2/artifacts/jev/outcomes/archive/{sha[:2]}/{sha}.blob"
        path = self.root / blob
        path.parent.mkdir(parents=True, exist_ok=True)
        if not missing:
            path.write_bytes(b'{"x":2}\n' if corrupt else data)
        entry = {"originalPath": "gate.json", "archivedPath": blob, "size": len(data), "sha256": sha}
        record = {"evidencePaths": ["gate.json"], "archivedEvidence": [entry]}
        return record

    def test_report_artifact_cap_fails_before_return_or_write(self):
        corpus = self.corpus([{"version": 2} for _ in range(5000)])
        with self.assertRaisesRegex(contracts.ContractError, "128KiB report-artifact limit"):
            reporter.build_report(self.root, corpus)
        self.assertFalse((self.root / ".img2").exists())
    def test_archive_tampering_and_missing_blob_are_rejected(self):
        for corrupt, missing in [(True, False), (False, True)]:
            with self.subTest(corrupt=corrupt, missing=missing):
                with self.assertRaises(contracts.ContractError):
                    reporter._archive_map(self.root, self._archive_case(corrupt, missing))


    def test_build_failed_and_inconclusive_are_counted_in_separate_strata(self):
        entries = [{"version": 2, "recommendationId": "r1", "attemptId": "a1", "outcome": "build_failed"}, {"version": 2, "recommendationId": "r2", "attemptId": "a2", "outcome": "inconclusive"}]
        with mock.patch.object(reporter, "_validate_record", side_effect=self.fake_validate):
            report = reporter.build_report(self.root, self.corpus(entries))
        self.assertEqual(report["attempt"]["denominator"], 1)
        self.assertEqual(report["attempt"]["statuses"]["build_failed"]["count"], 1)
        self.assertEqual(report["quality"]["denominator"], 0)
        self.assertEqual(report["inconclusive"]["count"], 1)


if __name__ == "__main__":
    unittest.main()
