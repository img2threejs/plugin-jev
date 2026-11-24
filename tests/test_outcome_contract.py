import copy
import unittest


from _harness import linked_harness

contracts = None
policy = None


def setUpModule():
    global contracts, policy
    with linked_harness():
        import jev_policy as policy_module
        import jev_contracts as contracts_module
    policy, contracts = policy_module, contracts_module


def metric(feature, value, direction="higher-is-better", unit="score"):
    return {"featureId": feature, "value": value, "unit": unit, "direction": direction}


def record(*, outcome="improved", evidence_class="observed", status="independent"):
    before_metrics = [metric("silhouette", 0.5), metric("noise", 0.4, "lower-is-better", "ratio")]
    after_metrics = [metric("silhouette", 0.7), metric("noise", 0.3, "lower-is-better", "ratio")]
    rows = [
        {"featureId": "silhouette", "beforeValue": 0.5, "afterValue": 0.7, "unit": "score", "direction": "higher-is-better"},
        {"featureId": "noise", "beforeValue": 0.4, "afterValue": 0.3, "unit": "ratio", "direction": "lower-is-better"},
    ]
    approved = {"action": "refine-code", "tactic": "parameter-patch"}
    result = {
        "kind": "img2.repair-outcome", "version": 2,
        "recommendationId": "rec-1", "attemptId": "attempt-1", "outcome": outcome,
        "recommendationHash": "a" * 64, "approvedAction": approved,
        "actualAction": copy.deepcopy(approved), "recommendationFollowed": True,
        "assetAdapter": "room",
        "beforeSnapshot": {
            "id": "b" * 64,
            "measurementContextHash": "e" * 64,
            "evaluator": {"id": "env-checks", "version": "1.2", "adapter": "room", "checksDigest": "c" * 64},
            "metrics": before_metrics,
        },
        "afterSnapshot": {
            "id": "d" * 64,
            "measurementContextHash": "e" * 64,
            "evaluator": {"id": "env-checks", "version": "1.2", "adapter": "room", "checksDigest": "c" * 64},
            "metrics": after_metrics,
        },
        "measurements": {"rows": rows},
        "adjudication": {
            "status": status, "adjudicatorId": "reviewer-1" if status == "independent" else None,
            "method": "blind-review" if status == "independent" else None,
            "recordedAt": "2026-09-28T12:00:00Z",
        },
        "evidencePaths": ["reports/before.json", "reports/after.json"],
        "buildFailureEvidencePaths": [],
        "evidenceClass": evidence_class,
    }
    if outcome == "build_failed":
        result["afterSnapshot"] = None
        result["measurements"] = {"rows": []}
        result["evidencePaths"] = ["build/failure.log"]
        result["buildFailureEvidencePaths"] = ["build/failure.log"]
    return result


class OutcomeContractTests(unittest.TestCase):
    def test_valid_record_boundaries_and_build_failure(self):
        value = record()
        self.assertIs(contracts.validate_outcome(value), value)
        boundary = copy.deepcopy(value)
        boundary["beforeSnapshot"]["metrics"] = [metric(f"feature-{i}", -1e308, unit="x") for i in range(32)]
        boundary["afterSnapshot"]["metrics"] = [metric(f"feature-{i}", -1e308, unit="x") for i in range(32)]
        boundary["measurements"]["rows"] = [
            {"featureId": f"feature-{i}", "beforeValue": -1e308, "afterValue": -1e308, "unit": "x", "direction": "higher-is-better"}
            for i in range(32)
        ]
        boundary["outcome"] = "unchanged"
        self.assertIs(contracts.validate_outcome(boundary), boundary)
        failed = record(outcome="build_failed")
        self.assertIs(contracts.validate_outcome(failed), failed)
        self.assertTrue(contracts.outcome_eligible(failed))
        bad = copy.deepcopy(failed)
        bad["buildFailureEvidencePaths"] = ["outside/failure.log"]
        with self.assertRaises(contracts.ContractError):
            contracts.validate_outcome(bad)
        bad = record()
        bad["buildFailureEvidencePaths"] = ["reports/before.json"]
        with self.assertRaises(contracts.ContractError):
            contracts.validate_outcome(bad)
    def test_evidence_path_limit_accepts_twelve_and_rejects_thirteen(self):
        value = record()
        value["evidencePaths"] = ["selected/evidence-" + str(index) + ".bin" for index in range(12)]
        self.assertIs(contracts.validate_outcome(value), value)
        value["evidencePaths"].append("selected/evidence-12.bin")
        with self.assertRaises(contracts.ContractError):
            contracts.validate_outcome(value)

    def test_arbitrary_precision_integers_are_finite(self):
        value = record(outcome="unchanged")
        huge = 10 ** 400
        for index, amount in enumerate((huge, -huge)):
            value["beforeSnapshot"]["metrics"][index]["value"] = amount
            value["afterSnapshot"]["metrics"][index]["value"] = amount
            value["measurements"]["rows"][index]["beforeValue"] = amount
            value["measurements"]["rows"][index]["afterValue"] = amount
        self.assertIs(contracts.validate_outcome(value), value)

    def test_mixed_numeric_precision_uses_order_not_subtraction(self):
        value = record(outcome="regressed")
        before, after = 9007199254740993, 9007199254740992.0
        value["beforeSnapshot"]["metrics"][0]["value"] = before
        value["afterSnapshot"]["metrics"][0]["value"] = after
        value["measurements"]["rows"][0]["beforeValue"] = before
        value["measurements"]["rows"][0]["afterValue"] = after
        self.assertIs(contracts.validate_outcome(value), value)
        value["outcome"] = "unchanged"
        with self.assertRaises(contracts.ContractError):
            contracts.validate_outcome(value)
    def test_rejects_invalid_hash_and_closed_shape_or_action_mismatch(self):
        bad_records = []
        bad = record()
        bad["recommendationHash"] = "A" * 64
        bad_records.append(("recommendationHash", bad))
        bad = record()
        bad["beforeSnapshot"]["id"] = "G" * 64
        bad_records.append(("snapshot id", bad))
        bad = record()
        bad["beforeSnapshot"]["evaluator"]["checksDigest"] = "z" * 63
        bad_records.append(("checksDigest", bad))
        for field, bad in bad_records:
            with self.subTest(field=field), self.assertRaises(contracts.ContractError):
                contracts.validate_outcome(bad)
        bad = record()
        bad["unexpected"] = True
        with self.assertRaises(contracts.ContractError):
            contracts.validate_outcome(bad)
        bad = record()
        bad["actualAction"]["tactic"] = "spec-review"
        with self.assertRaises(contracts.ContractError):
            contracts.validate_outcome(bad)
        bad = record()
        bad["actualAction"]["extra"] = "not-closed"
        with self.assertRaises(contracts.ContractError):
            contracts.validate_outcome(bad)

    def test_rejects_incomparable_evaluator_and_metrics(self):
        bad = record()
        bad["afterSnapshot"]["evaluator"]["checksDigest"] = "e" * 64
        with self.assertRaises(contracts.ContractError):
            contracts.validate_outcome(bad)
        bad = record()
        bad["afterSnapshot"]["measurementContextHash"] = "f" * 64
        with self.assertRaises(contracts.ContractError):
            contracts.validate_outcome(bad)
        bad = record()
        bad["afterSnapshot"]["evaluator"]["adapter"] = "street"
        with self.assertRaises(contracts.ContractError):
            contracts.validate_outcome(bad)
        bad = record()
        bad["afterSnapshot"]["metrics"][1]["featureId"] = "different"
        with self.assertRaises(contracts.ContractError):
            contracts.validate_outcome(bad)
        bad = record()
        bad["measurements"]["rows"][0]["featureId"] = "unknown"
        with self.assertRaises(contracts.ContractError):
            contracts.validate_outcome(bad)
        bad = record()
        bad["afterSnapshot"]["metrics"][1]["featureId"] = "silhouette"
        with self.assertRaises(contracts.ContractError):
            contracts.validate_outcome(bad)
        bad = record()
        bad["measurements"]["rows"].append(copy.deepcopy(bad["measurements"]["rows"][0]))
        with self.assertRaises(contracts.ContractError):
            contracts.validate_outcome(bad)

    def test_rejects_false_outcome_labels_and_wrong_direction(self):
        bad = record()
        bad["outcome"] = "regressed"
        with self.assertRaises(contracts.ContractError):
            contracts.validate_outcome(bad)
        bad = record()
        bad["outcome"] = "improved"
        bad["afterSnapshot"]["metrics"][0]["value"] = 0.4
        bad["measurements"]["rows"][0]["afterValue"] = 0.4
        with self.assertRaises(contracts.ContractError):
            contracts.validate_outcome(bad)
        bad = record()
        bad["outcome"] = "unchanged"
        with self.assertRaises(contracts.ContractError):
            contracts.validate_outcome(bad)

    def test_rejects_unsafe_paths(self):
        for path in ("../escape", "/absolute/file", "C:/absolute/file", r"reports\bad", ".img2/artifacts/jev/record.json", "reports/./bad", "reports/line\nfeed"):
            bad = record()
            bad["evidencePaths"] = [path]
            with self.subTest(path=path), self.assertRaises(contracts.ContractError):
                contracts.validate_outcome(bad)
        bad = record()
        bad["evidencePaths"] = []
        with self.assertRaises(contracts.ContractError):
            contracts.validate_outcome(bad)
        bad = record()
        bad["evidencePaths"] = ["reports/same", "reports/same"]
        with self.assertRaises(contracts.ContractError):
            contracts.validate_outcome(bad)
        bad = record()
        bad["evidencePaths"] = [["not-a-string"]]
        with self.assertRaises(contracts.ContractError):
            contracts.validate_outcome(bad)

    def test_synthetic_and_unadjudicated_records_are_valid_but_ineligible(self):
        synthetic = record(evidence_class="synthetic")
        unadjudicated = record(status="none")
        self.assertIs(contracts.validate_outcome(synthetic), synthetic)
        self.assertIs(contracts.validate_outcome(unadjudicated), unadjudicated)
        self.assertFalse(contracts.outcome_eligible(synthetic))
        self.assertFalse(contracts.outcome_eligible(unadjudicated))
        self.assertTrue(contracts.outcome_eligible(record()))


if __name__ == "__main__":
    unittest.main()
