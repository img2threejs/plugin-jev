import unittest


from _harness import linked_harness

policy = None


def setUpModule():
    global policy
    with linked_harness():
        import jev_policy as module
    policy = module



class JevPolicyTest(unittest.TestCase):


    def state(self):
        return {
            "schemaVersion": "repair-state-v1",
            "passId": "material",
            "assetType": "character",
            "focus": {
                "issueId": "jacket",
                "componentIds": ["jacket"],
                "symptom": "Reference matte jacket renders glossy",
                "requiredFeatureIds": ["finish"],
            },
            "components": [{
                "id": "jacket",
                "role": "jacket shell",
                "parentId": None,
                "sharedResourceUsers": [],
                "protectedProperties": [],
            }],
            "specification": {
                "requirements": [{
                    "featureId": "finish",
                    "statement": "Matte jacket",
                    "evidenceIds": ["spec-finish"],
                }],
                "implementationFacts": [{
                    "id": "impl-finish",
                    "source": "implementation",
                    "kind": "observation",
                    "statement": "Jacket roughness is 0.1",
                }],
            },
            "gates": [{
                "id": "typecheck",
                "status": "pass",
                "blocking": True,
                "coverage": "complete",
                "evidenceIds": ["build"],
            }],
            "evidence": {
                "facts": [
                    {"id": "spec-finish", "source": "spec", "kind": "observation", "statement": "Matte jacket"},
                    {"id": "build", "source": "validator", "kind": "observation", "statement": "Typecheck passed"},
                    {"id": "visual", "source": "vision", "kind": "observation", "statement": "Gloss on jacket unlike reference"},
                ],
                "missing": [],
                "comparison": "comparable",
                "conflicts": [],
            },
            "recentAttempts": [],
        }

    def control(self, **overrides):
        value = {
            "controllerStopped": False,
            "remainingBudgetUsd": 5,
            "remainingDeadlineMs": 60000,
            "passCorrectionsUsed": 0,
            "totalCorrectionsUsed": 0,
            "passCorrectionLimit": 3,
            "totalCorrectionLimit": 6,
            "evidenceJobsUsed": 0,
            "noProgressCount": 0,
            "oscillationDetected": False,
        }
        value.update(overrides)
        return value

    def answer(self, name, choice, confidence=0.9, probability=0.9):
        options = {
            "evidence": ["sufficient", "need_capture", "need_reference", "conflicting", "unknown"],
            "domain": ["capture", "hierarchy", "geometry", "material", "rigging", "animation", "vfx", "mixed", "unknown"],
            "specRelation": ["supported", "contradicted", "underspecified", "unknown"],
            "scope": ["parameter_patch", "component_rebuild", "cross_component", "unknown"],
        }[name]
        rest = (1.0 - probability) / (len(options) - 1)
        probabilities = {option: rest for option in options}
        probabilities[choice] = probability
        return {
            "type": "choice",
            "choice": choice,
            "probabilities": probabilities,
            "confidence": confidence,
        }

    def response(self, *, evidence="sufficient", domain="material", specRelation="supported", scope="parameter_patch", confidence=0.9, probability=0.9):
        return {
            "model": "jev-1.13.0",
            "answers": {
                "evidence": self.answer("evidence", evidence, confidence, probability),
                "domain": self.answer("domain", domain, confidence, probability),
                "specRelation": self.answer("specRelation", specRelation, confidence, probability),
                "scope": self.answer("scope", scope, confidence, probability),
            },
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }

    def assert_route(self, proposal, action, tactic, worker_tier=None):
        self.assertEqual(proposal["action"], action)
        self.assertEqual(proposal["tactic"], tactic)
        self.assertEqual(proposal["workerTier"], worker_tier)
        self.assertEqual(proposal["componentIds"], ["jacket"])
        self.assertTrue(proposal["requiresApproval"])
        self.assertIsInstance(proposal["reasonCodes"], list)

    def test_proposal_shape(self):
        proposal = policy.recommend(self.state(), self.control(), self.response())
        self.assertEqual(set(proposal), {"action", "tactic", "reasonCodes", "requiresApproval", "workerTier", "componentIds"})
        self.assert_route(proposal, "refine-code", "parameter-patch", "routine")

    def test_preflight_hard_stop_precedence(self):
        state = self.state()
        state["gates"][0]["status"] = "fail"
        proposal = policy.preflight(state, self.control(controllerStopped=True, remainingBudgetUsd=0, totalCorrectionsUsed=6))
        self.assert_route(proposal, "stop", "stop")

        proposal = policy.preflight(self.state(), self.control(remainingBudgetUsd=0, totalCorrectionsUsed=6))
        self.assert_route(proposal, "stop", "stop")
        proposal = policy.preflight(self.state(), self.control(passCorrectionsUsed=3))
        self.assert_route(proposal, "stop", "stop")

    def test_preflight_gate_safety_and_failure(self):
        state = self.state()
        state["gates"][0]["status"] = "unknown"
        self.assert_route(policy.preflight(state, self.control()), "request-input", "re-analyze")

        state = self.state()
        state["gates"][0]["coverage"] = "partial"
        self.assert_route(policy.preflight(state, self.control()), "request-input", "re-analyze")

        state = self.state()
        state["gates"][0]["status"] = "fail"
        self.assert_route(policy.preflight(state, self.control()), "refine-code", "hard-gate-repair", "standard")

        state["gates"][0]["status"] = "fail"
        state["gates"].append({
            "id": "visual-check",
            "status": "unknown",
            "blocking": True,
            "coverage": "none",
            "evidenceIds": [],
        })
        self.assert_route(policy.preflight(state, self.control()), "refine-code", "hard-gate-repair", "standard")

    def test_preflight_evidence_uncertainty_and_progress(self):
        state = self.state()
        state["evidence"]["comparison"] = "not_comparable"
        self.assert_route(policy.preflight(state, self.control()), "request-input", "re-render")

        state = self.state()
        state["evidence"]["comparison"] = "unknown"
        self.assert_route(policy.preflight(state, self.control()), "request-input", "re-analyze")

        state = self.state()
        state["evidence"]["conflicts"] = [["spec-finish", "visual"]]
        self.assert_route(policy.preflight(state, self.control()), "request-input", "re-analyze")

        state = self.state()
        state["evidence"]["missing"] = ["reference_view"]
        self.assert_route(policy.preflight(state, self.control()), "request-input", "request-reference")

        state = self.state()
        state["evidence"]["missing"] = ["render_view"]
        self.assert_route(policy.preflight(state, self.control()), "request-input", "re-render")

        self.assert_route(policy.preflight(self.state(), self.control(noProgressCount=2)), "refine-spec", "spec-review", "standard")
        self.assert_route(policy.preflight(self.state(), self.control(oscillationDetected=True)), "refine-spec", "spec-review", "standard")

    def test_recommend_response_fallback_and_evidence_budget(self):
        self.assert_route(policy.recommend(self.state(), self.control(), None), "defer", "fallback")

        state = self.state()
        state["evidence"]["missing"] = ["render_view"]
        proposal = policy.recommend(state, self.control(evidenceJobsUsed=1), self.response())
        self.assert_route(proposal, "request-input", "request-reference")

        # A completed evidence capture must not block a supported, bounded repair.
        proposal = policy.recommend(self.state(), self.control(evidenceJobsUsed=1), self.response())
        self.assert_route(proposal, "refine-code", "parameter-patch", "routine")

    def test_evidence_answer_routes(self):
        for choice, tactic in (("need_capture", "re-render"), ("need_reference", "request-reference"), ("conflicting", "re-analyze"), ("unknown", "re-analyze")):
            proposal = policy.recommend(self.state(), self.control(), self.response(evidence=choice))
            self.assert_route(proposal, "request-input", tactic)

    def test_answer_floors_defer_without_authority(self):
        proposal = policy.recommend(self.state(), self.control(), self.response(probability=0.79))
        self.assert_route(proposal, "defer", "re-analyze")
        proposal = policy.recommend(self.state(), self.control(), self.response(confidence=0.49))
        self.assert_route(proposal, "defer", "re-analyze")

    def test_spec_domain_and_scope_boundaries(self):
        self.assert_route(policy.recommend(self.state(), self.control(), self.response(specRelation="contradicted")), "refine-spec", "spec-review", "standard")
        self.assert_route(policy.recommend(self.state(), self.control(), self.response(specRelation="underspecified")), "refine-spec", "spec-review", "standard")
        self.assert_route(policy.recommend(self.state(), self.control(), self.response(specRelation="unknown")), "request-input", "re-analyze")
        self.assert_route(policy.recommend(self.state(), self.control(), self.response(domain="capture")), "request-input", "re-render")
        self.assert_route(policy.recommend(self.state(), self.control(), self.response(domain="mixed")), "request-input", "re-analyze")
        self.assert_route(policy.recommend(self.state(), self.control(), self.response(domain="rigging")), "defer", "fallback")
        self.assert_route(policy.recommend(self.state(), self.control(), self.response(scope="unknown")), "defer", "re-analyze")
        self.assert_route(policy.recommend(self.state(), self.control(), self.response(scope="component_rebuild")), "refine-code", "component-rebuild", "standard")
        self.assert_route(policy.recommend(self.state(), self.control(), self.response(scope="cross_component")), "refine-code", "cross-component", "standard")

    def test_positive_repairs_require_independent_evidence(self):
        state = self.state()
        state["specification"]["implementationFacts"] = []
        self.assert_route(policy.recommend(state, self.control(), self.response()), "request-input", "re-analyze")

        state = self.state()
        state["evidence"]["facts"] = [state["evidence"]["facts"][1], state["evidence"]["facts"][2]]
        self.assert_route(policy.recommend(state, self.control(), self.response()), "request-input", "re-analyze")

        state = self.state()
        state["evidence"]["facts"] = [state["evidence"]["facts"][0], state["evidence"]["facts"][1]]
        self.assert_route(policy.recommend(state, self.control(), self.response()), "request-input", "re-analyze")

    def test_shared_and_protected_material_footprint_defers(self):
        state = self.state()
        state["components"][0]["sharedResourceUsers"] = ["jacket", "sleeve"]
        self.assert_route(policy.recommend(state, self.control(), self.response()), "defer", "fallback")

        state = self.state()
        state["components"][0]["protectedProperties"] = ["finish"]
        self.assert_route(policy.recommend(state, self.control(), self.response()), "defer", "fallback")

    def test_clear_policy_has_no_accept_or_continue_route(self):
        proposals = [
            policy.preflight(self.state(), self.control()),
            policy.recommend(self.state(), self.control(), self.response()),
            policy.recommend(self.state(), self.control(), None),
        ]
        for proposal in proposals:
            if proposal is not None:
                self.assertNotIn(proposal["action"], {"accept", "continue"})
                self.assertTrue(proposal["requiresApproval"])


if __name__ == "__main__":
    unittest.main()
