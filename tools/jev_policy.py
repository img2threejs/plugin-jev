import os, sys
root = os.environ.get("IMG2_HOME")
if root: sys.path.insert(0, os.path.join(root, "harness"))
else:
    try: import _img2_local; sys.path.insert(0, _img2_local.CORE)
    except ImportError: sys.exit("img2: core not linked - run `img2 sync`")
from img2_core import require_core_api
require_core_api(1)


import math
from collections.abc import Mapping, Sequence
from typing import Any


POLICY_VERSION = "repair-policy-v1"

ACTIONS = frozenset({
    "refine-code",
    "refine-spec",
    "request-input",
    "stop",
    "defer",
})
TACTICS = frozenset({
    "parameter-patch",
    "component-rebuild",
    "cross-component",
    "re-render",
    "re-analyze",
    "request-reference",
    "spec-review",
    "hard-gate-repair",
    "stop",
    "fallback",
})
WORKER_TIERS = frozenset({"standard", "routine", None})

_ANSWER_OPTIONS = {
    "evidence": frozenset({"sufficient", "need_capture", "need_reference", "conflicting", "unknown"}),
    "domain": frozenset({"capture", "hierarchy", "geometry", "material", "rigging", "animation", "vfx", "mixed", "unknown"}),
    "specRelation": frozenset({"supported", "contradicted", "underspecified", "unknown"}),
    "scope": frozenset({"parameter_patch", "component_rebuild", "cross_component", "unknown"}),
}


def _component_ids(state: Any) -> list[str]:
    if not isinstance(state, Mapping):
        return []
    focus = state.get("focus")
    if not isinstance(focus, Mapping):
        return []
    values = focus.get("componentIds")
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes, bytearray)):
        return []
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if isinstance(value, str) and value and value not in seen:
            result.append(value)
            seen.add(value)
    return result


def _number(control: Mapping[str, Any], key: str, default: float | int) -> float | int:
    value = control.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    if not math.isfinite(value):
        return default
    return value


def _limit(control: Mapping[str, Any], key: str, default: int) -> int:
    value = _number(control, key, default)
    return min(default, max(0, int(value)))


def _proposal(
    action: str,
    tactic: str,
    reasons: Sequence[str],
    component_ids: Sequence[str],
    worker_tier: str | None = None,
) -> dict[str, Any]:
    # Keep this constructor as the sole proposal shape.  In particular, no
    # provider answer, control, or generated rationale is copied into it.
    if action not in ACTIONS or tactic not in TACTICS or worker_tier not in WORKER_TIERS:
        raise ValueError("invalid Jev policy proposal")
    return {
        "action": action,
        "tactic": tactic,
        "reasonCodes": list(reasons),
        "requiresApproval": True,
        "workerTier": worker_tier,
        "componentIds": list(component_ids),
    }


def _request(
    tactic: str,
    reasons: Sequence[str],
    component_ids: Sequence[str],
) -> dict[str, Any]:
    return _proposal("request-input", tactic, reasons, component_ids)


def _budget_proposal(
    proposal: dict[str, Any] | None,
    control: Mapping[str, Any],
    component_ids: Sequence[str],
) -> dict[str, Any] | None:
    """Bound repeated evidence requests without blocking valid repairs."""
    if proposal is None:
        return None
    if _number(control, "evidenceJobsUsed", 0) >= 1 and proposal["tactic"] in {"re-render", "re-analyze"}:
        return _request("request-reference", ["evidence-budget-exhausted"], component_ids)
    return proposal


def _stop(reason: str, component_ids: Sequence[str]) -> dict[str, Any]:
    return _proposal("stop", "stop", [reason], component_ids)


def _gate_preflight(state: Mapping[str, Any], component_ids: Sequence[str], *, allow_failed=False) -> dict[str, Any] | None:
    gates = state.get("gates")
    if not isinstance(gates, list) or not gates:
        return _request("re-analyze", ["blocking-gate-uncertain"], component_ids)

    uncertain: list[str] = []
    failed = False
    for gate in gates:
        if not isinstance(gate, Mapping) or not gate.get("blocking"):
            continue
        status = gate.get("status")
        coverage = gate.get("coverage")
        if status == "fail":
            failed = True
            continue
        if status in {"unknown", "not_run"}:
            uncertain.append("blocking-gate-uncertain")
        elif status in {"pass", "not_applicable"} and coverage != "complete":
            uncertain.append("blocking-gate-partial")
        elif status not in {"pass", "not_applicable"}:
            uncertain.append("blocking-gate-uncertain")

    if failed and not allow_failed:
        return _proposal("refine-code", "hard-gate-repair", ["blocking-gate-failed"], component_ids, "standard")
    if uncertain:
        return _request("re-analyze", list(dict.fromkeys(uncertain)), component_ids)
    return None


def _evidence_preflight(state: Mapping[str, Any], component_ids: Sequence[str]) -> dict[str, Any] | None:
    evidence = state.get("evidence")
    if not isinstance(evidence, Mapping):
        return _request("re-analyze", ["evidence-uncertain"], component_ids)

    conflicts = evidence.get("conflicts")
    if conflicts:
        return _request("re-analyze", ["conflicting-evidence"], component_ids)

    comparison = evidence.get("comparison")
    if comparison == "not_comparable":
        return _request("re-render", ["evidence-not-comparable"], component_ids)
    if comparison != "comparable":
        return _request("re-analyze", ["evidence-comparison-unknown"], component_ids)

    missing = evidence.get("missing")
    if not isinstance(missing, list):
        return _request("re-analyze", ["evidence-uncertain"], component_ids)
    if "reference_view" in missing:
        return _request("request-reference", ["reference-view-missing"], component_ids)
    if "implementation_fact" in missing:
        return _request("re-analyze", ["implementation-fact-missing"], component_ids)
    if missing:
        return _request("re-render", ["evidence-missing"], component_ids)
    return None


def _preflight(state: Mapping[str, Any], control: Mapping[str, Any], *, allow_failed_gates: bool) -> dict[str, Any] | None:
    state_map = state if isinstance(state, Mapping) else {}
    control_map = control if isinstance(control, Mapping) else {}
    component_ids = _component_ids(state_map)

    if control_map.get("controllerStopped") is True:
        return _stop("controller-stopped", component_ids)
    if _number(control_map, "remainingBudgetUsd", 0) <= 0:
        return _stop("budget-exhausted", component_ids)
    if _number(control_map, "remainingDeadlineMs", 0) <= 0:
        return _stop("deadline-exhausted", component_ids)

    pass_limit = _limit(control_map, "passCorrectionLimit", 3)
    total_limit = _limit(control_map, "totalCorrectionLimit", 6)
    if _number(control_map, "passCorrectionsUsed", 0) >= pass_limit:
        return _stop("pass-correction-ceiling", component_ids)
    if _number(control_map, "totalCorrectionsUsed", 0) >= total_limit:
        return _stop("total-correction-ceiling", component_ids)

    gate_proposal = _gate_preflight(state_map, component_ids, allow_failed=allow_failed_gates)
    if gate_proposal is not None:
        return _budget_proposal(gate_proposal, control_map, component_ids)
    evidence_proposal = _evidence_preflight(state_map, component_ids)
    if evidence_proposal is not None:
        return _budget_proposal(evidence_proposal, control_map, component_ids)

    no_progress = _number(control_map, "noProgressCount", 0) >= 2
    oscillation = control_map.get("oscillationDetected") is True
    if no_progress or oscillation:
        reasons: list[str] = []
        if no_progress:
            reasons.append("no-progress")
        if oscillation:
            reasons.append("oscillation-detected")
        return _proposal("refine-spec", "spec-review", reasons, component_ids, "standard")
    return None


def preflight(state: Mapping[str, Any], control: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return deterministic preflight advice for offline policy diagnostics."""
    return _preflight(state, control, allow_failed_gates=False)


def preflight_live(state: Mapping[str, Any], control: Mapping[str, Any]) -> dict[str, Any] | None:
    """Apply non-gate safety stops after the caller validates the complete failed Environment snapshot."""
    return _preflight(state, control, allow_failed_gates=True)


def _read_answer(response: Any, name: str) -> tuple[str | None, float | None, float | None]:
    if not isinstance(response, Mapping):
        return None, None, None
    answers = response.get("answers")
    if not isinstance(answers, Mapping):
        return None, None, None
    answer = answers.get(name)
    if not isinstance(answer, Mapping):
        return None, None, None

    selected = answer.get("selected")
    if not isinstance(selected, str):
        # ``choice`` is accepted for the provider's documented Choice alias;
        # no free-form prose is consulted.
        selected = answer.get("choice")
    if not isinstance(selected, str):
        return None, None, None

    probabilities = answer.get("probabilities")
    if not isinstance(probabilities, Mapping):
        probabilities = answer.get("distribution")
    if not isinstance(probabilities, Mapping):
        return selected, None, None
    probability = probabilities.get(selected)
    confidence = answer.get("confidence")
    if isinstance(probability, bool) or not isinstance(probability, (int, float)) or not math.isfinite(probability):
        probability = None
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not math.isfinite(confidence):
        confidence = None
    return selected, probability, confidence


def _answer_floor(
    response: Any,
    name: str,
    component_ids: Sequence[str],
) -> tuple[str | None, dict[str, Any] | None]:
    selected, probability, confidence = _read_answer(response, name)
    if selected is None or probability is None or confidence is None:
        return None, _proposal("defer", "re-analyze", [f"answer-floor-{name}"], component_ids)
    if probability < 0.8 or confidence < 0.5:
        return None, _proposal("defer", "re-analyze", [f"answer-floor-{name}"], component_ids)
    if selected not in _ANSWER_OPTIONS[name]:
        return None, _proposal("defer", "re-analyze", [f"answer-unsupported-{name}"], component_ids)
    return selected, None


def _positive_evidence(state: Mapping[str, Any]) -> tuple[bool, list[str]]:
    specification = state.get("specification")
    evidence = state.get("evidence")
    if not isinstance(specification, Mapping) or not isinstance(evidence, Mapping):
        return False, ["repair-evidence-uncertain"]

    implementation_facts = specification.get("implementationFacts")
    if not isinstance(implementation_facts, list) or not implementation_facts:
        return False, ["implementation-observation-missing"]
    if not any(
        isinstance(fact, Mapping)
        and fact.get("source") == "implementation"
        and fact.get("kind") == "observation"
        for fact in implementation_facts
    ):
        return False, ["implementation-observation-missing"]

    facts = evidence.get("facts")
    if not isinstance(facts, list):
        return False, ["repair-evidence-uncertain"]
    if not any(
        isinstance(fact, Mapping)
        and fact.get("source") == "spec"
        and fact.get("kind") == "observation"
        for fact in facts
    ):
        return False, ["spec-observation-missing"]
    if not any(
        isinstance(fact, Mapping)
        and fact.get("source") == "vision"
        and fact.get("kind") == "observation"
        for fact in facts
    ):
        return False, ["vision-observation-missing"]
    return True, []


def _material_footprint(state: Mapping[str, Any], component_ids: Sequence[str]) -> list[str]:
    components = state.get("components")
    if not isinstance(components, list):
        return ["repair-footprint-uncertain"]
    focus = set(component_ids)
    if not focus:
        return ["repair-footprint-uncertain"]

    reasons: list[str] = []
    found_focus = False
    for component in components:
        if not isinstance(component, Mapping) or component.get("id") not in focus:
            continue
        found_focus = True
        users = component.get("sharedResourceUsers")
        if isinstance(users, Sequence) and not isinstance(users, (str, bytes, bytearray)):
            if any(user not in focus for user in users):
                reasons.append("shared-resource-outside-focus")
        elif users is not None:
            reasons.append("repair-footprint-uncertain")
        protected = component.get("protectedProperties")
        if isinstance(protected, Sequence) and not isinstance(protected, (str, bytes, bytearray)):
            if protected:
                reasons.append("protected-property")
        elif protected is not None:
            reasons.append("repair-footprint-uncertain")
    if not found_focus:
        reasons.append("repair-footprint-uncertain")
    return list(dict.fromkeys(reasons))


def _recommend_raw(state: Mapping[str, Any], control: Mapping[str, Any], response: Mapping[str, Any] | None, *, allow_failed_gates=False) -> dict[str, Any]:
    """Map validated Jev answers to an approval-required proposal.

    The provider response is advisory only.  Hard stops and evidence checks
    are performed first, and no branch can produce an accept/continue action
    or execute a repair.
    """
    state_map = state if isinstance(state, Mapping) else {}
    control_map = control if isinstance(control, Mapping) else {}
    component_ids = _component_ids(state_map)

    preflight_proposal = _preflight(state_map, control_map, allow_failed_gates=allow_failed_gates)
    if preflight_proposal is not None:
        return preflight_proposal

    if response is None:
        return _proposal("defer", "fallback", ["provider-unavailable"], component_ids)


    evidence_answer, proposal = _answer_floor(response, "evidence", component_ids)
    if proposal is not None:
        return proposal
    if evidence_answer == "need_capture":
        return _request("re-render", ["need-capture"], component_ids)
    if evidence_answer == "need_reference":
        return _request("request-reference", ["need-reference"], component_ids)
    if evidence_answer in {"conflicting", "unknown"}:
        return _request("re-analyze", [f"evidence-{evidence_answer}"], component_ids)
    if evidence_answer != "sufficient":
        return _proposal("defer", "re-analyze", ["evidence-answer-unsupported"], component_ids)

    spec_relation, proposal = _answer_floor(response, "specRelation", component_ids)
    if proposal is not None:
        return proposal
    if spec_relation in {"contradicted", "underspecified"}:
        return _proposal("refine-spec", "spec-review", [f"spec-{spec_relation}"], component_ids, "standard")
    if spec_relation == "unknown":
        return _request("re-analyze", ["spec-relation-unknown"], component_ids)
    if spec_relation != "supported":
        return _proposal("defer", "re-analyze", ["spec-relation-unsupported"], component_ids)

    domain, proposal = _answer_floor(response, "domain", component_ids)
    if proposal is not None:
        return proposal
    if domain in {"mixed", "unknown"}:
        return _request("re-analyze", [f"domain-{domain}"], component_ids)
    if domain == "capture":
        return _request("re-render", ["capture-domain"], component_ids)
    if domain in {"rigging", "animation", "vfx"}:
        return _proposal("defer", "fallback", [f"unsupported-domain-{domain}"], component_ids)
    if domain not in {"hierarchy", "geometry", "material"}:
        return _proposal("defer", "fallback", ["domain-unsupported"], component_ids)

    scope, proposal = _answer_floor(response, "scope", component_ids)
    if proposal is not None:
        return proposal
    if scope == "unknown":
        return _proposal("defer", "re-analyze", ["scope-unknown"], component_ids)
    if scope not in {"parameter_patch", "component_rebuild", "cross_component"}:
        return _proposal("defer", "re-analyze", ["scope-unsupported"], component_ids)

    positive, evidence_reasons = _positive_evidence(state_map)
    if not positive:
        return _request("re-analyze", evidence_reasons, component_ids)

    if scope == "parameter_patch":
        if domain == "material":
            footprint_reasons = _material_footprint(state_map, component_ids)
            if footprint_reasons:
                return _proposal("defer", "fallback", footprint_reasons, component_ids)
            return _proposal("refine-code", "parameter-patch", ["material-parameter-patch"], component_ids, "routine")
        return _proposal("refine-code", "parameter-patch", ["parameter-patch"], component_ids, "standard")
    if scope == "component_rebuild":
        return _proposal("refine-code", "component-rebuild", ["component-rebuild"], component_ids, "standard")
    return _proposal("refine-code", "cross-component", ["cross-component"], component_ids, "standard")


def recommend(state: Mapping[str, Any], control: Mapping[str, Any], response: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return a deterministic or recorded-response proposal for offline diagnostics."""
    state_map = state if isinstance(state, Mapping) else {}
    control_map = control if isinstance(control, Mapping) else {}
    component_ids = _component_ids(state_map)
    return _budget_proposal(_recommend_raw(state_map, control_map, response), control_map, component_ids)


def recommend_live(state: Mapping[str, Any], control: Mapping[str, Any], response: Mapping[str, Any]) -> dict[str, Any]:
    """Build current advice only from a validated live response and safe preflight."""
    if not isinstance(response, Mapping):
        raise ValueError("live recommendation requires a validated provider response")
    state_map = state if isinstance(state, Mapping) else {}
    control_map = control if isinstance(control, Mapping) else {}
    component_ids = _component_ids(state_map)
    proposal = _recommend_raw(state_map, control_map, response, allow_failed_gates=True)
    return _budget_proposal(proposal, control_map, component_ids)
