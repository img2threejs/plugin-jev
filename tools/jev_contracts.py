import os, sys
root = os.environ.get("IMG2_HOME")
if root: sys.path.insert(0, os.path.join(root, "harness"))
else:
    try: import _img2_local; sys.path.insert(0, _img2_local.CORE)
    except ImportError: sys.exit("img2: core not linked - run `img2 sync`")
from img2_core import require_core_api
require_core_api(1)

import hashlib
import json
import math
import re
import tempfile
from pathlib import Path

PLUGIN_ID = "jev"
MAX_JSON_BYTES = 131072
MAX_BOUND_BYTES = 64 * 1024 * 1024
ROLES = {"reference", "spec", "source", "render-profile", "evaluation", "pipeline-state"}
ENVIRONMENT_SCENE_KINDS = {"room", "street", "vegetation-cluster", "building-exterior"}
ENVIRONMENT_GATE_IDS = (
    "01-scene-classify", "02-subject-inventory", "03-placement-consistency",
    "04-scale-anchors", "05-occlusion", "06-terrain-grounding",
    "07-material-independence", "08-multi-angle-legality",
    "09-llm-vs-forge-agreement", "10-code-only-contract",
    "11-screenshot-gate", "12-ip-provenance-hygiene",
)
MAX_STATE_BYTES = 24 * 1024
_GATE_REASON_CODE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,95}\Z")


class ContractError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ContractError(message)


def obj(value, keys, where):
    require(isinstance(value, dict) and set(value) == set(keys.split()), where + ": unexpected or missing fields")
    return value


def text(value, where, limit=600):
    require(isinstance(value, str) and 0 < len(value) <= limit, where + ": bounded nonempty text required")
    require(not any(ord(c) < 32 and c not in "\n\t" for c in value), where + ": control characters refused")
    return value


def identifier(value, where):
    require(isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None, where + ": invalid identifier")
    return value


def sequence(value, where, maximum, minimum=0):
    require(isinstance(value, list) and minimum <= len(value) <= maximum, where + ": invalid list length")
    return value


def choice(value, allowed, where):
    require(isinstance(value, str) and value in allowed, where + ": invalid value")


def boolean(value, where):
    require(type(value) is bool, where + ": boolean required")


def number(value, where, integer=False):
    require(type(value) in ((int,) if integer else (int, float)), where + ": numeric value required")
    require(math.isfinite(value) and value >= 0, where + ": finite nonnegative value required")


def ids(value, where, maximum=12):
    sequence(value, where, maximum)
    for item in value:
        identifier(item, where)
    require(len(set(value)) == len(value), where + ": duplicate IDs")
    return set(value)


def validate_state(value):
    obj(value, "schemaVersion passId sceneKind focus components specification gates evidence recentAttempts", "state")
    require(value["schemaVersion"] == "repair-state-v2", "unsupported repair state version")
    identifier(value["passId"], "passId")
    choice(value["sceneKind"], ENVIRONMENT_SCENE_KINDS, "scene kind")
    focus = obj(value["focus"], "issueId componentIds symptom requiredFeatureIds", "focus")
    identifier(focus["issueId"], "issueId")
    text(focus["symptom"], "symptom")
    targets = ids(focus["componentIds"], "focus components", 5)
    require(bool(targets), "at least one focus component required")
    features = ids(focus["requiredFeatureIds"], "required features")
    component_ids = set()
    for item in sequence(value["components"], "components", 12, 1):
        obj(item, "id role parentId sharedResourceUsers protectedProperties", "component")
        name = identifier(item["id"], "component ID")
        require(name not in component_ids, "duplicate component ID")
        component_ids.add(name)
        text(item["role"], "component role", 160)
        if item["parentId"] is not None:
            identifier(item["parentId"], "parent ID")
        ids(item["sharedResourceUsers"], "shared resource users")
        for prop in sequence(item["protectedProperties"], "protected properties", 12):
            text(prop, "protected property", 160)
    require(targets <= component_ids, "unknown focus component")
    spec = obj(value["specification"], "requirements implementationFacts", "specification")
    evidence = obj(value["evidence"], "facts missing comparison conflicts", "evidence")
    choice(evidence["comparison"], {"comparable", "not_comparable", "unknown"}, "comparison")
    for item in sequence(evidence["missing"], "missing evidence", 5):
        choice(item, {"reference_view", "render_view", "pose_capture", "material_isolation", "implementation_fact"}, "missing evidence")
    facts = sequence(evidence["facts"], "facts", 16, 1) + sequence(spec["implementationFacts"], "implementation facts", 12)
    fact_ids = set()
    for fact in facts:
        obj(fact, "id source kind statement", "fact")
        name = identifier(fact["id"], "fact ID")
        require(name not in fact_ids, "duplicate fact ID")
        fact_ids.add(name)
        choice(fact["source"], {"validator", "vision", "spec", "implementation", "measurement"}, "fact source")
        choice(fact["kind"], {"observation", "inference"}, "fact kind")
        text(fact["statement"], "fact statement")
        if fact in spec["implementationFacts"]:
            require(fact["source"] == "implementation", "implementationFacts must use implementation source")
    references = []
    requirement_ids = set()
    for item in sequence(spec["requirements"], "requirements", 12, 1):
        obj(item, "featureId statement evidenceIds", "requirement")
        name = identifier(item["featureId"], "feature ID")
        require(name not in requirement_ids, "duplicate feature ID")
        requirement_ids.add(name)
        text(item["statement"], "requirement statement")
        references.extend(ids(item["evidenceIds"], "requirement evidence", 16))
    require(features <= requirement_ids, "unknown required feature")
    for expected_id, gate in zip(ENVIRONMENT_GATE_IDS, sequence(value["gates"], "gates", 12, 12)):
        obj(gate, "id status blocking coverage reasonCodes evidenceIds", "gate")
        require(gate["id"] == expected_id, "Environment gate rows are not canonical and ordered")
        choice(gate["status"], {"pass", "fail", "unknown", "not_run", "not_applicable"}, "gate status")
        choice(gate["coverage"], {"complete", "partial", "none"}, "gate coverage")
        boolean(gate["blocking"], "gate blocking")
        reason_codes = sequence(gate["reasonCodes"], "gate reason codes", 8)
        require(all(isinstance(code, str) and _GATE_REASON_CODE.fullmatch(code) is not None for code in reason_codes), "gate reasons must be normalized codes")
        require(len(set(reason_codes)) == len(reason_codes), "duplicate gate reason code")
        if gate["status"] == "pass":
            require(not reason_codes, "passing gate cannot contain failure reason codes")
        elif gate["status"] == "fail":
            require(bool(reason_codes), "failed gate requires a normalized reason code")
        refs = ids(gate["evidenceIds"], "gate evidence", 16)
        if gate["status"] in {"pass", "fail", "not_applicable"}:
            require(bool(refs), "evaluated gate requires evidence")
        require(not (gate["status"] == "pass" and gate["coverage"] == "none"), "unmeasured gate cannot pass")
        references.extend(refs)
    for conflict in sequence(evidence["conflicts"], "conflicts", 12):
        sequence(conflict, "conflict", 2, 2)
        references.extend(ids(conflict, "conflicting facts", 2))
    for attempt in sequence(value["recentAttempts"], "recent attempts", 3):
        obj(attempt, "strategyId componentIds hypothesis outcome improvedFeatureIds regressedFeatureIds evidenceIds", "attempt")
        identifier(attempt["strategyId"], "strategy ID")
        ids(attempt["componentIds"], "attempt components")
        text(attempt["hypothesis"], "attempt hypothesis")
        choice(attempt["outcome"], {"improved", "unchanged", "regressed", "inconclusive", "build_failed"}, "attempt outcome")
        ids(attempt["improvedFeatureIds"], "improved features")
        ids(attempt["regressedFeatureIds"], "regressed features")
        references.extend(ids(attempt["evidenceIds"], "attempt evidence", 16))
    require(set(references) <= fact_ids, "unknown evidence reference")
    require(len(canonical(value)) <= MAX_STATE_BYTES, "decision state exceeds 24KiB; narrow focus without dropping protections")
    return value


def validate_control(value):
    obj(value, "controllerStopped remainingBudgetUsd remainingDeadlineMs passCorrectionsUsed totalCorrectionsUsed passCorrectionLimit totalCorrectionLimit evidenceJobsUsed noProgressCount oscillationDetected", "control")
    for key in ("controllerStopped", "oscillationDetected"):
        boolean(value[key], key)
    for key in set(value) - {"controllerStopped", "oscillationDetected"}:
        number(value[key], key, integer=key != "remainingBudgetUsd")
    require(value["passCorrectionLimit"] <= 3 and value["totalCorrectionLimit"] <= 6, "router cannot increase existing correction ceilings")
    require(value["passCorrectionsUsed"] <= value["totalCorrectionsUsed"], "pass count exceeds total count")
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def decode(data):
    require(len(data) <= MAX_JSON_BYTES, "JSON artifact exceeds 128KiB")
    try:
        return json.loads(data, object_pairs_hook=_unique_object, parse_constant=lambda _: (_ for _ in ()).throw(ContractError("nonfinite JSON number")))
    except (ValueError, UnicodeError, RecursionError) as err:
        raise ContractError("invalid JSON artifact") from err


def contained(workspace, relative):
    require(isinstance(relative, str), "artifact path must be a string")
    candidate = Path(relative)
    require(not candidate.is_absolute() and candidate.parts and ".." not in candidate.parts, "workspace-relative path required")
    require(candidate.as_posix() != ".img2/state.json", "cross-plugin mutable state is not an evidence handoff")
    current = Path(workspace)
    for part in candidate.parts:
        current = current / part
        require(not current.is_symlink(), "symlinked artifact path refused")
    require(current.resolve().is_relative_to(Path(workspace).resolve()), "artifact escapes workspace")
    return current


def read_json(workspace, relative):
    path = contained(workspace, relative)
    require(path.is_file(), "JSON artifact must be an existing regular file")
    with path.open("rb") as stream:
        return decode(stream.read(MAX_JSON_BYTES + 1))


def file_hash(workspace, relative):
    path = contained(workspace, relative)
    require(path.is_file() and path.stat().st_size <= MAX_BOUND_BYTES, "bound evidence must be a file of at most 64MiB")
    result = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            size += len(chunk)
            require(size <= MAX_BOUND_BYTES, "bound file grew beyond 64MiB")
            result.update(chunk)
    return result.hexdigest()


def write_artifact(workspace, relative, value):
    require(relative.startswith(".img2/artifacts/jev/"), "writes must stay in Jev artifact namespace")
    path = contained(workspace, relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical(value) + b"\n"
    require(len(payload) <= MAX_JSON_BYTES, "output artifact exceeds 128KiB")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".jev-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
        contained(workspace, relative)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return relative


def prepare(workspace, observation):
    obj(observation, "kind version state control bindings", "observation")
    require(observation["kind"] == "img2.repair-observation" and type(observation["version"]) is int and observation["version"] == 1, "unsupported observation kind/version")
    validate_state(observation["state"])
    validate_control(observation["control"])
    files = []
    seen = set()
    for binding in sequence(observation["bindings"], "bindings", 64, 6):
        obj(binding, "role path", "binding")
        choice(binding["role"], ROLES, "binding role")
        require(isinstance(binding["path"], str), "binding path must be text")
        require(binding["path"] not in seen, "duplicate bound file")
        seen.add(binding["path"])
        files.append({**binding, "sha256": file_hash(workspace, binding["path"])})
    require({item["role"] for item in files} == ROLES, "bind reference, spec, source, render-profile, evaluation and pipeline-state")
    result = {"kind": "img2.repair-state", "version": 2, "state": observation["state"], "control": observation["control"], "snapshot": {"id": digest(canonical(files)), "files": files}}
    validate_request(workspace, result)
    return result


def validate_request(workspace, request, *, check_freshness=True):
    obj(request, "kind version state control snapshot", "request")
    require(request["kind"] == "img2.repair-state" and type(request["version"]) is int and request["version"] == 2, "unsupported request kind/version")
    validate_state(request["state"])
    validate_control(request["control"])
    snapshot = obj(request["snapshot"], "id files", "snapshot")
    seen = set()
    for item in sequence(snapshot["files"], "snapshot files", 64, 6):
        obj(item, "role path sha256", "snapshot file")
        choice(item["role"], ROLES, "snapshot role")
        require(isinstance(item["path"], str), "snapshot path must be text")
        require(item["path"] not in seen, "duplicate bound file")
        seen.add(item["path"])
        require(isinstance(item["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None, "invalid snapshot digest")
        contained(workspace, item["path"])
        if check_freshness:
            require(item["sha256"] == file_hash(workspace, item["path"]), "stale snapshot: " + item["path"])
    require({item["role"] for item in snapshot["files"]} == ROLES, "incomplete snapshot roles")
    require(snapshot["id"] == digest(canonical(snapshot["files"])), "snapshot identifier mismatch")
    return request
# Outcome-v2 is an archival contract; validation is pure and does not touch the workspace.
_OUTCOME_HASH = re.compile(r"[0-9a-f]{64}\Z")
_OUTCOME_ADAPTERS = {"room", "street", "vegetation-cluster", "building-exterior"}
_OUTCOME_QUALIFIED_ADAPTERS = {"room"}
_OUTCOME_LABELS = {"improved", "unchanged", "regressed", "inconclusive", "build_failed"}
_OUTCOME_DIRECTIONS = {"higher-is-better", "lower-is-better"}

def _outcome_hash(value, where):
    require(isinstance(value, str) and _OUTCOME_HASH.fullmatch(value) is not None, where + ": lowercase SHA-256 required")

def _outcome_number(value, where):
    require(type(value) is int or (type(value) is float and math.isfinite(value)), where + ": finite numeric value required")

def _outcome_action(value, where):
    from jev_policy import ACTIONS, TACTICS
    obj(value, "action tactic", where)
    choice(value["action"], ACTIONS, where + " action")
    choice(value["tactic"], TACTICS, where + " tactic")
    return value

def _outcome_metrics(value, where):
    rows = sequence(value, where, 32, 1)
    by_id = {}
    for row in rows:
        obj(row, "featureId value unit direction", where + " metric")
        feature = identifier(row["featureId"], where + " featureId")
        require(feature not in by_id, where + ": duplicate featureId")
        _outcome_number(row["value"], where + " value")
        unit = text(row["unit"], where + " unit", 64)
        choice(row["direction"], _OUTCOME_DIRECTIONS, where + " direction")
        by_id[feature] = (row["value"], unit, row["direction"])
    return by_id

def _outcome_snapshot(value, where, adapter):
    obj(value, "id evaluator measurementContextHash metrics", where)
    _outcome_hash(value["id"], where + " id")
    evaluator = obj(value["evaluator"], "id version adapter checksDigest", where + " evaluator")
    text(evaluator["id"], where + " evaluator id", 160)
    text(evaluator["version"], where + " evaluator version", 80)
    choice(evaluator["adapter"], _OUTCOME_ADAPTERS, where + " evaluator adapter")
    require(evaluator["adapter"] == adapter, where + ": evaluator/asset adapter mismatch")
    _outcome_hash(evaluator["checksDigest"], where + " evaluator checksDigest")
    metrics = _outcome_metrics(value["metrics"], where + " metrics")
    _outcome_hash(value["measurementContextHash"], where + " measurementContextHash")
    return evaluator, metrics, value["measurementContextHash"]

def validate_outcome(value):
    """Validate and return a closed, internally consistent Jev outcome-v2 record."""
    obj(value, "kind version recommendationId attemptId outcome recommendationHash approvedAction actualAction recommendationFollowed assetAdapter beforeSnapshot afterSnapshot measurements adjudication evidencePaths buildFailureEvidencePaths evidenceClass", "outcome")
    require(value["kind"] == "img2.repair-outcome" and type(value["version"]) is int and value["version"] == 2, "unsupported outcome kind/version")
    identifier(value["recommendationId"], "recommendationId")
    identifier(value["attemptId"], "attemptId")
    label = value["outcome"]
    choice(label, _OUTCOME_LABELS, "outcome")
    _outcome_hash(value["recommendationHash"], "recommendationHash")
    approved = _outcome_action(value["approvedAction"], "approvedAction")
    actual = _outcome_action(value["actualAction"], "actualAction")
    boolean(value["recommendationFollowed"], "recommendationFollowed")
    require(value["recommendationFollowed"] == (approved["action"] == actual["action"] and approved["tactic"] == actual["tactic"]), "recommendationFollowed does not match exact action/tactic")
    adapter = value["assetAdapter"]
    choice(adapter, _OUTCOME_ADAPTERS, "assetAdapter")
    require(adapter in _OUTCOME_QUALIFIED_ADAPTERS, "assetAdapter is not fixture-qualified for outcome use")
    _, before, before_context = _outcome_snapshot(value["beforeSnapshot"], "beforeSnapshot", adapter)
    after_value = value["afterSnapshot"]
    measurements = obj(value["measurements"], "rows", "measurements")
    rows = sequence(measurements["rows"], "measurement rows", 32, 0 if label == "build_failed" else 1)
    if label == "build_failed":
        require(after_value is None and not rows, "build_failed requires a null afterSnapshot and empty measurements")
    else:
        _, after, after_context = _outcome_snapshot(after_value, "afterSnapshot", adapter)
        require(set(before) == set(after), "before/after metric feature IDs differ")
        require(value["beforeSnapshot"]["evaluator"] == after_value["evaluator"], "before/after evaluator identities differ")
        require(before_context == after_context, "before/after measurement context hashes differ")
        for feature in before:
            require(before[feature][1:] == after[feature][1:], "before/after metric unit or direction differs")
    measurement_ids = set()
    deltas = []
    for row in rows:
        obj(row, "featureId beforeValue afterValue unit direction", "measurement row")
        feature = identifier(row["featureId"], "measurement featureId")
        require(feature not in measurement_ids, "duplicate measurement featureId")
        measurement_ids.add(feature)
        _outcome_number(row["beforeValue"], "measurement beforeValue")
        _outcome_number(row["afterValue"], "measurement afterValue")
        text(row["unit"], "measurement unit", 64)
        choice(row["direction"], _OUTCOME_DIRECTIONS, "measurement direction")
        require(label != "build_failed", "build_failed cannot contain quality measurements")
        require(feature in before, "measurement contains unknown feature")
        b, unit, direction = before[feature]
        a, after_unit, after_direction = after[feature]
        require(row["beforeValue"] == b and row["afterValue"] == a and row["unit"] == unit == after_unit and row["direction"] == direction == after_direction, "measurement row differs from snapshots")
        comparison = 1 if a > b else -1 if a < b else 0
        deltas.append(comparison if direction == "higher-is-better" else -comparison)
    if label != "build_failed":
        require(measurement_ids == set(before), "measurement rows do not cover every snapshot feature")
    adjudication = obj(value["adjudication"], "status adjudicatorId method recordedAt", "adjudication")
    choice(adjudication["status"], {"independent", "self", "none"}, "adjudication status")
    for key in ("adjudicatorId", "method"):
        if adjudication["status"] == "independent":
            text(adjudication[key], "adjudication " + key, 160)
        elif adjudication[key] is not None:
            text(adjudication[key], "adjudication " + key, 160)
    text(adjudication["recordedAt"], "adjudication recordedAt", 80)
    evidence = sequence(value["evidencePaths"], "evidencePaths", 12, 1)
    require(all(isinstance(path, str) for path in evidence), "evidence paths must be strings")
    require(len(set(evidence)) == len(evidence), "duplicate evidence path")
    for path in evidence:
        text(path, "evidence path", 600)
        require("\\" not in path and not any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in path), "unsafe evidence path")
        require(not path.startswith("/") and re.match(r"^[A-Za-z]:", path) is None, "evidence path must be workspace-relative")
        parts = path.split("/")
        require(all(part not in ("", ".", "..") for part in parts), "unsafe evidence path traversal")
        require(path != ".img2/artifacts/jev" and not path.startswith(".img2/artifacts/jev/"), "Jev artifact paths are not evidence inputs")
    build_evidence = sequence(value["buildFailureEvidencePaths"], "buildFailureEvidencePaths", 12, 1 if label == "build_failed" else 0)
    require(all(isinstance(path, str) for path in build_evidence), "build-failure evidence paths must be strings")
    require(len(set(build_evidence)) == len(build_evidence), "duplicate build-failure evidence path")
    require(bool(build_evidence) == (label == "build_failed"), "buildFailureEvidencePaths must be nonempty only for build_failed")
    for path in build_evidence:
        text(path, "build-failure evidence path", 600)
        require(path in evidence, "build-failure evidence paths must be included in evidencePaths")
    choice(value["evidenceClass"], {"observed", "synthetic"}, "evidenceClass")
    if label == "improved":
        require(any(delta > 0 for delta in deltas) and not any(delta < 0 for delta in deltas), "improved label contradicts metric directions")
    elif label == "regressed":
        require(any(delta < 0 for delta in deltas), "regressed label has no direction-consistent negative delta")
    elif label == "unchanged":
        require(all(delta == 0 for delta in deltas), "unchanged label contradicts metric deltas")
    return value

def outcome_eligible(value):
    """Return whether a valid record is eligible for an observed report stratum."""
    validate_outcome(value)
    return value["evidenceClass"] == "observed" and value["adjudication"]["status"] == "independent"
