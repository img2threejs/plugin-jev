import os, sys
root = os.environ.get("IMG2_HOME")
if root: sys.path.insert(0, os.path.join(root, "harness"))
else:
    try: import _img2_local; sys.path.insert(0, _img2_local.CORE)
    except ImportError: sys.exit("img2: core not linked - run `img2 sync`")
from img2_core import require_core_api
require_core_api(1)

import argparse
from pathlib import Path
import hashlib
import math
import fcntl
import stat
import tempfile
import time
import uuid

from img2_core import state as core_state
from img2_core.paths import resolve_workspace
from jev_contracts import (
    ContractError, ENVIRONMENT_GATE_IDS, MAX_JSON_BYTES, canonical, choice, contained, decode, digest, file_hash, identifier,
    ids, number, obj, prepare, read_json, require, sequence, validate_control,
    validate_outcome, validate_request, validate_state, write_artifact,
)
from jev_client import MODEL, QUESTION_SET_VERSION, ProviderError, _serialize_request, validate_response
from jev_policy import POLICY_VERSION, preflight, preflight_live, recommend, recommend_live
from jev_transport import evaluate_bounded
from jev_outcome_report import build_report
from jev_checkpoint import consult as consult_checkpoint
from jev_auth import CredentialError, auth_status, login as login_credential, resolve_api_key
from jev_consent import POLICY_VERSION as CONSENT_POLICY_VERSION, ConsentError, require_consent, set_consent
from jev_projection import POLICY_VERSION as PROJECTION_POLICY_VERSION, project_state

PREFIX = ".img2/artifacts/jev/"
REQUEST_PATH = PREFIX + "repair-state.json"
REPORT_PATH = PREFIX + "recommendation.json"
VERSION = "0.3.0"


def emit(value):
    print(canonical(value).decode("utf-8"))


def remember(workspace, **fields):
    # Protect the core state output path from symlink redirection before core writes it.
    for relative in (".img2", ".img2/.lock", ".img2/state.json", ".img2/state.json.tmp"):
        path = workspace / relative
        require(not path.is_symlink(), "symlinked core state path refused")
        require(not path.exists() or (path.is_dir() if relative == ".img2" else path.is_file()), "nonregular core state path refused")
    core_state.update_plugin_state(workspace, "jev", lambda entry: {**entry, **fields})


def request_identity(request):
    return digest(canonical(request))


def validate_report(workspace, report, *, check_freshness=True):
    obj(report, "kind version id pluginVersion mode authority requestPath activeRequestPath requestHash snapshotId versions projectionHash consentHash consentPolicyVersion provider proposal elapsedMs", "recommendation")
    require(report["kind"] == "img2.repair-recommendation" and type(report["version"]) is int and report["version"] == 1, "unsupported recommendation kind/version")
    identifier(report["id"], "recommendation ID")
    require(report["pluginVersion"] == VERSION, "recommendation plugin version mismatch")
    choice(report["mode"], {"shadow", "assist"}, "mode")
    require(report["authority"] == "advisory-only", "recommendation cannot authorize execution")
    require(report["versions"] == {"questions": QUESTION_SET_VERSION, "policy": POLICY_VERSION, "normalizer": "repair-state-v2", "projection": PROJECTION_POLICY_VERSION, "calibration": "uncalibrated-assist-only"}, "recommendation version mismatch")
    require(PROJECTION_POLICY_VERSION == CONSENT_POLICY_VERSION, "disclosure policy versions are inconsistent")
    require(report["consentPolicyVersion"] == CONSENT_POLICY_VERSION, "consent policy version mismatch")
    require(report["activeRequestPath"] == REQUEST_PATH, "recommendation must bind the active prepared request")
    archive = obj(read_json(workspace, report["requestPath"]), "kind version request requestHash projectionHash consentHash consentPolicyVersion", "archived request")
    require(archive["kind"] == "img2.jev-outbound-request-archive" and type(archive["version"]) is int and archive["version"] == 2, "unsupported archived request")
    require(archive["requestHash"] == report["requestHash"] and archive["projectionHash"] == report["projectionHash"] and archive["consentPolicyVersion"] == report["consentPolicyVersion"] and archive["consentHash"] == report["consentHash"], "archived request disclosure binding mismatch")
    request = validate_request(workspace, archive["request"], check_freshness=check_freshness)
    require(request_identity(request) == report["requestHash"], "request changed after recommendation")
    if check_freshness:
        active = read_json(workspace, report["activeRequestPath"])
        require(request_identity(active) == report["requestHash"], "active repair request superseded recommendation")
    require(request["snapshot"]["id"] == report["snapshotId"], "report snapshot mismatch")
    _validate_live_environment_snapshot(workspace, request, current=check_freshness)
    projection = project_state(request["state"])
    require(report["projectionHash"] == digest(canonical(projection)), "outbound projection hash mismatch")
    consent_hash = report["consentHash"]
    require(isinstance(consent_hash, str) and len(consent_hash) == 64 and all(ch in "0123456789abcdef" for ch in consent_hash), "invalid consent hash")
    provider = obj(report["provider"], "status response errorCode", "provider")
    choice(provider["status"], {"evaluated"}, "provider status")
    response = validate_response(provider["response"])
    require(provider["errorCode"] is None, "successful provider contains error")
    consent = require_consent(workspace)
    require(consent_hash == digest(canonical(consent)), "workspace consent changed or was revoked")
    require(report["proposal"] == recommend_live(request["state"], request["control"], response), "recommendation violates deterministic policy")
    number(report["elapsedMs"], "elapsedMs", integer=True)
    return request


def run_prepare(workspace, args):
    request = prepare(workspace, read_json(workspace, args.input))
    write_artifact(workspace, REQUEST_PATH, request)
    remember(workspace, requestPath=REQUEST_PATH, requestHash=request_identity(request))
    return {"kind": "img2.jev-command", "version": 1, "status": "prepared", "artifact": REQUEST_PATH, "snapshotId": request["snapshot"]["id"]}


def _invalidate_current_recommendation(workspace):
    path = contained(workspace, REPORT_PATH)
    if path.exists():
        require(path.is_file(), "current Jev recommendation path is not a regular file")
        path.unlink()
    remember(workspace, lastRecommendation=None, lastRecommendationId=None, providerStatus=None)


def _validate_live_environment_snapshot(workspace, request, *, current=True):
    state = request["state"]
    evaluations = [item for item in request["snapshot"]["files"] if item["role"] == "evaluation" and item["path"].startswith(".img2/artifacts/environment/gate-results/") and item["path"].endswith(".json") and len(item["path"]) == len(".img2/artifacts/environment/gate-results/") + 69 and all(char in "0123456789abcdef" for char in item["path"].rsplit("/", 1)[-1][:-5])]
    require(len(evaluations) == 1, "live request must bind exactly one Environment gate result")
    gate_path = evaluations[0]["path"]
    gate_record = obj(
        read_json(workspace, gate_path),
        "kind version gate plugin status reasons evidence evaluator snapshot snapshotId snapshotPath resultPath",
        "Environment gate result",
    )
    gate = _validate_environment_gate(workspace, gate_path, gate_record["snapshotId"], current=current)
    require(gate["status"] == "fail", "live Jev routing requires an overall failed Environment snapshot")
    require(gate["evaluator"]["adapter"] == state["sceneKind"], "Environment gate adapter differs from repair-state-v2 scene kind")
    require(gate["evaluator"]["adapter"] in _ENVIRONMENT_QUALIFIED_ADAPTERS, "Environment adapter is not fixture-qualified for live routing")
    require(all(path in {item["path"] for item in gate["snapshot"]["files"]} for path in _ENVIRONMENT_DEPENDENCY_FILES[gate["evaluator"]["adapter"]]), "Environment gate snapshot does not bind its adapter dependencies")
    state_gates = state["gates"]
    environment_gates = gate["evidence"]["gates"]
    require(len(state_gates) == len(ENVIRONMENT_GATE_IDS) == len(environment_gates), "live Environment snapshot must contain all 12 canonical rows")
    for expected_id, state_gate, environment_gate in zip(ENVIRONMENT_GATE_IDS, state_gates, environment_gates):
        require(state_gate["id"] == environment_gate["id"] == expected_id, "repair-state-v2 gates differ from the canonical Environment order")
        require(state_gate["status"] == environment_gate["status"], "repair-state-v2 gate status differs from the Environment snapshot")
        require(state_gate["blocking"] and state_gate["coverage"] == "complete", "live Environment gate rows must be complete and blocking")
    require(any(item["status"] == "fail" for item in state_gates), "live Jev advice requires a failed Environment row")
    return gate


def run_route(workspace, args):
    started = time.monotonic()
    _invalidate_current_recommendation(workspace)
    require(PROJECTION_POLICY_VERSION == CONSENT_POLICY_VERSION, "disclosure policy versions are inconsistent")
    require(args.input == REQUEST_PATH, "live route requires the active prepared request")
    request = validate_request(workspace, read_json(workspace, REQUEST_PATH))
    _validate_live_environment_snapshot(workspace, request, current=True)
    original_hash = request_identity(request)
    state, control = request["state"], request["control"]
    stop = preflight_live(state, control)
    if stop is not None:
        raise ContractError("live route stopped by safety preflight: " + ",".join(stop["reasonCodes"]))
    projection = project_state(state)
    projection_hash = digest(canonical(projection))
    _serialize_request(projection)
    consent = require_consent(workspace)
    consent_hash = digest(canonical(consent))
    key = resolve_api_key()
    if not isinstance(key, str) or not key.strip():
        raise CredentialError("TypeSafe API key is unavailable")
    timeout = min(args.timeout, control["remainingDeadlineMs"] / 1000)
    require(timeout > 0, "request deadline exhausted")

    current = validate_request(workspace, read_json(workspace, REQUEST_PATH))
    require(request_identity(current) == original_hash, "request changed before provider dispatch")
    _validate_live_environment_snapshot(workspace, current, current=True)
    stop = preflight_live(current["state"], current["control"])
    if stop is not None:
        raise ContractError("live route stopped before provider dispatch: " + ",".join(stop["reasonCodes"]))
    current_projection = project_state(current["state"])
    require(digest(canonical(current_projection)) == projection_hash, "outbound projection changed before provider dispatch")
    _serialize_request(current_projection)
    require(digest(canonical(require_consent(workspace))) == consent_hash, "workspace consent changed before provider dispatch")

    response = validate_response(evaluate_bounded(projection, key, timeout=timeout))
    current = validate_request(workspace, read_json(workspace, REQUEST_PATH))
    require(request_identity(current) == original_hash, "request changed during provider evaluation")
    _validate_live_environment_snapshot(workspace, current, current=True)
    stop = preflight_live(current["state"], current["control"])
    if stop is not None:
        raise ContractError("live route stopped before advice consumption: " + ",".join(stop["reasonCodes"]))
    require(digest(canonical(require_consent(workspace))) == consent_hash, "workspace consent changed before advice consumption")
    current_projection = project_state(current["state"])
    require(digest(canonical(current_projection)) == projection_hash, "outbound projection changed before advice consumption")

    report = {
        "kind": "img2.repair-recommendation", "version": 1,
        "id": uuid.uuid4().hex, "pluginVersion": VERSION, "mode": args.mode,
        "authority": "advisory-only", "requestPath": REQUEST_PATH, "activeRequestPath": REQUEST_PATH,
        "requestHash": original_hash, "snapshotId": request["snapshot"]["id"],
        "projectionHash": projection_hash, "consentHash": consent_hash, "consentPolicyVersion": CONSENT_POLICY_VERSION,
        "versions": {"questions": QUESTION_SET_VERSION, "policy": POLICY_VERSION, "normalizer": "repair-state-v2", "projection": PROJECTION_POLICY_VERSION, "calibration": "uncalibrated-assist-only"},
        "provider": {"status": "evaluated", "response": response, "errorCode": None},
        "proposal": recommend_live(state, control, response),
        "elapsedMs": round((time.monotonic() - started) * 1000),
    }
    archived_request = PREFIX + "records/" + report["id"] + ".state.json"
    write_artifact(workspace, archived_request, {"kind": "img2.jev-outbound-request-archive", "version": 2, "request": request, "requestHash": original_hash, "projectionHash": projection_hash, "consentHash": consent_hash, "consentPolicyVersion": CONSENT_POLICY_VERSION})
    report["requestPath"] = archived_request
    validate_report(workspace, report)
    artifact = PREFIX + "records/" + report["id"] + ".json"
    write_artifact(workspace, artifact, report)
    write_artifact(workspace, REPORT_PATH, report)
    try:
        remember(workspace, lastRecommendation=artifact, lastRecommendationId=report["id"], mode=args.mode, providerStatus="evaluated")
    except Exception:
        contained(workspace, REPORT_PATH).unlink(missing_ok=True)
        raise
    return {"kind": "img2.jev-command", "version": 1, "status": "recommended", "artifact": artifact, "latest": REPORT_PATH, "providerStatus": "evaluated", "proposal": report["proposal"], "authority": "advisory-only"}


def run_outcome_v1(workspace, args):
    # The pre-repair snapshot should have changed after repair. Do not demand freshness here.
    report = read_json(workspace, args.recommendation)
    request = validate_report(workspace, report, check_freshness=False)
    outcome = read_json(workspace, args.input)
    obj(outcome, "kind version recommendationId outcome improvedFeatureIds regressedFeatureIds evidencePaths", "outcome")
    require(outcome["kind"] == "img2.repair-outcome" and type(outcome["version"]) is int and outcome["version"] == 1, "unsupported outcome kind/version")
    require(outcome["recommendationId"] == report["id"], "outcome recommendation mismatch")
    choice(outcome["outcome"], {"improved", "unchanged", "regressed", "inconclusive", "build_failed"}, "outcome")
    improved = ids(outcome["improvedFeatureIds"], "improved features")
    regressed = ids(outcome["regressedFeatureIds"], "regressed features")
    require(not improved.intersection(regressed), "feature cannot improve and regress in one comparison")
    if outcome["outcome"] == "improved":
        require(bool(improved) and not regressed, "improved outcome requires improvement and no regressions")
    elif outcome["outcome"] == "regressed":
        require(bool(regressed), "regressed outcome requires a regressed feature")
    else:
        require(not improved and not regressed, "non-comparative outcome cannot claim feature changes")
    files = []
    for path in sequence(outcome["evidencePaths"], "outcome evidence", 12, 1):
        resolved = contained(workspace, path)
        require(not resolved.relative_to(workspace).as_posix().startswith(PREFIX), "router artifacts are not repair outcome evidence")
        files.append({"path": path, "sha256": file_hash(workspace, path)})
    before = request["snapshot"]
    after_files = []
    for item in before["files"]:
        path = contained(workspace, item["path"])
        current_hash = file_hash(workspace, item["path"]) if path.exists() else None
        after_files.append({**item, "sha256": current_hash})
    prior_hashes = {item["path"]: item["sha256"] for item in before["files"]}
    changed = any(item["sha256"] != prior_hashes[item["path"]] for item in after_files if item["role"] in {"source", "spec", "evaluation"})
    new_evidence = any(item["sha256"] != prior_hashes.get(item["path"]) for item in files)
    if outcome["outcome"] in {"improved", "regressed", "build_failed"}:
        require(changed or new_evidence, "changed outcome requires changed artifact or new evaluator evidence")
    record = {**outcome, "reportedBy": "external-evaluator", "verification": "file-integrity-only",
              "evidence": files, "recommendationHash": digest(canonical(report)),
              "beforeSnapshot": before, "afterSnapshot": {"id": digest(canonical(after_files)), "files": after_files}}
    artifact = PREFIX + "outcomes/" + report["id"] + "-" + uuid.uuid4().hex + ".json"
    write_artifact(workspace, artifact, record)
    remember(workspace, lastOutcome=artifact)
    return {"kind": "img2.jev-command", "version": 1, "status": "recorded", "artifact": artifact, "verification": "file-integrity-only"}


_ENVIRONMENT_CHECKS = ENVIRONMENT_GATE_IDS
_OUTCOME_ARCHIVE = PREFIX + "outcomes/archive/"
_MAX_OUTCOME_BYTES = 64 * 1024 * 1024


_ENVIRONMENT_BASE_ARTIFACTS = (
    ".img2/artifacts/environment/scene-intake.json",
    ".img2/artifacts/environment/scene-spec.json",
    ".img2/artifacts/environment/scene-review.json",
    ".img2/artifacts/environment/reference-provenance.json",
)
_ENVIRONMENT_SOURCE_FILES = {
    "room": ".img2/artifacts/environment/createEnvironmentRoomsModel.ts",
    "street": ".img2/artifacts/environment/createEnvironmentStreetModel.ts",
    "vegetation-cluster": ".img2/artifacts/environment/createEnvironmentVegetationClusterModel.ts",
    "building-exterior": ".img2/artifacts/environment/createEnvironmentBuildingExteriorModel.ts",
}
_ENVIRONMENT_QUALIFIED_ADAPTERS = {"room"}
_ENVIRONMENT_DEPENDENCY_FILES = {
    adapter: (*_ENVIRONMENT_BASE_ARTIFACTS, source)
    for adapter, source in _ENVIRONMENT_SOURCE_FILES.items()
}
_OUTCOME_CONTEXT_ARTIFACTS = _ENVIRONMENT_BASE_ARTIFACTS[:3]
_OUTCOME_PAIR_INDEX = _OUTCOME_ARCHIVE + "pairs/"
def _acquire_outcome_archive_lock(workspace):
    directory = contained(workspace, _OUTCOME_ARCHIVE)
    directory.mkdir(parents=True, exist_ok=True)
    path = contained(workspace, _OUTCOME_ARCHIVE + ".transaction.lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        opened = os.fstat(descriptor)
        named = path.lstat()
        require(stat.S_ISREG(opened.st_mode) and stat.S_ISREG(named.st_mode) and (opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino), "unsafe Jev outcome archive lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        named_after_lock = path.lstat()
        require((opened.st_dev, opened.st_ino) == (named_after_lock.st_dev, named_after_lock.st_ino), "Jev outcome archive lock path changed")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _release_outcome_archive_lock(descriptor):
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)

def _validate_environment_gate(workspace, path, expected_id, *, current):
    gate = read_json(workspace, path)
    with contained(workspace, path).open("rb") as stream:
        raw = stream.read(131073)
    require(raw == canonical(gate), "Environment gate result is not canonical JSON")
    obj(gate, "kind version gate plugin status reasons evidence evaluator snapshot snapshotId snapshotPath resultPath", "Environment gate result")
    require(gate["kind"] == "img2.gate-verdict" and type(gate["version"]) is int and gate["version"] == 1, "unsupported Environment gate result")
    require(gate["gate"] == "environment" and gate["plugin"] == "environment", "gate is not an Environment result")
    choice(gate["status"], {"pass", "fail"}, "Environment gate status")
    require(isinstance(gate["reasons"], list), "Environment gate reasons must be a list")
    evidence = obj(gate["evidence"], "gates unevaluated", "Environment evidence")
    require(isinstance(evidence["unevaluated"], list) and not evidence["unevaluated"], "Environment gate contains unevaluated rows")
    rows = sequence(evidence["gates"], "Environment gate rows", 12, 12)
    for check_id, row in zip(_ENVIRONMENT_CHECKS, rows):
        obj(row, "id status reasons evidence", "Environment gate row")
        require(row["id"] == check_id, "Environment gate rows are not canonical and ordered")
        choice(row["status"], {"pass", "fail"}, "Environment row status")
        require(isinstance(row["reasons"], list) and isinstance(row["evidence"], dict), "malformed Environment gate row")
        require((row["status"] == "pass") == (not row["reasons"]), "Environment row reasons contradict status")
    require((gate["status"] == "pass") == all(row["status"] == "pass" for row in rows), "Environment gate status contradicts rows")
    require(gate["reasons"] == [reason for row in rows for reason in row["reasons"]], "Environment gate reasons differ from ordered rows")
    evaluator = obj(gate["evaluator"], "id plugin version adapter checks checkDigest", "Environment evaluator")
    require(evaluator["id"] == "environment-gate" and evaluator["plugin"] == "environment", "unexpected Environment evaluator")
    require(type(evaluator["version"]) is int and evaluator["version"] >= 1, "invalid Environment evaluator version")
    choice(evaluator["adapter"], {"room", "street", "vegetation-cluster", "building-exterior"}, "Environment adapter")
    require(evaluator["checks"] == list(_ENVIRONMENT_CHECKS), "Environment evaluator check list mismatch")
    require(isinstance(evaluator["checkDigest"], str) and len(evaluator["checkDigest"]) == 64 and all(c in "0123456789abcdef" for c in evaluator["checkDigest"]), "invalid Environment checks digest")
    snapshot = obj(gate["snapshot"], "id path evaluator files", "Environment snapshot")
    require(snapshot["id"] == expected_id == gate["snapshotId"], "Environment snapshot identity mismatch")
    require(snapshot["evaluator"] == evaluator, "snapshot evaluator differs from gate evaluator")
    expected_path = ".img2/artifacts/environment/gate-results/" + expected_id + ".json"
    require(snapshot["path"] == expected_path and gate["snapshotPath"] == expected_path and gate["resultPath"] == expected_path and path == expected_path, "Environment snapshot path mismatch")
    snapshot_files = sequence(snapshot["files"], "Environment snapshot files", 64, 1)
    seen = set()
    for item in snapshot_files:
        obj(item, "path size sha256", "Environment snapshot file")
        require(isinstance(item["path"], str) and item["path"] not in seen, "duplicate or invalid Environment dependency path")
        seen.add(item["path"])
        require(type(item["size"]) is int and item["size"] >= 0, "invalid Environment dependency size")
        require(isinstance(item["sha256"], str) and len(item["sha256"]) == 64 and all(c in "0123456789abcdef" for c in item["sha256"]), "invalid Environment dependency digest")
        dependency = contained(workspace, item["path"])
        if current:
            info = dependency.stat()
            require(stat.S_ISREG(info.st_mode) and info.st_size == item["size"] and file_hash(workspace, item["path"]) == item["sha256"], "stale after Environment dependency: " + item["path"])
    core = {"evaluator": evaluator, "files": snapshot_files, "status": gate["status"], "reasons": gate["reasons"], "evidence": evidence}
    require(digest(canonical(core)) == expected_id, "Environment snapshot digest mismatch")
    return gate


def _review_png_paths(workspace, review):
    paths = []
    seen = set()

    def add(value):
        require(isinstance(value, str) and value, "Environment review dependency must be a path")
        path = Path(value).as_posix()
        require(path == value and Path(path).suffix.lower() == ".png", "Environment review dependency must be a normalized PNG path")
        contained(workspace, path)
        require(path not in seen, "duplicate Environment review dependency")
        seen.add(path)
        paths.append(path)

    screenshots = review.get("screenshots")
    require(isinstance(screenshots, dict), "scene-review screenshots are missing")
    for value in screenshots.values():
        add(value)
    add(review.get("sideBySide"))
    for key in ("subjectPasses", "regionPasses"):
        passes = review.get(key)
        require(isinstance(passes, dict), "scene-review " + key + " are missing")
        for value in passes.values():
            add(value)
    return paths


def _expected_environment_dependencies(workspace, gate):
    adapter = gate["evaluator"]["adapter"]
    require(adapter in _ENVIRONMENT_SOURCE_FILES, "no T2 source manifest is defined for this Environment adapter")
    require(adapter in _ENVIRONMENT_QUALIFIED_ADAPTERS, "Environment adapter is not fixture-qualified for outcome use")
    paths = list(_ENVIRONMENT_DEPENDENCY_FILES[adapter])
    review = read_json(workspace, _ENVIRONMENT_BASE_ARTIFACTS[2])
    return paths + _review_png_paths(workspace, review)


def _validate_after_manifest(workspace, gate):
    expected = _expected_environment_dependencies(workspace, gate)
    files = gate["snapshot"]["files"]
    require([item["path"] for item in files] == expected, "after Environment dependency manifest is incomplete, extra, or out of canonical order")
    for item in files:
        path = contained(workspace, item["path"])
        info = path.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_size == item["size"] and file_hash(workspace, item["path"]) == item["sha256"], "stale after Environment dependency: " + item["path"])
    intake = read_json(workspace, _ENVIRONMENT_BASE_ARTIFACTS[0])
    require(isinstance(intake.get("sceneClassification"), dict) and intake["sceneClassification"].get("kind") == gate["evaluator"]["adapter"], "after Environment intake kind differs from gate adapter")
    return {item["path"]: {"size": item["size"], "sha256": item["sha256"]} for item in files}


def _context_from_evidence(workspace, gate, evidence_paths, *, historical):
    by_path = {item["path"]: item for item in gate["snapshot"]["files"]}
    require(gate["evaluator"]["adapter"] in _ENVIRONMENT_SOURCE_FILES, "no T2 measurement-context source mapping exists for this Environment adapter")
    require(gate["evaluator"]["adapter"] in _ENVIRONMENT_QUALIFIED_ADAPTERS, "Environment adapter is not fixture-qualified for outcome use")
    require(all(path in by_path for path in _ENVIRONMENT_DEPENDENCY_FILES[gate["evaluator"]["adapter"]]), "Environment gate snapshot does not bind its adapter dependencies")
    artifacts, bindings = {}, {}
    for path in _OUTCOME_CONTEXT_ARTIFACTS:
        manifest = by_path.get(path)
        require(manifest is not None, "Environment gate snapshot does not bind context artifact " + path)
        context_bytes, evidence_path = None, None
        if historical:
            if path in evidence_paths:
                context_bytes = _read_outcome_context_bytes(workspace, path, manifest)
                if context_bytes is not None:
                    evidence_path = path
            if context_bytes is None:
                for candidate in sorted({item for item in evidence_paths if item != path}):
                    context_bytes = _read_outcome_context_bytes(workspace, candidate, manifest)
                    if context_bytes is not None:
                        evidence_path = candidate
                        break
            require(context_bytes is not None, "before context artifact has no evidence copy matching its historical gate hash")
        else:
            require(path in evidence_paths, "after context artifact is absent from evidencePaths: " + path)
            evidence_path = path
            context_bytes = _read_outcome_context_bytes(workspace, path, manifest)
            require(context_bytes is not None, "after context artifact differs from current Environment gate: " + path)
        artifacts[path] = decode(context_bytes)
        bindings[evidence_path] = {"size": manifest["size"], "sha256": manifest["sha256"]}
    intake, spec, review = (artifacts[path] for path in _OUTCOME_CONTEXT_ARTIFACTS)
    require(isinstance(intake.get("sceneClassification"), dict) and intake["sceneClassification"].get("kind") == gate["evaluator"]["adapter"], "context intake kind differs from Environment adapter")
    source_views = sequence(intake.get("sourceViews"), "scene-intake.sourceViews", 32, 1)
    view_projection = []
    for view in source_views:
        require(isinstance(view, dict) and {"id", "path", "sha256"} <= view.keys(), "scene-intake source view must contain id, path, and sha256")
        require(isinstance(view["path"], str) and bool(view["path"]), "scene-intake source view path is required")
        identifier(view["id"], "scene-intake source view id")
        require(isinstance(view["sha256"], str) and len(view["sha256"]) == 64 and all(c in "0123456789abcdef" for c in view["sha256"]), "invalid scene-intake source view SHA-256")
        view_projection.append({"id": view["id"], "sha256": view["sha256"]})
    viewpoints = sequence(spec.get("reviewViewpoints"), "scene-spec.reviewViewpoints", 32, 1)
    require(all(isinstance(item, str) and item for item in viewpoints), "invalid scene-spec.reviewViewpoints")
    context_fields = ("camera", "renderer", "resolution", "exposure", "toneMapping", "background", "environment", "iblContribution")
    for key in context_fields:
        require(key in review and review[key] is not None, "scene-review measurement context is missing " + key)
    method = review.get("qualityMeasurementMethod")
    require(isinstance(method, str) and method.strip(), "scene-review.qualityMeasurementMethod must be explicit")
    quality_rows = sequence(review.get("qualityMeasurements"), "scene-review.qualityMeasurements", 32, 1)
    qualities = {}
    for row in quality_rows:
        obj(row, "featureId value unit direction", "scene-review quality measurement")
        feature = identifier(row["featureId"], "quality measurement featureId")
        require(feature not in qualities, "duplicate scene-review quality measurement featureId")
        require(type(row["value"]) is int or type(row["value"]) is float and math.isfinite(row["value"]), "scene-review quality measurement value must be finite")
        require(isinstance(row["unit"], str) and row["unit"], "scene-review quality measurement unit is required")
        choice(row["direction"], {"higher-is-better", "lower-is-better"}, "scene-review quality measurement direction")
        qualities[feature] = (row["value"], row["unit"], row["direction"])
    projection = {
        "adapter": gate["evaluator"]["adapter"], "sourceViews": view_projection,
        "reviewViewpoints": viewpoints,
        **{key: review[key] for key in context_fields},
        "qualityMeasurementMethod": method,
    }
    return digest(canonical(projection)), qualities, bindings


def _read_outcome_context_bytes(workspace, path, manifest):
    descriptor = None
    try:
        source = contained(workspace, path)
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != manifest["size"] or before.st_size > MAX_JSON_BYTES:
            return None
        content, hasher = bytearray(), hashlib.sha256()
        while chunk := os.read(descriptor, 65536):
            content.extend(chunk)
            hasher.update(chunk)
            if len(content) > before.st_size:
                return None
        after = os.fstat(descriptor)
        current_path = contained(workspace, path).lstat()
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if (identity(before) != identity(after) or identity(after) != identity(current_path)
                or len(content) != manifest["size"] or hasher.hexdigest() != manifest["sha256"]):
            return None
        return bytes(content)
    except (ContractError, OSError):
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _require_metrics_match_quality(snapshot, qualities, where):
    metrics = {row["featureId"]: (row["value"], row["unit"], row["direction"]) for row in snapshot["metrics"]}
    require(metrics == qualities, where + " Jev metrics do not match typed scene-review.qualityMeasurements")


def _archive_outcome_files(workspace, paths):
    require(len(paths) <= 12, "outcome archive allows at most 12 files")
    staging, published, entries = [], [], []
    total, temporary = 0, None
    try:
        for relative in paths:
            source = contained(workspace, relative)
            descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            try:
                before = os.fstat(descriptor)
                require(stat.S_ISREG(before.st_mode), "outcome evidence must be a regular file")
                require(before.st_size <= _MAX_OUTCOME_BYTES - total, "outcome evidence exceeds 64MiB aggregate")
                total += before.st_size
                hasher, size = hashlib.sha256(), 0
                folder = contained(workspace, _OUTCOME_ARCHIVE + ".tmp")
                folder.mkdir(parents=True, exist_ok=True)
                temporary = contained(workspace, _OUTCOME_ARCHIVE + ".tmp") / uuid.uuid4().hex
                with os.fdopen(os.dup(descriptor), "rb") as reader, temporary.open("xb") as writer:
                    while chunk := reader.read(65536):
                        size += len(chunk)
                        require(size <= before.st_size, "outcome evidence grew while copying")
                        hasher.update(chunk)
                        writer.write(chunk)
                    writer.flush()
                    os.fsync(writer.fileno())
                after = os.fstat(descriptor)
                path_after = contained(workspace, relative).stat()
                before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                path_identity = (path_after.st_dev, path_after.st_ino, path_after.st_size, path_after.st_mtime_ns, path_after.st_ctime_ns)
                require(before_identity == after_identity == path_identity and size == before.st_size, "outcome evidence changed while copying")
            finally:
                os.close(descriptor)
            sha = hasher.hexdigest()
            target_relative = _OUTCOME_ARCHIVE + sha[:2] + "/" + sha + ".blob"
            target = contained(workspace, target_relative)
            staging.append((temporary, target, target_relative, size, sha, relative))
        for temporary, target, target_relative, size, sha, relative in staging:
            target.parent.mkdir(parents=True, exist_ok=True)
            target = contained(workspace, target_relative)
            try:
                os.link(temporary, target)
                published.append(target)
            except FileExistsError:
                info = target.lstat()
                require(stat.S_ISREG(info.st_mode) and info.st_size == size and file_hash(workspace, target_relative) == sha, "conflicting outcome archive collision")
            temporary.unlink()
            entries.append({"originalPath": relative, "archivedPath": target_relative, "size": size, "sha256": sha})
        return entries, published, [item[0] for item in staging]
    except Exception:
        if temporary is not None: temporary.unlink(missing_ok=True)
        for staged, *_ in staging: staged.unlink(missing_ok=True)
        for target in published: target.unlink(missing_ok=True)
        raise

def _read_persisted_outcome_record_bytes(workspace, relative):
    source = contained(workspace, relative)
    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_JSON_BYTES, "persisted outcome record is non-regular or exceeds 128KiB")
        content = bytearray()
        while len(content) < MAX_JSON_BYTES + 1:
            chunk = os.read(descriptor, min(65536, MAX_JSON_BYTES + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        require(len(content) <= MAX_JSON_BYTES, "persisted outcome record exceeds 128KiB")
        after = os.fstat(descriptor)
        current_path = contained(workspace, relative).lstat()
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        require(identity(before) == identity(after) == identity(current_path) and len(content) == before.st_size, "persisted outcome record changed while reading")
        return bytes(content)
    finally:
        os.close(descriptor)

def _validate_persisted_outcome_record(workspace, path, record, raw):
    obj(record, "kind version recommendationId attemptId outcome recommendationHash approvedAction actualAction recommendationFollowed assetAdapter beforeSnapshot afterSnapshot measurements adjudication evidencePaths buildFailureEvidencePaths evidenceClass verification archivedEvidence beforeGatePath afterGatePath advisoryOnly", "persisted outcome record")
    require(raw == canonical(record) + bytes((10,)) and len(raw) <= MAX_JSON_BYTES and digest(canonical(record)) == path.stem, "persisted outcome record is noncanonical, oversized, or filename-inconsistent")
    require(record["verification"] == "environment-gate-and-archived-evidence" and record["advisoryOnly"] is True, "persisted outcome record metadata is invalid")
    outcome_keys = "kind version recommendationId attemptId outcome recommendationHash approvedAction actualAction recommendationFollowed assetAdapter beforeSnapshot afterSnapshot measurements adjudication evidencePaths buildFailureEvidencePaths evidenceClass".split()
    outcome = {key: record[key] for key in outcome_keys}
    validate_outcome(outcome)
    before_path = ".img2/artifacts/environment/gate-results/" + outcome["beforeSnapshot"]["id"] + ".json"
    require(record["beforeGatePath"] == before_path and before_path in outcome["evidencePaths"], "persisted before-gate path does not match its snapshot/evidence")
    if outcome["outcome"] == "build_failed":
        require(record["afterGatePath"] is None, "build-failed record unexpectedly names an after gate")
    else:
        after_path = ".img2/artifacts/environment/gate-results/" + outcome["afterSnapshot"]["id"] + ".json"
        require(record["afterGatePath"] == after_path and after_path in outcome["evidencePaths"], "persisted after-gate path does not match its snapshot/evidence")
    entries = sequence(record["archivedEvidence"], "persisted archivedEvidence", 12, 1)
    require(len(entries) == len(outcome["evidencePaths"]), "persisted archivedEvidence count differs from evidencePaths")
    total_bytes = 0
    blob_checks = []
    for original, entry in zip(outcome["evidencePaths"], entries):
        obj(entry, "originalPath archivedPath size sha256", "persisted archived evidence")
        require(entry["originalPath"] == original, "persisted archivedEvidence order differs from evidencePaths")
        require(type(entry["size"]) is int and entry["size"] >= 0, "persisted archived evidence size is invalid")
        require(entry["size"] <= _MAX_OUTCOME_BYTES - total_bytes, "persisted archived evidence exceeds 64MiB aggregate")
        total_bytes += entry["size"]
        sha = entry["sha256"]
        require(isinstance(sha, str) and len(sha) == 64 and all(char in "0123456789abcdef" for char in sha), "persisted archived evidence hash is invalid")
        expected_path = _OUTCOME_ARCHIVE + sha[:2] + "/" + sha + ".blob"
        require(entry["archivedPath"] == expected_path, "persisted archived evidence path does not match its content hash")
        blob_checks.append((expected_path, entry["size"], sha))
    for expected_path, size, sha in blob_checks:
        blob = contained(workspace, expected_path)
        info = blob.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_size == size and file_hash(workspace, expected_path) == sha, "persisted archived evidence blob is missing, stale, or malformed")


def _reserve_outcome_pair(workspace, outcome):
    records = contained(workspace, _OUTCOME_ARCHIVE + "records")
    record_paths = []
    try:
        records.stat()
    except FileNotFoundError:
        try:
            records.lstat()
        except FileNotFoundError:
            pass
        except OSError as err:
            raise ContractError("cannot inspect outcome record directory") from err
        else:
            raise ContractError("outcome record directory is not a regular directory")
    except OSError as err:
        raise ContractError("cannot inspect outcome record directory") from err
    else:
        try:
            info = records.lstat()
            require(stat.S_ISDIR(info.st_mode), "outcome record path is not a regular directory")
            with os.scandir(records) as entries:
                record_paths = sorted((Path(item.path) for item in entries if item.name.endswith(".json")), key=lambda item: item.name)
        except (ContractError, OSError) as err:
            raise ContractError("cannot enumerate outcome record directory") from err
    for path in record_paths:
        try:
            relative = path.relative_to(workspace).as_posix()
            raw = _read_persisted_outcome_record_bytes(workspace, relative)
            committed = decode(raw)
            _validate_persisted_outcome_record(workspace, path, committed, raw)
        except (ContractError, OSError, ValueError) as err:
            raise ContractError("cannot establish outcome-pair uniqueness because a committed record is unreadable or malformed: " + path.name) from err
        if committed["recommendationId"] == outcome["recommendationId"] and committed["attemptId"] == outcome["attemptId"]:
            require(False, "duplicate recommendationId+attemptId outcome pair")
    pair = digest(canonical([outcome["recommendationId"], outcome["attemptId"]]))
    relative = _OUTCOME_PAIR_INDEX + pair[:2] + "/" + pair + ".json"
    path = contained(workspace, relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical({"kind": "img2.jev-outcome-pair", "version": 1, "recommendationId": outcome["recommendationId"], "attemptId": outcome["attemptId"], "status": "reserved"})
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as err:
        raise ContractError("duplicate recommendationId+attemptId outcome pair") from err
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return relative, path


def _commit_outcome_pair_index(path, outcome, artifact):
    payload = canonical({"kind": "img2.jev-outcome-pair", "version": 1, "recommendationId": outcome["recommendationId"], "attemptId": outcome["attemptId"], "status": "committed", "recordPath": artifact})
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".jev-pair-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None: temporary.unlink(missing_ok=True)


def run_outcome_v2(workspace, args, outcome):
    validate_outcome(outcome)
    lock = _acquire_outcome_archive_lock(workspace)
    try:
        return _run_outcome_v2_locked(workspace, args, outcome)
    finally:
        _release_outcome_archive_lock(lock)


def _run_outcome_v2_locked(workspace, args, outcome):
    _, reservation = _reserve_outcome_pair(workspace, outcome)
    published, temporaries, record_path = [], [], None
    try:
        report = read_json(workspace, args.recommendation)
        request = validate_report(workspace, report, check_freshness=False)
        require(outcome["recommendationId"] == report["id"] and outcome["recommendationHash"] == digest(canonical(report)), "outcome recommendation identity mismatch")
        gate_ids = [(outcome["beforeSnapshot"]["id"], "before")]
        if outcome["outcome"] != "build_failed": gate_ids.append((outcome["afterSnapshot"]["id"], "after"))
        expected_gate_ids = {item[0] for item in gate_ids}
        found_gate_ids = []
        for relative in outcome["evidencePaths"]:
            try: candidate = read_json(workspace, relative)
            except (ContractError, OSError): continue
            if isinstance(candidate, dict) and candidate.get("kind") == "img2.gate-verdict" and candidate.get("gate") == "environment": found_gate_ids.append(candidate.get("snapshotId"))
        require(set(found_gate_ids) == expected_gate_ids and len(found_gate_ids) == len(expected_gate_ids), "evidence must contain only the required Environment gate results")
        gates, gate_hashes = [], {}
        for expected_id, label in gate_ids:
            matches = []
            for relative in outcome["evidencePaths"]:
                try: data = read_json(workspace, relative)
                except (ContractError, OSError): continue
                if isinstance(data, dict) and data.get("kind") == "img2.gate-verdict" and data.get("gate") == "environment" and data.get("snapshotId") == expected_id: matches.append(relative)
            require(len(matches) == 1, "outcome must include exactly one matching " + label + " Environment gate result")
            gate = _validate_environment_gate(workspace, matches[0], expected_id, current=(label == "after"))
            gate_hashes[matches[0]] = file_hash(workspace, matches[0])
            evaluator = gate["evaluator"]
            snap = outcome[label + "Snapshot"]
            expected_evaluator = {"id": evaluator["id"], "version": str(evaluator["version"]), "adapter": evaluator["adapter"], "checksDigest": evaluator["checkDigest"]}
            require(snap["evaluator"] == expected_evaluator and outcome["assetAdapter"] == evaluator["adapter"], label + " evaluator/adapter mismatch")
            gates.append((matches[0], gate))
        before_path, before_gate = gates[0]
        bound = [item for item in request["snapshot"]["files"] if item["role"] == "evaluation" and item["path"] == before_path]
        require(len(bound) == 1 and bound[0]["sha256"] == gate_hashes[before_path], "before Environment gate is not bound by archived request")
        before_context_hash, before_qualities, before_context_bindings = _context_from_evidence(workspace, before_gate, outcome["evidencePaths"], historical=True)
        require(outcome["beforeSnapshot"]["measurementContextHash"] == before_context_hash, "before measurementContextHash differs from bound Environment context")
        _require_metrics_match_quality(outcome["beforeSnapshot"], before_qualities, "before")
        after_context_bindings, after_manifest = {}, {}
        if len(gates) == 2:
            after_path, after_gate = gates[1]
            after_manifest = _validate_after_manifest(workspace, after_gate)
            after_context_hash, after_qualities, after_context_bindings = _context_from_evidence(workspace, after_gate, outcome["evidencePaths"], historical=False)
            require(outcome["afterSnapshot"]["measurementContextHash"] == after_context_hash == before_context_hash, "after measurementContextHash differs from bound Environment context")
            _require_metrics_match_quality(outcome["afterSnapshot"], after_qualities, "after")
        files, published, temporaries = _archive_outcome_files(workspace, outcome["evidencePaths"])
        archived_by_path = {item["originalPath"]: item for item in files}
        for gate_path, gate in gates:
            archived_gate = archived_by_path.get(gate_path)
            require(archived_gate is not None and archived_gate["sha256"] == gate_hashes[gate_path], "Environment gate result changed while archiving")
            if gate_path != before_path:
                require(_validate_environment_gate(workspace, gate_path, gate["snapshotId"], current=True) == gate, "after Environment gate changed while archiving")
        for expected_bindings in (before_context_bindings, after_context_bindings):
            for evidence_path, expected in expected_bindings.items():
                archived = archived_by_path.get(evidence_path)
                require(archived is not None and archived["size"] == expected["size"] and archived["sha256"] == expected["sha256"], "bound context evidence changed while archiving: " + evidence_path)
        for evidence_path, archived in archived_by_path.items():
            expected = after_manifest.get(evidence_path)
            if expected is not None:
                require(archived["size"] == expected["size"] and archived["sha256"] == expected["sha256"], "selected after dependency changed while archiving: " + evidence_path)
        record = {**outcome, "verification": "environment-gate-and-archived-evidence", "archivedEvidence": files, "beforeGatePath": before_path, "afterGatePath": gates[1][0] if len(gates) > 1 else None, "advisoryOnly": True}
        serialized = canonical(record)
        payload = serialized + bytes((10,))
        require(len(payload) <= MAX_JSON_BYTES, "content-addressed outcome record exceeds the 128KiB JSON artifact limit")
        artifact = _OUTCOME_ARCHIVE + "records/" + digest(serialized) + ".json"
        target = contained(workspace, artifact)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".jev-outcome-", delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            contained(workspace, artifact)
            try:
                os.link(temporary, target)
                record_path = target
            except FileExistsError as err:
                raise ContractError("duplicate content-addressed outcome record") from err
        finally:
            if temporary is not None: temporary.unlink(missing_ok=True)
        _commit_outcome_pair_index(reservation, outcome, artifact)
        for temporary in temporaries: temporary.unlink(missing_ok=True)
        return {"kind": "img2.jev-command", "version": 1, "status": "recorded", "artifact": artifact, "verification": record["verification"]}
    except Exception:
        if record_path is not None: record_path.unlink(missing_ok=True)
        for target in published: target.unlink(missing_ok=True)
        for temporary in temporaries: temporary.unlink(missing_ok=True)
        reservation.unlink(missing_ok=True)
        raise


def run_outcome(workspace, args):
    outcome = read_json(workspace, args.input)
    if isinstance(outcome, dict) and type(outcome.get("version")) is int and outcome["version"] == 1: return run_outcome_v1(workspace, args)
    return run_outcome_v2(workspace, args, outcome)
def run_replay(workspace, args):
    path = contained(workspace, args.input)
    require(path.is_file() and path.stat().st_size <= 8 * 1024 * 1024, "replay corpus exceeds 8MiB or is missing")
    cases = []
    case_ids = set()
    totals = {"rules": {"acceptable": 0, "actionable": 0, "acceptableActionable": 0}, "recorded": {"acceptable": 0, "actionable": 0, "acceptableActionable": 0}}
    tokens = {"input_tokens": 0, "output_tokens": 0}
    with path.open("rb") as stream:
        for line in stream:
            if not line.strip():
                continue
            require(len(cases) < 1000, "replay case limit exceeded")
            case = decode(line)
            obj(case, "caseId state control response acceptable", "replay case")
            case_id = identifier(case["caseId"], "case ID")
            require(case_id not in case_ids, "duplicate replay case ID")
            case_ids.add(case_id)
            validate_state(case["state"])
            validate_control(case["control"])
            acceptable = []
            for label in sequence(case["acceptable"], "acceptable labels", 12, 1):
                obj(label, "action tactic", "acceptable label")
                choice(label["action"], {"refine-code", "refine-spec", "request-input", "stop", "defer"}, "label action")
                choice(label["tactic"], {"parameter-patch", "component-rebuild", "cross-component", "re-render", "re-analyze", "request-reference", "spec-review", "hard-gate-repair", "stop", "fallback"}, "label tactic")
                acceptable.append(label)
            response = case["response"]
            if response is not None:
                validate_response(response)
                for key in tokens:
                    tokens[key] += response["usage"][key]
            row = {"caseId": case_id}
            for arm, provider in (("rules", None), ("recorded", response)):
                proposal = recommend(case["state"], case["control"], provider)
                matched = {"action": proposal["action"], "tactic": proposal["tactic"]} in acceptable
                actionable = proposal["action"] in {"refine-code", "refine-spec"}
                totals[arm]["acceptable"] += int(matched)
                totals[arm]["actionable"] += int(actionable)
                totals[arm]["acceptableActionable"] += int(matched and actionable)
                row[arm] = {"action": proposal["action"], "tactic": proposal["tactic"], "acceptable": matched}
            cases.append(row)
    require(bool(cases), "empty replay corpus")
    for total in totals.values():
        total["acceptableRate"] = total["acceptable"] / len(cases)
        total["actionableCoverage"] = total["actionable"] / len(cases)
        total["actionablePrecision"] = total["acceptableActionable"] / total["actionable"] if total["actionable"] else None
    result = {"kind": "img2.jev-replay", "version": 1, "policyVersion": POLICY_VERSION, "questionSetVersion": QUESTION_SET_VERSION, "model": MODEL, "caseCount": len(cases), "corpusHash": file_hash(workspace, args.input), "evidenceVerification": "not-performed-offline", "liveCalls": 0, "recordedUsage": tokens, "arms": totals, "cases": cases}
    artifact = PREFIX + "replays/" + uuid.uuid4().hex + ".json"
    write_artifact(workspace, artifact, result)
    return {"kind": "img2.jev-command", "version": 1, "status": "replayed", "artifact": artifact, "caseCount": len(cases), "arms": totals, "liveCalls": 0}

def run_report_outcomes(workspace, args):
    report = build_report(workspace, args.input)
    artifact = PREFIX + "reports/" + digest(canonical(report)) + ".json"
    write_artifact(workspace, artifact, report)
    return {"kind": "img2.jev-command", "version": 1, "status": report["status"], "artifact": artifact, "corpusPath": args.input, "liveCalls": 0, "calibrationStatus": "uncalibrated"}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Advisory Jev repair routing; no scene mutations or acceptance authority.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("login", help="Store a TypeSafe API key in macOS Keychain")
    commands.add_parser("auth-status", help="Report local credential presence without exposing the key")
    consent_command = commands.add_parser("consent", help="Authorize or revoke workspace disclosure")
    consent_command.add_argument("action", choices=("authorize", "revoke"))
    consent_command.add_argument("--workspace", default=None)
    for name in ("prepare", "route", "consult", "record-outcome", "replay", "report-outcomes"):
        sub = commands.add_parser(name)
        sub.add_argument("--workspace", default=None)
        if name == "route":
            sub.set_defaults(input=REQUEST_PATH)
        elif name == "consult":
            sub.add_argument("--input", required=True, help="Workspace-relative checkpoint context JSON path")
            sub.add_argument("--timeout", type=float, default=15.0)
        else:
            sub.add_argument("--input", required=True, help="Workspace-relative JSON/JSONL path")
        if name == "route":
            sub.add_argument("--mode", choices=("shadow", "assist"), default="shadow")
            sub.add_argument("--timeout", type=float, default=15.0)
        elif name == "record-outcome":
            sub.add_argument("--recommendation", required=True, help="Workspace-relative recommendation record path")
    args = parser.parse_args(argv)
    try:
        if args.command == "login":
            login_credential()
            emit({"kind": "img2.jev-command", "version": 1, "status": "credential-stored"})
            return 0
        if args.command == "auth-status":
            result = auth_status()
            emit({"kind": "img2.jev-command", "version": 1, **result})
            return {"present": 0, "missing": 3, "storage-error": 1}[result["status"]]
        workspace = resolve_workspace(args.workspace) if args.command != "consent" or args.workspace else resolve_workspace(None)
        if args.command == "consent":
            result = set_consent(workspace, args.action == "authorize")
            emit({"kind": "img2.jev-command", "version": 1, "status": "consent-updated", **result})
            return 0
        require(not (workspace / "plugin.json").exists(), "workspace must not be a plugin checkout")
        if args.command in {"route", "consult"}:
            number(args.timeout, "timeout")
            require(0 < args.timeout <= 30, "timeout must be in (0, 30] seconds")
        if args.command == "consult":
            result = consult_checkpoint(workspace, args.input, timeout=args.timeout)
            emit({"kind": "img2.jev-command", "version": 1, **result})
            return 0
        handler = {"prepare": run_prepare, "route": run_route, "record-outcome": run_outcome, "replay": run_replay, "report-outcomes": run_report_outcomes}[args.command]
        emit(handler(workspace, args))
        return 0
    except (ContractError, CredentialError, ConsentError, ProviderError, OSError, RuntimeError, TypeError, ValueError, OverflowError) as err:
        # Never print request bodies, provider exceptions, credentials or tracebacks.
        reason = str(err) if isinstance(err, (ContractError, CredentialError, ConsentError)) else "local artifact or workspace operation failed"
        emit({"kind": "img2.jev-command", "version": 1, "status": "error", "reason": reason})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
