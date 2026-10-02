"""Offline, observational reports over an explicitly selected Jev outcome corpus."""
from __future__ import annotations

import hashlib
import json
import math
import os
import stat
from pathlib import Path
from typing import Any

try:
    from . import jev_contracts as contracts
except ImportError:  # Loaded as a plugin tool module by the CLI.
    import jev_contracts as contracts

try:
    from .jev_consent import POLICY_VERSION as CONSENT_POLICY_VERSION, require_consent
    from .jev_projection import POLICY_VERSION as PROJECTION_POLICY_VERSION, project_state
except ImportError:  # Loaded as a plugin tool module by the CLI.
    from jev_consent import POLICY_VERSION as CONSENT_POLICY_VERSION, require_consent
    from jev_projection import POLICY_VERSION as PROJECTION_POLICY_VERSION, project_state

MAX_CORPUS_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 100_000
GATE_IDS = ["01-scene-classify", "02-subject-inventory", "03-placement-consistency", "04-scale-anchors", "05-occlusion", "06-terrain-grounding", "07-material-independence", "08-multi-angle-legality", "09-llm-vs-forge-agreement", "10-code-only-contract", "11-screenshot-gate", "12-ip-provenance-hygiene"]
CONTEXT_PATHS = (".img2/artifacts/environment/scene-intake.json", ".img2/artifacts/environment/scene-spec.json", ".img2/artifacts/environment/scene-review.json")
ENVIRONMENT_SOURCE_FILES = {
    "room": ".img2/artifacts/environment/createEnvironmentRoomsModel.ts",
    "street": ".img2/artifacts/environment/createEnvironmentStreetModel.ts",
    "vegetation-cluster": ".img2/artifacts/environment/createEnvironmentVegetationClusterModel.ts",
    "building-exterior": ".img2/artifacts/environment/createEnvironmentBuildingExteriorModel.ts",
}
ENVIRONMENT_QUALIFIED_ADAPTERS = {"room"}
ENVIRONMENT_DEPENDENCY_FILES = {
    adapter: (*CONTEXT_PATHS, ".img2/artifacts/environment/reference-provenance.json", source)
    for adapter, source in ENVIRONMENT_SOURCE_FILES.items()
}


def _file_identity(info) -> tuple[int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _safe_file(workspace: Path, relative: str, limit: int) -> bytes:
    root = Path(workspace).resolve(strict=True)
    contracts.contained(root, relative)
    components = Path(relative).parts
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    leaf_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptors = []
    try:
        root_fd = os.open(root, dir_flags)
        descriptors.append(root_fd)
        root_info = os.fstat(root_fd)
        contracts.require(stat.S_ISDIR(root_info.st_mode), "workspace root is not a regular directory")
        parent_fd = root_fd
        directory_infos = [root_info]
        for component in components[:-1]:
            parent_fd = os.open(component, dir_flags, dir_fd=parent_fd)
            descriptors.append(parent_fd)
            info = os.fstat(parent_fd)
            contracts.require(stat.S_ISDIR(info.st_mode), "workspace path component is not a directory")
            directory_infos.append(info)
        descriptor = os.open(components[-1], leaf_flags, dir_fd=parent_fd)
        descriptors.append(descriptor)
        before = os.fstat(descriptor)
        contracts.require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "archive file is missing, nonregular, or oversized")
        chunks = bytearray()
        while len(chunks) <= limit:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(descriptor)
        contracts.require(_file_identity(before) == _file_identity(after) and len(chunks) <= limit and len(chunks) == before.st_size, "workspace file changed or exceeds its size bound")
        current_fd = os.dup(root_fd)
        descriptors.append(current_fd)
        contracts.require(_file_identity(os.fstat(current_fd)) == _file_identity(directory_infos[0]), "workspace root changed while reading")
        for index, component in enumerate(components[:-1], 1):
            current_fd = os.open(component, dir_flags, dir_fd=current_fd)
            descriptors.append(current_fd)
            current = os.fstat(current_fd)
            contracts.require(stat.S_ISDIR(current.st_mode) and _file_identity(current) == _file_identity(directory_infos[index]), "workspace directory changed or was replaced while reading")
        current_file = os.stat(components[-1], dir_fd=current_fd, follow_symlinks=False)
        contracts.require(stat.S_ISREG(current_file.st_mode) and _file_identity(current_file) == _file_identity(after), "workspace file changed or was replaced while reading")
        contracts.contained(root, relative)
        return bytes(chunks)
    except OSError as err:
        raise contracts.ContractError("cannot safely read workspace file: " + relative) from err
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _strict_json(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8"), object_pairs_hook=contracts._unique_object, parse_constant=lambda _: (_ for _ in ()).throw(contracts.ContractError("non-finite JSON number")))


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _recommendation(workspace: Path, record: dict) -> tuple[dict, dict]:
    rid = record["recommendationId"]
    base = ".img2/artifacts/jev/records/" + rid
    raw_rec = _safe_file(workspace, base + ".json", contracts.MAX_JSON_BYTES)
    recommendation = _strict_json(raw_rec)
    contracts.require(raw_rec == contracts.canonical(recommendation) + b"\n", "archived recommendation is not canonical")
    contracts.require(recommendation.get("id") == rid and _hash(contracts.canonical(recommendation)) == record["recommendationHash"], "archived recommendation identity/hash mismatch")
    req_path = base + ".state.json"
    contracts.require(recommendation.get("requestPath") == req_path, "recommendation does not name its deterministic archived request")
    request_raw = _safe_file(workspace, req_path, contracts.MAX_JSON_BYTES)
    archive = _strict_json(request_raw)
    contracts.require(request_raw == contracts.canonical(archive) + b"\n", "archived outbound request is not canonical")
    contracts.require(isinstance(archive, dict) and set(archive) == {"kind", "version", "request", "requestHash", "projectionHash", "consentHash", "consentPolicyVersion"}, "archived outbound request fields invalid")
    contracts.require(archive["kind"] == "img2.jev-outbound-request-archive" and type(archive["version"]) is int and archive["version"] == 2, "unsupported archived outbound request")
    contracts.require(PROJECTION_POLICY_VERSION == CONSENT_POLICY_VERSION, "projection and consent policy versions diverge")
    contracts.require(recommendation.get("consentPolicyVersion") == CONSENT_POLICY_VERSION and recommendation.get("versions", {}).get("projection") == PROJECTION_POLICY_VERSION, "recommendation disclosure policy mismatch")
    contracts.require(archive["consentPolicyVersion"] == recommendation["consentPolicyVersion"], "archived request consent policy mismatch")
    contracts.require(archive["requestHash"] == recommendation.get("requestHash") and archive["projectionHash"] == recommendation.get("projectionHash") and archive["consentHash"] == recommendation.get("consentHash"), "archived request disclosure binding mismatch")
    consent_hash = recommendation.get("consentHash")
    contracts.require(consent_hash is None or (isinstance(consent_hash, str) and len(consent_hash) == 64 and all(char in "0123456789abcdef" for char in consent_hash)), "invalid recommendation consent binding")
    provider = recommendation.get("provider")
    contracts.require(isinstance(provider, dict) and provider.get("status") in {"rules", "evaluated", "unavailable"}, "invalid recommendation provider status")
    if provider["status"] in {"evaluated", "unavailable"}:
        contracts.require(consent_hash is not None, "live provider recommendation lacks consent binding")
    else:
        contracts.require(consent_hash is None, "rules recommendation cannot carry a live consent binding")
    if consent_hash is not None:
        consent = require_consent(workspace)
        contracts.require(_hash(contracts.canonical(consent)) == consent_hash, "workspace consent changed or was revoked")
    request = archive["request"]
    contracts.validate_request(workspace, request, check_freshness=False)
    contracts.require(_hash(contracts.canonical(request)) == archive["requestHash"], "archived recommendation request hash mismatch")
    projection = project_state(request["state"])
    contracts.require(_hash(contracts.canonical(projection)) == archive["projectionHash"], "archived outbound projection hash mismatch")
    before = record["beforeGatePath"]
    gate_entry = record["archivedEvidence"]
    before_entry = next((item for item in gate_entry if item.get("originalPath") == before), None)
    matching_evaluations = [item for item in request["snapshot"]["files"] if item.get("role") == "evaluation" and item.get("path") == before]
    contracts.require(before_entry is not None and len(matching_evaluations) == 1 and matching_evaluations[0].get("sha256") == before_entry.get("sha256"), "before gate is not bound by archived request evaluation role")
    return recommendation, request


def _archive_map(workspace: Path, record: dict) -> dict[str, bytes]:
    evidence = record["evidencePaths"]
    entries = record["archivedEvidence"]
    contracts.require(isinstance(entries, list) and len(entries) == len(evidence), "archived evidence does not match evidencePaths")
    result = {}
    total = 0
    for original, entry in zip(evidence, entries):
        contracts.require(entry.get("originalPath") == original, "archived evidence order differs from evidencePaths")
        sha = entry.get("sha256")
        contracts.require(isinstance(sha, str) and len(sha) == 64 and all(c in "0123456789abcdef" for c in sha), "invalid archived evidence hash")
        blob_path = ".img2/artifacts/jev/outcomes/archive/" + sha[:2] + "/" + sha + ".blob"
        contracts.require(entry.get("archivedPath") == blob_path, "archived evidence path does not match hash")
        size = entry.get("size")
        contracts.require(type(size) is int and size >= 0 and size <= contracts.MAX_BOUND_BYTES - total, "invalid or excessive archived evidence size")
        total += size
        data = _safe_file(workspace, blob_path, contracts.MAX_BOUND_BYTES)
        contracts.require(len(data) == size and _hash(data) == sha, "archived evidence bytes do not match persisted digest")
        result[original] = data
    return result




def _sha256(value: Any, where: str) -> None:
    contracts.require(isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value), where + ": lowercase SHA-256 required")


def _gate(workspace: Path, archive: dict[str, bytes], path: str, snapshot: dict, record: dict) -> dict:
    entry = next((item for item in record["archivedEvidence"] if item.get("originalPath") == path), None)
    contracts.require(entry is not None and path in archive, "gate result missing from archived evidence")
    raw = archive[path]
    contracts.require(len(raw) <= contracts.MAX_JSON_BYTES, "Environment gate result exceeds the JSON artifact limit")
    gate = _strict_json(raw)
    contracts.require(raw == contracts.canonical(gate), "Environment gate result is not canonical JSON")
    contracts.obj(gate, "kind version gate plugin status reasons evidence evaluator snapshot snapshotId snapshotPath resultPath", "Environment gate result")
    contracts.require(gate["kind"] == "img2.gate-verdict" and type(gate["version"]) is int and gate["version"] == 1, "unsupported Environment gate result")
    contracts.require(gate["gate"] == "environment" and gate["plugin"] == "environment", "gate is not an Environment result")
    contracts.choice(gate["status"], {"pass", "fail"}, "Environment gate status")
    contracts.require(isinstance(gate["reasons"], list), "Environment gate reasons must be a list")
    evidence = contracts.obj(gate["evidence"], "gates unevaluated", "Environment evidence")
    contracts.require(isinstance(evidence["unevaluated"], list) and not evidence["unevaluated"], "Environment gate contains unevaluated rows")
    rows = contracts.sequence(evidence["gates"], "Environment gate rows", 12, 12)
    for check_id, row in zip(GATE_IDS, rows):
        contracts.obj(row, "id status reasons evidence", "Environment gate row")
        contracts.require(row["id"] == check_id, "Environment gate rows are not canonical and ordered")
        contracts.choice(row["status"], {"pass", "fail"}, "Environment row status")
        contracts.require(isinstance(row["reasons"], list) and isinstance(row["evidence"], dict), "malformed Environment gate row")
        contracts.require((row["status"] == "pass") == (not row["reasons"]), "Environment row reasons contradict status")
    contracts.require((gate["status"] == "pass") == all(row["status"] == "pass" for row in rows), "Environment gate status contradicts rows")
    contracts.require(gate["reasons"] == [reason for row in rows for reason in row["reasons"]], "Environment gate reasons differ from ordered rows")
    evaluator = contracts.obj(gate["evaluator"], "id plugin version adapter checks checkDigest", "Environment evaluator")
    contracts.require(evaluator["id"] == "environment-gate" and evaluator["plugin"] == "environment", "unexpected Environment evaluator")
    contracts.require(type(evaluator["version"]) is int and evaluator["version"] >= 1, "invalid Environment evaluator version")
    contracts.choice(evaluator["adapter"], {"room", "street", "vegetation-cluster", "building-exterior"}, "Environment adapter")
    contracts.require(evaluator["checks"] == GATE_IDS, "Environment evaluator check list mismatch")
    _sha256(evaluator["checkDigest"], "Environment checks digest")
    gate_snapshot = contracts.obj(gate["snapshot"], "id path evaluator files", "Environment snapshot")
    expected_id = snapshot["id"]
    expected_path = ".img2/artifacts/environment/gate-results/" + expected_id + ".json"
    contracts.require(gate_snapshot["id"] == expected_id == gate["snapshotId"], "Environment snapshot identity mismatch")
    contracts.require(gate_snapshot["evaluator"] == evaluator, "snapshot evaluator differs from gate evaluator")
    contracts.require(gate_snapshot["path"] == expected_path and gate["snapshotPath"] == expected_path and gate["resultPath"] == expected_path and path == expected_path, "Environment snapshot path mismatch")
    files = contracts.sequence(gate_snapshot["files"], "Environment snapshot files", 64, 1)
    seen = set()
    for file in files:
        contracts.obj(file, "path size sha256", "Environment snapshot file")
        contracts.require(isinstance(file["path"], str) and file["path"] and file["path"] not in seen, "duplicate or invalid Environment dependency path")
        seen.add(file["path"])
        contracts.require(type(file["size"]) is int and file["size"] >= 0, "invalid Environment dependency size")
        _sha256(file["sha256"], "Environment dependency digest")
        contracts.contained(workspace, file["path"])
    core = {"evaluator": evaluator, "files": files, "status": gate["status"], "reasons": gate["reasons"], "evidence": evidence}
    contracts.require(_hash(contracts.canonical(core)) == expected_id, "Environment snapshot digest mismatch")
    expected_evaluator = snapshot["evaluator"]
    contracts.require(evaluator["id"] == expected_evaluator["id"] and str(evaluator["version"]) == expected_evaluator["version"] and evaluator["adapter"] == expected_evaluator["adapter"] and evaluator["checkDigest"] == expected_evaluator["checksDigest"], "gate evaluator identity mismatch")
    return gate


def _verify_context(gate: dict, snapshot: dict, archive: dict[str, bytes], record: dict) -> None:
    adapter = gate["evaluator"]["adapter"]
    contracts.require(adapter in ENVIRONMENT_SOURCE_FILES, "no T2 measurement-context source mapping exists for this Environment adapter")
    contracts.require(adapter in ENVIRONMENT_QUALIFIED_ADAPTERS, "Environment adapter is not fixture-qualified for reporting")
    contracts.require(snapshot["evaluator"]["adapter"] == adapter, "snapshot evaluator adapter differs from gate context")
    by_path = {item["path"]: item for item in gate["snapshot"]["files"]}
    artifacts = {}
    contracts.require(all(path in by_path for path in ENVIRONMENT_DEPENDENCY_FILES[adapter]), "Environment gate snapshot does not bind its adapter dependencies")
    for path in CONTEXT_PATHS:
        manifest = by_path.get(path)
        contracts.require(manifest is not None, "Environment gate snapshot does not bind context artifact " + path)
        entry = next((item for item in record["archivedEvidence"] if item.get("size") == manifest["size"] and item.get("sha256") == manifest["sha256"]), None)
        contracts.require(entry is not None and entry["originalPath"] in archive, "archived context bytes do not match gate dependency: " + path)
        artifacts[path] = _strict_json(archive[entry["originalPath"]])
    intake, spec, review = (artifacts[path] for path in CONTEXT_PATHS)
    contracts.require(isinstance(intake, dict) and isinstance(spec, dict) and isinstance(review, dict), "archived context artifacts must be objects")
    classification = intake.get("sceneClassification")
    contracts.require(isinstance(classification, dict) and classification.get("kind") == adapter, "context intake kind differs from Environment adapter")
    source_views = contracts.sequence(intake.get("sourceViews"), "scene-intake.sourceViews", 32, 1)
    view_projection = []
    for view in source_views:
        contracts.require(isinstance(view, dict) and {"id", "path", "sha256"} <= view.keys(), "scene-intake source view must contain id, path, and sha256")
        contracts.require(isinstance(view["path"], str) and bool(view["path"]), "scene-intake source view path is required")
        contracts.identifier(view["id"], "scene-intake source view id")
        _sha256(view["sha256"], "scene-intake source view SHA-256")
        view_projection.append({"id": view["id"], "sha256": view["sha256"]})
    viewpoints = contracts.sequence(spec.get("reviewViewpoints"), "scene-spec.reviewViewpoints", 32, 1)
    contracts.require(all(isinstance(value, str) and value for value in viewpoints), "invalid scene-spec.reviewViewpoints")
    context_fields = ("camera", "renderer", "resolution", "exposure", "toneMapping", "background", "environment", "iblContribution")
    for key in context_fields:
        contracts.require(key in review and review[key] is not None, "scene-review measurement context is missing " + key)
    method = review.get("qualityMeasurementMethod")
    contracts.require(isinstance(method, str) and method.strip(), "scene-review.qualityMeasurementMethod must be explicit")
    quality_rows = contracts.sequence(review.get("qualityMeasurements"), "scene-review.qualityMeasurements", 32, 1)
    quality_metrics = {}
    for row in quality_rows:
        contracts.obj(row, "featureId value unit direction", "scene-review quality measurement")
        feature = contracts.identifier(row["featureId"], "quality measurement featureId")
        contracts.require(feature not in quality_metrics, "duplicate scene-review quality measurement featureId")
        value = row["value"]
        contracts.require(type(value) is int or (type(value) is float and math.isfinite(value)), "scene-review quality measurement value must be finite")
        contracts.require(isinstance(row["unit"], str) and bool(row["unit"]), "scene-review quality measurement unit is required")
        contracts.choice(row["direction"], contracts._OUTCOME_DIRECTIONS, "scene-review quality measurement direction")
        quality_metrics[feature] = (value, row["unit"], row["direction"])
    projection = {"adapter": adapter, "sourceViews": view_projection, "reviewViewpoints": viewpoints, **{key: review[key] for key in context_fields}, "qualityMeasurementMethod": method}
    contracts.require(_hash(contracts.canonical(projection)) == snapshot["measurementContextHash"], "archived gate context does not match measurementContextHash")
    snapshot_metrics = contracts._outcome_snapshot(snapshot, "snapshot", adapter)[1]
    contracts.require(snapshot_metrics == quality_metrics, "archived quality metrics do not match gate-bound context")


def _validate_outcome_shape(core: dict) -> bool:
    contracts.choice(core.get("outcome"), contracts._OUTCOME_LABELS, "outcome")
    if core["outcome"] == "build_failed":
        contracts.validate_outcome(core)
        return False
    before_snapshot, after_snapshot = core["beforeSnapshot"], core["afterSnapshot"]
    before_eval, before_metrics, before_context = contracts._outcome_snapshot(before_snapshot, "beforeSnapshot", before_snapshot.get("evaluator", {}).get("adapter"))
    after_eval, after_metrics, after_context = contracts._outcome_snapshot(after_snapshot, "afterSnapshot", after_snapshot.get("evaluator", {}).get("adapter"))
    metric_identity = lambda metrics: {feature: (value[1], value[2]) for feature, value in metrics.items()}
    incomparable = before_eval != after_eval or before_eval["adapter"] != core["assetAdapter"] or after_eval["adapter"] != core["assetAdapter"] or before_context != after_context or metric_identity(before_metrics) != metric_identity(after_metrics)
    if not incomparable:
        contracts.validate_outcome(core)
        return False
    rows = contracts.sequence(core["measurements"]["rows"], "measurement rows", 32, 1)
    row_ids = set()
    for row in rows:
        contracts.obj(row, "featureId beforeValue afterValue unit direction", "measurement row")
        feature = contracts.identifier(row["featureId"], "measurement featureId")
        contracts.require(feature not in row_ids, "duplicate measurement featureId")
        row_ids.add(feature)
        contracts._outcome_number(row["beforeValue"], "measurement beforeValue")
        contracts._outcome_number(row["afterValue"], "measurement afterValue")
        unit = contracts.text(row["unit"], "measurement unit", 64)
        direction = row["direction"]
        contracts.choice(direction, contracts._OUTCOME_DIRECTIONS, "measurement direction")
        before_metric, after_metric = before_metrics.get(feature), after_metrics.get(feature)
        identities = [metric[1:] for metric in (before_metric, after_metric) if metric is not None]
        contracts.require(identities, "measurement feature is absent from both snapshots")
        contracts.require(any((unit, direction) == identity for identity in identities), "measurement metadata matches neither archived snapshot")
        contracts.require(before_metric is None or row["beforeValue"] == before_metric[0], "measurement before value does not match snapshot")
        contracts.require(after_metric is None or row["afterValue"] == after_metric[0], "measurement after value does not match snapshot")
    contracts.require(row_ids == set(before_metrics) | set(after_metrics), "measurement rows do not cover all feature IDs across snapshots")
    normalized = json.loads(json.dumps(core))
    normalized["outcome"] = "inconclusive"
    normalized["beforeSnapshot"]["evaluator"]["adapter"] = normalized["assetAdapter"]
    normalized["afterSnapshot"]["evaluator"] = normalized["beforeSnapshot"]["evaluator"]
    normalized["afterSnapshot"]["measurementContextHash"] = normalized["beforeSnapshot"]["measurementContextHash"]
    normalized["afterSnapshot"]["metrics"] = normalized["beforeSnapshot"]["metrics"]
    normalized["measurements"]["rows"] = [{"featureId": row["featureId"], "beforeValue": row["value"], "afterValue": row["value"], "unit": row["unit"], "direction": row["direction"]} for row in normalized["beforeSnapshot"]["metrics"]]
    contracts.validate_outcome(normalized)
    return True


def _proposal_action(recommendation: dict) -> dict:
    proposal = recommendation.get("proposal")
    contracts.require(isinstance(proposal, dict), "archived recommendation proposal is missing")
    return contracts._outcome_action({"action": proposal.get("action"), "tactic": proposal.get("tactic")}, "archived recommendation proposal")


def _follows_proposal(record: dict, proposal_action: dict) -> bool:
    actual = record["actualAction"]
    return actual["action"] == proposal_action["action"] and actual["tactic"] == proposal_action["tactic"]


def _validate_record(workspace: Path, record: dict, raw: bytes) -> tuple[dict, dict]:
    contracts.require(raw == contracts.canonical(record) + b"\n", "persisted outcome is noncanonical")
    record_hash = _hash(contracts.canonical(record))
    persisted_path = ".img2/artifacts/jev/outcomes/archive/records/" + record_hash + ".json"
    persisted = _safe_file(workspace, persisted_path, contracts.MAX_JSON_BYTES)
    contracts.require(persisted == raw, "persisted outcome does not match its content-addressed record blob")
    fields = "kind version recommendationId attemptId outcome recommendationHash approvedAction actualAction recommendationFollowed assetAdapter beforeSnapshot afterSnapshot measurements adjudication evidencePaths buildFailureEvidencePaths evidenceClass".split()
    core = {key: record[key] for key in fields}
    incomparable = _validate_outcome_shape(core)
    contracts.require(record.get("verification") == "environment-gate-and-archived-evidence" and record.get("advisoryOnly") is True, "persisted record verification metadata invalid")
    before_path = ".img2/artifacts/environment/gate-results/" + core["beforeSnapshot"]["id"] + ".json"
    contracts.require(record.get("beforeGatePath") == before_path and before_path in core["evidencePaths"], "before gate path does not match snapshot")
    if core["outcome"] == "build_failed":
        contracts.require(record.get("afterGatePath") is None, "build_failed must not have an after gate")
    else:
        after_path = ".img2/artifacts/environment/gate-results/" + core["afterSnapshot"]["id"] + ".json"
        contracts.require(record.get("afterGatePath") == after_path and after_path in core["evidencePaths"], "after gate path does not match snapshot")
    archive = _archive_map(workspace, record)
    recommendation, request = _recommendation(workspace, record)
    before_gate = _gate(workspace, archive, before_path, core["beforeSnapshot"], record)
    _verify_context(before_gate, core["beforeSnapshot"], archive, record)
    if core["outcome"] != "build_failed":
        after_gate = _gate(workspace, archive, record["afterGatePath"], core["afterSnapshot"], record)
        _verify_context(after_gate, core["afterSnapshot"], archive, record)
    recommendation_proposal = _proposal_action(recommendation)
    policy_version = recommendation.get("versions", {}).get("policy")
    contracts.require(isinstance(policy_version, str) and policy_version, "archived recommendation lacks policy version")
    return core, {"policyVersion": policy_version, "archive": archive, "recommendation": recommendation, "request": request, "incomparable": incomparable, "recommendationProposal": recommendation_proposal}


def _wilson(successes: int, total: int) -> dict | None:
    if total == 0:
        return None
    z = 1.96
    p = successes / total
    den = 1 + z * z / total
    center = (p + z * z / (2 * total)) / den
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / den
    return {"level": 0.95, "lower": max(0.0, center - margin), "upper": min(1.0, center + margin)}


def _aggregate(records: list[dict]) -> dict:
    labels = ("improved", "unchanged", "regressed", "build_failed", "inconclusive")
    counts = {label: sum(r["outcome"] == label for r in records) for label in labels}
    quality_n = sum(counts[k] for k in labels[:3])
    attempt_n = quality_n + counts["build_failed"]
    quality = {k: {"count": counts[k], "rate": counts[k] / quality_n if quality_n else None, "wilson95": _wilson(counts[k], quality_n)} for k in labels[:3]}
    attempt = {k: {"count": counts[k], "rate": counts[k] / attempt_n if attempt_n else None, "wilson95": _wilson(counts[k], attempt_n)} for k in labels[:4]}
    return {"counts": counts, "quality": {"denominator": quality_n, "statuses": quality}, "attempt": {"denominator": attempt_n, "statuses": attempt}, "inconclusive": {"count": counts["inconclusive"], "outsideDenominators": True}}


def build_report(workspace: str | os.PathLike, input_relative_jsonl: str) -> dict:
    """Build a deterministic observational report from exactly one workspace-local JSONL corpus."""
    root = Path(workspace).resolve(strict=True)
    raw = _safe_file(root, input_relative_jsonl, MAX_CORPUS_BYTES)
    lines = raw.splitlines()
    contracts.require(len(lines) <= MAX_RECORDS, "corpus has too many records")
    seen: set[tuple[str, str]] = set()
    eligible = []
    excluded = []
    for number, line in enumerate(lines, 1):
        if not line:
            excluded.append({"line": number, "reason": "empty-line"})
            continue
        item = None
        try:
            contracts.require(len(line) <= contracts.MAX_JSON_BYTES, "JSONL record exceeds 128KiB")
            item = _strict_json(line)
            if isinstance(item, dict) and item.get("version") == 1:
                excluded.append({"line": number, "reason": "legacy-v1"})
                continue
            contracts.require(isinstance(item, dict) and item.get("version") == 2, "unsupported or malformed outcome record")
            pair = (item.get("recommendationId"), item.get("attemptId"))
            contracts.require(all(isinstance(x, str) for x in pair), "missing recommendationId/attemptId pair")
            contracts.require(pair not in seen, "duplicate recommendationId+attemptId pair")
            seen.add(pair)
            core, verified = _validate_record(root, item, line + b"\n")
            reason = None
            if core["evidenceClass"] == "synthetic":
                reason = "synthetic"
            elif core["adjudication"]["status"] != "independent":
                reason = "unadjudicated"
            elif verified["incomparable"]:
                reason = "incomparable"
            if reason:
                excluded.append({"line": number, "reason": reason, "recommendationId": pair[0], "attemptId": pair[1]})
            else:
                eligible.append({"record": core, "recommendationFollowed": _follows_proposal(core, verified["recommendationProposal"]), **{k: verified[k] for k in ("policyVersion",)}, "line": number})
        except Exception as exc:
            if "duplicate recommendationId+attemptId" in str(exc):
                raise
            exclusion = {"line": number, "reason": "invalid-record"}
            if isinstance(item, dict):
                for key in ("recommendationId", "attemptId"):
                    if isinstance(item.get(key), str):
                        exclusion[key] = item[key]
            excluded.append(exclusion)
    strata: dict[str, list[dict]] = {}
    for entry in eligible:
        r = entry["record"]
        evaluator = r["beforeSnapshot"]["evaluator"]
        key_obj = {"adapter": r["assetAdapter"], "evaluatorVersion": evaluator["version"], "evaluatorDigest": evaluator["checksDigest"], "policyVersion": entry["policyVersion"], "actualAction": r["actualAction"], "recommendationFollowed": entry["recommendationFollowed"]}
        key = json.dumps(key_obj, sort_keys=True, separators=(",", ":"))
        strata.setdefault(key, []).append(r)
    stratum_rows = []
    for key in sorted(strata):
        meta = json.loads(key)
        stratum_rows.append({**meta, **_aggregate(strata[key])})
    status = "ok" if eligible else "insufficient-data"
    eligible_records = [x["record"] for x in eligible]
    followed = sum(entry["recommendationFollowed"] for entry in eligible)
    base = {"kind": "img2.jev-outcome-report", "version": 1, "status": status, "wording": "Observational descriptive outcomes only; no causal-success inference and no acceptance authority.", "liveCalls": 0, "calibrationStatus": "uncalibrated", "corpusPath": input_relative_jsonl, "corpusHash": _hash(raw), "eligibleCount": len(eligible), **_aggregate(eligible_records), "strata": stratum_rows, "excludedCount": len(excluded), "exclusions": excluded}
    base["routingAgreement"] = {"count": followed, "denominator": len(eligible_records), "rate": followed / len(eligible_records) if eligible_records else None, "wilson95": _wilson(followed, len(eligible_records))}
    contracts.require(len(contracts.canonical(base) + b"\n") <= contracts.MAX_JSON_BYTES, "outcome report exceeds the 128KiB report-artifact limit; reduce or split the input corpus")
    return base
