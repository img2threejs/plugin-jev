"""Jev checkpoint consultation: local evidence bindings, aggregate-only projection, advisory output."""
import fcntl
import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path

from jev_contracts import ContractError, canonical, contained, file_hash, read_json, require
from jev_consent import POLICY_VERSION as CONSENT_POLICY_VERSION, ConsentError, require_consent
from jev_auth import CredentialError, resolve_api_key
from jev_transport import evaluate_checkpoint_bounded
from jev_checkpoint_client import validate_response as validate_checkpoint_response

KIND = "img2.jev-checkpoint-context"
QUESTION_SET_VERSION = "checkpoint-questions-v1"
POLICY_VERSION = "checkpoint-advice-v1"
CHECKPOINTS = {"inventory-review", "scene-analysis-review", "production-brief-review"}
ROLES = {"scene-intake", "source-view", "image-analysis", "coverage-contact-sheet", "production-brief"}
SIGNALS = {"partial-visibility", "occluded-subject", "unknown-visibility", "unknown-scene-dimension", "not-inferable-hypothesis", "unapproved-hypothesis", "creative-addition", "missing-timebase-profile", "request-input"}
_ACTIONS = {"human-review", "request-input", "revise-artifact", "defer", "stop"}
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_METRICS = {
 "inventory-review": {"sourceViewCount", "subjectCount", "groupCount", "coverageRegionCount", "visibilityCounts", "representationCounts", "regionDispositionCounts"},
 "scene-analysis-review": {"observationCounts", "unknownTopics", "hypothesisCounts", "unapprovedHypothesisCount"},
 "production-brief-review": {"storyBeatCount", "storyBeatBasisCounts", "requirementCountsByCategory", "requirementCountsByBasis", "standardReferenceCount", "profileBoundRequirementCount", "creativeStoryBeatCount", "creativeRequirementCount"},
}
_COUNT_KEYS = {"visibilityCounts": {"visible", "partial", "occluded", "unknown"}, "representationCounts": {"model", "non-3d", "effect", "unresolved"}, "regionDispositionCounts": {"subject", "background", "shadow", "reflection", "text", "non-3d", "effect", "unresolved"}, "observationCounts": {"observed", "unknown"}, "hypothesisCounts": {"proposed", "not-inferable"}, "storyBeatBasisCounts": {"observed", "inferred", "creative"}, "requirementCountsByCategory": {"animation", "vfx", "sfx"}, "requirementCountsByBasis": {"observed", "inferred", "creative"}}
_TOPICS = {"camera", "lighting", "time", "color", "space", "context"}
ARTIFACT_PREFIX = ".img2/artifacts/jev/checkpoints/"
MAX_CONTEXT_BYTES = 32768
MAX_BINDING_TOTAL_BYTES = 64 * 1024 * 1024
MAX_METRIC_COUNT = 2**31 - 1


def _check_counts(value, where):
    if isinstance(value, dict):
        require(set(value) in _COUNT_KEYS.values(), where + " has unknown count categories")
        for k, v in value.items():
            require(type(v) is int and 0 <= v <= MAX_METRIC_COUNT, where + " counts must be bounded nonnegative integers")
    else:
        require(type(value) is int and 0 <= value <= MAX_METRIC_COUNT, where + " must be a bounded nonnegative integer")


def validate_context(workspace, context):
    require(type(context) is dict and set(context) == {"kind", "version", "checkpoint", "status", "proposalSha256", "sceneAnalysisSha256", "briefSha256", "metrics", "signals", "bindings", "contextSha256"}, "checkpoint context fields mismatch")
    require(context["kind"] == KIND and type(context["version"]) is int and context["version"] == 1, "unsupported checkpoint context")
    require(context["checkpoint"] in CHECKPOINTS and context["status"] == "ready-for-review", "checkpoint context is not eligible")
    stage = context["checkpoint"]
    required = {"proposalSha256": True, "sceneAnalysisSha256": stage != "inventory-review", "briefSha256": stage == "production-brief-review"}
    for key, needed in required.items():
        value = context[key]
        if needed:
            require(isinstance(value, str) and _HEX.fullmatch(value) is not None, "invalid stage digest")
        else:
            require(value is None, "unexpected stage digest")
    metrics = context["metrics"]
    require(type(metrics) is dict and set(metrics) == _METRICS[stage], "checkpoint metrics mismatch")
    for key, value in metrics.items():
        if key in _COUNT_KEYS:
            require(set(value) == _COUNT_KEYS[key], "checkpoint count categories mismatch")
            _check_counts(value, key)
        elif key == "unknownTopics":
            require(type(value) is list and all(type(x) is str and x in _TOPICS for x in value) and len(value) == len(set(value)), "invalid unknown topics")
        else:
            _check_counts(value, key)
    require(type(context["signals"]) is list and len(context["signals"]) == len(set(context["signals"])), "invalid checkpoint signals")
    require(all(type(s) is str and s in SIGNALS for s in context["signals"]), "unknown checkpoint signal")
    bindings = context["bindings"]
    require(type(bindings) is list and 1 <= len(bindings) <= 64, "invalid binding list")
    seen = set()
    total_binding_bytes = 0
    for binding in bindings:
        require(type(binding) is dict and set(binding) == {"path", "role", "size", "sha256"}, "invalid binding shape")
        path = binding["path"]
        require(type(path) is str and path and "\\" not in path and not path.startswith("/") and ".." not in Path(path).parts, "invalid workspace-relative binding")
        require(binding["role"] in ROLES and type(binding["size"]) is int and binding["size"] >= 0 and binding["size"] <= 64 * 1024 * 1024 and isinstance(binding["sha256"], str) and _HEX.fullmatch(binding["sha256"]) is not None, "invalid binding metadata")
        total_binding_bytes += binding["size"]
        require(total_binding_bytes <= MAX_BINDING_TOTAL_BYTES, "checkpoint bindings exceed aggregate size limit")
        require(path not in seen, "duplicate binding path")
        seen.add(path)
        file = contained(workspace, path)
        require(file.is_file() and not file.is_symlink() and file.stat().st_size == binding["size"] and file.stat().st_size <= 64 * 1024 * 1024 and file_hash(workspace, path) == binding["sha256"], "checkpoint binding is stale")
    unsigned = {k: v for k, v in context.items() if k != "contextSha256"}
    require(isinstance(context["contextSha256"], str) and _HEX.fullmatch(context["contextSha256"]) is not None and hashlib.sha256(canonical(unsigned)).hexdigest() == context["contextSha256"], "checkpoint context digest mismatch")
    require(len(canonical(context)) <= MAX_CONTEXT_BYTES, "checkpoint context exceeds limit")
    return context


def projection(context):
    metrics = dict(context["metrics"])
    if "unknownTopics" in metrics:
        metrics["unknownTopicCount"] = len(metrics.pop("unknownTopics"))
    return {"checkpoint": context["checkpoint"], "metrics": metrics, "signals": context["signals"]}


def validate_checkpoint_projection(value):
    require(type(value) is dict and set(value) == {"checkpoint", "metrics", "signals"}, "checkpoint projection fields mismatch")
    require(type(value["checkpoint"]) is str and value["checkpoint"] in CHECKPOINTS, "invalid checkpoint projection stage")
    stage = value["checkpoint"]
    expected = {
        "inventory-review": {"sourceViewCount", "subjectCount", "groupCount", "coverageRegionCount", "visibilityCounts", "representationCounts", "regionDispositionCounts"},
        "scene-analysis-review": {"observationCounts", "unknownTopicCount", "hypothesisCounts", "unapprovedHypothesisCount"},
        "production-brief-review": {"storyBeatCount", "storyBeatBasisCounts", "requirementCountsByCategory", "requirementCountsByBasis", "standardReferenceCount", "profileBoundRequirementCount", "creativeStoryBeatCount", "creativeRequirementCount"},
    }[stage]
    metrics = value["metrics"]
    require(type(metrics) is dict and set(metrics) == expected, "checkpoint projection metrics mismatch")
    for key, counts in metrics.items():
        if key in _COUNT_KEYS:
            require(type(counts) is dict and set(counts) == _COUNT_KEYS[key], "checkpoint projection count categories mismatch")
            _check_counts(counts, key)
        else:
            _check_counts(counts, key)
    if stage == "scene-analysis-review":
        require(metrics["unknownTopicCount"] <= len(_TOPICS), "unknown topic count exceeds closed enum")
    signals = value["signals"]
    require(type(signals) is list and len(signals) <= len(SIGNALS) and len(signals) == len(set(signals)) and all(type(signal) is str and signal in SIGNALS for signal in signals), "checkpoint projection signals mismatch")
    return value


def _lock(workspace, name):
    path = contained(workspace, ARTIFACT_PREFIX + name)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise ContractError("unsafe checkpoint lock")
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def _release(fd):
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)


def suggested_action(response, context):
    answers = response["answers"]
    if "request-input" in context["signals"] or answers["evidence"]["choice"] == "insufficient-evidence" or any(a["choice"] == "request-input" for a in answers.values()):
        return "request-input"
    if any(a["choice"] == "uncertain" for a in answers.values()):
        return "defer"
    if any(a["probabilities"][a["choice"]] < 0.8 or a["confidence"] < 0.5 for a in answers.values()):
        return "defer"
    dispositions = set()
    if answers["risk"]["choice"] == "stop" or answers["scope"]["choice"] == "stop":
        dispositions.add("stop")
    if answers["artifact"]["choice"] == "revise":
        dispositions.add("revise-artifact")
    if answers["risk"]["choice"] == "defer" or answers["scope"]["choice"] == "defer":
        dispositions.add("defer")
    if answers["risk"]["choice"] == "human-review" or answers["scope"]["choice"] == "human-review" or answers["artifact"]["choice"] == "uncertain":
        dispositions.add("human-review")
    if len(dispositions) != 1:
        return "defer"
    return next(iter(dispositions))


def consult(workspace, input_path, timeout=15.0):
    context = validate_context(workspace, read_json(workspace, input_path))
    if "request-input" in context["signals"]:
        return {"status": "not-consulted", "reasonCode": "request-input-required"}
    try:
        consent = require_consent(workspace)
    except ConsentError:
        return {"status": "not-consulted", "reasonCode": "consent-required"}
    if type(consent) is not dict or set(consent) != {"user", "workspace", "policyVersion", "generation"} or consent["policyVersion"] != CONSENT_POLICY_VERSION:
        return {"status": "not-consulted", "reasonCode": "consent-required"}
    consent_hash = hashlib.sha256(canonical(consent)).hexdigest()
    cache_identity = hashlib.sha256(canonical({"contextSha256": context["contextSha256"], "consentHash": consent_hash, "consentPolicyVersion": CONSENT_POLICY_VERSION, "pluginVersion": "0.3.0", "questions": QUESTION_SET_VERSION, "policy": POLICY_VERSION})).hexdigest()
    fd = _lock(workspace, cache_identity + ".lock")
    try:
        validate_context(workspace, context)
        cache_path = ARTIFACT_PREFIX + "cache/" + cache_identity + ".json"
        cached = contained(workspace, cache_path)
        if cached.is_file() and not cached.is_symlink():
            index = read_json(workspace, cache_path)
            if type(index) is dict and set(index) == {"kind", "recordPath", "recordSha256"} and index["kind"] == "img2.jev-checkpoint-cache" and type(index["recordPath"]) is str and type(index["recordSha256"]) is str and _HEX.fullmatch(index["recordSha256"]) is not None:
                expected_record_path = ARTIFACT_PREFIX + "records/" + index["recordSha256"] + ".json"
                artifact = index["recordPath"]
                if artifact == expected_record_path:
                    record_path = contained(workspace, artifact)
                    if record_path.is_file() and not record_path.is_symlink():
                        result = read_json(workspace, artifact)
                        if hashlib.sha256(canonical(result)).hexdigest() == index["recordSha256"] and type(result) is dict and set(result) == {"kind", "version", "pluginVersion", "contextSha256", "consentHash", "consentPolicyVersion", "questionSetVersion", "policyVersion", "checkpoint", "provider", "suggestedAction", "authority", "usage", "elapsedMs"} and result.get("contextSha256") == context["contextSha256"] and result.get("consentHash") == consent_hash and result.get("pluginVersion") == "0.3.0" and result.get("version") == 1 and result.get("consentPolicyVersion") == CONSENT_POLICY_VERSION and result.get("questionSetVersion") == QUESTION_SET_VERSION and result.get("policyVersion") == POLICY_VERSION and result.get("kind") == "img2.jev-checkpoint-advisory" and result.get("checkpoint") == context["checkpoint"] and result.get("authority") == "advisory-only" and result.get("suggestedAction") in _ACTIONS and type(result.get("elapsedMs")) is int and result["elapsedMs"] >= 0:
                            from jev_checkpoint_client import validate_response
                            require(type(result.get("provider")) is dict and set(result["provider"]) == {"status", "response"} and result["provider"]["status"] == "evaluated", "invalid cached provider result")
                            validate_response(result["provider"]["response"])
                            require(result["usage"] == result["provider"]["response"]["usage"], "cached token usage mismatch")
                            require(result["suggestedAction"] == suggested_action(result["provider"]["response"], context), "cached advisory is inconsistent")
                            validate_context(workspace, context)
                            current_consent = require_consent(workspace)
                            if current_consent.get("policyVersion") == CONSENT_POLICY_VERSION and hashlib.sha256(canonical(current_consent)).hexdigest() == consent_hash:
                                return {"status": "cached", "artifact": artifact, "contextSha256": context["contextSha256"], "suggestedAction": result["suggestedAction"], "authority": "advisory-only"}
        attempt_path = ARTIFACT_PREFIX + "attempts/" + cache_identity + ".json"
        attempt_file = contained(workspace, attempt_path)
        if attempt_file.exists():
            require(attempt_file.is_file() and not attempt_file.is_symlink(), "unsafe checkpoint attempt marker")
            attempt = read_json(workspace, attempt_path)
            require(type(attempt) is dict and set(attempt) == {"kind", "contextSha256", "consentHash", "consentPolicyVersion", "pluginVersion", "questionSetVersion", "policyVersion"} and attempt["kind"] == "img2.jev-checkpoint-attempt" and attempt["contextSha256"] == context["contextSha256"] and attempt["consentHash"] == consent_hash and attempt["consentPolicyVersion"] == CONSENT_POLICY_VERSION and attempt["pluginVersion"] == "0.3.0" and attempt["questionSetVersion"] == QUESTION_SET_VERSION and attempt["policyVersion"] == POLICY_VERSION, "invalid checkpoint attempt marker")
            return {"status": "not-consulted", "reasonCode": "already-attempted"}
        try:
            key = resolve_api_key()
        except CredentialError:
            return {"status": "not-consulted", "reasonCode": "credential-required"}
        if not isinstance(key, str) or not key.strip():
            return {"status": "not-consulted", "reasonCode": "credential-required"}
        validate_context(workspace, context)
        current_consent = require_consent(workspace)
        if current_consent.get("policyVersion") != CONSENT_POLICY_VERSION or hashlib.sha256(canonical(current_consent)).hexdigest() != consent_hash:
            return {"status": "not-consulted", "reasonCode": "consent-changed"}
        started = time.monotonic()
        safe_projection = validate_checkpoint_projection(projection(context))
        validate_context(workspace, context)
        current_consent = require_consent(workspace)
        if current_consent.get("policyVersion") != CONSENT_POLICY_VERSION or hashlib.sha256(canonical(current_consent)).hexdigest() != consent_hash:
            return {"status": "not-consulted", "reasonCode": "consent-changed"}
        from jev_contracts import write_artifact
        write_artifact(workspace, attempt_path, {"kind": "img2.jev-checkpoint-attempt", "contextSha256": context["contextSha256"], "consentHash": consent_hash, "consentPolicyVersion": CONSENT_POLICY_VERSION, "pluginVersion": "0.3.0", "questionSetVersion": QUESTION_SET_VERSION, "policyVersion": POLICY_VERSION})
        response = validate_checkpoint_response(evaluate_checkpoint_bounded(safe_projection, key, timeout=timeout))
        validate_context(workspace, context)
        current_consent = require_consent(workspace)
        if current_consent.get("policyVersion") != CONSENT_POLICY_VERSION or hashlib.sha256(canonical(current_consent)).hexdigest() != consent_hash:
            raise ContractError("workspace consent changed during consultation")
        action = suggested_action(response, context)
        require(action in _ACTIONS, "invalid advisory action")
        record = {"kind": "img2.jev-checkpoint-advisory", "version": 1, "pluginVersion": "0.3.0", "contextSha256": context["contextSha256"], "consentHash": consent_hash, "consentPolicyVersion": CONSENT_POLICY_VERSION, "questionSetVersion": QUESTION_SET_VERSION, "policyVersion": POLICY_VERSION, "checkpoint": context["checkpoint"], "provider": {"status": "evaluated", "response": response}, "suggestedAction": action, "authority": "advisory-only", "usage": response["usage"], "elapsedMs": round((time.monotonic() - started) * 1000)}
        record_hash = hashlib.sha256(canonical(record)).hexdigest()
        artifact = ARTIFACT_PREFIX + "records/" + record_hash + ".json"
        write_artifact(workspace, artifact, record)
        write_artifact(workspace, cache_path, {"kind": "img2.jev-checkpoint-cache", "recordPath": artifact, "recordSha256": record_hash})
        return {"status": "consulted", "artifact": artifact, "contextSha256": context["contextSha256"], "suggestedAction": action, "authority": "advisory-only"}
    finally:
        _release(fd)
