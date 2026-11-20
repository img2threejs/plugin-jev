"""Consent-bound, file-free adapter from decision contexts to TypeSafe.

The controller must admit evidence and obtain disclosure/paid-call consent
before invoking this module. ``assets`` is an explicitly prepared map keyed by
``observations.images[*].asset``; values may be image-module preparation records
or TypeSafe image assets. No paths are resolved, files opened, auth discovered,
or images prepared here. Only post_systemone performs network I/O.

Projection is an allowlist, not prose redaction: unknown fields and free text
are omitted, including filenames, paths, credentials and executable proposals.
Opaque controller ids and the enumerated structured vocabulary are the only
string data disclosed. The digest still covers the entire incoming context,
including any local fields supplied by the caller; it does not prove freshness.
"""

import base64
import binascii
import hashlib
import json

from jev_decision_questions import (
    DecisionQuestionError, _canonical, _context_digest, _identifier, _require,
    _missing_evidence, _review_items, build_questions, validate_answers,
)
from jev_decision_transport import post_systemone

# These are data-field names, never arbitrary user/provider map keys. Adding a
# field or controlled term is a disclosure-policy change and requires tests.
_ID_FIELDS = {
    "id", "label", "componentId", "featureId", "parentId", "candidateId",
    "routeId", "planId", "hypothesisId", "passId", "instanceOf", "asset",
}
_ID_LIST_FIELDS = {"componentIds", "featureIds", "dependencies", "prerequisites"}
_ENUM_FIELDS = {
    "operation", "operations", "representation", "topology", "projection",
    "geometry", "camera", "material", "materialFamily", "detailPriority",
    "articulation", "outputKind", "inputKind", "role", "scope", "passScope",
    "action", "domain", "status", "flatness", "tier", "direction",
    "targetMetric", "metric", "field", "fields", "specField", "sourceKind",
    "primitive", "tool", "kind", "type", "requiredViews", "availableViews",
}
_STRUCTURED_FIELDS = {
    "components", "deltas", "specDeltas", "tradeoffs", "expectedCosts", "costs",
    "measurements", "metrics", "evidence", "features", "failures", "defects",
    "gates", "gateResults", "criteria", "tolerances", "values", "value",
    "expected", "observed", "bounds", "dimensions", "position", "rotation",
    "scale", "pivot", "approxBox", "requiredViews", "availableViews", "views",
    "materialSource", "source", "provenance", "allowedFields", "allowedComponents",
    "geometry", "camera", "material", "articulation", "detailPriorities",
}
_NUMERIC_FIELDS = {
    "width", "height", "depth", "radius", "length", "thickness", "roughness",
    "metalness", "opacity", "x", "y", "z", "yaw", "pitch", "roll", "fov",
    "frontArea", "sideArea", "closed", "twoSided", "selfIntersectionCount",
    "partCoveragePassed", "silhouetteIoU", "interiorDifference", "orbitConsistency",
    "cost", "timeMs", "elapsedMs", "tokenCost", "minImprovement", "maxRegression",
    "score", "threshold", "count", "coverage", "locked", "required", "applicable",
    "min", "max", "expectedCost", "rigRequired", "placementRequired",
}
# This deliberately does not admit arbitrary natural-language strings. Candidate
# descriptions live in controlled structure, not an instructions channel.
_TERMS = {
    "flat", "volumetric", "3d-object", "rigged-3d", "3d-scene", "2d", "3d",
    "image", "mesh", "rig", "scene", "reference", "render", "camera", "gate",
    "source", "spec", "geometry", "material", "lighting", "placement",
    "input-evidence", "animation", "hierarchy", "topology", "silhouette",
    "silhouette-proportions", "part-relationships", "material-appearance",
    "identity-features", "critical", "important", "optional", "required",
    "pass", "fail", "uncertain", "unevaluated", "missing", "available", "admitted",
    "refine-spec", "refine-code", "request-input", "stop", "min", "max",
    "front", "rear", "back", "left", "right", "top", "bottom", "side",
    "orthographic", "perspective", "matched", "fixed", "lathe", "sweep",
    "extrude", "bevel", "subdivide", "loft", "boolean", "union", "difference",
    "intersection", "continuous-mesh", "parametric", "primitive", "plane",
    "box", "sphere", "cylinder", "cone", "torus", "capsule", "curve",
    "procedural", "pbr", "physical", "standard", "lambert", "matte", "glossy",
    "metal", "glass", "plastic", "wood", "fabric", "ceramic", "paint",
    "licensed", "user-provided", "reference-derived", "original", "none",
    "rigid", "skinned", "deformable", "articulated", "hinge", "pivot",
    "low", "medium", "high", "unlocked", "component", "object", "scene-container",
    "silhouetteIoU", "interiorDifference", "orbitConsistency", "selfIntersectionCount",
    "roughness", "metalness", "opacity", "width", "height", "depth", "radius",
    "geometry.parameters", "material.roughness", "material.metalness",
    "camera.projection", "camera.fov", "transform.position", "transform.rotation",
    "transform.scale",
}
_OMIT = object()


def _project_data(value, field=None):
    if type(value) is dict:
        result = {}
        for key, item in value.items():
            if key not in _ID_FIELDS | _ID_LIST_FIELDS | _ENUM_FIELDS | _STRUCTURED_FIELDS | _NUMERIC_FIELDS:
                continue
            projected = _project_data(item, key)
            if projected is not _OMIT:
                result[key] = projected
        return result
    if type(value) is list:
        result = []
        for item in value:
            projected = _project_data(item, field)
            if projected is not _OMIT:
                result.append(projected)
        return result
    if value is None or type(value) in (bool, int, float):
        return value
    if type(value) is str:
        if field in _ID_FIELDS | _ID_LIST_FIELDS and _identifier(value):
            return value
        if field in _ENUM_FIELDS | _STRUCTURED_FIELDS and value in _TERMS:
            return value
    return _OMIT


def _project_requirement(item):
    result = _project_data(item)
    # Evidence roles are opaque controller identifiers, not arbitrary prose.
    if "evidenceRoles" in item:
        result["evidenceRoles"] = list(item["evidenceRoles"])
    return result


def _project_state(context):
    requirements = context["requirements"]
    projected_requirements = _project_requirement(requirements)
    projected_requirements["criticalFeatures"] = [
        _project_requirement(feature) for feature in requirements.get("criticalFeatures", [])
    ]
    if "dimensions" in requirements:
        projected_requirements["dimensions"] = [
            item if isinstance(item, str) else _project_requirement(item)
            for item in requirements["dimensions"]
        ]
    decomposition = requirements.get("decomposition")
    if decomposition is not None:
        # The actual image placeholder occurs once, in observations.images.
        images = context["observations"]["images"]
        projected_requirements["decomposition"] = {
            "imageIndex": next(index for index, image in enumerate(images)
                               if image["asset"] == decomposition["image"]),
            "objects": [_project_data(obj) for obj in decomposition["objects"]],
        }
    observations = _project_data(context["observations"])
    observations["images"] = [dict(image) for image in context["observations"].get("images", [])]
    return {
        "kind": context["kind"], "version": context["version"],
        "group": context["group"], "subject": dict(context["subject"]),
        "bindings": [{"role": item["role"], "sha256": item["sha256"]}
                     for item in context["bindings"]],
        "candidates": [_project_data(item) for item in context["candidates"]],
        "observations": observations, "requirements": projected_requirements,
        "policyVersion": context["policyVersion"],
        "questionSetVersion": context["questionSetVersion"],
        "requestedModel": context["requestedModel"],
    }


def _prepare_assets(context, assets):
    expected = {image["asset"] for image in context["observations"].get("images", [])}
    if assets is None:
        assets = {}
    _require(type(assets) is dict and set(assets) == expected, "invalid-assets")
    result = {}
    for key, image in assets.items():
        _require(_identifier(key) and type(image) is dict, "invalid-assets")
        wire_keys = {"type", "format", "data_base64"}
        prepared_keys = {"format", "data_base64", "sha256", "width", "height", "transform"}
        _require(set(image) <= wire_keys or set(image) == prepared_keys, "invalid-assets")
        _require({"format", "data_base64"} <= set(image), "invalid-assets")
        _require(image.get("type", "image") == "image", "invalid-assets")
        _require(image["format"] in ("png", "jpg", "jpeg"), "invalid-assets")
        data = image["data_base64"]
        _require(type(data) is str and 0 < len(data) <= 32 * 1024 * 1024, "invalid-assets")
        try:
            decoded = base64.b64decode(data, validate=True)
        except (ValueError, binascii.Error):
            raise DecisionQuestionError("invalid-assets") from None
        _require(bool(decoded) and base64.b64encode(decoded).decode("ascii") == data, "invalid-assets")
        if "sha256" in image:
            _require(hashlib.sha256(decoded).hexdigest() == image["sha256"], "invalid-assets")
        result[key] = {"type": "image", "format": image["format"], "data_base64": data}
    return result


def evaluate_context(context, *, api_key, assets=None, timeout=15.0):
    """Consult the real transport using only explicitly prepared, consented data.

    Returns advisory evidence, never a canonical acceptance, execution plan or
    availability determination. Valid uncertain answers remain unchanged.
    Missing all review evidence is a local missing-evidence error, not an outage.
    """
    # Freeze input identity before constructing questions or calling untrusted I/O.
    snapshot = json.loads(_canonical(context))
    questions = build_questions(snapshot)
    if not questions:
        details = [{"assessment": key, **_missing_evidence(snapshot, item)}
                   for key, item in _review_items(snapshot)]
        raise DecisionQuestionError("missing-evidence", details=details)
    state = _project_state(snapshot)
    prepared = _prepare_assets(snapshot, assets)
    payload = {"model": snapshot["requestedModel"], "state": state, "questions": questions}
    if prepared:
        payload["assets"] = prepared
    # Even a misplaced credential in an otherwise opaque id must not be sent.
    _require(type(api_key) is str and bool(api_key), "invalid-credential")
    _require(api_key.encode("utf-8") not in _canonical(payload), "credential-in-context")
    response = post_systemone(payload, api_key, timeout=timeout)
    validated = validate_answers(snapshot, response)
    return {
        "kind": "img2.decision-advisory", "version": 1,
        "group": snapshot["group"], "subject": dict(snapshot["subject"]),
        "contextDigest": _context_digest(snapshot), "model": validated["model"],
        "answers": validated["answers"], "usage": validated["usage"],
    }
