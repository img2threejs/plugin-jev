"""Strict Character material v1 facts; core owns native attestation and replay."""
import base64
import hashlib
import io
import json
import math

POLICY = "native-character-material-policy-v1"
QUESTIONS = "character-material-questions-v1"
MODE = "original-material-fixed-lighting-v1"
PIXELS = {"format": "RGBA8", "rawRowOrigin": "bottom-left", "pngRowOrigin": "top-left",
          "colorSpace": "srgb", "alphaMode": "straight"}
LIGHTING = {"importedLights": "hidden", "hemisphere": {"skyColor": 16777215, "groundColor": 4473924,
            "intensity": 1}, "directional": {"color": 16777215, "intensity": 3,
            "position": [3,5,4], "target": [0,0,0]}}
RENDERER = {"name": "threejs", "outputColorSpace": "srgb", "toneMapping": "none", "alpha": True,
            "antialias": False, "pixelRatio": 1, "clearColor": [0,0,0,0]}
MAX_FILE = 64 * 1024 * 1024


class MaterialEvidenceError(ValueError):
    pass


def _need(condition):
    if not condition:
        raise MaterialEvidenceError("invalid-material-evidence")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def is_material(context):
    observations = context.get("observations", {})
    subject = context.get("subject", {})
    if type(observations) is not dict or type(subject) is not dict:
        return False
    native = observations.get("nativeEvidence", {})
    return (subject.get("passId") == "character-terminal-review" or "characterMaterial" in observations
            or (type(native) is dict and native.get("provider") == "character")
            or context.get("policyVersion") == POLICY or context.get("questionSetVersion") == QUESTIONS)


def _exact(value, keys):
    _need(type(value) is dict and set(value) == set(keys))


def _number(value, low=-1e12, high=1e12):
    return type(value) in (int, float) and low <= value <= high and math.isfinite(value)


def _fixed(value, expected):
    if type(expected) is dict:
        _exact(value, expected)
        for key in expected:
            _fixed(value[key], expected[key])
    elif type(expected) is list:
        _need(type(value) is list and len(value) == len(expected))
        for item, template in zip(value, expected):
            _fixed(item, template)
    elif type(expected) in (int, float):
        _need(_number(value) and value == expected)
    else:
        _need(type(value) is type(expected) and value == expected)


def _ids(values, maximum=32):
    from jev_decision_questions import _identifier
    _need(type(values) is list and len(values) <= maximum and all(_identifier(item) for item in values))
    _need(len(set(values)) == len(values))


def physical_view(matrix):
    _need(type(matrix) is list and len(matrix) == 16 and all(_number(item) for item in matrix))
    _need(matrix[3] == matrix[7] == matrix[11] == 0 and matrix[15] == 1)
    _need(math.hypot(matrix[8], matrix[10]) > 1e-12)
    angle = math.degrees(math.atan2(matrix[8], matrix[10]))
    view = int(round(angle / 90)) % 4 * 90
    # Compare in the exact cardinal basis: converting to degrees first rounds
    # an on-boundary 1e-4 value upward. No epsilon or tolerance widening.
    x, z = matrix[8], matrix[10]
    dot, cross = ((z, x), (x, -z), (-z, -x), (-x, z))[view // 90]
    _need(dot > 0 and abs(cross) <= dot * math.tan(math.radians(1e-4)))
    return view


def validate_context(context):
    """Validate only bounded disclosed facts, never confer native authority."""
    from jev_decision_questions import _identifier, AXES, _review_items, _missing_evidence
    if not is_material(context):
        return None
    _need(context["group"] == "quality-review" and context["policyVersion"] == POLICY
          and context["questionSetVersion"] == QUESTIONS
          and context["subject"]["passId"] == "character-terminal-review")
    observations = context["observations"]
    native = observations.get("nativeEvidence")
    _need(type(native) is dict and native.get("provider") == "character")
    lane = observations.get("characterMaterial")
    _exact(lane, {"version", "mode", "provenance", "pixels", "renderer", "lighting", "configurationSha256",
                  "requiredParts", "criticalFeatures", "requiredVisualRoles", "coverage", "frames"})
    _need(type(lane["version"]) is int and lane["version"] == 1 and lane["mode"] == MODE)
    _fixed(lane["pixels"], PIXELS)
    renderer = lane["renderer"]
    _exact(renderer, set(RENDERER) | {"revision"})
    _need(_identifier(renderer["revision"]))
    _fixed({key: renderer[key] for key in RENDERER}, RENDERER)
    _fixed(lane["lighting"], LIGHTING)
    configuration = {key: lane[key] for key in ("pixels", "renderer", "lighting")}
    _need(lane["configurationSha256"] == hashlib.sha256(canonical(configuration)).hexdigest())
    bindings = context["bindings"]
    by_role = {item["role"]: item["sha256"] for item in bindings}
    _need(len(by_role) == len(bindings))
    categories = {"character-material-capture": "manifest"}
    _need("character-material-capture" in by_role)

    def reference(value, category):
        _exact(value, {"role", "sha256"})
        role = value["role"]
        _need(type(role) is str and role in by_role and value["sha256"] == by_role[role])
        _need(role not in categories or categories[role] == category)
        categories[role] = category
        return role

    _exact(lane["provenance"], {"candidate", "producer", "runtime"})
    provenance_roles = [reference(lane["provenance"][name], "provenance") for name in ("candidate", "producer", "runtime")]
    _need(len(set(provenance_roles)) == 3)
    _ids(lane["requiredParts"]); _ids(lane["criticalFeatures"])
    _ids(lane["requiredVisualRoles"])
    images = observations.get("images", [])
    image_roles = [item["role"] for item in images]
    _need(len(image_roles) == len(set(image_roles)) and set(image_roles) == set(lane["requiredVisualRoles"]))
    _need({"reference", "rest-render", "render"} <= set(image_roles))
    for role in image_roles:
        _need(role in by_role and role not in categories)
        categories[role] = "image"
    requirements = context["requirements"]
    items = _review_items(context)
    dimensions = [key for key, _ in items if key.startswith("dimension:")]
    _need(set(dimensions) == {"dimension:" + axis for axis in AXES[:5]} and len(dimensions) == 5)
    critical = {"part:" + item for item in lane["requiredParts"]} | {"feature:" + item for item in lane["criticalFeatures"]}
    _need({item["id"] for item in requirements.get("criticalFeatures", [])} == critical)
    for _, item in items:
        _need(not any(_missing_evidence(context, item).values()))
        _need(set(requirements.get("evidenceRoles", [])) | set(item.get("evidenceRoles", [])) <= set(image_roles))
    coverage = lane["coverage"]
    _exact(coverage, {"clipIds", "times", "physicalViews"})
    _ids(coverage["clipIds"])
    times = coverage["times"]
    _need(coverage["clipIds"] and type(times) is list and 4 <= len(times) <= 30
          and all(_number(time, 0, 1) for time in times) and len(set(times)) == len(times)
          and 0 in times and 1 in times)
    _fixed(coverage["physicalViews"], [0,90,180,270])
    _need(all(_number(view, 0, 270) and view in (0,90,180,270)
              for view in observations.get("availableViews", [])))
    _need(set(observations.get("availableViews", [])) == {0,90,180,270})
    expected = {(clip, time, view) for clip in coverage["clipIds"] for time in times for view in (0,90,180,270)}
    frames = lane["frames"]
    _need(type(frames) is list and 1 <= len(frames) <= 30 and len(frames) == len(expected))
    seen, raw_roles = set(), set()
    for index, frame in enumerate(frames):
        _exact(frame, {"index", "role", "sha256", "rgbaRole", "rgbaSha256", "width", "height", "clipId", "time",
                       "side", "azimuth", "camera", "roi"})
        _need(type(frame["index"]) is int and frame["index"] == index)
        _need(frame["role"] == ("render" if index == 0 else "domain-pose-" + str(index)))
        _need(frame["role"] in image_roles and by_role[frame["role"]] == frame["sha256"])
        role = reference({"role": frame["rgbaRole"], "sha256": frame["rgbaSha256"]}, "rgba")
        _need(role not in raw_roles); raw_roles.add(role)
        width, height = frame["width"], frame["height"]
        _need(type(width) is int and type(height) is int and width > 0 and height > 0 and width*height*4 <= MAX_FILE)
        _need(_identifier(frame["clipId"]) and _identifier(frame["side"]) and _number(frame["time"], 0, 1)
              and _number(frame["azimuth"], 0, 360) and frame["azimuth"] < 360)
        camera = frame["camera"]
        _exact(camera, {"role", "sha256", "projection", "matrixWorld", "projectionMatrix", "viewport"})
        reference({key: camera[key] for key in ("role", "sha256")}, "camera")
        projection = camera["projectionMatrix"]
        _need(type(projection) is list and len(projection) == 16 and all(_number(item) for item in projection))
        _need(projection[15] in (0,1) and projection[0] != 0 and projection[5] != 0)
        _need(camera["projection"] == ("orthographic" if projection[15] == 1 else "perspective"))
        _need(type(camera["viewport"]) is list and all(type(item) is int for item in camera["viewport"])
              and camera["viewport"] == [width,height])
        key = (frame["clipId"], frame["time"], physical_view(camera["matrixWorld"]))
        _need(key in expected and key not in seen); seen.add(key)
        roi = frame["roi"]
        _exact(roi, {"role", "sha256", "format", "rowOrigin"})
        _need(roi["format"] == "mask8" and roi["rowOrigin"] == "bottom-left")
        reference({key: roi[key] for key in ("role", "sha256")}, "roi")
    _need(seen == expected)
    return lane


def _json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result)
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(MaterialEvidenceError("invalid-material-evidence")))


def validate_files(context, read, assets=None):
    """read(role, cap) returns the same admitted/hash-verified source bytes."""
    from PIL import Image
    from jev_decision_images import prepare_image
    lane = validate_context(context)
    _need(lane is not None)
    _need(canonical(_json(read("character-material-capture", 256*1024))) == canonical(lane))
    by_image = {image["role"]: image["asset"] for image in context["observations"]["images"]}
    prepared = set()

    def verify_upload(role, source):
        if assets is None:
            return
        expected = prepare_image(io.BytesIO(source))
        actual = assets[by_image[role]]
        _need(all(actual[key] == expected[key] for key in ("format", "width", "height", "transform")))
        with Image.open(io.BytesIO(base64.b64decode(actual["data_base64"], validate=True))) as received, \
                Image.open(io.BytesIO(base64.b64decode(expected["data_base64"]))) as original:
            received.load(); original.load()
            _need(received.mode == original.mode == "RGB" and received.size == original.size
                  and received.tobytes() == original.tobytes())
        prepared.add(role)

    for frame in lane["frames"]:
        source = read(frame["role"], MAX_FILE)
        # Validate source RGBA before any white-background RGB preparation.
        _need(len(source) >= 29 and source[:8] == b"\x89PNG\r\n\x1a\n" and source[24] == 8 and source[25] in (2,6))
        with Image.open(io.BytesIO(source)) as image:
            _need(image.format == "PNG" and image.size == (frame["width"],frame["height"])
                  and getattr(image, "n_frames", 1) == 1 and set(image.info) <= {"srgb"}
                  and ("srgb" not in image.info or image.info["srgb"] == 0))
            image.verify()
        raw = read(frame["rgbaRole"], frame["width"]*frame["height"]*4)
        _need(len(raw) == frame["width"]*frame["height"]*4)
        with Image.open(io.BytesIO(source)) as image:
            image.load()
            _need(image.convert("RGBA").transpose(Image.Transpose.FLIP_TOP_BOTTOM).tobytes() == raw)
        roi = read(frame["roi"]["role"], frame["width"]*frame["height"])
        _need(len(roi) == frame["width"]*frame["height"] and set(roi) <= {0,1} and 1 in roi)
        camera = _json(read(frame["camera"]["role"], 256*1024))
        _exact(camera, {"glbSha256", "baselineGlbSha256", "clip", "time", "side", "azimuth", "matrixWorld", "projectionMatrix"})
        _need(camera["glbSha256"] == lane["provenance"]["candidate"]["sha256"])
        baseline = camera["baselineGlbSha256"]
        _need(type(baseline) is str and len(baseline) == 64 and all(char in "0123456789abcdef" for char in baseline))
        _need(type(camera["clip"]) is str and 0 < len(camera["clip"].encode()) <= 4096)
        _need(frame["clipId"] == "clip-" + hashlib.sha256(camera["clip"].encode()).hexdigest())
        for key in ("time", "side", "azimuth"):
            _fixed(camera[key], frame[key])
        for key in ("matrixWorld", "projectionMatrix"):
            _fixed(camera[key], frame["camera"][key])
        verify_upload(frame["role"], source)
    if assets is not None:
        for role in by_image.keys() - prepared:
            verify_upload(role, read(role, MAX_FILE))
