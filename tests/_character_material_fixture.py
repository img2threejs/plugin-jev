"""Owned synthetic protocol fixtures; never native/producer attestations."""
import hashlib
import io
import json
import math
from pathlib import Path

from jev_decision_images import prepare_image
from test_decision_questions import make_context


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def material_fixture(directory):
    from PIL import Image
    directory = Path(directory)
    context = make_context("quality-review")
    context["bindings"] = []
    context["candidates"] = []
    context["subject"]["passId"] = "character-terminal-review"
    context["policyVersion"] = "native-character-material-policy-v1"
    context["questionSetVersion"] = "character-material-questions-v1"
    context["observations"] = {"nativeEvidence": {"provider": "character"},
                               "availableViews": [0, 90, 180, 270], "images": []}
    context["requirements"] = {"requiredViews": [0, 90, 180, 270], "criticalFeatures": [
        {"id": "part:body"}, {"id": "feature:identity"}]}
    assets = {}

    def store(role, data):
        if not isinstance(data, bytes):
            data = canonical(data)
        path = "private/material/" + role + ".bin"
        destination = directory / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        record = {"role": role, "path": path, "sha256": hashlib.sha256(data).hexdigest()}
        context["bindings"].append(record)
        return {"role": role, "sha256": record["sha256"]}

    image = Image.new("RGBA", (5, 3))
    image.putdata([(20+row*30+column, 70, 160, 64+64*((row+column)%3))
                   for row in range(3) for column in range(5)])
    output = io.BytesIO(); image.save(output, format="PNG")
    png = output.getvalue()
    upright = image.tobytes()
    raw = b"".join(upright[row*20:(row+1)*20] for row in reversed(range(3)))

    def visual(role):
        record = store(role, png)
        asset = "image-" + role
        context["observations"]["images"].append({"role": role, "asset": asset})
        assets[asset] = prepare_image(directory / next(
            item["path"] for item in context["bindings"] if item["role"] == role))
        return record

    provenance = {key: store(key, ("owned-" + key + "-unit-bytes").encode())
                  for key in ("candidate", "producer", "runtime")}
    baseline = hashlib.sha256(b"owned-baseline-unit-bytes").hexdigest()
    visual("reference"); visual("rest-render")
    clip = "owned-clip"
    clip_id = "clip-" + hashlib.sha256(clip.encode()).hexdigest()
    frames = []
    for time in (0, 0.25, 0.5, 1):
        for angle in (0, 90, 180, 270):
            index = len(frames)
            role = "render" if index == 0 else "domain-pose-" + str(index)
            source = visual(role)
            theta = math.radians(angle)
            sine, cosine = math.sin(theta), math.cos(theta)
            matrix = [cosine,0,-sine,0,0,1,0,0,sine,0,cosine,0,3*sine,0,3*cosine,1]
            projection = [1,0,0,0,0,1,0,0,0,0,-0.1,0,0,0,0,1]
            side, azimuth = ("back" if angle >= 180 else "front"), angle % 180
            camera = store("camera-" + str(index), {
                "glbSha256": provenance["candidate"]["sha256"], "baselineGlbSha256": baseline,
                "clip": clip, "time": time, "side": side, "azimuth": azimuth,
                "matrixWorld": matrix, "projectionMatrix": projection})
            rgba = store("rgba-" + str(index), raw)
            roi = store("roi-" + str(index), b"\0"*5+b"\1"*5+b"\0"*5)
            frames.append({"index": index, "role": role, "sha256": source["sha256"],
                           "rgbaRole": rgba["role"], "rgbaSha256": rgba["sha256"],
                           "width": 5, "height": 3, "clipId": clip_id, "time": time,
                           "side": side, "azimuth": azimuth,
                           "camera": {**camera, "projection": "orthographic", "matrixWorld": matrix,
                                      "projectionMatrix": projection, "viewport": [5,3]},
                           "roi": {**roi, "format": "mask8", "rowOrigin": "bottom-left"}})
    pixels = {"format": "RGBA8", "rawRowOrigin": "bottom-left", "pngRowOrigin": "top-left",
              "colorSpace": "srgb", "alphaMode": "straight"}
    renderer = {"name": "threejs", "revision": "186", "outputColorSpace": "srgb", "toneMapping": "none",
                "alpha": True, "antialias": False, "pixelRatio": 1, "clearColor": [0,0,0,0]}
    lighting = {"importedLights": "hidden", "hemisphere": {"skyColor": 16777215, "groundColor": 4473924,
                 "intensity": 1}, "directional": {"color": 16777215, "intensity": 3,
                 "position": [3,5,4], "target": [0,0,0]}}
    lane = {"version": 1, "mode": "original-material-fixed-lighting-v1", "provenance": provenance,
            "pixels": pixels, "renderer": renderer, "lighting": lighting,
            "configurationSha256": hashlib.sha256(canonical({"pixels": pixels, "renderer": renderer,
                                                            "lighting": lighting})).hexdigest(),
            "requiredParts": ["body"], "criticalFeatures": ["identity"],
            "requiredVisualRoles": [item["role"] for item in context["observations"]["images"]],
            "coverage": {"clipIds": [clip_id], "times": [0,0.25,0.5,1], "physicalViews": [0,90,180,270]},
            "frames": frames}
    context["observations"]["characterMaterial"] = lane
    store("character-material-capture", lane)
    return context, assets


def rewrite_binding(directory, context, role, data):
    if not isinstance(data, bytes):
        data = canonical(data)
    binding = next(item for item in context["bindings"] if item["role"] == role)
    (Path(directory) / binding["path"]).write_bytes(data)
    binding["sha256"] = hashlib.sha256(data).hexdigest()
    return binding["sha256"]


def sync_manifest(directory, context):
    rewrite_binding(directory, context, "character-material-capture", context["observations"]["characterMaterial"])
