"""Consent-gated local image preparation; coordinates use the EXIF-upright raster.

A crop is half-open [left, top, right, bottom] in upright source pixels. Lists
get a 10% object-size margin on each side; {"box": [...], "margin": 0} disables
it explicitly. The recorded crop includes the clipped, outward-rounded margin.
No image path, metadata or image bytes belong in a persisted decision receipt.
"""

import base64
import hashlib
import io
import math
import warnings


_MIN_SIDE = 280
_MAX_SIDE = 1568
_MAX_IMAGE_BYTES = 16 * 1024 * 1024


class DecisionImageError(ValueError):
    """A non-sensitive local preparation failure."""


def _finite(value):
    try:
        return (isinstance(value, (int, float)) and not isinstance(value, bool)
                and math.isfinite(value))
    except OverflowError:
        return False


def _crop_bounds(crop, width, height):
    if crop is None:
        return [0, 0, width, height]
    margin = 0.1
    if isinstance(crop, dict):
        if set(crop) != {"box", "margin"}:
            raise DecisionImageError("invalid crop")
        margin, crop = crop["margin"], crop["box"]
    if (not _finite(margin) or not 0 <= margin <= 1
            or not isinstance(crop, (list, tuple)) or len(crop) != 4
            or not all(_finite(v) for v in crop)):
        raise DecisionImageError("invalid crop")
    left, top, right, bottom = crop
    if not (0 <= left < right <= width and 0 <= top < bottom <= height):
        raise DecisionImageError("invalid crop")
    dx, dy = (right - left) * margin, (bottom - top) * margin
    return [max(0, math.floor(left - dx)), max(0, math.floor(top - dy)),
            min(width, math.ceil(right + dx)), min(height, math.ceil(bottom + dy))]


def prepare_image(path, *, crop=None):
    """Return metadata-free PNG plus the exact resize/pad inverse transform.

    Only this function imports optional Pillow. Small images are padded rather
    than stretched; large images are uniformly downscaled before padding.
    Caller owns consent and path/hash admission before invoking preparation.
    """
    try:
        from PIL import Image, ImageOps
    except ImportError:
        raise DecisionImageError("image dependency unavailable") from None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(path) as original:
                if getattr(original, "n_frames", 1) != 1:
                    raise DecisionImageError("animated image unsupported")
                upright = ImageOps.exif_transpose(original)
                width, height = upright.size
                bounds = _crop_bounds(crop, width, height)
                region = upright.crop(bounds).convert("RGBA")
        crop_width, crop_height = region.size
        ratio = min(1.0, _MAX_SIDE / crop_width, _MAX_SIDE / crop_height)
        scaled_width = max(1, min(_MAX_SIDE, round(crop_width * ratio)))
        scaled_height = max(1, min(_MAX_SIDE, round(crop_height * ratio)))
        if region.size != (scaled_width, scaled_height):
            region = region.resize((scaled_width, scaled_height), Image.Resampling.LANCZOS)
        output_width = max(_MIN_SIDE, scaled_width)
        output_height = max(_MIN_SIDE, scaled_height)
        pad_x = (output_width - scaled_width) // 2
        pad_y = (output_height - scaled_height) // 2
        # Alpha is composited over a known neutral background, not discarded.
        canvas = Image.new("RGB", (output_width, output_height), "white")
        canvas.paste(region, (pad_x, pad_y), region)
        # New canvas carries none of the source EXIF/comments/ICC/path metadata.
        output = io.BytesIO()
        canvas.save(output, format="PNG")
        data = output.getvalue()
        if len(data) > _MAX_IMAGE_BYTES:
            raise DecisionImageError("prepared image too large")
    except DecisionImageError:
        raise
    except Exception:
        raise DecisionImageError("image preparation failed") from None
    return {
        "format": "png", "data_base64": base64.b64encode(data).decode("ascii"),
        "sha256": hashlib.sha256(data).hexdigest(),
        "width": output_width, "height": output_height,
        "transform": {
            "sourceWidth": width, "sourceHeight": height, "crop": bounds,
            "scaleX": scaled_width / crop_width, "scaleY": scaled_height / crop_height,
            "padX": pad_x, "padY": pad_y,
        },
    }


def map_box(box, transform):
    """Invert normalized TypeSafe edges to upright source pixels without rounding.

    The output canvas is reconstructed exactly, including odd padding. Boxes
    touching padding are clipped to the crop. A padding-only box is rejected.
    """
    if isinstance(box, dict) and set(box) == {"left", "top", "right", "bottom"}:
        box = [box["left"], box["top"], box["right"], box["bottom"]]
    if (not isinstance(box, (list, tuple)) or len(box) != 4
            or not all(_finite(v) for v in box)
            or not (0 <= box[0] < box[2] <= 1 and 0 <= box[1] < box[3] <= 1)):
        raise DecisionImageError("invalid box")
    try:
        source_width, source_height = transform["sourceWidth"], transform["sourceHeight"]
        bounds = transform["crop"]
        sx, sy = transform["scaleX"], transform["scaleY"]
        px, py = transform["padX"], transform["padY"]
        values = [source_width, source_height, sx, sy, px, py]
        if (not all(_finite(v) for v in values) or sx <= 0 or sy <= 0
                or not isinstance(source_width, int) or not isinstance(source_height, int)
                or source_width <= 0 or source_height <= 0
                or px < 0 or py < 0 or px != int(px) or py != int(py)):
            raise ValueError
        bounds = _crop_bounds({"box": bounds, "margin": 0}, source_width, source_height)
        left, top, right, bottom = bounds
        scaled_width = round((right - left) * sx)
        scaled_height = round((bottom - top) * sy)
        width, height = max(_MIN_SIDE, scaled_width), max(_MIN_SIDE, scaled_height)
        if (not 1 <= scaled_width <= _MAX_SIDE or not 1 <= scaled_height <= _MAX_SIDE
                or px != (width - scaled_width) // 2 or py != (height - scaled_height) // 2):
            raise ValueError
        mapped = [max(left, min(right, left + (box[0] * width - px) / sx)),
                  max(top, min(bottom, top + (box[1] * height - py) / sy)),
                  max(left, min(right, left + (box[2] * width - px) / sx)),
                  max(top, min(bottom, top + (box[3] * height - py) / sy))]
        if mapped[0] >= mapped[2] or mapped[1] >= mapped[3]:
            raise ValueError
        return mapped
    except (KeyError, TypeError, ValueError, OverflowError):
        raise DecisionImageError("invalid image transform or padding-only box") from None
