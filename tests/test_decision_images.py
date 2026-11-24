"""Verify actual encoded pixels and inverse transforms using disposable images."""

import base64
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

try:
    from PIL import Image
except ImportError:
    Image = None

_SPEC = importlib.util.spec_from_file_location(
    "decision_images_test", Path(__file__).resolve().parents[1] / "tools/jev_decision_images.py")
images = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(images)


class OptionalDependencyTests(unittest.TestCase):
    def test_missing_dependency_is_explicit_and_local(self):
        with mock.patch.dict("sys.modules", {"PIL": None}):
            with self.assertRaisesRegex(images.DecisionImageError, "dependency unavailable"):
                images.prepare_image("never-open-this-private-path")


@unittest.skipIf(Image is None, "install optional plugin requirements-decisions.txt to verify pixels")
class DecisionImageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="decision-image-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def save(self, size, name="source.png", color="red", **kwargs):
        path = self.root / name
        Image.new("RGB", size, color).save(path, **kwargs)
        return path

    def decode(self, prepared):
        data = base64.b64decode(prepared["data_base64"], validate=True)
        self.assertEqual(hashlib.sha256(data).hexdigest(), prepared["sha256"])
        image = Image.open(io.BytesIO(data))
        image.load()
        self.assertEqual(image.format, "PNG")
        self.assertEqual(image.size, (prepared["width"], prepared["height"]))
        self.assertEqual(len(image.getexif()), 0)
        self.assertNotIn("exif", image.info)
        self.assertNotIn("icc_profile", image.info)
        return image

    def assertBoxAlmostEqual(self, actual, expected):
        for a, b in zip(actual, expected):
            self.assertAlmostEqual(a, b, places=8)

    def test_small_crop_pads_without_distorting_pixels(self):
        result = images.prepare_image(self.save((120, 90)))
        sent = self.decode(result)
        self.assertEqual(sent.size, (280, 280))
        self.assertEqual(result["transform"], {
            "sourceWidth": 120, "sourceHeight": 90, "crop": [0, 0, 120, 90],
            "scaleX": 1, "scaleY": 1, "padX": 80, "padY": 95})
        self.assertEqual(sent.getpixel((79, 95)), (255, 255, 255))
        self.assertEqual(sent.getpixel((80, 95)), (255, 0, 0))
        self.assertEqual(sent.getpixel((199, 184)), (255, 0, 0))
        self.assertBoxAlmostEqual(images.map_box({
            "left": 80 / 280, "top": 95 / 280,
            "right": 200 / 280, "bottom": 185 / 280}, result["transform"]),
            [0, 0, 120, 90])

    def test_exif_six_rotates_actual_pixels_before_crop(self):
        path = self.root / "rotated.jpg"
        source = Image.new("RGB", (400, 300), "red")
        source.paste("blue", (200, 0, 400, 300))
        exif = Image.Exif()
        exif[274] = 6
        exif[270] = "private metadata"
        source.save(path, quality=100, subsampling=0, exif=exif)
        result = images.prepare_image(path)
        sent = self.decode(result)
        self.assertEqual(sent.size, (300, 400))
        self.assertEqual((result["transform"]["sourceWidth"],
                          result["transform"]["sourceHeight"]), (300, 400))
        self.assertGreater(sent.getpixel((150, 50))[0], 245)
        self.assertGreater(sent.getpixel((150, 350))[2], 245)
        cropped = images.prepare_image(path, crop={"box": [0, 200, 300, 400], "margin": 0})
        crop_pixels = self.decode(cropped)
        self.assertGreater(crop_pixels.getpixel((150, 140))[2], 245)
        self.assertBoxAlmostEqual(images.map_box([0, 40 / 280, 1, 240 / 280],
                                                cropped["transform"]), [0, 200, 300, 400])

    def test_default_margin_is_ten_percent_clipped_and_outward_rounded(self):
        path = self.save((500, 400))
        result = images.prepare_image(path, crop=[10, 10, 110, 90])
        self.assertEqual(result["transform"]["crop"], [0, 2, 120, 98])
        result = images.prepare_image(path, crop=[1, 1, 120, 90])
        self.assertEqual(result["transform"]["crop"], [0, 0, 132, 99])
        result = images.prepare_image(path, crop={"box": [10, 10, 110, 90], "margin": 0})
        self.assertEqual(result["transform"]["crop"], [10, 10, 110, 90])

    def test_oversize_panorama_preserves_shape_and_odd_padding_inverse(self):
        result = images.prepare_image(self.save((4000, 101)))
        sent = self.decode(result)
        self.assertEqual(sent.size, (1568, 280))
        transform = result["transform"]
        self.assertEqual(transform["padY"], 120)  # 40 content pixels, even padding.
        self.assertBoxAlmostEqual(images.map_box(
            [0.25, 130 / 280, 0.75, 150 / 280], transform),
            [1000, 25.25, 3000, 75.75])
        odd = images.prepare_image(self.save((501, 99), name="odd.png"))
        self.assertEqual(odd["transform"]["padY"], 90)
        self.assertBoxAlmostEqual(images.map_box(
            [0, 90 / 280, 1, 189 / 280], odd["transform"]), [0, 0, 501, 99])

    def test_nonzero_origin_scaled_crop_inverse(self):
        result = images.prepare_image(self.save((2500, 1000)),
                                      crop={"box": [200, 100, 2200, 900], "margin": 0})
        self.decode(result)
        self.assertBoxAlmostEqual(images.map_box([0.25, 0.25, 0.75, 0.75],
                                                result["transform"]), [700, 300, 1700, 700])

    def test_padding_is_clipped_and_padding_only_answer_is_rejected(self):
        result = images.prepare_image(self.save((120, 90)))
        self.assertBoxAlmostEqual(images.map_box([0, 0, 1, 1], result["transform"]),
                                  [0, 0, 120, 90])
        with self.assertRaises(images.DecisionImageError):
            images.map_box([0, 0, 0.1, 0.1], result["transform"])

    def test_invalid_crops_and_boxes_are_rejected_not_repaired(self):
        path = self.save((500, 400))
        for crop in ([0, 0, 0, 10], [-1, 0, 10, 10], [0, 0, 501, 400],
                     [True, 0, 10, 10], [0, 0, float("nan"), 10],
                     {"box": [0, 0, 10, 10], "margin": -0.1}):
            with self.subTest(crop=crop), self.assertRaises(images.DecisionImageError):
                images.prepare_image(path, crop=crop)
        transform = images.prepare_image(path)["transform"]
        for box in ([0.2, 0, 0.1, 1], [-0.1, 0, 1, 1], [0, 0, 1, 1.1],
                    [0, 0, float("inf"), 1], [False, 0, 1, 1],
                    {"left": 0, "top": 0, "right": 1, "bottom": 1, "extra": 1}):
            with self.subTest(box=box), self.assertRaises(images.DecisionImageError):
                images.map_box(box, transform)

    def test_alpha_is_composited_on_white(self):
        path = self.root / "alpha.png"
        Image.new("RGBA", (280, 280), (255, 0, 0, 0)).save(path)
        self.assertEqual(self.decode(images.prepare_image(path)).getpixel((20, 20)), (255, 255, 255))

    def test_animation_and_decode_failures_do_not_expose_paths(self):
        path = self.root / "private-animation.png"
        Image.new("RGB", (280, 280), "red").save(path, save_all=True,
            append_images=[Image.new("RGB", (280, 280), "blue")], duration=100, loop=0)
        with self.assertRaisesRegex(images.DecisionImageError, "animated"):
            images.prepare_image(path)
        missing = self.root / "private-name.jpg"
        with self.assertRaises(images.DecisionImageError) as caught:
            images.prepare_image(missing)
        self.assertNotIn(str(missing), str(caught.exception))

    def test_embedded_rgb_profile_is_converted_to_srgb_before_metadata_removal(self):
        from PIL import ImageCms
        # Owned synthetic RGB color space: exchange the red/blue primaries of
        # LittleCMS's generated profile, retaining a valid complete ICC record.
        profile = bytearray(ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes())
        tags = {}
        for index in range(int.from_bytes(profile[128:132], "big")):
            start = 132 + index * 12
            tags[bytes(profile[start:start + 4])] = (
                int.from_bytes(profile[start + 4:start + 8], "big"),
                int.from_bytes(profile[start + 8:start + 12], "big"))
        red, size = tags[b"rXYZ"]
        blue, blue_size = tags[b"bXYZ"]
        self.assertEqual(size, blue_size)
        profile[red:red + size], profile[blue:blue + size] = profile[blue:blue + size], profile[red:red + size]
        source_profile = ImageCms.ImageCmsProfile(io.BytesIO(profile))
        source = Image.new("RGB", (280, 280), (200, 70, 30))
        expected = ImageCms.profileToProfile(source, source_profile, ImageCms.createProfile("sRGB"),
                                             outputMode="RGB").getpixel((20, 20))
        self.assertNotEqual(expected, source.getpixel((20, 20)))
        path = self.root / "owned-color-space.png"
        source.save(path, icc_profile=bytes(profile))
        actual = self.decode(images.prepare_image(path)).getpixel((20, 20))
        for value, reference in zip(actual, expected):
            self.assertLessEqual(abs(value - reference), 1)
        source = source.convert("RGBA")
        source.putalpha(128)
        source.save(path, icc_profile=bytes(profile))
        actual = self.decode(images.prepare_image(path)).getpixel((20, 20))
        for value, reference in zip(actual, expected):
            composite = (reference * 128 + 255 * 127 + 127) // 255
            self.assertLessEqual(abs(value - composite), 1)

    def test_malformed_embedded_profile_is_refused_not_reinterpreted(self):
        path = self.save((280, 280), icc_profile=b"owned-invalid-profile")
        with self.assertRaises(images.DecisionImageError):
            images.prepare_image(path)



if __name__ == "__main__":
    unittest.main()
