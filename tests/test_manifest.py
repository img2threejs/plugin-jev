import json
import unittest
from pathlib import Path


PLUGIN_DIR = Path(__file__).resolve().parent.parent


class ManifestContractTests(unittest.TestCase):
    def test_requires_img2_harness_025_for_img2_jev_command(self):
        manifest = json.loads((PLUGIN_DIR / "plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["requires"]["harness"], ">=0.2.5")
        from _harness import linked_harness
        with linked_harness():
            import jev
            import jev_checkpoint
        self.assertEqual(manifest["version"], jev.VERSION)
        self.assertEqual(manifest["version"], jev_checkpoint.PLUGIN_VERSION)
        self.assertNotEqual(manifest["version"], "0.3.0")
        self.assertIn({"from":"img2.jev-checkpoint-context","to":"img2.jev-checkpoint-advisory"}, manifest["capabilities"])


if __name__ == "__main__":
    unittest.main()
