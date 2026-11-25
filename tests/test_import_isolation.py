"""The documented source-only test environment must not depend on import order."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class ImportIsolationTests(unittest.TestCase):
    def test_checkpoint_and_enrollment_run_in_both_orders_without_installed_home(self):
        root = Path(__file__).resolve().parents[1]
        harness = os.environ.get("IMG2_HARNESS_DIR", str(root.parent / "img2"))
        names = [
            "test_checkpoint.CheckpointTests.test_cli_consult_smoke_uses_separate_result_envelope",
            "test_decision_enrollment.DecisionCliTests.test_four_commands_use_real_adapter_projection_and_completed_cache",
        ]
        with tempfile.TemporaryDirectory(prefix="jev-import-order-") as home:
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": home,
                   "IMG2_HARNESS_DIR": harness, "PYTHONDONTWRITEBYTECODE": "1",
                   "PYTHONPATH": str(root / "tests")}
            for order in (names, list(reversed(names))):
                with self.subTest(first=order[0]):
                    result = subprocess.run([sys.executable, "-m", "unittest", "-v", *order],
                                            cwd=root, env=env, capture_output=True, text=True, timeout=20)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
