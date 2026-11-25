import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

PLUGIN = Path(__file__).resolve().parent.parent
HARNESS = Path(os.environ.get("IMG2_HARNESS_DIR", PLUGIN.parent / "img2")).resolve()


def setUpModule():
    global temporary, previous_home, previous_path, transport
    temporary = tempfile.TemporaryDirectory(prefix="jev-transport-test-")
    home = Path(temporary.name)
    (home / "harness").symlink_to(HARNESS, target_is_directory=True)
    previous_home = os.environ.get("IMG2_HOME")
    previous_path = list(sys.path)
    os.environ["IMG2_HOME"] = str(home)
    sys.path.insert(0, str(PLUGIN / "tools"))
    spec = importlib.util.spec_from_file_location("jev_transport_test", PLUGIN / "tools/jev_transport.py")
    transport = importlib.util.module_from_spec(spec)
    from _harness import linked_harness
    with linked_harness():
        spec.loader.exec_module(transport)


def tearDownModule():
    sys.path[:] = previous_path
    if previous_home is None:
        os.environ.pop("IMG2_HOME", None)
    else:
        os.environ["IMG2_HOME"] = previous_home
    temporary.cleanup()


class TransportBoundsTests(unittest.TestCase):
    def run_child(self, code, timeout=2):
        return transport._run_worker([sys.executable, "-c", code], dict(os.environ), b"{}", timeout)

    def test_exact_stdout_limit_preserves_payload(self):
        payload = self.run_child("import sys; sys.stdin.buffer.read(); sys.stdout.buffer.write(b'x' * 131072)")
        self.assertEqual(payload, b"x" * 131072)

    def test_stdout_overflow_rejects_child(self):
        with self.assertRaises(transport.ProviderError):
            self.run_child("import os; os.write(1, b'x' * 131073)")

    def test_stderr_overflow_rejects_without_disclosing_content(self):
        with self.assertRaises(transport.ProviderError) as raised:
            self.run_child("import os; os.write(2, b'private-provider-data' * 65536)")
        self.assertNotIn("private-provider-data", str(raised.exception))

    def test_nonterminating_child_is_killed_on_deadline(self):
        started = time.monotonic()
        with self.assertRaises(transport.ProviderError):
            self.run_child("import time; time.sleep(10)", timeout=0.05)
        self.assertLess(time.monotonic() - started, 3)

    def test_failed_child_cannot_supply_success_payload(self):
        with self.assertRaises(transport.ProviderError):
            self.run_child("import sys; print('{}'); sys.exit(1)")


if __name__ == "__main__":
    unittest.main()
