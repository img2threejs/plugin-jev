"""Local-only credential status tests; no Keychain or provider access."""

import importlib.util
import io
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock


_SPEC = importlib.util.spec_from_file_location(
    "decision_auth_test", Path(__file__).resolve().parents[1] / "tools/jev_auth.py")
auth = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(auth)
_SECRET = "synthetic-private-api-key"


class AuthStatusTests(unittest.TestCase):
    def setUp(self):
        patch = mock.patch.object(auth, "_security_path", return_value="/usr/bin/security")
        patch.start()
        self.addCleanup(patch.stop)

    def test_override_is_present_without_storage_or_secret_output(self):
        with mock.patch.object(auth.subprocess, "run") as run:
            result = auth.auth_status({"TYPESAFE_API_KEY": _SECRET})
        self.assertEqual(result, {"status": "present", "reasonCode": "credential-present"})
        self.assertNotIn(_SECRET, json.dumps(result))
        run.assert_not_called()

    def test_enrolled_key_is_present_without_logging_it(self):
        output = io.StringIO()
        with mock.patch.object(auth.subprocess, "run", return_value=SimpleNamespace(
                returncode=0, stdout=_SECRET + "\n", stderr=_SECRET)) as run, \
                mock.patch("sys.stdout", output), mock.patch("sys.stderr", output):
            result = auth.auth_status({})
        self.assertEqual(result["status"], "present")
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn(_SECRET, repr(result))
        self.assertNotIn(_SECRET, repr(run.call_args))
        self.assertTrue(run.call_args.kwargs["capture_output"])
        self.assertEqual(run.call_args.kwargs["timeout"], 10)

    def test_only_item_not_found_is_missing(self):
        for code, expected in ((44, "missing"), (1, "storage-error"),
                               (36, "storage-error"), (128, "storage-error")):
            with self.subTest(code=code), mock.patch.object(auth.subprocess, "run",
                    return_value=SimpleNamespace(returncode=code, stdout="", stderr=_SECRET)):
                result = auth.auth_status({"TYPESAFE_API_KEY": "  "})
                self.assertEqual(result["status"], expected)
                self.assertNotIn(_SECRET, repr(result))

    def test_empty_enrollment_is_storage_error_not_missing_or_present(self):
        with mock.patch.object(auth.subprocess, "run", return_value=SimpleNamespace(
                returncode=0, stdout=" \n")):
            self.assertEqual(auth.auth_status({})["reasonCode"], "credential-storage-error")

    def test_read_failures_are_sanitized_storage_errors(self):
        failures = (OSError(_SECRET), subprocess.TimeoutExpired(_SECRET, 10),
                    UnicodeDecodeError("utf-8", b"\xff", 0, 1, _SECRET))
        for failure in failures:
            with self.subTest(error=type(failure)), mock.patch.object(
                    auth.subprocess, "run", side_effect=failure):
                result = auth.auth_status({})
                self.assertEqual(result, {"status": "storage-error",
                                          "reasonCode": "credential-storage-error"})
                self.assertNotIn(_SECRET, repr(result))

    def test_unsupported_storage_is_error_without_subprocess(self):
        with mock.patch.object(auth, "_security_path", side_effect=auth.CredentialError(_SECRET)), \
                mock.patch.object(auth.subprocess, "run") as run:
            self.assertEqual(auth.auth_status({})["status"], "storage-error")
        run.assert_not_called()

    def test_old_resolver_still_returns_override_and_raises_for_absent_key(self):
        self.assertEqual(auth.resolve_api_key({"TYPESAFE_API_KEY": _SECRET}), _SECRET)
        with mock.patch.object(auth.subprocess, "run", return_value=SimpleNamespace(
                returncode=44, stdout="")):
            with self.assertRaises(auth.CredentialError):
                auth.resolve_api_key({})


if __name__ == "__main__":
    unittest.main()
