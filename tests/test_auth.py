import importlib.util
import io
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


PLUGIN = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("jev_auth", PLUGIN / "tools" / "jev_auth.py")
assert _SPEC is not None and _SPEC.loader is not None
auth = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(auth)


class CredentialEnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.security = mock.patch.object(auth, "_security_path", return_value="/usr/bin/security")
        self.security.start()
        self.addCleanup(self.security.stop)

    def test_environment_override_takes_precedence_without_keychain_access(self):
        secret = "synthetic-jev-key-not-for-output"
        with mock.patch.object(auth.subprocess, "run") as run:
            self.assertEqual(auth.resolve_api_key({"TYPESAFE_API_KEY": secret}), secret)
        run.assert_not_called()

    def test_resolves_keychain_secret_without_echoing_or_logging_it(self):
        secret = "synthetic-jev-key-not-for-output"
        result = SimpleNamespace(returncode=0, stdout=secret + "\n")
        with mock.patch.object(auth.subprocess, "run", return_value=result) as run:
            self.assertEqual(auth.resolve_api_key({}), secret)
        argv = run.call_args.args[0]
        self.assertNotIn(secret, argv)
        self.assertTrue(run.call_args.kwargs["capture_output"])

    def test_login_uses_hidden_security_prompt_without_key_in_argv_or_output(self):
        secret = "synthetic-jev-key-not-for-output"
        stdin = SimpleNamespace(isatty=lambda: True)
        stdout = io.StringIO()
        with mock.patch.object(auth.sys, "stdin", stdin), \
             mock.patch.object(auth.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run, \
             mock.patch("sys.stdout", stdout):
            auth.login()
        argv = run.call_args.args[0]
        self.assertEqual(argv[-1], "-w")
        self.assertNotIn(secret, argv)
        self.assertNotIn(secret, stdout.getvalue())
        self.assertNotIn("input", run.call_args.kwargs)

    def test_login_requires_interactive_terminal(self):
        with mock.patch.object(auth.sys, "stdin", SimpleNamespace(isatty=lambda: False)), \
             mock.patch.object(auth.subprocess, "run") as run:
            with self.assertRaisesRegex(auth.CredentialError, "interactive terminal"):
                auth.login()
        run.assert_not_called()

    def test_keychain_read_failure_is_explicit_not_an_empty_key(self):
        for returncode, stdout in ((1, ""), (44, ""), (0, "\n")):
            with self.subTest(returncode=returncode, stdout=stdout), \
                 mock.patch.object(auth.subprocess, "run", return_value=SimpleNamespace(returncode=returncode, stdout=stdout)):
                with self.assertRaisesRegex(auth.CredentialError, "missing or could not be read"):
                    auth.resolve_api_key({})

    def test_keychain_denial_or_cancellation_is_an_explicit_failure(self):
        with mock.patch.object(auth.sys, "stdin", SimpleNamespace(isatty=lambda: True)), \
             mock.patch.object(auth.subprocess, "run", return_value=SimpleNamespace(returncode=1)):
            with self.assertRaisesRegex(auth.CredentialError, "denied or cancelled"):
                auth.login()

    def test_unsupported_secure_storage_fails_without_plaintext_fallback(self):
        self.security.stop()
        with mock.patch.object(auth.sys, "platform", "linux"), \
             mock.patch.object(auth.sys, "stdin", SimpleNamespace(isatty=lambda: True)), \
             mock.patch.object(auth.subprocess, "run") as run:
            with self.assertRaisesRegex(auth.CredentialError, "secure storage is unavailable"):
                auth.login()
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
