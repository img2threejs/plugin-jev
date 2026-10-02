"""Secure storage for the Jev TypeSafe API key on macOS."""

import os
import subprocess
import sys
from pathlib import Path


SERVICE = "ai.typesafe.api-key"
ACCOUNT = "jev"
_SECURITY = "/usr/bin/security"


class CredentialError(RuntimeError):
    """Credential storage is unavailable or could not complete securely."""


def _security_path():
    if sys.platform != "darwin" or not Path(_SECURITY).is_file():
        raise CredentialError("macOS Keychain secure storage is unavailable")
    return _SECURITY


def login():
    """Prompt the security utility to store a key without receiving it in argv."""
    if not sys.stdin.isatty():
        raise CredentialError("jev login requires an interactive terminal")
    security = _security_path()
    try:
        # With -w last, `security` prompts on the terminal without echoing the key.
        result = subprocess.run(
            [security, "add-generic-password", "-U", "-a", ACCOUNT, "-s", SERVICE, "-w"],
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise CredentialError("macOS Keychain could not store the credential") from None
    if result.returncode != 0:
        raise CredentialError("macOS Keychain denied or cancelled credential storage")


def resolve_api_key(environ=None):
    """Return the automation override or an enrolled key, without logging it."""
    environ = os.environ if environ is None else environ
    override = environ.get("TYPESAFE_API_KEY", "")
    if override.strip():
        return override
    security = _security_path()
    try:
        result = subprocess.run(
            [security, "find-generic-password", "-a", ACCOUNT, "-s", SERVICE, "-w"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        raise CredentialError("macOS Keychain could not read the credential") from None
    if result.returncode != 0:
        raise CredentialError("macOS Keychain credential is missing or could not be read")
    key = result.stdout.strip()
    if not key:
        raise CredentialError("macOS Keychain credential is missing or could not be read")
    return key
