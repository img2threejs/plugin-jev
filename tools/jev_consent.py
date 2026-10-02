"""User-owned Jev disclosure consent, never stored in a workspace artifact."""
import fcntl
import hashlib
import json
import os
import stat
import tempfile
import uuid
from pathlib import Path

POLICY_VERSION = "jev-disclosure-v3"


class ConsentError(ValueError):
    pass


def _user_binding():
    return hashlib.sha256((str(os.getuid()) + "\0" + str(Path.home().resolve())).encode()).hexdigest()


def workspace_binding(workspace):
    return hashlib.sha256(str(Path(workspace).resolve(strict=True)).encode("utf-8")).hexdigest()


def _config_path(workspace=None):
    home = os.environ.get("IMG2_HOME")
    if not home:
        raise ConsentError("IMG2_HOME is required for user-owned Jev consent")
    path = Path(home).expanduser().resolve() / "config" / "jev-consent.json"
    if workspace is not None:
        workspace = Path(workspace).resolve(strict=True)
        if path == workspace or workspace in path.parents:
            raise ConsentError("IMG2_HOME consent must be outside the shareable workspace")
    return path


def _load(path):
    if not path.exists():
        return {"kind": "img2.jev-user-consents", "version": 1, "entries": []}
    if path.is_symlink() or path.parent.is_symlink() or not path.is_file():
        raise ConsentError("unsafe Jev consent configuration path")
    info = path.stat()
    directory = path.parent.stat()
    if info.st_uid != os.getuid() or directory.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077 or stat.S_IMODE(directory.st_mode) & 0o077:
        raise ConsentError("Jev consent configuration must be private and user-owned")
    if info.st_size > 32768:
        raise ConsentError("Jev consent configuration exceeds 32KiB")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as error:
        raise ConsentError("invalid Jev consent configuration") from error
    if (not isinstance(value, dict) or set(value) != {"kind", "version", "entries"}
            or value["kind"] != "img2.jev-user-consents" or type(value["version"]) is not int
            or value["version"] != 1 or not isinstance(value["entries"], list) or len(value["entries"]) > 128):
        raise ConsentError("invalid Jev consent configuration shape")
    fields = {"user", "workspace", "policyVersion", "enabled"}
    for entry in value["entries"]:
        if (not isinstance(entry, dict) or set(entry) not in (fields, fields | {"generation"})
                or not isinstance(entry["user"], str) or len(entry["user"]) != 64
                or not isinstance(entry["workspace"], str) or len(entry["workspace"]) != 64
                or not isinstance(entry["policyVersion"], str) or not entry["policyVersion"] or len(entry["policyVersion"]) > 64 or type(entry["enabled"]) is not bool):
            raise ConsentError("invalid Jev consent entry")
        if "generation" in entry and (not isinstance(entry["generation"], str) or len(entry["generation"]) != 32 or any(ch not in "0123456789abcdef" for ch in entry["generation"])):
            raise ConsentError("invalid Jev consent generation")
    return value


def _store(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or path.parent.is_symlink():
        raise ConsentError("unsafe Jev consent configuration path")
    os.chmod(path.parent, 0o700)
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + chr(10)
    fd, temporary = tempfile.mkstemp(prefix=".jev-consent-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _lock_consent(path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink():
        raise ConsentError("unsafe Jev consent configuration path")
    os.chmod(path.parent, 0o700)
    lock_path = path.with_name(path.name + ".lock")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(lock_path, flags, 0o600)
    except OSError as error:
        raise ConsentError("unsafe Jev consent lock path") from error
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode):
            raise ConsentError("Jev consent lock must be a regular user-owned file")
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _unlock_consent(fd):
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def set_consent(workspace, enabled):
    if type(enabled) is not bool:
        raise ConsentError("consent state must be boolean")
    path = _config_path(workspace)
    fd = _lock_consent(path)
    try:
        value = _load(path)
        user, identity = _user_binding(), workspace_binding(workspace)
        entry = {"user": user, "workspace": identity, "policyVersion": POLICY_VERSION, "enabled": enabled, "generation": uuid.uuid4().hex}
        value["entries"] = [item for item in value["entries"] if not (item["user"] == user and item["workspace"] == identity)]
        if len(value["entries"]) >= 128:
            raise ConsentError("Jev consent workspace limit reached")
        value["entries"].append(entry)
        _store(path, value)
    finally:
        _unlock_consent(fd)
    return {"enabled": enabled, "policyVersion": POLICY_VERSION}


def require_consent(workspace):
    value = _load(_config_path(workspace))
    user, identity = _user_binding(), workspace_binding(workspace)
    for entry in value["entries"]:
        if entry["user"] == user and entry["workspace"] == identity and entry["policyVersion"] == POLICY_VERSION:
            if entry["enabled"] and "generation" in entry:
                return {"user": user, "workspace": identity, "policyVersion": POLICY_VERSION, "generation": entry["generation"]}
            break
    raise ConsentError("Jev workspace consent is absent or revoked")
