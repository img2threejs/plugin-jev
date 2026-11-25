"""User-owned Jev disclosure consent, never stored in a workspace artifact."""
import fcntl
import hashlib
import json
import os
import stat
import tempfile
import uuid
from pathlib import Path
from contextlib import contextmanager
import re
import shutil
import time

POLICY_VERSION = "jev-disclosure-v3"
DECISION_POLICY_VERSION = "jev-disclosure-v4"
DECISION_PURPOSES = ("routing", "build-strategy", "quality-review", "repair")
DECISION_DISCLOSURES = ("image", "reference", "render")
DECISION_REQUEST_TOKENS = 64000


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
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
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


class DecisionConsentError(ConsentError):
    def __init__(self, reason_code):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _decision_id(value):
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}", value) is None:
        raise DecisionConsentError("context-fault")
    return value


def _decision_path(workspace):
    # A separate store keeps v3 APIs, grants and historical advice unchanged.
    return _config_path(workspace).with_name("jev-decision-consent.json")


def _private_json(path, default, maximum):
    if not path.exists():
        if path.is_symlink():
            raise DecisionConsentError("consent-storage-error")
        return default
    if path.is_symlink() or path.parent.is_symlink():
        raise DecisionConsentError("consent-storage-error")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        raise DecisionConsentError("consent-storage-error") from None
    try:
        info, parent = os.fstat(fd), path.parent.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or parent.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077
                or stat.S_IMODE(parent.st_mode) & 0o077 or info.st_size > maximum):
            raise DecisionConsentError("consent-storage-error")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise DecisionConsentError("consent-storage-error")
        def pairs(items):
            result = {}
            for key, item in items:
                if key in result:
                    raise ValueError
                result[key] = item
            return result
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (OSError, ValueError, UnicodeError, RecursionError):
        raise DecisionConsentError("consent-storage-error") from None
    finally:
        os.close(fd)


def _validate_decision_entry(entry):
    fields = {"user", "workspace", "runId", "policyVersion", "generation", "enabled",
              "purposes", "disclosures", "tokenBudget"}
    if type(entry) is not dict or set(entry) != fields:
        raise DecisionConsentError("consent-storage-error")
    for field, size in (("user", 64), ("workspace", 64), ("generation", 32)):
        if type(entry[field]) is not str or re.fullmatch("[0-9a-f]{" + str(size) + "}", entry[field]) is None:
            raise DecisionConsentError("consent-storage-error")
    _decision_id(entry["runId"])
    if (entry["policyVersion"] != DECISION_POLICY_VERSION or type(entry["enabled"]) is not bool
            or entry["purposes"] != list(DECISION_PURPOSES)
            or entry["disclosures"] != list(DECISION_DISCLOSURES)
            or type(entry["tokenBudget"]) is not int or not 0 < entry["tokenBudget"] <= 2**53 - 1):
        raise DecisionConsentError("consent-storage-error")
    return entry


def _legacy_decision_entries(path):
    value = _private_json(path, {"kind": "img2.jev-decision-consents", "version": 4, "entries": []}, 128 * 1024)
    if (type(value) is not dict or set(value) != {"kind", "version", "entries"}
            or value["kind"] != "img2.jev-decision-consents" or type(value["version"]) is not int
            or value["version"] != 4 or type(value["entries"]) is not list or len(value["entries"]) > 128):
        raise DecisionConsentError("consent-storage-error")
    seen = set()
    for entry in value["entries"]:
        _validate_decision_entry(entry)
        key = (entry["user"], entry["workspace"], entry["runId"])
        if key in seen:
            raise DecisionConsentError("consent-storage-error")
        seen.add(key)
    return value


def _private_directory(path, *, create=False):
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077):
        raise DecisionConsentError("consent-storage-error")


@contextmanager
def _decision_lock(path, *, shared=False):
    """Contention is explicit and bounded below the provider bridge deadline."""
    _private_directory(path.parent, create=True)
    try:
        fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError:
        raise DecisionConsentError("consent-storage-error") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise DecisionConsentError("consent-storage-error")
        deadline = time.monotonic() + 2.0
        operation = (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB
        while True:
            try:
                fcntl.flock(fd, operation)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise DecisionConsentError("consent-busy") from None
                time.sleep(0.01)
        yield
    finally:
        _unlock_consent(fd)


def _workspace_key(user, identity):
    return hashlib.sha256((user + identity).encode()).hexdigest()


def _run_name(run_id):
    return "run-" + hashlib.sha256(run_id.encode()).hexdigest() + ".json"


def _run_record(entry, generation="0" * 32, *, retired=False):
    return {"version": 5, "entry": entry, "workspaceGeneration": generation, "retired": retired}


def _decision_root(workspace):
    """Publish the complete migration before fencing old binaries; one authority."""
    legacy = _decision_path(workspace)
    root = legacy.with_name("jev-decision-consents-v5")
    with _decision_lock(legacy.with_name(legacy.name + ".lock")):
        raw = _private_json(legacy, None, 128 * 1024)
        if root.exists() or root.is_symlink():
            _private_directory(root)
            marker = _private_json(root / "migration.json", None, 1024)
            if (type(marker) is not dict or set(marker) != {"version", "legacySha256"}
                    or type(marker["version"]) is not int or marker["version"] != 5
                    or type(marker["legacySha256"]) is not str
                    or re.fullmatch("[0-9a-f]{64}", marker["legacySha256"]) is None):
                raise DecisionConsentError("consent-storage-error")
            if raw != marker:
                # A crash between directory publication and the legacy fence is
                # recoverable only if the original authority is byte-equivalent.
                old = _legacy_decision_entries(legacy)
                if _consent_digest(old) != marker["legacySha256"]:
                    raise DecisionConsentError("consent-storage-error")
                _store(legacy, marker)
            return root
        old = _legacy_decision_entries(legacy)
        marker = {"version": 5, "legacySha256": _consent_digest(old)}
        stage = Path(tempfile.mkdtemp(prefix=".jev-decision-migration-", dir=legacy.parent))
        try:
            for entry in old["entries"]:
                directory = stage / _workspace_key(entry["user"], entry["workspace"])
                _store(directory / _run_name(entry["runId"]), _run_record(entry))
                # Ledgers stay at their one canonical identity/path, unchanged.
                ledger_id = hashlib.sha256((entry["user"] + entry["workspace"] + entry["runId"]).encode()).hexdigest()
                _decision_ledger(legacy.with_name("jev-decision-run-" + ledger_id + ".json"))
            _store(stage / "migration.json", marker)
            os.replace(stage, root)
            _store(legacy, marker)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
        return root


def _decision_workspace(workspace):
    directory = _decision_root(workspace) / _workspace_key(_user_binding(), workspace_binding(workspace))
    _private_directory(directory, create=True)
    return directory


def _decision_run_path(workspace, run_id):
    _decision_id(run_id)
    return _decision_workspace(workspace) / _run_name(run_id)


def _workspace_generation(directory):
    value = _private_json(directory / "workspace.json", {"generation": "0" * 32}, 1024)
    if (type(value) is not dict or set(value) != {"generation"} or type(value["generation"]) is not str
            or re.fullmatch("[0-9a-f]{32}", value["generation"]) is None):
        raise DecisionConsentError("consent-storage-error")
    return value["generation"]


def _read_run(path):
    value = _private_json(path, None, 4096)
    if value is None and not path.exists():
        return None
    if (type(value) is not dict or set(value) != {"version", "entry", "workspaceGeneration", "retired"}
            or type(value["version"]) is not int or value["version"] != 5
            or type(value["retired"]) is not bool or type(value["workspaceGeneration"]) is not str
            or re.fullmatch("[0-9a-f]{32}", value["workspaceGeneration"]) is None):
        raise DecisionConsentError("consent-storage-error")
    _validate_decision_entry(value["entry"])
    return value


def _decision_entry(workspace, run_id, *, include_declined=False):
    path = _decision_run_path(workspace, run_id)
    record = _read_run(path)
    if record is None:
        raise DecisionConsentError("consent-required")
    entry = dict(record["entry"])
    if (entry["user"], entry["workspace"], entry["runId"]) != (
            _user_binding(), workspace_binding(workspace), run_id):
        raise DecisionConsentError("consent-storage-error")
    epoch = _workspace_generation(path.parent)
    if record["workspaceGeneration"] != epoch or record["retired"]:
        entry.update(enabled=False, generation=hashlib.sha256(
            (entry["generation"] + epoch).encode()).hexdigest()[:32])
    if entry["enabled"] or include_declined:
        return entry
    raise DecisionConsentError("consent-declined")


def _consent_digest(entry):
    return hashlib.sha256(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def set_decision_consent(workspace, run_id, token_budget, *, images=False, paid=False):
    """Only an explicit user authorization command may call this enrollment API."""
    if images is not True or paid is not True:
        raise DecisionConsentError("consent-required")
    return _set_decision_consent(workspace, run_id, token_budget, enabled=True)


def decline_decision_consent(workspace, run_id, token_budget):
    """Record explicit Jev refusal, not image disclosure or paid-call approval."""
    return _set_decision_consent(workspace, run_id, token_budget, enabled=False)


def _set_decision_consent(workspace, run_id, token_budget, *, enabled):
    _decision_id(run_id)
    if type(token_budget) is not int or not 0 < token_budget <= 2**53 - 1:
        raise DecisionConsentError("invalid-budget")
    directory = _decision_workspace(workspace)
    path = directory / _run_name(run_id)
    with _decision_lock(directory / "workspace.lock", shared=True), _decision_lock(path.with_suffix(".lock")):
        record = _read_run(path)
        old = record["entry"] if record is not None else None
        user, identity = _user_binding(), workspace_binding(workspace)
        if old is not None:
            if (old["user"], old["workspace"], old["runId"]) != (user, identity, run_id):
                raise DecisionConsentError("consent-storage-error")
            if token_budget < old["tokenBudget"]:
                raise DecisionConsentError("invalid-budget")
        entry = {"user": user, "workspace": identity, "runId": run_id,
                 "policyVersion": DECISION_POLICY_VERSION, "generation": uuid.uuid4().hex,
                 "enabled": enabled, "purposes": list(DECISION_PURPOSES),
                 "disclosures": list(DECISION_DISCLOSURES), "tokenBudget": token_budget}
        _store(path, _run_record(entry, _workspace_generation(directory)))
    return decision_consent_status(workspace, run_id, include_declined=True)


def revoke_decision_consent(workspace, run_id=None):
    directory = _decision_workspace(workspace)
    if run_id is None:
        # One atomic epoch update revokes every existing run, even after a crash.
        with _decision_lock(directory / "workspace.lock"):
            _store(directory / "workspace.json", {"generation": uuid.uuid4().hex})
    else:
        path = directory / _run_name(_decision_id(run_id))
        with _decision_lock(directory / "workspace.lock", shared=True), _decision_lock(path.with_suffix(".lock")):
            record = _read_run(path)
            if record is not None:
                record["entry"].update(enabled=False, generation=uuid.uuid4().hex)
                _store(path, record)
    return {"granted": False, "policyVersion": DECISION_POLICY_VERSION}


def retire_decision_consent(workspace, run_id):
    """Explicit retirement keeps the grant ceiling and all historical spend."""
    path = _decision_run_path(workspace, run_id)
    with _decision_lock(path.parent / "workspace.lock", shared=True), _decision_lock(path.with_suffix(".lock")):
        record = _read_run(path)
        if record is None:
            raise DecisionConsentError("consent-required")
        record["entry"].update(enabled=False, generation=uuid.uuid4().hex)
        record["retired"] = True
        _store(path, record)
    return {"granted": False, "policyVersion": DECISION_POLICY_VERSION}


def decision_consent_status(workspace, run_id, *, include_declined=False):
    """Probe a live grant, optionally exposing an explicit refusal to the controller.

    The default remains fail-closed for provider callers and revoked grants.
    Disabled entries expose their private identity and ceiling, never purposes.
    """
    entry = _decision_entry(workspace, run_id, include_declined=include_declined)
    return {"granted": entry["enabled"], "purposes": list(entry["purposes"]) if entry["enabled"] else [],
            "sha256": _consent_digest(entry), "tokenBudget": entry["tokenBudget"]}


def _decision_ledger_path(workspace, run_id):
    identity = hashlib.sha256((_user_binding() + workspace_binding(workspace) + run_id).encode()).hexdigest()
    return _decision_path(workspace).with_name("jev-decision-run-" + identity + ".json")


def _decision_ledger(path):
    ledger = _private_json(path, {"version": 1, "attempts": {}}, 256 * 1024)
    if (type(ledger) is not dict or set(ledger) != {"version", "attempts"}
            or type(ledger["version"]) is not int or ledger["version"] != 1
            or type(ledger["attempts"]) is not dict or len(ledger["attempts"]) > 256):
        raise DecisionConsentError("budget-storage-error")
    for key, attempt in ledger["attempts"].items():
        if (type(key) is not str or re.fullmatch("[0-9a-f]{64}", key) is None
                or type(attempt) is not dict or set(attempt) != {"status", "chargedTokens", "resultSha256"}
                or attempt["status"] not in ("in-flight", "charged", "completed", "over-budget", "rejected")
                or type(attempt["chargedTokens"]) is not int or not 0 <= attempt["chargedTokens"] <= 2**54 - 2
                or (attempt["status"] == "in-flight" and attempt["chargedTokens"] != DECISION_REQUEST_TOKENS)
                or (attempt["status"] in ("charged", "completed") and attempt["chargedTokens"] > DECISION_REQUEST_TOKENS)
                or (attempt["status"] == "rejected" and attempt["chargedTokens"] != 0)
                or (attempt["status"] == "over-budget" and attempt["chargedTokens"] <= DECISION_REQUEST_TOKENS)
                or (attempt["status"] != "completed" and attempt["resultSha256"] is not None)
                or (attempt["status"] == "completed" and
                    (type(attempt["resultSha256"]) is not str or re.fullmatch("[0-9a-f]{64}", attempt["resultSha256"]) is None))):
            raise DecisionConsentError("budget-storage-error")
    return ledger


class _DecisionSession:
    def __init__(self, workspace, run_id, entry):
        self.workspace, self.run_id, self.entry = workspace, run_id, entry
        self.path = _decision_ledger_path(workspace, run_id)
        self.ledger = _decision_ledger(self.path)

    def recheck(self):
        if _decision_entry(self.workspace, self.run_id) != self.entry:
            raise DecisionConsentError("consent-changed")

    def previous(self, request_digest):
        return self.ledger["attempts"].get(request_digest)

    def reserve(self, request_digest):
        self.recheck()
        if type(request_digest) is not str or re.fullmatch("[0-9a-f]{64}", request_digest) is None:
            raise DecisionConsentError("context-fault")
        if (request_digest in self.ledger["attempts"]
                and self.ledger["attempts"][request_digest]["status"] != "rejected"):
            raise DecisionConsentError("ambiguous-paid-attempt")
        spent = sum(item["chargedTokens"] for item in self.ledger["attempts"].values())
        if spent + DECISION_REQUEST_TOKENS > self.entry["tokenBudget"]:
            raise DecisionConsentError("budget-exhausted")
        if request_digest not in self.ledger["attempts"] and len(self.ledger["attempts"]) >= 256:
            raise DecisionConsentError("budget-storage-error")
        self.ledger["attempts"][request_digest] = {
            "status": "in-flight", "chargedTokens": DECISION_REQUEST_TOKENS, "resultSha256": None}
        _store(self.path, self.ledger)

    def reject(self, request_digest):
        """Only a definite 401/403 for the current reserved attempt is releasable."""
        attempt = self.ledger["attempts"].get(request_digest)
        if attempt is None or attempt["status"] != "in-flight":
            raise DecisionConsentError("budget-storage-error")
        attempt.update(status="rejected", chargedTokens=0, resultSha256=None)
        _store(self.path, self.ledger)

    def account(self, request_digest, usage):
        self.recheck()
        # Successful wire responses are accounted even if local freshness fails.
        if (type(usage) is not dict or set(usage) != {"input_tokens", "output_tokens"}
                or any(type(value) is not int or not 0 <= value <= 2**53 - 1 for value in usage.values())):
            raise DecisionConsentError("invalid-usage")
        total = usage["input_tokens"] + usage["output_tokens"]
        self.ledger["attempts"][request_digest] = {
            "status": "over-budget" if total > DECISION_REQUEST_TOKENS else "charged",
            "chargedTokens": total, "resultSha256": None}
        _store(self.path, self.ledger)
        if total > DECISION_REQUEST_TOKENS:
            raise DecisionConsentError("provider-token-bound-exceeded")

    def complete(self, request_digest, result_sha256):
        self.recheck()
        attempt = self.ledger["attempts"][request_digest]
        if attempt["status"] != "charged":
            raise DecisionConsentError("budget-storage-error")
        attempt.update(status="completed", resultSha256=result_sha256)
        _store(self.path, self.ledger)


@contextmanager
def decision_session(workspace, run_id):
    """Serialize one run and order workspace revocation without blocking other workspaces."""
    path = _decision_run_path(workspace, run_id)
    with _decision_lock(path.parent / "workspace.lock", shared=True), _decision_lock(path.with_suffix(".lock")):
        yield _DecisionSession(workspace, run_id, _decision_entry(workspace, run_id))
