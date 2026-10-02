import json
import fcntl
import multiprocessing
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))
import jev_consent


def _consent_race_worker(role, workspace, enabled, lock_path, first_paused, release_first, events, mode):
    original_lock = jev_consent._lock_consent
    original_load = jev_consent._load
    original_store = jev_consent._store
    held_fd = None

    def observed_lock(path):
        nonlocal held_fd
        if role == "first":
            held_fd = original_lock(path)
            return held_fd

        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        probe_fd = os.open(lock_path, flags, 0o600)
        try:
            try:
                fcntl.flock(probe_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                result = "contended"
            else:
                result = "acquired"
                fcntl.flock(probe_fd, fcntl.LOCK_UN)
        finally:
            os.close(probe_fd)
        events.put(("probe", result))
        return original_lock(path)

    def observed_load(path):
        value = original_load(path)
        if role == "first" and mode == "early_unlock":
            fcntl.flock(held_fd, fcntl.LOCK_UN)
        return value

    def paused_store(path, value):
        if role == "first":
            first_paused.set()
            if not release_first.wait(20):
                raise RuntimeError("timed out waiting for parent to release first store")
        return original_store(path, value)

    try:
        with mock.patch.object(jev_consent, "_lock_consent", side_effect=observed_lock), \
                mock.patch.object(jev_consent, "_load", side_effect=observed_load), \
                mock.patch.object(jev_consent, "_store", side_effect=paused_store):
            jev_consent.set_consent(workspace, enabled)
        events.put(("done", role))
    except BaseException as error:
        events.put(("error", role, repr(error)))
        raise
class ConsentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="jev consent test ")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.home = self.base / "private-home"
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.copy = self.base / "workspace-copy"
        self.copy.mkdir()
        self.env = mock.patch.dict(os.environ, {"IMG2_HOME": str(self.home)})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_consent_is_external_and_bound_to_user_workspace_and_policy(self):
        granted = jev_consent.set_consent(self.workspace, True)
        binding = jev_consent.require_consent(self.workspace)
        consent_file = self.home / "config" / "jev-consent.json"
        stored = json.loads(consent_file.read_text(encoding="utf-8"))
        entry = stored["entries"][0]
        self.assertEqual(granted["policyVersion"], jev_consent.POLICY_VERSION)
        self.assertEqual(entry["policyVersion"], jev_consent.POLICY_VERSION)
        self.assertEqual(entry["user"], binding["user"])
        self.assertEqual(entry["workspace"], jev_consent.workspace_binding(self.workspace))
        self.assertTrue(entry["enabled"])
        self.assertEqual(consent_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(consent_file.parent.stat().st_mode & 0o777, 0o700)
        self.assertFalse((self.workspace / ".img2").exists())
        with mock.patch.object(jev_consent, "_user_binding", return_value="0" * 64):
            with self.assertRaises(jev_consent.ConsentError):
                jev_consent.require_consent(self.workspace)
        with self.assertRaises(jev_consent.ConsentError):
            jev_consent.require_consent(self.copy)

    def test_denial_and_revocation_block_workspace(self):
        with self.assertRaises(jev_consent.ConsentError):
            jev_consent.require_consent(self.workspace)
        jev_consent.set_consent(self.workspace, True)
        jev_consent.require_consent(self.workspace)
        jev_consent.set_consent(self.workspace, False)
        with self.assertRaises(jev_consent.ConsentError):
            jev_consent.require_consent(self.workspace)

    def test_canonical_path_change_does_not_inherit_consent(self):
        jev_consent.set_consent(self.workspace, True)
        moved = self.base / "moved-workspace"
        self.workspace.rename(moved)
        with self.assertRaises(jev_consent.ConsentError):
            jev_consent.require_consent(moved)

    def test_old_policy_consent_is_rejected_until_reauthorized(self):
        jev_consent.set_consent(self.workspace, True)
        consent_file = self.home / "config" / "jev-consent.json"
        stored = json.loads(consent_file.read_text(encoding="utf-8"))
        stored["entries"][0]["policyVersion"] = "jev-disclosure-old"
        consent_file.write_text(json.dumps(stored), encoding="utf-8")
        with self.assertRaises(jev_consent.ConsentError):
            jev_consent.require_consent(self.workspace)
        jev_consent.set_consent(self.workspace, True)
        jev_consent.require_consent(self.workspace)
        renewed = json.loads(consent_file.read_text(encoding="utf-8"))
        self.assertEqual(len(renewed["entries"]), 1)
        self.assertEqual(renewed["entries"][0]["policyVersion"], jev_consent.POLICY_VERSION)

    def _assert_updates_hold_lock_through_store(self, first_workspace, first_enabled, second_workspace, second_enabled, mode="normal"):
        context = multiprocessing.get_context("spawn")
        first_paused = context.Event()
        release_first = context.Event()
        events = context.Queue()
        lock_path = str(self.home / "config" / "jev-consent.json.lock")
        workers = [
            context.Process(
                target=_consent_race_worker,
                args=("first", str(first_workspace), first_enabled, lock_path, first_paused, release_first, events, mode),
            ),
            context.Process(
                target=_consent_race_worker,
                args=("second", str(second_workspace), second_enabled, lock_path, first_paused, release_first, events, mode),
            ),
        ]
        deadline = time.monotonic() + 15
        messages = []

        def receive(expected_kind):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError("timed out waiting for consent race worker event: " + expected_kind)
            try:
                message = events.get(timeout=remaining)
            except Exception as error:
                raise AssertionError("timed out waiting for consent race worker event: " + expected_kind) from error
            if message[0] == "error":
                raise AssertionError("consent race worker failed: " + repr(message))
            return message

        try:
            workers[0].start()
            if not first_paused.wait(max(0, deadline - time.monotonic())):
                raise AssertionError("first update did not pause inside _store")
            workers[1].start()
            probe = receive("real flock probe")
            self.assertEqual(probe, ("probe", "contended"), "competing update acquired lock while first store was paused")
            release_first.set()

            completed = set()
            while completed != {"first", "second"}:
                message = receive("serialized update completion")
                if message[0] == "probe":
                    self.assertEqual(message[1], "contended")
                elif message[0] == "done":
                    completed.add(message[1])
            for worker in workers:
                worker.join(max(0, deadline - time.monotonic()))
                self.assertFalse(worker.is_alive(), "consent race worker exceeded parent deadline")
                self.assertEqual(worker.exitcode, 0, "consent race worker exited unsuccessfully")
        finally:
            release_first.set()
            for worker in workers:
                if worker.pid is not None and worker.is_alive():
                    worker.terminate()
            for worker in workers:
                if worker.pid is not None:
                    worker.join(1)
            for worker in workers:
                if worker.pid is not None and worker.is_alive():
                    worker.kill()
            for worker in workers:
                if worker.pid is not None:
                    worker.join(1)
            survivors = [worker for worker in workers if worker.pid is not None and worker.is_alive()]
            events.cancel_join_thread()
            events.close()
            if survivors:
                raise AssertionError("consent race worker survived terminate and kill")
        stored = json.loads((self.home / "config" / "jev-consent.json").read_text(encoding="utf-8"))
        if first_workspace == second_workspace:
            self.assertEqual(len(stored["entries"]), 1)
            self.assertEqual(stored["entries"][0]["workspace"], jev_consent.workspace_binding(second_workspace))
            self.assertFalse(stored["entries"][0]["enabled"])
        else:
            self.assertEqual(len(stored["entries"]), 2)
            by_workspace = {entry["workspace"]: entry["enabled"] for entry in stored["entries"]}
            expected_by_workspace = {
                jev_consent.workspace_binding(first_workspace): first_enabled,
                jev_consent.workspace_binding(second_workspace): second_enabled,
            }
            self.assertEqual(by_workspace, expected_by_workspace)

    def test_concurrent_different_workspace_updates_preserve_revocation(self):
        first_workspace = self.base / "race-authorized-workspace"
        second_workspace = self.base / "race-revoked-workspace"
        first_workspace.mkdir()
        second_workspace.mkdir()
        jev_consent.set_consent(second_workspace, True)

        self._assert_updates_hold_lock_through_store(first_workspace, True, second_workspace, False)

    def test_same_workspace_authorize_then_revoke_keeps_later_update(self):
        self._assert_updates_hold_lock_through_store(self.workspace, True, self.workspace, False)
    def test_lock_probe_rejects_controlled_early_unlock(self):
        with self.assertRaisesRegex(AssertionError, "acquired lock while first store was paused"):
            self._assert_updates_hold_lock_through_store(
                self.workspace, True, self.workspace, False, mode="early_unlock"
            )

    def test_each_authorize_and_revoke_transition_rotates_generation(self):
        jev_consent.set_consent(self.workspace, True)
        first = jev_consent.require_consent(self.workspace)
        jev_consent.set_consent(self.workspace, False)
        with self.assertRaises(jev_consent.ConsentError):
            jev_consent.require_consent(self.workspace)
        jev_consent.set_consent(self.workspace, True)
        renewed = jev_consent.require_consent(self.workspace)
        self.assertNotEqual(first["generation"], renewed["generation"])
        self.assertEqual(len(renewed["generation"]), 32)
        stored = json.loads((self.home / "config" / "jev-consent.json").read_text(encoding="utf-8"))
        self.assertEqual(stored["entries"][0]["generation"], renewed["generation"])


if __name__ == "__main__":
    unittest.main()
