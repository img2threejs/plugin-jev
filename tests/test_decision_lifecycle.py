"""Private synthetic stores only; no credentials, network or installed state."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import jev_consent as consent


class DecisionLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="jev-lifecycle-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.other = self.root / "other"
        self.other.mkdir()
        patch = mock.patch.dict(os.environ, {"IMG2_HOME": str(self.root / "home")})
        patch.start()
        self.addCleanup(patch.stop)

    def grant(self, workspace=None, run="run-1", budget=64000):
        return consent.set_decision_consent(workspace or self.workspace, run, budget,
                                           images=True, paid=True)

    def legacy(self):
        entry = {"user": consent._user_binding(), "workspace": consent.workspace_binding(self.workspace),
                 "runId": "run-1", "policyVersion": consent.DECISION_POLICY_VERSION,
                 "generation": "a" * 32, "enabled": False,
                 "purposes": list(consent.DECISION_PURPOSES),
                 "disclosures": list(consent.DECISION_DISCLOSURES), "tokenBudget": 128000}
        path = consent._decision_path(self.workspace)
        consent._store(path, {"kind": "img2.jev-decision-consents", "version": 4, "entries": [entry]})
        ledger = consent._decision_ledger_path(self.workspace, "run-1")
        consent._store(ledger, {"version": 1, "attempts": {
            "b" * 64: {"status": "in-flight", "chargedTokens": 64000, "resultSha256": None}}})
        return entry, ledger, ledger.read_bytes()

    def test_more_than_128_authorize_revoke_and_decline_cycles_preserve_old_spend(self):
        self.grant(budget=128000)
        with consent.decision_session(self.workspace, "run-1") as session:
            session.reserve("c" * 64)
        for index in range(130):
            run = "run-" + str(index + 2)
            self.grant(run=run)
            consent.revoke_decision_consent(self.workspace, run)
            consent.decline_decision_consent(self.workspace, "declined-" + run, 64000)
        self.grant(budget=128000)
        with consent.decision_session(self.workspace, "run-1") as session:
            self.assertEqual(session.previous("c" * 64)["chargedTokens"], 64000)
        with self.assertRaisesRegex(consent.DecisionConsentError, "invalid-budget"):
            self.grant(budget=64000)

    def test_another_workspace_can_dispatch_while_one_run_is_in_flight(self):
        self.grant()
        self.grant(self.other)
        finished = threading.Event()
        errors = []
        def independent():
            try:
                with consent.decision_session(self.other, "run-1") as session:
                    session.reserve("d" * 64)
            except Exception as error:
                errors.append(error)
            finally:
                finished.set()
        with consent.decision_session(self.workspace, "run-1"):
            thread = threading.Thread(target=independent)
            thread.start()
            proceeded = finished.wait(1)
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(proceeded, "unrelated workspace waited for an in-flight request")

    def test_explicit_migration_preserves_disabled_generation_budget_and_ledger(self):
        entry, ledger, original = self.legacy()
        status = consent.decision_consent_status(self.workspace, "run-1", include_declined=True)
        expected = hashlib.sha256(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(status, {"granted": False, "purposes": [], "sha256": expected, "tokenBudget": 128000})
        self.assertEqual(ledger.read_bytes(), original)
        self.assertEqual(json.loads(consent._decision_path(self.workspace).read_text())["version"], 5)
        with self.assertRaisesRegex(consent.DecisionConsentError, "invalid-budget"):
            self.grant(budget=64000)
        self.grant(budget=128000)
        with consent.decision_session(self.workspace, "run-1") as session:
            self.assertEqual(session.previous("b" * 64)["chargedTokens"], 64000)

    def test_interrupted_migration_is_not_a_new_empty_authority(self):
        entry, ledger, original = self.legacy()
        with mock.patch.object(consent, "_store", side_effect=OSError("synthetic interrupted store")):
            with self.assertRaises((OSError, consent.DecisionConsentError)):
                consent.decision_consent_status(self.workspace, "run-1", include_declined=True)
        self.assertEqual(ledger.read_bytes(), original)
        self.assertEqual(json.loads(consent._decision_path(self.workspace).read_text())["version"], 4)
        self.assertEqual(consent.decision_consent_status(self.workspace, "run-1", include_declined=True)["tokenBudget"], 128000)

    def test_corrupt_legacy_store_never_creates_a_fresh_grant(self):
        self.legacy()
        consent._decision_path(self.workspace).write_bytes(b"{")
        with self.assertRaisesRegex(consent.DecisionConsentError, "consent-storage-error"):
            self.grant()


    def test_retirement_preserves_budget_floor_and_spend_across_reenrollment(self):
        self.grant(budget=128000)
        with consent.decision_session(self.workspace, "run-1") as session:
            session.reserve("e" * 64)
        ledger = consent._decision_ledger_path(self.workspace, "run-1")
        original = ledger.read_bytes()
        consent.retire_decision_consent(self.workspace, "run-1")
        self.assertFalse(consent.decision_consent_status(
            self.workspace, "run-1", include_declined=True)["granted"])
        with self.assertRaisesRegex(consent.DecisionConsentError, "invalid-budget"):
            self.grant(budget=64000)
        self.grant(budget=128000)
        self.assertEqual(ledger.read_bytes(), original)

    def test_workspace_revocation_is_bounded_and_ordered_after_inflight_send(self):
        self.grant()
        started = threading.Event()
        errors = []
        def revoke():
            started.set()
            try:
                consent.revoke_decision_consent(self.workspace)
            except consent.DecisionConsentError as error:
                errors.append(error.reason_code)
        with consent.decision_session(self.workspace, "run-1") as session:
            session.reserve("f" * 64)
            thread = threading.Thread(target=revoke)
            thread.start()
            self.assertTrue(started.wait(1))
            thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, ["consent-busy"])
            session.recheck()
        consent.revoke_decision_consent(self.workspace)
        with self.assertRaisesRegex(consent.DecisionConsentError, "consent-declined"):
            with consent.decision_session(self.workspace, "run-1"):
                self.fail("revoked grant admitted another send")

    def test_crashed_process_leaves_durable_reservation_not_a_free_retry(self):
        import subprocess
        self.grant()
        code = ("import os,sys;sys.path.insert(0,sys.argv[1]);import jev_consent as c;"
                "s=c.decision_session(sys.argv[2],'run-1');a=s.__enter__();"
                "a.reserve('a'*64);os._exit(7)")
        process = subprocess.run([sys.executable, "-c", code,
                                  str(Path(consent.__file__).parent), str(self.workspace)], timeout=10)
        self.assertEqual(process.returncode, 7)
        with consent.decision_session(self.workspace, "run-1") as session:
            self.assertEqual(session.previous("a" * 64)["chargedTokens"], 64000)
            with self.assertRaisesRegex(consent.DecisionConsentError, "ambiguous-paid-attempt"):
                session.reserve("a" * 64)

    def test_publication_interruption_recovers_without_losing_legacy_authority(self):
        entry, ledger, original = self.legacy()
        store = consent._store
        legacy = consent._decision_path(self.workspace)
        def interrupted(path, value):
            if path == legacy and value.get("version") == 5:
                raise OSError("synthetic fence interruption")
            return store(path, value)
        with mock.patch.object(consent, "_store", side_effect=interrupted):
            with self.assertRaises(OSError):
                consent.decision_consent_status(self.workspace, "run-1", include_declined=True)
        self.assertEqual(ledger.read_bytes(), original)
        recovered = consent.decision_consent_status(self.workspace, "run-1", include_declined=True)
        self.assertFalse(recovered["granted"])
        self.assertEqual(recovered["tokenBudget"], entry["tokenBudget"])
        self.assertEqual(ledger.read_bytes(), original)


    def test_downgrade_or_missing_published_store_cannot_reset_spend(self):
        self.grant()
        with consent.decision_session(self.workspace, "run-1") as session:
            session.reserve("d" * 64)
        ledger = consent._decision_ledger_path(self.workspace, "run-1")
        original = ledger.read_bytes()
        root = consent._decision_root(self.workspace)
        root.rename(root.with_name("owned-test-quarantine"))
        with self.assertRaisesRegex(consent.DecisionConsentError, "consent-storage-error"):
            self.grant()
        self.assertEqual(ledger.read_bytes(), original)


    def test_noninteger_negative_or_oversized_ledger_charge_fails_closed(self):
        self.grant()
        ledger = consent._decision_ledger_path(self.workspace, "run-1")
        for charge in (-1, True, 1.5, "64000", 2**54 - 1):
            consent._store(ledger, {"version": 1, "attempts": {
                "b" * 64: {"status": "charged", "chargedTokens": charge, "resultSha256": None}}})
            with self.subTest(charge=charge), self.assertRaisesRegex(
                    consent.DecisionConsentError, "budget-storage-error"):
                with consent.decision_session(self.workspace, "run-1"):
                    self.fail("malformed ledger admitted")


if __name__ == "__main__":
    unittest.main()
