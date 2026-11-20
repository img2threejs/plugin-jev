"""Offline v4 enrollment/CLI probes. No Keychain, network, or paid calls."""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock
import zlib

PLUGIN = Path(__file__).resolve().parents[1]
TOOLS = PLUGIN / "tools"
for path in (TOOLS, PLUGIN / "tests"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import jev_consent as consent
import jev_decision_provider as provider
from jev_decision_images import prepare_image
from jev_decision_transport import DecisionTransportError
from test_decision_questions import make_context, response_for

KEY = "offline-only-enrollment-credential"


class _WorkspaceFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="jev decision enrollment ")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.home = self.base / "private-home"
        patch = mock.patch.dict(os.environ, {"IMG2_HOME": str(self.home)})
        patch.start()
        self.addCleanup(patch.stop)

    def grant(self, budget=256000):
        return consent.set_decision_consent(self.workspace, "run-1", budget, images=True, paid=True)


class EnrollmentTests(_WorkspaceFixture):
    def test_v3_never_authorizes_v4_and_v4_does_not_change_v3(self):
        consent.set_consent(self.workspace, True)
        original = consent.require_consent(self.workspace)
        with self.assertRaisesRegex(consent.DecisionConsentError, "consent-required"):
            consent.decision_consent_status(self.workspace, "run-1")
        self.grant()
        self.assertEqual(consent.require_consent(self.workspace), original)
        self.assertEqual(consent.POLICY_VERSION, "jev-disclosure-v3")
        self.assertEqual(consent.DECISION_POLICY_VERSION, "jev-disclosure-v4")

    def test_disclosure_and_paid_authorization_are_both_required(self):
        for images, paid in ((False, False), (True, False), (False, True)):
            with self.subTest(images=images, paid=paid), self.assertRaisesRegex(
                    consent.DecisionConsentError, "consent-required"):
                consent.set_decision_consent(self.workspace, "run-1", 64000, images=images, paid=paid)
        for budget in (True, 0, -1, 1.5, None, 2**53):
            with self.subTest(budget=budget), self.assertRaises(consent.DecisionConsentError):
                self.grant(budget)

    def test_four_purposes_and_budget_bound_to_user_workspace_run(self):
        grant = self.grant(128000)
        self.assertEqual(set(grant), {"granted", "purposes", "sha256", "tokenBudget"})
        self.assertEqual(grant["purposes"], ["routing", "build-strategy", "quality-review", "repair"])
        self.assertEqual(grant["tokenBudget"], 128000)
        entry = json.loads(consent._decision_path(self.workspace).read_text())["entries"][0]
        self.assertEqual(entry["disclosures"], ["image", "reference", "render"])
        self.assertEqual(consent._decision_path(self.workspace).stat().st_mode & 0o777, 0o600)
        with self.assertRaises(consent.DecisionConsentError):
            consent.decision_consent_status(self.workspace, "run-2")
        elsewhere = self.base / "elsewhere"
        elsewhere.mkdir()
        with self.assertRaises(consent.DecisionConsentError):
            consent.decision_consent_status(elsewhere, "run-1")
        with mock.patch.object(consent, "_user_binding", return_value="0" * 64):
            with self.assertRaises(consent.DecisionConsentError):
                consent.decision_consent_status(self.workspace, "run-1")

    def test_revoke_and_reauthorize_rotate_generation_without_resetting_spend(self):
        old = self.grant(64000)
        with consent.decision_session(self.workspace, "run-1") as session:
            session.reserve("a" * 64)
        consent.revoke_decision_consent(self.workspace, "run-1")
        with self.assertRaisesRegex(consent.DecisionConsentError, "consent-declined"):
            consent.decision_consent_status(self.workspace, "run-1")
        renewed = self.grant(64000)
        self.assertNotEqual(old["sha256"], renewed["sha256"])
        with consent.decision_session(self.workspace, "run-1") as session:
            with self.assertRaisesRegex(consent.DecisionConsentError, "budget-exhausted"):
                session.reserve("b" * 64)
        self.grant(128000)
        with consent.decision_session(self.workspace, "run-1") as session:
            session.reserve("b" * 64)
        with self.assertRaisesRegex(consent.DecisionConsentError, "invalid-budget"):
            self.grant(64000)

    def test_one_durable_budget_across_all_group_requests_and_actual_usage(self):
        self.grant(64504)
        for index, group in enumerate(consent.DECISION_PURPOSES):
            with self.subTest(group=group), consent.decision_session(self.workspace, "run-1") as session:
                request = hashlib.sha256(group.encode()).hexdigest()
                session.reserve(request)
                session.account(request, {"input_tokens": 123, "output_tokens": 45})
                session.complete(request, str(index) * 64)
        ledger = consent._decision_ledger(consent._decision_ledger_path(self.workspace, "run-1"))
        self.assertEqual(sum(item["chargedTokens"] for item in ledger["attempts"].values()), 672)
        with consent.decision_session(self.workspace, "run-1") as session:
            with self.assertRaisesRegex(consent.DecisionConsentError, "budget-exhausted"):
                session.reserve("f" * 64)

    def test_interruption_retains_full_reservation_and_refuses_duplicate_send(self):
        self.grant(64000)
        with consent.decision_session(self.workspace, "run-1") as session:
            session.reserve("a" * 64)
        with consent.decision_session(self.workspace, "run-1") as resumed:
            self.assertEqual(resumed.previous("a" * 64)["chargedTokens"], 64000)
            with self.assertRaisesRegex(consent.DecisionConsentError, "ambiguous-paid-attempt"):
                resumed.reserve("a" * 64)
            with self.assertRaisesRegex(consent.DecisionConsentError, "budget-exhausted"):
                resumed.reserve("b" * 64)

    def test_provider_overage_is_recorded_without_reusable_advice(self):
        self.grant(64000)
        with consent.decision_session(self.workspace, "run-1") as session:
            session.reserve("a" * 64)
            with self.assertRaisesRegex(consent.DecisionConsentError, "provider-token-bound-exceeded"):
                session.account("a" * 64, {"input_tokens": 64000, "output_tokens": 1})
        ledger = consent._decision_ledger(consent._decision_ledger_path(self.workspace, "run-1"))
        self.assertEqual(ledger["attempts"]["a" * 64], {
            "status": "over-budget", "chargedTokens": 64001, "resultSha256": None})

    def test_symlinked_private_ledger_is_not_a_budget_reset(self):
        self.grant()
        ledger = consent._decision_ledger_path(self.workspace, "run-1")
        target = self.base / "missing-ledger"
        ledger.symlink_to(target)
        with self.assertRaises(consent.DecisionConsentError):
            with consent.decision_session(self.workspace, "run-1"):
                self.fail("unsafe private ledger admitted")

    def test_session_holds_the_same_lock_as_revocation_and_other_edges(self):
        import fcntl
        self.grant()
        lock_path = consent._decision_path(self.workspace).with_name("jev-decision-consent.json.lock")
        with consent.decision_session(self.workspace, "run-1"):
            descriptor = os.open(lock_path, os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(descriptor)

    def test_run_scoped_revocation_does_not_revoke_another_run(self):
        self.grant()
        consent.set_decision_consent(self.workspace, "run-2", 64000, images=True, paid=True)
        consent.revoke_decision_consent(self.workspace, "run-1")
        self.assertTrue(consent.decision_consent_status(self.workspace, "run-2")["granted"])
        with self.assertRaisesRegex(consent.DecisionConsentError, "consent-declined"):
            consent.decision_consent_status(self.workspace, "run-1")

    def test_declared_edges_have_matching_executable_steps(self):
        manifest = json.loads((PLUGIN / "plugin.json").read_text())
        steps = json.loads((PLUGIN / "steps.json").read_text())
        by_id = {step["id"]: step for step in steps}
        for group, stem in (("routing", "route"), ("build-strategy", "build-strategy"),
                            ("quality-review", "quality-review"), ("repair", "repair")):
            self.assertIn({"from": "img2." + stem + "-context", "to": "img2." + stem + "-advisory"},
                          manifest["capabilities"])
            step = by_id["jev-decision-" + group]
            self.assertEqual(step["actor"], "program")
            self.assertIn("tools/jev.py decision-" + group + " ", step["command"])
            self.assertIn("--input .img2/artifacts/jev/contexts/" + group + ".json", step["command"])


def png_bytes():
    def chunk(kind, payload):
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 280, 280, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress((b"\0" + b"\xff\xff\xff" * 280) * 280)) + chunk(b"IEND", b""))


class DecisionCliTests(_WorkspaceFixture):
    def setUp(self):
        super().setUp()
        harness = Path(os.environ.get("IMG2_HARNESS_DIR", PLUGIN.parent / "img2")).resolve()
        self.home.mkdir()
        (self.home / "harness").symlink_to(harness, target_is_directory=True)
        spec = importlib.util.spec_from_file_location("jev_decision_enrollment_cli", TOOLS / "jev.py")
        self.cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.cli)
        self.network = mock.patch.object(provider, "post_systemone", side_effect=AssertionError("unexpected network"))
        self.post = self.network.start()
        self.addCleanup(self.network.stop)
        self.auth = mock.patch.object(self.cli, "auth_status", return_value={"status": "present", "reasonCode": "credential-present"})
        self.auth_mock = self.auth.start()
        self.addCleanup(self.auth.stop)
        patch = mock.patch.object(self.cli, "resolve_api_key", return_value=KEY)
        self.key_mock = patch.start()
        self.addCleanup(patch.stop)
        self.context = make_context()
        for binding in self.context["bindings"]:
            path = self.workspace / binding["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(png_bytes())
            binding["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assets = {image["asset"]: prepare_image(self.workspace / next(
            item["path"] for item in self.context["bindings"] if item["role"] == image["role"]))
            for image in self.context["observations"]["images"]}
        self.write_inputs()

    def write_inputs(self, group="routing"):
        self.context["group"] = group
        self.context["kind"] = {"routing": "img2.route-context", "build-strategy": "img2.build-strategy-context",
                                "quality-review": "img2.quality-review-context", "repair": "img2.repair-context"}[group]
        from jev_decision_questions import QUESTION_SET_VERSIONS
        self.context["questionSetVersion"] = QUESTION_SET_VERSIONS[group]
        (self.workspace / "context.json").write_text(json.dumps(self.context))
        (self.workspace / "assets.json").write_text(json.dumps(self.assets))

    def invoke(self, group="routing", extra=()):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = self.cli.main(["decision-" + group, "--workspace", str(self.workspace),
                                  "--input", "context.json", "--assets", "assets.json", *extra])
        result = json.loads(output.getvalue())
        self.assertNotIn(KEY, output.getvalue())
        return code, result

    def test_v3_cli_never_reads_assets_or_resolves_credentials(self):
        consent.set_consent(self.workspace, True)
        with mock.patch.object(self.cli, "_decision_assets") as assets, \
                mock.patch.object(self.cli, "_decision_json", wraps=self.cli._decision_json) as reads:
            code, result = self.invoke()
        self.assertEqual((code, result["reasonCode"]), (2, "consent-required"))
        self.assertEqual(reads.call_count, 1)
        assets.assert_not_called()
        self.auth_mock.assert_not_called()
        self.key_mock.assert_not_called()
        self.post.assert_not_called()

    def test_missing_login_requests_user_and_stops_before_asset_read(self):
        self.grant()
        self.auth_mock.return_value = {"status": "missing", "reasonCode": "credential-missing"}
        with mock.patch.object(self.cli, "_decision_json", wraps=self.cli._decision_json) as reads:
            code, result = self.invoke()
        self.assertEqual((code, result["reasonCode"]), (2, "credential-missing"))
        self.assertEqual(result["requestedCommand"], "img2-jev login")
        self.assertEqual(reads.call_count, 1)
        self.key_mock.assert_not_called()
        self.post.assert_not_called()

    def test_storage_error_is_not_reported_as_missing_or_rejected(self):
        self.grant()
        self.auth_mock.return_value = {"status": "storage-error", "reasonCode": "credential-storage-error"}
        code, result = self.invoke()
        self.assertEqual((code, result["reasonCode"]), (2, "credential-storage-error"))
        self.post.assert_not_called()

    def test_four_commands_use_real_adapter_projection_and_completed_cache(self):
        self.grant()
        self.context["observations"].update(notes="private customer filename", path="/private/reference.png")
        for group in consent.DECISION_PURPOSES:
            self.write_inputs(group)
            self.post.side_effect = None
            self.post.return_value = response_for(self.context)
            before = self.post.call_count
            code, result = self.invoke(group)
            self.assertEqual((code, result["reasonCode"]), (0, "answered"))
            self.assertEqual(result["advisory"]["group"], group)
            projected = copy.deepcopy(self.context)
            projected["bindings"] = [{"role": item["role"], "sha256": item["sha256"]}
                                     for item in self.context["bindings"]]
            projected_digest = hashlib.sha256(json.dumps(
                projected, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                allow_nan=False).encode("utf-8")).hexdigest()
            original_digest = hashlib.sha256(json.dumps(
                self.context, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                allow_nan=False).encode("utf-8")).hexdigest()
            self.assertEqual(result["advisory"]["contextDigest"], projected_digest)
            self.assertNotEqual(result["advisory"]["contextDigest"], original_digest)
            self.assertTrue(all("path" in item for item in self.context["bindings"]))
            self.assertEqual(self.post.call_count, before + 1)
            payload, key = self.post.call_args.args
            self.assertEqual(key, KEY)
            self.assertNotIn("private", json.dumps(payload))
            self.assertEqual(set(payload["assets"]),
                             {image["asset"] for image in payload["state"]["observations"]["images"]})
            self.assertEqual(len(payload["assets"]), len(self.assets))
            self.assertEqual(self.post.call_args.kwargs["timeout"], 15.0)
            code, replay = self.invoke(group)
            self.assertEqual(code, 0)
            self.assertTrue(replay["cached"])
            self.assertEqual(replay["advisory"]["contextDigest"], projected_digest)
            self.assertEqual(self.post.call_count, before + 1)

    def test_projection_keeps_post_transport_local_binding_checks(self):
        self.grant()
        response = response_for(self.context)
        def changed_binding(_payload, _key, **_kwargs):
            reference = self.workspace / self.context["bindings"][0]["path"]
            reference.write_bytes(b"changed during provider consultation")
            return response
        self.post.side_effect = changed_binding
        code, result = self.invoke()
        self.assertEqual((code, result["reasonCode"]), (2, "stale-evidence"))
        self.post.assert_called_once()
        ledger = consent._decision_ledger(consent._decision_ledger_path(self.workspace, "run-1"))
        self.assertEqual(len(ledger["attempts"]), 1)
        attempt = next(iter(ledger["attempts"].values()))
        self.assertEqual(attempt["status"], "charged")
        self.assertEqual(attempt["chargedTokens"], 168)
        self.assertIsNone(attempt["resultSha256"])

    def test_rejected_credential_retains_reservation_and_does_not_silently_retry(self):
        self.grant(64000)
        self.post.side_effect = DecisionTransportError("credential-rejected")
        code, result = self.invoke()
        self.assertEqual((code, result["reasonCode"]), (2, "credential-rejected"))
        self.assertEqual(result["requestedCommand"], "img2-jev login")
        code, result = self.invoke()
        self.assertEqual((code, result["reasonCode"]), (2, "ambiguous-paid-attempt"))
        self.post.assert_called_once()
        self.write_inputs("repair")
        code, result = self.invoke("repair")
        self.assertEqual((code, result["reasonCode"]), (2, "budget-exhausted"))
        self.post.assert_called_once()

    def test_revoke_blocks_later_group_before_opening_image_assets(self):
        self.grant()
        self.post.side_effect = None
        self.post.return_value = response_for(self.context)
        self.assertEqual(self.invoke()[0], 0)
        consent.revoke_decision_consent(self.workspace)
        self.write_inputs("repair")
        with mock.patch.object(self.cli, "_decision_assets") as assets:
            code, result = self.invoke("repair")
        self.assertEqual((code, result["reasonCode"]), (2, "consent-declined"))
        assets.assert_not_called()
        self.post.assert_called_once()

    def test_changed_grant_before_transport_is_rechecked(self):
        self.grant()
        original = self.cli._decision_assets
        def changed(context, assets):
            result = original(context, assets)
            path = consent._decision_path(self.workspace)
            stored = json.loads(path.read_text())
            stored["entries"][0]["enabled"] = False
            consent._store(path, stored)
            return result
        with mock.patch.object(self.cli, "_decision_assets", side_effect=changed):
            code, result = self.invoke()
        self.assertEqual(code, 2)
        self.assertIn(result["reasonCode"], {"consent-declined", "consent-changed"})
        self.post.assert_not_called()

    def test_stale_or_symlinked_evidence_and_wrong_group_never_dispatch(self):
        self.grant()
        reference = self.workspace / self.context["bindings"][0]["path"]
        reference.write_bytes(b"changed")
        self.assertEqual(self.invoke()[1]["reasonCode"], "stale-evidence")
        reference.unlink()
        reference.symlink_to(self.workspace / self.context["bindings"][1]["path"])
        self.assertEqual(self.invoke()[0], 2)
        self.assertEqual(self.invoke("repair")[1]["reasonCode"], "context-fault")
        self.post.assert_not_called()

    def test_unprepared_or_tampered_images_and_unsafe_paths_never_dispatch(self):
        self.grant()
        original = copy.deepcopy(self.assets)
        key = next(iter(self.assets))
        for mutate in (lambda a: a[key].update(sha256="0" * 64),
                       lambda a: a[key].update(path="/private/arbitrary.png"),
                       lambda a: a[key].update(width=1)):
            self.assets = copy.deepcopy(original)
            mutate(self.assets)
            self.write_inputs()
            self.assertEqual(self.invoke()[1]["reasonCode"], "invalid-assets")
        for path in ("../assets.json", "/tmp/assets.json", "private/../assets.json"):
            self.assertEqual(self.invoke(extra=("--assets", path))[0], 2)
        self.post.assert_not_called()

    def test_authorize_cli_requires_both_acknowledgements_and_status_is_local(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = self.cli.main(["consent", "authorize-decisions", "--workspace", str(self.workspace),
                                  "--run-id", "run-1", "--token-budget", "128000"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["reasonCode"], "consent-required")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = self.cli.main(["consent", "authorize-decisions", "--workspace", str(self.workspace),
                                  "--run-id", "run-1", "--token-budget", "128000",
                                  "--accept-image-disclosure", "--accept-paid-calls"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["tokenBudget"], 128000)
        self.post.assert_not_called()
        self.key_mock.assert_not_called()

    def test_invalid_deadlines_never_read_assets_or_dispatch(self):
        self.grant()
        for timeout in ("0", "-1", "31", "nan", "inf"):
            with self.subTest(timeout=timeout), mock.patch.object(self.cli, "_decision_assets") as assets:
                code, result = self.invoke(extra=("--timeout", timeout))
                self.assertEqual((code, result["reasonCode"]), (2, "context-fault"))
                assets.assert_not_called()
        self.post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
