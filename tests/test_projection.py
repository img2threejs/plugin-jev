import copy
import hashlib
import json
import unittest
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parent.parent
from _harness import linked_harness

projection = None
contracts = None


def setUpModule():
    global projection, contracts
    with linked_harness():
        import jev_contracts as contracts_module
        import jev_projection as projection_module
    contracts = contracts_module
    projection = projection_module


class ProjectionTests(unittest.TestCase):
    def state(self):
        observation = json.loads((PLUGIN_DIR / "examples" / "observation.json").read_text(encoding="utf-8"))
        return copy.deepcopy(observation["state"])

    def state_at_v2_collection_limits(self, statement):
        state = self.state()
        facts = state["evidence"]["facts"]
        fact_id = facts[0]["id"]
        for fact in facts:
            fact["statement"] = statement
        while len(facts) < 16:
            index = len(facts)
            facts.append({"id": f"size-evidence-{index:02d}", "source": "vision", "kind": "observation", "statement": statement})
        implementations = state["specification"]["implementationFacts"]
        for fact in implementations:
            fact["statement"] = statement
        while len(implementations) < 12:
            index = len(implementations)
            implementations.append({"id": f"size-implementation-{index:02d}", "source": "implementation", "kind": "observation", "statement": statement})
        feature_ids = [f"size-feature-{index:02d}" for index in range(12)]
        state["focus"]["requiredFeatureIds"] = feature_ids
        state["specification"]["requirements"] = [
            {"featureId": feature_id, "statement": statement, "evidenceIds": [fact_id]}
            for feature_id in feature_ids
        ]
        return state

    def test_projection_preserves_safe_decision_text_and_pseudonymizes_ids(self):
        projected = projection.project_state(self.state())
        encoded = contracts.canonical(projected).decode("utf-8")
        component_id = projected["components"][0]["id"]
        evidence_id = projected["evidence"]["facts"][0]["id"]
        self.assertRegex(component_id, r"c[1-9][0-9]*")
        self.assertRegex(evidence_id, r"e[1-9][0-9]*")
        self.assertIn("c1 renders glossy instead of matte", encoded)
        self.assertIn("matte c1", encoded)
        self.assertIn("roughness is 0.1", encoded)
        self.assertNotIn('"jacket"', encoded)
        self.assertNotIn('"spec-finish"', encoded)
        self.assertNotIn('"impl-finish"', encoded)
        self.assertEqual(projected["schemaVersion"], "repair-state-v2")
        self.assertEqual(projected["sceneKind"], "room")
        self.assertEqual([gate["id"] for gate in projected["gates"]], ["01-scene-classify", "02-subject-inventory", "03-placement-consistency", "04-scale-anchors", "05-occlusion", "06-terrain-grounding", "07-material-independence", "08-multi-angle-legality", "09-llm-vs-forge-agreement", "10-code-only-contract", "11-screenshot-gate", "12-ip-provenance-hygiene"])
        self.assertEqual(projected["gates"][-1]["reasonCodes"], ["provenance-missing"])

    def test_v2_projection_enforces_independent_evidence_and_implementation_limits(self):
        state = self.state()
        state["evidence"]["facts"].extend(
            {"id": f"vision-extra-{index:02d}", "source": "vision", "kind": "observation", "statement": "Synthetic visual fact " + str(index)}
            for index in range(13)
        )
        state["specification"]["implementationFacts"].extend(
            {"id": f"implementation-extra-{index:02d}", "source": "implementation", "kind": "observation", "statement": "Synthetic implementation fact " + str(index)}
            for index in range(11)
        )
        projected = projection.project_state(state)
        self.assertEqual(len(projected["evidence"]["facts"]), 16)
        self.assertEqual(len(projected["specification"]["implementationFacts"]), 12)

        too_many_facts = copy.deepcopy(state)
        too_many_facts["evidence"]["facts"].append({"id": "vision-overflow", "source": "vision", "kind": "observation", "statement": "Excess evidence"})
        with self.assertRaises(ValueError):
            projection.project_state(too_many_facts)

        too_many_implementations = copy.deepcopy(state)
        too_many_implementations["specification"]["implementationFacts"].append({"id": "implementation-overflow", "source": "implementation", "kind": "observation", "statement": "Excess implementation"})
        with self.assertRaises(ValueError):
            projection.project_state(too_many_implementations)

    def test_repair_state_v2_accepts_exact_24kib_and_refuses_one_byte_more(self):
        state = self.state_at_v2_collection_limits("x" * 600)
        size = len(contracts.canonical(state))
        self.assertGreater(size, contracts.MAX_STATE_BYTES)

        at_limit = copy.deepcopy(state)
        excess = len(contracts.canonical(at_limit)) - contracts.MAX_STATE_BYTES
        texts = (
            at_limit["evidence"]["facts"]
            + at_limit["specification"]["implementationFacts"]
            + at_limit["specification"]["requirements"]
        )
        for item in texts:
            if excess == 0:
                break
            reduction = min(len(item["statement"]) - 1, excess)
            item["statement"] = item["statement"][:-reduction]
            excess -= reduction
        self.assertEqual(excess, 0)
        self.assertEqual(len(contracts.canonical(at_limit)), contracts.MAX_STATE_BYTES)
        contracts.validate_state(at_limit)

        one_over = copy.deepcopy(at_limit)
        one_over["evidence"]["facts"][0]["statement"] += "x"
        self.assertEqual(len(contracts.canonical(one_over)), contracts.MAX_STATE_BYTES + 1)
        with self.assertRaisesRegex(contracts.ContractError, "decision state exceeds 24KiB"):
            contracts.validate_state(one_over)

    def test_projection_redaction_expansion_refuses_over_24kib(self):
        state = self.state_at_v2_collection_limits("a@b.co " * 35)
        self.assertLess(len(contracts.canonical(state)), contracts.MAX_STATE_BYTES)
        contracts.validate_state(state)
        with self.assertRaisesRegex(ValueError, "outbound projection exceeds 24KiB"):
            projection.project_state(state)

    def test_projection_redacts_local_paths_secrets_and_pii_and_rejects_unhandled_file_refs(self):
        state = self.state()
        state["focus"]["symptom"] = "Gloss appears at /Users/private/scene because password: secret123 belongs to private@example.com"
        projected = projection.project_state(state)
        symptom = projected["focus"]["symptom"]
        self.assertIn("Gloss appears", symptom)
        self.assertIn("[redacted local path]", symptom)
        self.assertIn("[redacted credential]", symptom)
        self.assertIn("[redacted email]", symptom)
        for sensitive in ("/Users/private/scene", "secret123", "private@example.com"):
            self.assertNotIn(sensitive, symptom)

        state = self.state()
        state["focus"]["symptom"] = "Use nested/sourceFile.ts to load the private render"
        with self.assertRaises(ValueError):
            projection.project_state(state)
        for phone in ("+1234567890123456", "+44 1234 5678 9012 3456", "+44 20/7946 0958"):
            state = self.state()
            state["focus"]["symptom"] = "Contact " + phone
            with self.assertRaises(ValueError):
                projection.project_state(state)

    def test_projection_hash_is_canonical_and_changes_with_decision_relevant_text(self):
        initial = projection.project_state(self.state())
        reordered = projection.project_state(self.state())
        initial_hash = hashlib.sha256(contracts.canonical(initial)).hexdigest()
        self.assertEqual(initial_hash, hashlib.sha256(contracts.canonical(reordered)).hexdigest())
        changed = self.state()
        changed["evidence"]["facts"][0]["statement"] = "Observed roughness is 0.8"
        changed_hash = hashlib.sha256(contracts.canonical(projection.project_state(changed))).hexdigest()
        self.assertNotEqual(initial_hash, changed_hash)

    def test_historical_attempt_component_and_feature_ids_are_pseudonymized(self):
        state = self.state()
        state["recentAttempts"] = [{
            "strategyId": "retry-1",
            "componentIds": ["retired-component"],
            "hypothesis": "Changing the retired material response should reduce gloss",
            "outcome": "unchanged",
            "improvedFeatureIds": ["retired-feature"],
            "regressedFeatureIds": [],
            "evidenceIds": ["build"],
        }]
        projected = projection.project_state(state)
        encoded = contracts.canonical(projected).decode("utf-8")
        attempt = projected["recentAttempts"][0]
        self.assertRegex(attempt["componentIds"][0], r"c[1-9][0-9]*")
        self.assertRegex(attempt["improvedFeatureIds"][0], r"f[1-9][0-9]*")
        self.assertNotIn("retired-component", encoded)
        self.assertNotIn("retired-feature", encoded)
        self.assertIn("reduce gloss", attempt["hypothesis"])

    def test_historical_id_combining_mark_filename_overlaps_are_fully_redacted(self):
        from jev_client import _serialize_request

        state = self.state()
        state["recentAttempts"] = [{
            "strategyId": "retry-1",
            "componentIds": ["retired-component"],
            "hypothesis": "Inspect retired-component.q\u0301secret and retired-feature.f\u0301secret.",
            "outcome": "unchanged",
            "improvedFeatureIds": ["retired-feature"],
            "regressedFeatureIds": [],
            "evidenceIds": ["build"],
        }]
        original = copy.deepcopy(state)
        serialized = _serialize_request(projection.project_state(state))
        for private in ("q\u0301secret", "f\u0301secret", "c3\u0301secret", "f3\u0301secret"):
            self.assertNotIn(private.encode("utf-8"), serialized)
        self.assertEqual(serialized.count(b"[redacted filename]"), 2)
        self.assertEqual(state, original)
    def test_serialized_request_redacts_credentials_and_private_filenames(self):
        from jev_client import _serialize_request
        state = self.state()
        state["focus"]["symptom"] = "Authorization: Bearer example-private-key" + chr(10) + "appears beside confidential.md"
        serialized = _serialize_request(projection.project_state(state))
        self.assertNotIn(b"example-private-key", serialized)
        self.assertNotIn(b"confidential.md", serialized)
        self.assertIn(b"[redacted credential]", serialized)
        self.assertIn(b"[redacted filename]", serialized)

    def test_serialized_request_redacts_domestic_phone_extensions_as_complete_tokens(self):
        from jev_client import _serialize_request

        cases = (
            ("415-555-0123x456", (b"415-555-0123", b"x456")),
            ("415-555-0123 ext 123", (b"415-555-0123", b"ext 123", b"123")),
            ("415-555-0123 ext: 123", (b"415-555-0123", b"ext: 123", b"123")),
            ("415-555-0123#123", (b"415-555-0123", b"#123", b"123")),
            ("07700 900123x456", (b"07700 900123", b"x456")),
            ("4155550123x456", (b"4155550123", b"x456")),
            ("07700900123 ext:456", (b"07700900123", b"ext:456", b"456")),
        )
        for phone, sensitive_parts in cases:
            with self.subTest(phone=phone):
                state = self.state()
                state["focus"]["symptom"] = "Contact " + phone + " for assistance"
                serialized = _serialize_request(projection.project_state(state))
                self.assertIn(b"[redacted contact number] for assistance", serialized)
                for sensitive in sensitive_parts:
                    self.assertNotIn(sensitive, serialized)

    def test_serialized_request_fails_closed_on_malformed_domestic_extensions(self):
        from jev_client import _serialize_request

        malformed = (
            ("415-555-0123 x123_456", (b"415-555-0123", b"x123_456")),
            ("415-555-0123 ext:ABC_def", (b"415-555-0123", b"ext:ABC_def")),
            ("415-555-0123 ext 123_456", (b"415-555-0123", b"ext 123_456")),
            ("415-555-0123x123-456", (b"415-555-0123", b"x123-456", b"456")),
            ("415-555-0123 ext 123.456", (b"415-555-0123", b"ext 123.456", b"456")),
            ("07700 900123 ext:123/456", (b"07700 900123", b"ext:123/456", b"123", b"456")),
            ("415-555-0123ABC", (b"415-555-0123", b"ABC")),
            ("415-555-0123_ABC", (b"415-555-0123", b"_ABC")),
            ("4155550123_ABC", (b"4155550123", b"_ABC")),
            ("07700900123x123ABC", (b"07700900123", b"x123ABC")),
            ("4155550123x123_456", (b"4155550123", b"x123_456")),
            ("07700900123x123_456", (b"07700900123", b"x123_456")),
        )
        for phone, sensitive_parts in malformed:
            with self.subTest(phone=phone):
                state = self.state()
                state["focus"]["symptom"] = "Contact " + phone + " for assistance"
                try:
                    serialized = _serialize_request(projection.project_state(state))
                except ValueError:
                    continue
                self.assertNotIn(b"415-555-0123", serialized)
                for sensitive in sensitive_parts:
                    self.assertNotIn(sensitive, serialized)
    def test_serialized_request_rejects_unicode_letter_after_numeric_domestic_extension(self):
        from jev_client import _serialize_request

        malformed = (
            "4155550123x123é",
            "07700900123x123α123",
            "415-555-0123x123é",
            "07700 900123x123α123",
            "4155550123x123e\u0301",
        )
        for phone in malformed:
            with self.subTest(phone=phone):
                state = self.state()
                state["focus"]["symptom"] = "Contact " + phone + " for assistance"
                with self.assertRaises(ValueError):
                    _serialize_request(projection.project_state(state))
    def test_serialized_request_redacts_domestic_phone_groups_with_repeated_whitespace(self):
        from jev_client import _serialize_request

        for phone in ("07700  900123", "(415) 555\t0123"):
            with self.subTest(phone=repr(phone)):
                state = self.state()
                state["focus"]["symptom"] = "Contact " + phone + " for assistance"
                serialized = _serialize_request(projection.project_state(state))
                self.assertIn(b"[redacted contact number] for assistance", serialized)
                for digit in (b"07700", b"900123", b"415", b"555", b"0123"):
                    if digit in phone.encode("ascii"):
                        self.assertNotIn(digit, serialized)

    def test_serialized_request_redacts_international_phone_suffixes_after_whitespace(self):
        from jev_client import _serialize_request

        for separator in ("  ", "\t"):
            with self.subTest(separator=repr(separator)):
                state = self.state()
                state["focus"]["symptom"] = "Contact +44 20 7946" + separator + "0958 for assistance"
                original = copy.deepcopy(state)
                serialized = _serialize_request(projection.project_state(state))
                self.assertNotIn(b"0958", serialized)
                self.assertIn(b"[redacted contact number] for assistance", serialized)
                self.assertEqual(state, original)

    def test_extension_continuations_across_whitespace_and_punctuation_fail_closed(self):
        from jev_client import _serialize_request

        continuations = (
            "x123\next 456", "x123\rext 456", "x123\t#456",
            "x123\r\next 456", "x123\u2003ext 456",
            "x123)456", "x123) 456", "x123—456", "x123 ext 456",
        )
        for continuation in continuations:
            for phone in ("415-555-0123 ", "+44 20 7946 0958 "):
                with self.subTest(phone=phone, continuation=repr(continuation)):
                    state = self.state()
                    state["focus"]["symptom"] = "Contact " + phone + continuation
                    try:
                        serialized = _serialize_request(projection.project_state(state))
                    except ValueError:
                        continue
                    for sensitive in (b"415-555-0123", b"07700 900123", b"+44 20 7946 0958", b"x123", b"456"):
                        self.assertNotIn(sensitive, serialized)
    def test_serialized_request_rejects_unconsumed_numeric_phone_tails_before_disclosure(self):
        from jev_client import _serialize_request

        for contact in ("415-555-0123-456", "415-555-0123 x123 456", "+44 20 7946 0958--123"):
            with self.subTest(contact=contact):
                state = self.state()
                state["focus"]["symptom"] = "Contact " + contact + " for assistance"
                with self.assertRaises(ValueError):
                    _serialize_request(projection.project_state(state))
    def test_serialized_request_rejects_repeated_phone_extensions_before_disclosure(self):
        from jev_client import _serialize_request

        malformed = (
            "415-555-0123 x123 ext 456",
            "415-555-0123 ext 123 #456",
            "07700 900123 ext 123 x456",
            "+44 20 7946 0958 x123 x456",
            "+44 20 7946 0958x123-456",
            "+44 20 7946 0958 ext:123-456",
            "+44 20 7946 0958 x123 x456",
        )
        for phone in malformed:
            with self.subTest(phone=phone):
                state = self.state()
                state["focus"]["symptom"] = "Contact " + phone + " for assistance"
                with self.assertRaises(ValueError):
                    _serialize_request(projection.project_state(state))
    def test_serialized_request_preserves_signed_and_unsigned_unit_measurements_with_distinct_hashes(self):
        from jev_client import _serialize_request

        measurements = ("+0.25m", "+0.75m", "+1.25m", "+1.75m", "-0.25m", "-0.75m", "0.25m", "0.75m")
        serialized = {}
        hashes = {}
        serialized_hashes = {}
        for measurement in measurements:
            state = self.state()
            state["focus"]["symptom"] = "Offsets " + measurement
            projected = projection.project_state(state)
            serialized[measurement] = _serialize_request(projected)
            self.assertEqual(state["focus"]["symptom"], "Offsets " + measurement)
            serialized_hashes[measurement] = hashlib.sha256(serialized[measurement]).hexdigest()
            hashes[measurement] = hashlib.sha256(contracts.canonical(projected)).hexdigest()
            self.assertIn(("Offsets " + measurement).encode("utf-8"), serialized[measurement])
        self.assertEqual(len(set(hashes.values())), len(measurements))
        self.assertEqual(len(set(serialized_hashes.values())), len(measurements))

    def test_serialized_request_preserves_unit_measures_adjacent_to_parenthesized_and_tab_phones(self):
        from jev_client import _serialize_request

        measurements = ("+0.25m", "+0.75m", "+1/2m", "+1/4m")
        for phone in ("+44 (20) 7946 0958 ", "+44 (20) 7946\t0958\t"):
            hashes = {}
            for measurement in measurements:
                state = self.state()
                state["focus"]["symptom"] = "Contact " + phone + measurement
                projected = projection.project_state(state)
                serialized = _serialize_request(projected)
                hashes[measurement] = hashlib.sha256(contracts.canonical(projected)).hexdigest()
                self.assertIn(b"[redacted contact number]", serialized)
                self.assertIn(measurement.encode("utf-8"), serialized)
            self.assertEqual(len(set(hashes.values())), len(measurements))

        state = self.state()
        state["focus"]["symptom"] = "Contact +44 (20) 7946\t0958\t-0.25m"
        serialized_negative = _serialize_request(projection.project_state(state))
        self.assertIn(b"[redacted contact number]", serialized_negative)
        self.assertIn(b"-0.25m", serialized_negative)
    def test_serialized_request_preserves_signed_domestic_extension_measurements_and_hashes(self):
        from jev_client import _serialize_request

        cases = (("415-555-0123 x123 ", "-0.25m"), ("415-555-0123 x123 ", "+0.25m"), ("(415)\t555\t0123 ext:123 ", "-1/2m"), ("(415)\t555\t0123 ext:123 ", "+1/2m"))
        hashes = set()
        for phone, measurement in cases:
            with self.subTest(phone=phone, measurement=measurement):
                state = self.state()
                state["focus"]["symptom"] = "Contact " + phone + measurement
                projected = projection.project_state(state)
                serialized = _serialize_request(projected)
                self.assertIn(b"[redacted contact number]", serialized)
                self.assertIn(measurement.encode("ascii"), serialized)
                hashes.add(hashlib.sha256(contracts.canonical(projected)).hexdigest())
        self.assertEqual(len(hashes), len(cases))
    def test_serialized_request_preserves_signed_international_extension_measurements_and_hashes(self):
        from jev_client import _serialize_request

        measurements = ("-0.25m", "+0.25m", "-1/2m", "+1/2m")
        for phone in (
            "+44 20 7946 0958 x123 ",
            "+44 (20) 7946\t0958 x123\t",
            "+44 20 7946 0958 x123, ",
            "+44 20 7946 0958 x123; ",
            "+44 20 7946 0958 x123); ",
            "(415-555-0123 x123); ",
            "+44 20 7946 0958 x123);",
            "(415-555-0123 x123);",
            "+44 20 7946 0958 x123) ; ",
            "(415-555-0123 x123, ) ; ",
            "+44 20 7946 0958 x123) ;",
            "(415-555-0123 x123, ) ;",
        ):
            hashes = set()
            for measurement in measurements:
                with self.subTest(phone=phone, measurement=measurement):
                    state = self.state()
                    state["focus"]["symptom"] = "Contact " + phone + measurement + " for assistance"
                    original = copy.deepcopy(state)
                    projected = projection.project_state(state)
                    serialized = _serialize_request(projected)
                    self.assertEqual(state, original)
                    self.assertIn(b"[redacted contact number]", serialized)
                    self.assertIn(measurement.encode("ascii"), serialized)
                    hashes.add(hashlib.sha256(contracts.canonical(projected)).hexdigest())
            self.assertEqual(len(hashes), len(measurements))

    def test_serialized_request_still_redacts_plus_prefixed_phone_candidates(self):
        from jev_client import _serialize_request

        for phone in ("+442079460958", "+44 7700 900123"):
            with self.subTest(phone=phone):
                state = self.state()
                state["focus"]["symptom"] = "Contact " + phone + " for assistance"
                serialized = _serialize_request(projection.project_state(state))
                self.assertNotIn(phone.encode("ascii"), serialized)
                self.assertIn(b"[redacted contact number] for assistance", serialized)
    def test_serialized_request_redacts_authorization_phone_decimal_and_compound_filename_boundaries(self):
        from jev_client import _serialize_request
        state = self.state()
        state["focus"]["symptom"] = (
            "Proxy-Authorization: Basic cHJveHktdXNlcjpwYXNz" + chr(10)
            + "Authorization: Basic dXNlcjpwYXNz" + chr(10)
            + "Contact +44 2079460958 and +44 20 7946 0958123 for assistance; preserve +44 20 7946 0958 12.34, 12/34, 0.25, 0.123456789, and 1.5mm. "
            "Inspect confidential.backup.mobile-provision., private.d.ts., private.tar.gz., "
            "and .env.production.; keep the trailing punctuation."
        )
        serialized = _serialize_request(projection.project_state(state))
        for sensitive in (
            b"Basic", b"dXNlcjpwYXNz", b"+44 20 7946 0958",
            b"Basic", b"cHJveHktdXNlcjpwYXNz", b"dXNlcjpwYXNz", b"Proxy-Authorization",
            b"+44 20 7946 0958", b"+44 2079460958", b"+44 20 7946 0958123",
            b"confidential.backup.mobile-provision", b"private.d.ts",
            b"private.tar.gz", b".env.production",
        ):
            self.assertNotIn(sensitive, serialized)
        self.assertIn(b"[redacted credential]", serialized)
        self.assertIn(b"[redacted contact number] for assistance", serialized)
        self.assertIn(b"[redacted contact number] 12.34", serialized)
        self.assertIn(b"0.123456789", serialized)
        self.assertIn(b"12.34, 12/34, 0.25, 0.123456789, and 1.5mm", serialized)
        self.assertIn(b"[redacted filename].", serialized)
        self.assertIn(b"keep the trailing punctuation.", serialized)
        decimal_state = self.state()
        decimal_state["focus"]["symptom"] = "Contact +44 20 7946 0958 12.34 for assistance"
        changed_decimal = copy.deepcopy(decimal_state)
        changed_decimal["focus"]["symptom"] = decimal_state["focus"]["symptom"].replace("12.34", "12.35")
        projection_a = projection.project_state(decimal_state)
        projection_b = projection.project_state(changed_decimal)
        self.assertIn(b"[redacted contact number] 12.34 for assistance", _serialize_request(projection_a))
        self.assertIn(b"[redacted contact number] 12.35 for assistance", _serialize_request(projection_b))
        self.assertNotEqual(
            hashlib.sha256(contracts.canonical(projection_a)).hexdigest(),
            hashlib.sha256(contracts.canonical(projection_b)).hexdigest(),
        )

    def test_serialized_request_redacts_maximum_grouped_phone_and_normalizes_filename_unicode(self):
        from jev_client import _serialize_request
        state = self.state()
        grouped_phone = "+1 2 3 4 5 6 7 8 9 0 1 2 3 4"
        maximum_grouped_phone = grouped_phone + " 5"
        state["focus"]["symptom"] = (
            f"Contact {grouped_phone} and {maximum_grouped_phone}; preserve 0.123mm vs0.987mm and 1.25m; "
            "inspect résumé.pdf and re\u0301sume\u0301.pdf and privateq\u0301.backup.pdf; keep 12.34"
        )
        serialized = _serialize_request(projection.project_state(state))
        self.assertIn(b"[redacted contact number] and [redacted contact number]; preserve 0.123mm vs0.987mm and 1.25m", serialized)
        self.assertIn(b"inspect [redacted filename] and [redacted filename] and [redacted filename]; keep 12.34", serialized)
        for filename in ("résumé.pdf", "re\u0301sume\u0301.pdf", "privateq\u0301.backup.pdf"):
            self.assertNotIn(filename.encode("utf-8"), serialized)
        for fragment in ("privateq", "\u0301", "backup.pdf"):
            self.assertNotIn(fragment.encode("utf-8"), serialized)
        changed = copy.deepcopy(state)
        changed["focus"]["symptom"] = changed["focus"]["symptom"].replace("0.123mm", "0.124mm")
        changed_serialized = _serialize_request(projection.project_state(changed))
        self.assertIn(b"0.124mm vs0.987mm and 1.25m", changed_serialized)
        self.assertNotEqual(hashlib.sha256(serialized).hexdigest(), hashlib.sha256(changed_serialized).hexdigest())

    def test_safe_decimal_hashes_remain_distinct(self):
        first = self.state()
        first["evidence"]["facts"][0]["statement"] = "Contact +442079460958. 0.123456789 is measured; domestic 415-555-0123"
        second = copy.deepcopy(first)
        second["evidence"]["facts"][0]["statement"] = "Contact +442079460958. 0.987654321 is measured; domestic 415-555-0123"
        projection_a = projection.project_state(first)
        projection_b = projection.project_state(second)
        encoded_a = contracts.canonical(projection_a).decode("utf-8")
        encoded_b = contracts.canonical(projection_b).decode("utf-8")
        from jev_client import _serialize_request
        serialized_a = _serialize_request(projection_a)
        serialized_b = _serialize_request(projection_b)
        for sensitive in (b"+442079460958", b"415-555-0123"):
            self.assertNotIn(sensitive, serialized_a)
            self.assertNotIn(sensitive, serialized_b)
        self.assertIn("0.123456789", encoded_a)
        self.assertIn("0.987654321", encoded_b)
        self.assertIn(b"0.123456789", serialized_a)
        self.assertIn(b"0.987654321", serialized_b)
        self.assertNotEqual(hashlib.sha256(contracts.canonical(projection_a)).hexdigest(), hashlib.sha256(contracts.canonical(projection_b)).hexdigest())
    def test_unit_fractions_hash_distinctly_and_paths_stay_redacted(self):
        from jev_client import _serialize_request
        first = self.state()
        first["evidence"]["facts"][0]["statement"] = "Contact +44 20 7946 0958; ratio is 1/2m with decimal 0.123m at /Users/private/scene"
        second = copy.deepcopy(first)
        second["evidence"]["facts"][0]["statement"] = "Contact +44 20 7946 0958; ratio is 1/4m with decimal 0.123m at /Users/private/scene"
        projection_a = projection.project_state(first)
        projection_b = projection.project_state(second)
        serialized_a = _serialize_request(projection_a)
        serialized_b = _serialize_request(projection_b)
        self.assertIn(b"[redacted contact number]; ratio is 1/2m", serialized_a)
        self.assertIn(b"[redacted contact number]; ratio is 1/4m", serialized_b)
        self.assertIn(b"1/4m with decimal 0.123m", serialized_b)
        for serialized in (serialized_a, serialized_b):
            self.assertIn(b"[redacted local path]", serialized)
            self.assertNotIn(b"/Users/private/scene", serialized)
        self.assertNotEqual(hashlib.sha256(serialized_a).hexdigest(), hashlib.sha256(serialized_b).hexdigest())

    def test_current_and_text_only_historical_ids_are_pseudonymized_everywhere(self):
        state = self.state()
        component_id = state["components"][0]["id"]
        feature_id = state["specification"]["requirements"][0]["featureId"]
        state["focus"]["symptom"] = f"{component_id} affects {feature_id}"
        state["components"][0]["role"] = f"role {component_id}"
        state["components"][0]["protectedProperties"] = [f"protect {component_id} and {feature_id}"]
        state["specification"]["requirements"][0]["statement"] = f"require {component_id} for {feature_id}"
        state["evidence"]["facts"][0]["statement"] = f"fact {component_id} {feature_id}"
        state["recentAttempts"] = [{
            "strategyId": "retry-1", "componentIds": ["retired-component"],
            "hypothesis": f"retired-component retired-feature text-only-component text-only-feature {component_id} {feature_id}",
            "outcome": "unchanged", "improvedFeatureIds": ["retired-feature"],
            "regressedFeatureIds": [], "evidenceIds": ["build"],
        }]
        encoded = contracts.canonical(projection.project_state(state)).decode("utf-8")
        for raw in (component_id, feature_id, "retired-component", "retired-feature", "text-only-component", "text-only-feature"):
            self.assertNotIn(raw, encoded)

    def test_canonical_unicode_is_normalized_before_identifier_pseudonymization(self):
        from jev_client import _serialize_request

        state = self.state()
        state["components"][0]["id"] = "K-panel"
        state["focus"]["componentIds"] = ["K-panel"]
        state["focus"]["symptom"] = "Inspect K-panel and K-panel."
        original = copy.deepcopy(state)
        projected = projection.project_state(state)
        serialized = _serialize_request(projected)
        self.assertIn(b"Inspect c1 and c1.", serialized)
        self.assertNotIn(b"K-panel", serialized)
        self.assertNotIn("K-panel".encode("utf-8"), serialized)
        canonical_state = copy.deepcopy(state)
        canonical_state["focus"]["symptom"] = "Inspect K-panel and K-panel."
        canonical_projection = projection.project_state(canonical_state)
        canonical_serialized = _serialize_request(canonical_projection)
        self.assertEqual(serialized, canonical_serialized)
        self.assertEqual(state, original)

        main = self.state()
        main["components"][0]["id"] = "K.main"
        main["focus"]["componentIds"] = ["K.main", "K.trim"]
        second_component = copy.deepcopy(main["components"][0])
        second_component["id"] = "K.trim"
        main["components"].append(second_component)
        main["focus"]["symptom"] = "Inspect K.main."
        canonical_main = copy.deepcopy(main)
        canonical_main["focus"]["symptom"] = "Inspect K.main."
        trim = copy.deepcopy(main)
        trim["focus"]["symptom"] = "Inspect K.trim."

        main_projection = projection.project_state(main)
        canonical_projection = projection.project_state(canonical_main)
        trim_projection = projection.project_state(trim)
        main_bytes = _serialize_request(main_projection)
        trim_bytes = _serialize_request(trim_projection)
        self.assertIn(b"Inspect c1.", main_bytes)
        self.assertIn(b"Inspect c2.", trim_bytes)
        for raw in (b"K.main", b"K.trim", "K.main".encode(), "K.trim".encode()):
            self.assertNotIn(raw, main_bytes + trim_bytes)
        main_hash = hashlib.sha256(contracts.canonical(main_projection)).hexdigest()
        self.assertEqual(main_hash, hashlib.sha256(contracts.canonical(canonical_projection)).hexdigest())
        self.assertNotEqual(main_hash, hashlib.sha256(contracts.canonical(trim_projection)).hexdigest())
    def test_serialized_projection_redacts_phone_dotfiles_and_numeric_extensions(self):
        from jev_client import _serialize_request
        state = self.state()
        long_filename = "confidential." + "x" * 200
        state["focus"]["symptom"] = f"Contact +1 (415) 555-0123 and +442079460958; inspect .env, .env.production., confidential.2026, confidential.backup.mobileprovision., private.d.ts., private.tar.gz., and {long_filename}. Values 0.25 and 1/2"
        serialized = _serialize_request(projection.project_state(state))
        for sensitive in (b"+1 (415) 555-0123", b"+442079460958", b".env", b".env.production", b"confidential.2026", b"confidential.backup.mobileprovision", b"private.d.ts", b"private.tar.gz", long_filename.encode()):
            self.assertNotIn(sensitive, serialized)
        self.assertIn(b"[redacted contact number]", serialized)
        self.assertGreaterEqual(serialized.count(b"[redacted filename]"), 2)
        self.assertIn(b"[redacted filename].", serialized)
        self.assertIn(b"[redacted filename]. Values", serialized)
        self.assertIn(b"0.25", serialized)
        state_075 = copy.deepcopy(state)
        state_075["focus"]["symptom"] = state_075["focus"]["symptom"].replace("0.25", "0.75")
        self.assertNotEqual(hashlib.sha256(contracts.canonical(projection.project_state(state))).hexdigest(), hashlib.sha256(contracts.canonical(projection.project_state(state_075))).hexdigest())
        self.assertIn(b"0.75", _serialize_request(projection.project_state(state_075)))
        self.assertIn(b"1/2", serialized)

    def test_sentence_punctuation_identifier_is_pseudonymized_without_dotted_partial_match(self):
        from jev_client import _serialize_request
        state = self.state()
        state["focus"]["symptom"] = "adjust jacket. keep jacket.extra unchanged"
        serialized = _serialize_request(projection.project_state(state))
        self.assertIn(b"adjust c1.", serialized)
        self.assertNotIn(b"c1.extra", serialized)
        self.assertIn(b"[redacted filename]", serialized)
        self.assertNotIn(b"adjust jacket.", serialized)


    def test_serialized_request_redacts_sentence_terminal_filenames(self):
        from jev_client import _serialize_request
        state = self.state()
        state["focus"]["symptom"] = "Inspect .env. and confidential.txt. plus confidential.2026."
        serialized = _serialize_request(projection.project_state(state))
        for filename in (b".env", b"confidential.txt", b"confidential.2026"):
            self.assertNotIn(filename, serialized)
        self.assertIn(b"[redacted filename].", serialized)

    def test_project_state_and_serialized_request_redact_standalone_bearer_credential(self):
        from jev_client import _serialize_request
        state = self.state()
        state["focus"]["symptom"] = "Bearer private-access-key should not be retained"
        projected = projection.project_state(state)
        serialized = _serialize_request(projected)
        self.assertNotIn("private-access-key", projected["focus"]["symptom"])
        self.assertNotIn(b"private-access-key", serialized)
        self.assertIn(b"[redacted credential]", serialized)

    def test_known_dotted_component_ids_are_pseudonymized_before_filename_screening(self):
        first_id, second_id = "jacket.main", "jacket.trim"
        first = self.state()
        first["components"][0]["id"] = first_id
        first["focus"]["componentIds"] = [first_id]
        first["focus"]["symptom"] = f"inspect {first_id}. keep {second_id}-extra distinct; private {first_id}-backup.privatekey remains private"
        first["components"].append({"id": second_id, "role": "trim", "parentId": None, "sharedResourceUsers": [], "protectedProperties": []})
        projected_first = projection.project_state(first)
        encoded_first = contracts.canonical(projected_first).decode("utf-8")
        self.assertIn("inspect c1.", encoded_first)
        self.assertIn("keep [redacted filename] distinct", encoded_first)
        self.assertIn("private [redacted filename] remains private", encoded_first)
        from jev_client import _serialize_request
        serialized_first = _serialize_request(projected_first)
        self.assertNotIn(b"jacket.main-backup.privatekey", serialized_first)
        self.assertNotIn(b"backup.privatekey", serialized_first)
        second = copy.deepcopy(first)
        second["focus"]["componentIds"] = [second_id]
        second["focus"]["symptom"] = f"inspect {second_id}. keep {first_id}-extra distinct; private {second_id}-backup.privatekey remains private"
        encoded_second = contracts.canonical(projection.project_state(second)).decode("utf-8")
        self.assertIn("inspect c2.", encoded_second)
        self.assertIn("keep [redacted filename] distinct", encoded_second)
        self.assertIn("private [redacted filename] remains private", encoded_second)
        self.assertNotEqual(hashlib.sha256(encoded_first.encode()).hexdigest(), hashlib.sha256(encoded_second.encode()).hexdigest())

    def test_serialized_request_redacts_full_digest_and_proxy_authorization_values(self):
        from jev_client import _serialize_request
        state = self.state()
        state["focus"]["symptom"] = (
            'Authorization: Digest username="alice",' + chr(10)
            + ' realm="private", nonce="challenge123", response="0123456789abcdef0123456789abcdef"' + chr(10)
            + 'Proxy-Authorization: Basic' + chr(10) + ' dXNlcjpwYXNz' + chr(10) + 'normal trailing text'
        )
        serialized = _serialize_request(projection.project_state(state))
        for secret in (b"alice", b"private", b"challenge123", b"0123456789abcdef0123456789abcdef", b"dXNlcjpwYXNz", b"Proxy-Authorization"):
            self.assertNotIn(secret, serialized)
        self.assertIn(b"[redacted credential]", serialized)
        self.assertIn(b"normal trailing text", serialized)

    def test_adjacent_decimals_and_fractions_keep_distinct_values_and_hashes(self):
        from jev_client import _serialize_request
        first = self.state()
        first["focus"]["symptom"] = "+123456789012345 0.25; +44 20 7946 0958 1234.56; +44 20 7946 0958 12/34 vs +44 20 7946 0958 56/78; measurements 12.34/56.78"
        second = copy.deepcopy(first)
        second["focus"]["symptom"] = first["focus"]["symptom"].replace("0.25", "0.26").replace("56/78", "56/79")
        projected_first = projection.project_state(first)
        projected_second = projection.project_state(second)
        serialized_first = _serialize_request(projected_first)
        serialized_second = _serialize_request(projected_second)
        for value in (b"0.25", b"1234.56", b"12.34/56.78", b"12/34 vs", b"56/78"):
            self.assertIn(value, serialized_first)
        self.assertIn(b"[redacted contact number] 0.25", serialized_first)
        self.assertIn(b"[redacted contact number] 1234.56", serialized_first)
        self.assertNotIn(b"+123456789012345", serialized_first)
        self.assertNotIn(b"+44 20 7946 0958", serialized_first)
        self.assertIn(b"0.26", serialized_second)
        self.assertIn(b"56/79", serialized_second)
        self.assertNotEqual(hashlib.sha256(contracts.canonical(projected_first)).hexdigest(), hashlib.sha256(contracts.canonical(projected_second)).hexdigest())
        overlong = self.state()
        overlong["focus"]["symptom"] = "Contact +1234567890123456 now"
        with self.assertRaises(ValueError):
            projection.project_state(overlong)
        overlong = self.state()
        overlong["focus"]["symptom"] = "Contact +44 20 1234 5678 9012 now"
        with self.assertRaises(ValueError):
            projection.project_state(overlong)
    def test_serialized_projection_redacts_single_digit_international_group(self):
        from jev_client import _serialize_request
        state = self.state()
        state["focus"]["symptom"] = (
            "Contact +33 6 12 34 56 78, +442079460958, "
            "+44 20 7 946 0958, and +44 20 7946 0 958 for assistance with the scene."
        )
        serialized = _serialize_request(projection.project_state(state))
        for phone in (
            b"+33 6 12 34 56 78", b"+442079460958",
            b"+44 20 7 946 0958", b"+44 20 7946 0 958",
        ):
            self.assertNotIn(phone, serialized)
        self.assertIn(b"[redacted contact number] for assistance with the scene.", serialized)

    def test_serialized_request_redacts_entire_international_phone_extension(self):
        from jev_client import _serialize_request
        state = self.state()
        state["focus"]["symptom"] = "Contact +447700900123x456 and +44 20 7946 0958x123 for assistance."
        serialized = _serialize_request(projection.project_state(state))
        self.assertNotIn(b"+447700900123", serialized)
        self.assertNotIn(b"x456", serialized)
        self.assertNotIn(b"+44 20 7946 0958", serialized)
        self.assertNotIn(b"x123", serialized)
        self.assertEqual(serialized.count(b"[redacted contact number]"), 2)
        self.assertIn(b"[redacted contact number] and [redacted contact number] for assistance.", serialized)

    def test_serialized_request_redacts_extension_marker_variants(self):
        from jev_client import _serialize_request
        state = self.state()
        state["focus"]["symptom"] = "Contact +447700900124ext.456 and +44 20 7946 0959#789."
        serialized = _serialize_request(projection.project_state(state))
        self.assertNotIn(b"+447700900124", serialized)
        self.assertNotIn(b"ext.456", serialized)
        self.assertNotIn(b"+44 20 7946 0959", serialized)
        self.assertNotIn(b"#789", serialized)
        self.assertEqual(serialized.count(b"[redacted contact number]"), 2)
        self.assertIn(b"[redacted contact number] and [redacted contact number].", serialized)
    def test_international_phone_candidates_do_not_leak_tab_or_unknown_suffix_digits(self):
        from jev_client import _serialize_request
        cases = (
            ("Contact +44 (20) 7946\t0958 for assistance", True),
            ("Contact +44 20 7946 0958xABC for assistance", False),
            ("Contact +44 20 7946 0958ext:ABC for assistance", False),
            ("Contact +44 20 7946 0958ABC for assistance", False),
            ("Contact +44 20 7946 0958 123ABC for assistance", False),
            ("Contact +44 20 7946 0958_123 for assistance", False),
        )
        for symptom, can_redact in cases:
            with self.subTest(symptom=symptom):
                state = self.state()
                state["focus"]["symptom"] = symptom
                if can_redact:
                    serialized = _serialize_request(projection.project_state(state))
                    self.assertNotIn(b"+44", serialized)
                    self.assertNotIn(b"0958", serialized)
                    self.assertIn(b"[redacted contact number]", serialized)
                else:
                    with self.assertRaises(ValueError):
                        projection.project_state(state)
    def test_malformed_international_phone_candidates_are_refused_before_serialization(self):
        cases = (
            "+442079460958ABC",
            "+442079460958_123",
            "+44 (20) 7946 (0958ABC)",
            "+44 20 7946 0958 x123_456",
            "+44 20 7946 0958 ext:ABC_def",
        )
        for candidate in cases:
            with self.subTest(candidate=candidate):
                state = self.state()
                state["focus"]["symptom"] = "Contact " + candidate + " for assistance"
                with self.assertRaises(ValueError):
                    projection.project_state(state)
    def test_serialized_projection_refuses_incomplete_phone_suffix_candidates(self):
        from jev_client import _serialize_request
        cases = (
            "Contact 415-555-0123 x123--456 for assistance",
            "Contact 415-555-0123 x123 -456 for assistance",
            "Contact 415-555-0123\u0301123 for assistance",
            "Contact +44 20 7946 0958 x123-ABC456 for assistance",
            "Contact 415-555-0123é for assistance",
            "Contact 415-555-0123α123 for assistance",
            "Contact 415-555-0123 x123:456 for assistance",
            "Contact +44 20 7946 0958 x123:456 for assistance",
            "Contact +44 20 7946 0958 x123 (456) for assistance",
            "Contact +44 20 7946 0958 x123(456) for assistance",
            "Contact +44 20 7946 0958 x123\t(456) for assistance",
            "Contact 415-555-0123 x123 (456) for assistance",
            "Contact 415-555-0123 x123(456) for assistance",
            "Contact 415-555-0123 x123\t(456) for assistance",
            "Contact 415-555-0123 x123:456.789 for assistance",
            "Contact +44 20 7946 0958 x123:456.789 for assistance",
            "Contact 415-555-0123 x123:456.789m for assistance",
            "Contact +44 20 7946 0958 x123:456.789m for assistance",
            "Contact +44 20 7946 0958 x123(456.789m) for assistance",
            "Contact +44 20 7946 0958 x123-456.789m for assistance",
            "Contact 415-555-0123 x123+456 for assistance",
            "Contact 415-555-0123 x123 +456 for assistance",
            "Contact +44 20 7946 0958 x123+456 for assistance",
            "Contact +44 20 7946 0958 x123 +456 for assistance",
            "Contact 4155550123x123,ext 456 for assistance",
            "Contact 07700900123x123;456 for assistance",
            "Contact +44 20 7946 0958 x123;ext 456 for assistance",
            "Contact 4155550123x123,,ext 456 for assistance",
            "Contact +44 20 7946 0958 x123;;ext 456 for assistance",
            "Contact 07700900123x123,;456 for assistance",
            "Contact 415-555-0123 x123) ext 456 for assistance",
            "Contact +44 20 7946 0958 x123 — ext 456 for assistance",
            "Contact +44 20 7946 0958 x123: ext 456 for assistance",
            "Contact +44 20 7946 0958 x123, ) ext 456 for assistance",
            "Contact 415-555-0123 x123) ; ext 456 for assistance",
            "Contact 415-555-0123 x123, ) -ABC456 for assistance",
            "Contact 415-555-0123 x123) ; 456 for assistance",
            "Contact 415-555-0123 x123=456 for assistance",
            "Contact +44 20 7946 0958 x123|ABC456 for assistance",
            "Contact 415-555-0123 x123=ext456 for assistance",
        )
        for symptom in cases:
            with self.subTest(symptom=symptom):
                state = self.state()
                state["focus"]["symptom"] = symptom
                with self.assertRaises(ValueError):
                    _serialize_request(projection.project_state(state))
    def test_signed_unit_measurements_remain_distinct_and_hashable(self):
        from jev_client import _serialize_request
        first = self.state()
        first["focus"]["symptom"] = "Offsets -0.25m and 0.25m with ratio 1/2m"
        second = copy.deepcopy(first)
        second["focus"]["symptom"] = first["focus"]["symptom"].replace("-0.25m", "-0.75m")
        projected_first = projection.project_state(first)
        projected_second = projection.project_state(second)
        serialized_first = _serialize_request(projected_first)
        serialized_second = _serialize_request(projected_second)
        self.assertIn(b"-0.25m and 0.25m with ratio 1/2m", serialized_first)
        self.assertIn(b"-0.75m and 0.25m with ratio 1/2m", serialized_second)
        self.assertNotEqual(hashlib.sha256(contracts.canonical(projected_first)).hexdigest(), hashlib.sha256(contracts.canonical(projected_second)).hexdigest())

    def test_numeric_component_ids_do_not_rewrite_fraction_measurements(self):
        from jev_client import _serialize_request
        first = self.state()
        first["components"][0]["id"] = "1"
        first["focus"]["componentIds"] = ["1"]
        first["focus"]["symptom"] = "Offset +1/2m on component 1"
        second = copy.deepcopy(first)
        second["focus"]["symptom"] = second["focus"]["symptom"].replace("+1/2m", "+1/4m")
        projected_first = projection.project_state(first)
        projected_second = projection.project_state(second)
        serialized_first = _serialize_request(projected_first)
        serialized_second = _serialize_request(projected_second)
        self.assertIn(b"Offset +1/2m on component c1", serialized_first)
        self.assertIn(b"Offset +1/4m on component c1", serialized_second)
        self.assertNotIn(b"on component 1", serialized_first)
        self.assertNotIn(b"on component 1", serialized_second)
        self.assertNotEqual(hashlib.sha256(contracts.canonical(projected_first)).hexdigest(), hashlib.sha256(contracts.canonical(projected_second)).hexdigest())

    def test_uk_grouped_phones_and_single_digit_groups_are_redacted(self):
        from jev_client import _serialize_request
        state = self.state()
        state["focus"]["symptom"] = (
            "Contact +44 7700 900123,, 07700 900123, +33 6 12 34 56 78, "
            "+44 20 7946 0958, +1 2 3 4 5 6 7 8 9 0 1 2 3 4, and 0.25 for assistance."
        )
        serialized = _serialize_request(projection.project_state(state))
        for phone in (
            b"+44 7700 900123", b"07700 900123", b"+33 6 12 34 56 78",
            b"+44 20 7946 0958", b"+1 2 3 4 5 6 7 8 9 0 1 2 3 4",
        ):
            self.assertNotIn(phone, serialized)
        self.assertEqual(serialized.count(b"[redacted contact number]"), 5)
        self.assertIn(b"0.25 for assistance.", serialized)

    def test_unicode_filenames_redact_without_changing_unit_measurements(self):
        from jev_client import _serialize_request
        first = self.state()
        first["focus"]["symptom"] = (
            "Inspect résumé.pdf. and résumé.backup.tar.gz.; measurements are 0.123mm and 1.25m."
        )
        second = copy.deepcopy(first)
        second["focus"]["symptom"] = first["focus"]["symptom"].replace("0.123mm", "0.987mm")
        projected_first = projection.project_state(first)
        projected_second = projection.project_state(second)
        serialized_first = _serialize_request(projected_first)
        serialized_second = _serialize_request(projected_second)
        for filename in ("résumé.pdf", "résumé.backup.tar.gz"):
            self.assertNotIn(filename.encode(), serialized_first)
            self.assertNotIn(filename.encode(), serialized_second)
        self.assertGreaterEqual(serialized_first.count(b"[redacted filename]"), 2)
        self.assertIn(b"[redacted filename].", serialized_first)
        self.assertIn(b"[redacted filename].;", serialized_first)
        for measure in (b"0.123mm", b"1.25m"):
            self.assertIn(measure, serialized_first)
        self.assertIn(b"0.987mm", serialized_second)
        self.assertNotEqual(
            hashlib.sha256(contracts.canonical(projected_first)).hexdigest(),
            hashlib.sha256(contracts.canonical(projected_second)).hexdigest(),
        )
    def test_serialized_request_preserves_signed_fraction_unit_measurements(self):
        from jev_client import _serialize_request

        measurements = ("+1/2m", "+1/4m", "-1/2m", "-1/4m")
        projection_hashes = set()
        serialized_hashes = set()
        for measurement in measurements:
            with self.subTest(measurement=measurement):
                state = self.state()
                original = copy.deepcopy(state)
                state["focus"]["symptom"] = "Offsets " + measurement
                original["focus"]["symptom"] = "Offsets " + measurement
                projected = projection.project_state(state)
                serialized = _serialize_request(projected)
                self.assertEqual(state, original)
                self.assertEqual(projected["focus"]["symptom"], "Offsets " + measurement)
                self.assertIn(("Offsets " + measurement).encode("utf-8"), serialized)
                projection_hashes.add(hashlib.sha256(contracts.canonical(projected)).hexdigest())
                serialized_hashes.add(hashlib.sha256(serialized).hexdigest())

        self.assertEqual(len(projection_hashes), len(measurements))
        self.assertEqual(len(serialized_hashes), len(measurements))

        for measurement in ("1/2m", "1/4m"):
            state = self.state()
            state["focus"]["symptom"] = "Offsets " + measurement
            projected = projection.project_state(state)
            self.assertEqual(projected["focus"]["symptom"], "Offsets " + measurement)

        state = self.state()
        state["focus"]["symptom"] = "Contact +1/2"
        with self.assertRaises(ValueError):
            projection.project_state(state)


if __name__ == "__main__":
    unittest.main()
