import copy
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock


PLUGIN_DIR = Path(__file__).resolve().parent.parent
HARNESS_DIR = Path(os.environ.get("IMG2_HARNESS_DIR", PLUGIN_DIR.parent / "img2")).resolve()
_TEST_HOME = None
if not os.environ.get("IMG2_HOME"):
    _TEST_HOME = Path(tempfile.mkdtemp(prefix="jev-client-img2-home-"))
    (_TEST_HOME / "harness").symlink_to(HARNESS_DIR)
    os.environ["IMG2_HOME"] = str(_TEST_HOME)

_SPEC = importlib.util.spec_from_file_location("jev_client", PLUGIN_DIR / "tools" / "jev_client.py")
assert _SPEC is not None and _SPEC.loader is not None
client = importlib.util.module_from_spec(_SPEC)
sys.modules["jev_client"] = client
_SPEC.loader.exec_module(client)


class _FakeResponse:
    def __init__(self, body, status=200, headers=None, chunks=None):
        self.body = body
        self.status = status
        self.headers = headers or {}
        self._chunks = list(chunks) if chunks is not None else None
        self.closed = False

    def read(self, _size=-1):
        if self._chunks is not None:
            return self._chunks.pop(0) if self._chunks else b""
        body, self.body = self.body, b""
        return body

    def read1(self, size=-1):
        return self.read(size)

    def getcode(self):
        return self.status

    def close(self):
        self.closed = True


def valid_response():
    answers = {}
    for question_id, question in client.QUESTIONS.items():
        options = list(question["criteria"])
        probabilities = {option: 0.0 for option in options}
        probabilities[options[0]] = 1.0
        answers[question_id] = {
            "type": "choice",
            "choice": options[0],
            "probabilities": probabilities,
            "confidence": 1.0,
        }
    return {
        "model": client.MODEL,
        "answers": answers,
        "usage": {"input_tokens": 12, "output_tokens": 8},
    }


class JevClientTest(unittest.TestCase):


    def test_malformed_and_adversarial_responses_are_rejected(self):
        cases = []

        missing_top_level = valid_response()
        del missing_top_level["usage"]
        cases.append(missing_top_level)

        extra_top_level = valid_response()
        extra_top_level["prose"] = "do not accept generated text"
        cases.append(extra_top_level)

        wrong_model = valid_response()
        wrong_model["model"] = "jev-latest"
        cases.append(wrong_model)

        extra_question = valid_response()
        extra_question["answers"]["unexpected"] = copy.deepcopy(extra_question["answers"]["evidence"])
        cases.append(extra_question)

        wrong_answer_type = valid_response()
        wrong_answer_type["answers"]["evidence"]["type"] = "score"
        cases.append(wrong_answer_type)

        missing_probability = valid_response()
        del missing_probability["answers"]["domain"]["probabilities"]["capture"]
        cases.append(missing_probability)

        nan_probability = valid_response()
        nan_probability["answers"]["evidence"]["probabilities"]["sufficient"] = float("nan")
        cases.append(nan_probability)

        huge_probability = valid_response()
        huge_probability["answers"]["evidence"]["probabilities"]["sufficient"] = 10**1000
        cases.append(huge_probability)

        negative_probability = valid_response()
        negative_probability["answers"]["evidence"]["probabilities"]["sufficient"] = -0.1
        negative_probability["answers"]["evidence"]["probabilities"]["unknown"] = 1.1
        cases.append(negative_probability)

        bad_sum = valid_response()
        bad_sum["answers"]["scope"]["probabilities"]["parameter_patch"] = 0.9
        cases.append(bad_sum)

        non_maximal_choice = valid_response()
        probabilities = non_maximal_choice["answers"]["domain"]["probabilities"]
        probabilities["capture"] = 0.1
        probabilities["geometry"] = 0.9
        non_maximal_choice["answers"]["domain"]["choice"] = "capture"
        cases.append(non_maximal_choice)

        bool_confidence = valid_response()
        bool_confidence["answers"]["scope"]["confidence"] = True
        cases.append(bool_confidence)

        bool_usage = valid_response()
        bool_usage["usage"]["input_tokens"] = True
        cases.append(bool_usage)

        negative_usage = valid_response()
        negative_usage["usage"]["output_tokens"] = -1
        cases.append(negative_usage)

        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(client.ProviderError):
                    client.validate_response(value)

    def test_duplicate_json_fields_are_rejected_without_body_in_error(self):
        response = valid_response()
        body = json.dumps(response, separators=(",", ":"))
        body = body.replace(
            '"model":"' + client.MODEL + '"',
            '"model":"' + client.MODEL + '","model":"provider-secret"',
            1,
        ).encode()
        with mock.patch.object(client, "_open_request", return_value=_FakeResponse(body)):
            with self.assertRaises(client.ProviderError) as raised:
                client.evaluate({}, "secret-api-key", timeout=1.0)
        self.assertNotIn("provider-secret", str(raised.exception))
        self.assertNotIn("secret-api-key", str(raised.exception))

    def test_deeply_nested_json_is_rejected_as_provider_error(self):
        body = (b"[" * 10000) + (b"]" * 10000)
        with mock.patch.object(client, "_open_request", return_value=_FakeResponse(body)):
            with self.assertRaises(client.ProviderError):
                client.evaluate({}, "secret-api-key", timeout=1.0)

    def test_missing_key_and_oversized_input_never_open_transport(self):
        with mock.patch.object(client, "_open_request") as opened:
            with self.assertRaises(client.ProviderError):
                client.evaluate({}, "   ")
            opened.assert_not_called()

        with mock.patch.object(client, "_open_request") as opened:
            with self.assertRaises(client.ProviderError):
                client.evaluate({"blob": "x" * (48 * 1024)}, "secret-api-key")
            opened.assert_not_called()

    def test_request_size_limit_accepts_exact_48kib_and_rejects_one_more(self):
        maximum = client._MAX_REQUEST_BYTES
        fixed_size = len(client._serialize_request({"blob": ""}))
        blob_size = maximum - fixed_size
        exact_state = {"blob": "x" * blob_size}
        self.assertEqual(len(client._serialize_request(exact_state)), maximum)
        response = _FakeResponse(json.dumps(valid_response()).encode("utf-8"))
        with mock.patch.object(client, "_open_request", return_value=response) as opened:
            client.evaluate(exact_state, "synthetic-test-key", timeout=1.0)
        opened.assert_called_once()
        self.assertTrue(response.closed)

        with mock.patch.object(client, "_open_request") as opened:
            with self.assertRaises(client.ProviderError):
                client.evaluate({"blob": "x" * (blob_size + 1)}, "synthetic-test-key", timeout=1.0)
            opened.assert_not_called()

    def test_provider_errors_are_bounded_and_do_not_echo_body_or_key(self):
        secret_body = b'{"error":"api-key=secret-api-key"'
        response = _FakeResponse(secret_body)
        with mock.patch.object(client, "_open_request", return_value=response):
            with self.assertRaises(client.ProviderError) as raised:
                client.evaluate({}, "secret-api-key", timeout=1.0)
        self.assertNotIn("secret-api-key", str(raised.exception))
        self.assertNotIn(secret_body.decode(), str(raised.exception))
        self.assertTrue(response.closed)

        redirect = _FakeResponse(b"redirect body with secret-api-key", status=302, headers={"Location": "https://evil.invalid/secret-api-key"})
        with mock.patch.object(client, "_open_request", return_value=redirect):
            with self.assertRaises(client.ProviderError) as raised:
                client.evaluate({}, "secret-api-key", timeout=1.0)
        self.assertNotIn("secret-api-key", str(raised.exception))
        self.assertTrue(redirect.closed)

    def test_streamed_reads_obey_total_deadline(self):
        clock = [100.0]

        def monotonic():
            return clock[0]

        class SlowResponse(_FakeResponse):
            def read(self, size=-1):
                clock[0] = 102.0
                return super().read(size)

        with mock.patch.object(client.time, "monotonic", side_effect=monotonic):
            with mock.patch.object(client, "_open_request", return_value=SlowResponse(json.dumps(valid_response()).encode())):
                with self.assertRaises(client.ProviderError) as raised:
                    client.evaluate({}, "secret-api-key", timeout=1.0)
        self.assertNotIn("secret-api-key", str(raised.exception))

    def test_redirect_handler_refuses_redirect_without_echoing_target(self):
        request = urllib.request.Request(client._ENDPOINT, data=b"{}", method="POST")
        target = "https://evil.invalid/secret-api-key"
        with self.assertRaises(client.ProviderError) as raised:
            client._NoRedirectHandler().redirect_request(request, None, 302, "Found", {}, target)
        self.assertNotIn(target, str(raised.exception))



def tearDownModule():
    if _TEST_HOME is not None and _TEST_HOME.exists():
        shutil.rmtree(_TEST_HOME, ignore_errors=True)

if __name__ == "__main__":
    unittest.main()
