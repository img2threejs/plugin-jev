"""Exercise real HTTP framing/worker code against local socket/process stubs only."""

import base64
from email import policy
from email.parser import BytesParser
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
import unittest
from unittest import mock
import zlib


_PATH = Path(__file__).resolve().parents[1] / "tools/jev_decision_transport.py"
_SPEC = importlib.util.spec_from_file_location("decision_transport_test", _PATH)
transport = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(transport)
_SECRET = "synthetic-secret-never-in-errors"
_ANSWER = {"model": "jev-1.14.0", "answers": {},
           "usage": {"input_tokens": 3, "output_tokens": 2}}


def png():
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 280, 280, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress((b"\x00" + b"\xff\x00\x00" * 280) * 280))
            + chunk(b"IEND", b""))


def payload(images=False):
    result = {"model": "jev-1.14.0", "state": {"id": "object-a"},
              "questions": {"anyFits": {"type": "noul", "instructions": "Any option fits?"}}}
    if images:
        result["state"]["reference"] = "asset-unique-reference"
        result["assets"] = {"asset-unique-reference": {
            "type": "image", "format": "png", "data_base64": base64.b64encode(png()).decode("ascii")}}
    return result


class StubSocket:
    def __init__(self, response):
        self.response = response
        self.sent = []
        self.closed = False
        self.timeouts = []

    def setsockopt(self, *args):
        pass

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def sendall(self, data):
        self.sent.append(bytes(data))

    def makefile(self, mode):
        return io.BytesIO(self.response)

    def close(self):
        self.closed = True


class DecisionTransportTests(unittest.TestCase):
    def raw_response(self, body=None, status=200, headers=None):
        body = json.dumps(_ANSWER).encode() if body is None else body
        headers = {"Content-Length": str(len(body)), **(headers or {})}
        return (f"HTTP/1.1 {status} Local stub\r\n".encode()
                + b"".join(f"{key}: {value}\r\n".encode() for key, value in headers.items())
                + b"\r\n" + body)

    def request(self, raw, request=None):
        stub = StubSocket(raw)
        body, content_type, images = transport._encode_request(request or payload())
        with mock.patch.object(transport.socket, "create_connection", return_value=stub) as connect, \
                mock.patch.object(transport.ssl.SSLContext, "wrap_socket", return_value=stub) as tls:
            result = transport._post_https(body, _SECRET, content_type, images,
                                           time.monotonic() + 5)
        connect.assert_called_once()
        self.assertEqual(connect.call_args.args[0], ("api.typesafe.ai", 443))
        self.assertEqual(tls.call_args.kwargs["server_hostname"], "api.typesafe.ai")
        self.assertTrue(stub.closed)
        return result, b"".join(stub.sent)

    def assertReason(self, reason, call):
        with self.assertRaises(transport.DecisionTransportError) as caught:
            call()
        self.assertEqual(caught.exception.reason_code, reason)
        self.assertEqual(str(caught.exception), reason)
        self.assertNotIn(_SECRET, str(caught.exception))

    def test_real_http_implementation_posts_json_to_pinned_https_host(self):
        result, wire = self.request(self.raw_response())
        self.assertEqual(result, _ANSWER)
        headers, body = wire.split(b"\r\n\r\n", 1)
        self.assertTrue(headers.startswith(b"POST /v1/systemone HTTP/1.1\r\n"))
        self.assertIn(b"Host: api.typesafe.ai", headers)
        self.assertIn(("Authorization: Bearer " + _SECRET).encode(), headers)
        self.assertNotIn(b"TypeSafe-Danger-Zone-Images", headers)
        self.assertEqual(json.loads(body), payload())

    def test_environment_proxies_are_not_consulted(self):
        with mock.patch.dict(os.environ, {
                "https_proxy": "http://proxy.invalid:666", "HTTPS_PROXY": "http://proxy.invalid:666",
                "ALL_PROXY": "socks5://proxy.invalid:666", "no_proxy": ""}):
            result, _ = self.request(self.raw_response())
        self.assertEqual(result, _ANSWER)

    def test_images_use_header_and_real_multipart_bytes_without_mutating_input(self):
        source = payload(images=True)
        original = json.dumps(source, sort_keys=True)
        result, wire = self.request(self.raw_response(), source)
        self.assertEqual(result, _ANSWER)
        headers, body = wire.split(b"\r\n\r\n", 1)
        self.assertIn(b"TypeSafe-Danger-Zone-Images: true", headers)
        mime_headers = headers.split(b"\r\n", 1)[1]
        message = BytesParser(policy=policy.default).parsebytes(mime_headers + b"\r\n\r\n" + body)
        parts = list(message.iter_parts())
        self.assertEqual(len(parts), 2)
        self.assertEqual(parts[0].get_param("name", header="content-disposition"), "request")
        request = json.loads(parts[0].get_payload(decode=True))
        self.assertEqual(request["assets"]["asset-unique-reference"],
                         {"type": "image", "format": "png", "part": "image-0"})
        self.assertEqual(parts[1].get_payload(decode=True), png())
        self.assertEqual(parts[1].get_content_type(), "image/png")
        self.assertNotIn(b"data_base64", body)
        self.assertEqual(json.dumps(source, sort_keys=True), original)
        self.assertEqual(transport._encode_request(source), transport._encode_request(source))

    def test_box_enables_header_even_without_assets(self):
        request = payload()
        request["questions"] = {"target": {"type": "box", "instructions": "Target"}}
        _, wire = self.request(self.raw_response(), request)
        self.assertIn(b"TypeSafe-Danger-Zone-Images: true", wire)

    def test_credentials_rejections_are_distinct_and_error_bodies_are_not_read(self):
        for status, reason in ((401, "credential-rejected"), (403, "credential-rejected"),
                               (400, "provider-error"), (429, "provider-error"),
                               (500, "provider-error"), (413, "request-too-large")):
            with self.subTest(status=status):
                self.assertReason(reason, lambda: self.request(self.raw_response(
                    body=_SECRET.encode(), status=status)))

    def test_redirects_are_never_followed(self):
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                self.assertReason("provider-redirect-refused", lambda: self.request(
                    self.raw_response(status=status, headers={"Location": "https://evil.invalid/" + _SECRET})))

    def test_header_and_stream_oversize_are_rejected(self):
        self.assertReason("response-too-large", lambda: self.request(self.raw_response(
            headers={"Content-Length": str(transport._MAX_RESPONSE_BYTES + 1)})))
        raw = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + b"x" * (transport._MAX_RESPONSE_BYTES + 1)
        self.assertReason("response-too-large", lambda: self.request(raw))

    def test_invalid_json_lengths_and_compression_are_rejected(self):
        for body in (b"[]", b'{"a":1,"a":2}', b'{"a":NaN}', b"\xff", _SECRET.encode()):
            with self.subTest(body=body):
                self.assertReason("invalid-response", lambda: self.request(self.raw_response(body=body)))
        for headers in ({"Content-Length": "invalid"}, {"Content-Length": "-1"},
                        {"Content-Length": "10000"}, {"Content-Encoding": "gzip"}):
            with self.subTest(headers=headers):
                self.assertReason("invalid-response", lambda: self.request(self.raw_response(headers=headers)))

    def test_socket_errors_and_timeouts_are_sanitized(self):
        for error, reason in ((socket.timeout(_SECRET), "provider-timeout"),
                              (OSError(_SECRET), "provider-error")):
            with self.subTest(error=type(error)), mock.patch.object(
                    transport.http.client, "HTTPSConnection", side_effect=error):
                self.assertReason(reason, lambda: transport._post_https(
                    b"{}", _SECRET, "application/json", False, time.monotonic() + 5))

    def test_invalid_inputs_and_oversize_never_spawn_worker(self):
        with mock.patch.object(transport, "_run_worker") as worker:
            for key in ("", " abc", "abc\r\nInjected: value", "abc\x00", "é", None):
                self.assertReason("invalid-credential", lambda: transport.post_systemone(payload(), key))
            for timeout in (False, 0, -1, float("nan"), float("inf"), 10 ** 1000, "15"):
                self.assertReason("invalid-timeout", lambda: transport.post_systemone(
                    payload(), _SECRET, timeout=timeout))
            with mock.patch.object(transport, "_MAX_REQUEST_BYTES", 20):
                self.assertReason("request-too-large", lambda: transport.post_systemone(payload(), _SECRET))
                self.assertReason("request-too-large", lambda: transport.post_systemone(payload(True), _SECRET))
            invalid = payload(True)
            invalid["assets"]["asset-unique-reference"]["data_base64"] = "not base64!"
            self.assertReason("invalid-request", lambda: transport.post_systemone(invalid, _SECRET))
            invalid = payload(True)
            invalid["assets"]["asset-unique-reference"]["path"] = "/private/path"
            self.assertReason("invalid-request", lambda: transport.post_systemone(invalid, _SECRET))
            invalid = payload()
            invalid["state"]["nonfinite"] = float("nan")
            self.assertReason("invalid-request", lambda: transport.post_systemone(invalid, _SECRET))
        worker.assert_not_called()

    def test_error_constructor_never_accepts_arbitrary_body(self):
        for value in (_SECRET, {"secret": _SECRET}, [_SECRET], None):
            error = transport.DecisionTransportError(value)
            self.assertEqual(str(error), "provider-error")


# These snippets run in disposable local children. The production worker and
# HTTPS implementation remain real; only the network connection is replaced.
_CHILD_PREFIX = '''
import io, json, runpy, sys, time
namespace = runpy.run_path(sys.argv[1], run_name="local_transport_fixture")
class Response:
    status = 200
    def __init__(self): self.body = io.BytesIO(b'{"model":"jev-1.14.0","answers":{},"usage":{"input_tokens":3,"output_tokens":2}}')
    def getheader(self, key, default=None): return default
    def read1(self, size): return self.body.read(size)
    def close(self): pass
class Connection:
    sock = None
    def __init__(self, host, **kwargs): assert host == "api.typesafe.ai"
    def request(self, method, path, body, headers):
        assert method == "POST" and path == "/v1/systemone"
        assert headers["Authorization"] == "Bearer synthetic-secret-never-in-errors"
        assert headers["Content-Type"] == "application/json"
        assert json.loads(body)["model"] == "jev-1.14.0"
    def getresponse(self): return Response()
    def close(self): pass
namespace["http"].client.HTTPSConnection = Connection
'''


class WorkerBoundaryTests(unittest.TestCase):
    def spawn_stub(self, code):
        real_popen = subprocess.Popen

        def spawn(argv, **kwargs):
            self.assertEqual(argv, [sys.executable, "-I", str(_PATH), "--worker"])
            self.assertNotIn(_SECRET, repr(argv))
            self.assertNotIn("TYPESAFE_API_KEY", kwargs["env"])
            return real_popen([sys.executable, "-I", "-c", code, str(_PATH)], **kwargs)
        return mock.patch.object(transport.subprocess, "Popen", side_effect=spawn)

    def test_public_api_reaches_actual_worker_and_https_implementation(self):
        code = _CHILD_PREFIX + '\nraise SystemExit(namespace["_worker"]())\n'
        with self.spawn_stub(code), mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "unused-private-env-key"}):
            self.assertEqual(transport.post_systemone(payload(), _SECRET, timeout=5), _ANSWER)

    def test_total_deadline_kills_stalled_dns_header_and_trickling_body(self):
        setups = (
            'Connection.__init__ = lambda self, *a, **kw: time.sleep(10)',
            'Connection.getresponse = lambda self: (time.sleep(10), Response())[1]',
            'Response.read1 = lambda self, size: (time.sleep(0.04), b" ")[1]',
        )
        for setup in setups:
            with self.subTest(setup=setup):
                code = _CHILD_PREFIX + '\n' + setup + '\nnamespace["_worker"]()\n'
                started = time.monotonic()
                with self.spawn_stub(code):
                    with self.assertRaises(transport.DecisionTransportError) as caught:
                        transport.post_systemone(payload(), _SECRET, timeout=0.3)
                self.assertEqual(caught.exception.reason_code, "provider-timeout")
                self.assertNotIn(_SECRET, str(caught.exception))
                self.assertLess(time.monotonic() - started, 3)

    def test_credential_error_survives_worker_boundary(self):
        code = _CHILD_PREFIX + '\nResponse.status = 401\nnamespace["_worker"]()\n'
        with self.spawn_stub(code):
            with self.assertRaises(transport.DecisionTransportError) as caught:
                transport.post_systemone(payload(), _SECRET, timeout=5)
        self.assertEqual(caught.exception.reason_code, "credential-rejected")

    def test_excess_worker_output_is_killed_and_not_exposed(self):
        code = 'import os, sys; sys.stdin.buffer.read(); os.write(1, b"private" * 1000000)'
        with self.spawn_stub(code):
            with self.assertRaises(transport.DecisionTransportError) as caught:
                transport.post_systemone(payload(), _SECRET, timeout=5)
        self.assertEqual(caught.exception.reason_code, "response-too-large")
        self.assertNotIn("private", str(caught.exception))

    def test_worker_start_failure_has_no_exception_detail(self):
        with mock.patch.object(transport.subprocess, "Popen", side_effect=OSError(_SECRET)):
            with self.assertRaises(transport.DecisionTransportError) as caught:
                transport.post_systemone(payload(), _SECRET)
        self.assertEqual(str(caught.exception), "provider-unavailable")


if __name__ == "__main__":
    unittest.main()
