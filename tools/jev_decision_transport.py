"""Real TypeSafe HTTPS transport, isolated to enforce a total wall-clock deadline.

No environment proxies, redirects, retries, global credentials or provider-body
errors. Images arrive explicitly prepared after consent; multipart sends only
wire asset fields, never filenames, transforms or local paths. Oversize requests
are rejected before I/O; the controller must journal any split as a new attempt.
"""

import base64
import binascii
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading
import time


_HOST = "api.typesafe.ai"
_PATH = "/v1/systemone"
_MAX_REQUEST_BYTES = 32 * 1024 * 1024
_MAX_RESPONSE_BYTES = 256 * 1024
_MAX_IMAGE_BYTES = 16 * 1024 * 1024
_CHUNK = 16 * 1024
_REASONS = frozenset({
    "invalid-request", "invalid-credential", "invalid-timeout", "request-too-large",
    "response-too-large", "invalid-response", "credential-rejected", "provider-timeout",
    "provider-error", "provider-redirect-refused", "provider-unavailable",
})


class DecisionTransportError(RuntimeError):
    """Only allowlisted codes, never a credential, URL, exception or response body."""

    def __init__(self, reason_code):
        self.reason_code = reason_code if isinstance(reason_code, str) and reason_code in _REASONS else "provider-error"
        super().__init__(self.reason_code)


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise DecisionTransportError("provider-timeout")
    return remaining


def _json_bytes(value):
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        raise DecisionTransportError("invalid-request") from None


def _encode_request(payload):
    if not isinstance(payload, dict):
        raise DecisionTransportError("invalid-request")
    assets = payload.get("assets", {})
    if not isinstance(assets, dict):
        raise DecisionTransportError("invalid-request")
    questions = payload.get("questions", {})
    images = bool(assets) or (isinstance(questions, dict) and any(
        isinstance(q, dict) and q.get("type") == "box" for q in questions.values()))
    if not assets:
        body = _json_bytes(payload)
        if len(body) > _MAX_REQUEST_BYTES:
            raise DecisionTransportError("request-too-large")
        return body, "application/json", images

    wire = dict(payload)
    wire["assets"] = {}
    files = []
    total = 0
    if any(not isinstance(key, str) for key in assets):
        raise DecisionTransportError("invalid-request")
    for index, (reference, asset) in enumerate(sorted(assets.items())):
        if (not isinstance(reference, str) or not reference.strip()
                or not isinstance(asset, dict)
                or set(asset) - {"type", "format", "data_base64"}
                or asset.get("type", "image") != "image"
                or asset.get("format") not in ("png", "jpg", "jpeg")
                or not isinstance(asset.get("data_base64"), str)):
            raise DecisionTransportError("invalid-request")
        encoded = asset["data_base64"]
        if len(encoded) > 4 * ((_MAX_IMAGE_BYTES + 2) // 3):
            raise DecisionTransportError("request-too-large")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise DecisionTransportError("invalid-request") from None
        if not data or len(data) > _MAX_IMAGE_BYTES:
            raise DecisionTransportError("request-too-large")
        total += len(data)
        if total > _MAX_REQUEST_BYTES:
            raise DecisionTransportError("request-too-large")
        part = "image-" + str(index)
        fmt = asset["format"]
        wire["assets"][reference] = {"type": "image", "part": part, "format": fmt}
        files.append((part, "image/png" if fmt == "png" else "image/jpeg", data))
    request = _json_bytes(wire)
    # Content-addressed framing is stable across identical calls and cannot
    # accidentally be interpreted inside any part (check and extend if needed).
    digest = hashlib.sha256(request)
    for _, _, data in files:
        digest.update(data)
    boundary = ("img2-" + digest.hexdigest()).encode("ascii")
    while boundary in request or any(boundary in data for _, _, data in files):
        boundary += b"x"
    parts = [b"--" + boundary + b'\r\nContent-Disposition: form-data; name="request"\r\n'
             b"Content-Type: application/json\r\n\r\n" + request + b"\r\n"]
    for part, content_type, data in files:
        parts.append(b"--" + boundary + b'\r\nContent-Disposition: form-data; name="'
                     + part.encode("ascii") + b'"; filename="image"\r\nContent-Type: '
                     + content_type.encode("ascii") + b"\r\n\r\n" + data + b"\r\n")
    parts.append(b"--" + boundary + b"--\r\n")
    if sum(map(len, parts)) > _MAX_REQUEST_BYTES:
        raise DecisionTransportError("request-too-large")
    return b"".join(parts), "multipart/form-data; boundary=" + boundary.decode("ascii"), images


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _constant(_value):
    raise ValueError


def _float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError
    return result


def _decode_response(data):
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=_constant, parse_float=_float)
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise DecisionTransportError("invalid-response") from None


def _post_https(body, api_key, content_type, images, deadline):
    """Network implementation used by the disposable worker (also stub-testable)."""
    connection = None
    response = None
    try:
        # http.client never consults proxy variables and never follows redirects.
        connection = http.client.HTTPSConnection(
            _HOST, timeout=_remaining(deadline), context=ssl.create_default_context())
        headers = {"Authorization": "Bearer " + api_key, "Content-Type": content_type,
                   "Accept": "application/json", "Accept-Encoding": "identity"}
        if images:
            headers["TypeSafe-Danger-Zone-Images"] = "true"
        connection.request("POST", _PATH, body=body, headers=headers)
        response = connection.getresponse()
        _remaining(deadline)
        if response.status in (401, 403):
            raise DecisionTransportError("credential-rejected")
        if 300 <= response.status < 400:
            raise DecisionTransportError("provider-redirect-refused")
        if response.status == 413:
            raise DecisionTransportError("request-too-large")
        if not 200 <= response.status < 300:
            raise DecisionTransportError("provider-error")
        encoding = response.getheader("Content-Encoding", "identity")
        if encoding.lower() != "identity":
            raise DecisionTransportError("invalid-response")
        length = response.getheader("Content-Length")
        if length is not None:
            try:
                size = int(length)
            except (TypeError, ValueError):
                raise DecisionTransportError("invalid-response") from None
            if size < 0:
                raise DecisionTransportError("invalid-response")
            if size > _MAX_RESPONSE_BYTES:
                raise DecisionTransportError("response-too-large")
        chunks, total = [], 0
        while True:
            remaining = _remaining(deadline)
            if connection.sock is not None:
                connection.sock.settimeout(remaining)
            chunk = response.read1(min(_CHUNK, _MAX_RESPONSE_BYTES + 1 - total))
            _remaining(deadline)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_RESPONSE_BYTES:
                raise DecisionTransportError("response-too-large")
            chunks.append(chunk)
        if length is not None and total != size:
            raise DecisionTransportError("invalid-response")
        return _decode_response(b"".join(chunks))
    except DecisionTransportError:
        raise
    except (TimeoutError, socket.timeout):
        raise DecisionTransportError("provider-timeout") from None
    except Exception:
        raise DecisionTransportError("provider-error") from None
    finally:
        for resource in (response, connection):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    pass


def _run_worker(data, deadline):
    """Bound both pipes, and kill the child even on stalled DNS/header trickling."""
    env = {key: value for key, value in os.environ.items() if key != "TYPESAFE_API_KEY"}
    try:
        process = subprocess.Popen(
            [sys.executable, "-I", str(Path(__file__).resolve()), "--worker"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    except OSError:
        raise DecisionTransportError("provider-unavailable") from None
    overflow = threading.Event()
    failed = threading.Event()
    output = []

    def kill():
        try:
            process.kill()
        except OSError:
            pass

    def drain(pipe, retained):
        total = 0
        try:
            while True:
                chunk = pipe.read(_CHUNK)
                if not chunk:
                    return
                total += len(chunk)
                if total > _MAX_RESPONSE_BYTES + 1024:
                    overflow.set()
                    kill()
                    return
                if retained is not None:
                    retained.append(chunk)
        except (OSError, ValueError):
            failed.set()
            kill()

    def feed():
        try:
            process.stdin.write(data)
            process.stdin.close()
        except (OSError, ValueError):
            failed.set()
            kill()

    threads = [threading.Thread(target=drain, args=(process.stdout, output), daemon=True),
               threading.Thread(target=drain, args=(process.stderr, None), daemon=True),
               threading.Thread(target=feed, daemon=True)]
    for thread in threads:
        thread.start()
    expired = False
    try:
        process.wait(timeout=_remaining(deadline))
    except (subprocess.TimeoutExpired, DecisionTransportError):
        expired = True
        kill()
    finally:
        process.wait()
        for thread in threads:
            thread.join(timeout=max(0, deadline - time.monotonic()))
        for pipe in (process.stdin, process.stdout, process.stderr):
            try:
                pipe.close()
            except (OSError, ValueError):
                pass
    if expired or time.monotonic() >= deadline:
        raise DecisionTransportError("provider-timeout")
    if overflow.is_set():
        raise DecisionTransportError("response-too-large")
    if failed.is_set() or process.returncode != 0:
        raise DecisionTransportError("provider-error")
    result = _decode_response(b"".join(output))
    if set(result) == {"error"}:
        raise DecisionTransportError(result["error"])
    if set(result) != {"response"} or not isinstance(result["response"], dict):
        raise DecisionTransportError("invalid-response")
    return result["response"]


def post_systemone(payload, api_key, *, timeout=15.0):
    """POST the full payload to TypeSafe, with one non-renewable total deadline."""
    if (not isinstance(api_key, str) or not api_key or len(api_key) > 4096
            or api_key != api_key.strip() or any(ord(c) < 33 or ord(c) > 126 for c in api_key)):
        raise DecisionTransportError("invalid-credential")
    try:
        valid_timeout = (not isinstance(timeout, bool) and isinstance(timeout, (int, float))
                         and math.isfinite(timeout) and timeout > 0)
    except OverflowError:
        valid_timeout = False
    if not valid_timeout:
        raise DecisionTransportError("invalid-timeout")
    deadline = time.monotonic() + timeout
    body, content_type, images = _encode_request(payload)
    metadata = _json_bytes({"apiKey": api_key, "contentType": content_type,
                            "images": images, "deadline": deadline})
    _remaining(deadline)
    return _run_worker(metadata + b"\n" + body, deadline)


def _worker():
    try:
        line = sys.stdin.buffer.readline(16385)
        if len(line) > 16384 or not line.endswith(b"\n"):
            raise DecisionTransportError("invalid-request")
        metadata = _decode_response(line)
        body = sys.stdin.buffer.read(_MAX_REQUEST_BYTES + 1)
        if len(body) > _MAX_REQUEST_BYTES:
            raise DecisionTransportError("request-too-large")
        response = _post_https(body, metadata["apiKey"], metadata["contentType"],
                               metadata["images"], metadata["deadline"])
        result = {"response": response}
    except DecisionTransportError as error:
        result = {"error": error.reason_code}
    except Exception:
        result = {"error": "provider-error"}
    sys.stdout.buffer.write(_json_bytes(result))
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--worker"]:
        raise SystemExit(_worker())
    raise SystemExit(2)
