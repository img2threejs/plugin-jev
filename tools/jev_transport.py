import os, sys
root = os.environ.get("IMG2_HOME")
if root: sys.path.insert(0, os.path.join(root, "harness"))
else:
    try: import _img2_local; sys.path.insert(0, _img2_local.CORE)
    except ImportError: sys.exit("img2: core not linked - run `img2 sync`")
from img2_core import require_core_api
require_core_api(1)

import math
import subprocess
import threading
import time
from pathlib import Path
from jev_client import ProviderError, evaluate, validate_response
from jev_checkpoint_client import evaluate as evaluate_checkpoint, validate_response as validate_checkpoint_response
from jev_contracts import canonical, decode, validate_state


def _run_worker(argv, env, payload, timeout):
    """Bound both pipes while waiting; never buffer an untrusted child's full output."""
    deadline = time.monotonic() + timeout
    failed = threading.Event()
    stdout = []
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    except OSError:
        raise ProviderError("provider worker could not start") from None

    def terminate():
        try:
            process.kill()
        except OSError:
            pass

    def drain(pipe, limit, retained):
        size = 0
        try:
            while chunk := pipe.read1(4096):
                size += len(chunk)
                if size > limit:
                    failed.set()
                    terminate()
                    return
                if retained is not None:
                    retained.append(chunk)
        except OSError:
            failed.set()
            terminate()

    def feed():
        try:
            process.stdin.write(payload)
            process.stdin.close()
        except (OSError, ValueError):
            failed.set()
            terminate()

    threads = [
        threading.Thread(target=drain, args=(process.stdout, 131072, stdout), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, 65536, None), daemon=True),
        threading.Thread(target=feed, daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        process.wait(timeout=max(0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        failed.set()
        terminate()
        process.wait()
    finally:
        for thread in threads:
            thread.join()
        for pipe in (process.stdin, process.stdout, process.stderr):
            pipe.close()
    if failed.is_set() or process.returncode != 0 or time.monotonic() > deadline:
        raise ProviderError("provider worker failed, expired or exceeded output limits")
    return b"".join(stdout)


def evaluate_bounded(state, api_key, timeout=15.0):
    """Kill the network worker on expiry, including stalled DNS and response headers."""
    validate_state(state)
    if type(timeout) not in (int, float) or not 0 < timeout <= 30 or not math.isfinite(timeout):
        raise ProviderError("invalid timeout")
    env = {key: os.environ[key] for key in ("PATH", "HOME", "LANG", "LC_ALL", "IMG2_HOME") if key in os.environ}
    env["TYPESAFE_API_KEY"] = api_key
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    output = _run_worker(
        [sys.executable, str(Path(__file__).resolve()), "--worker", str(timeout)],
        env, canonical(state), timeout,
    )
    try:
        return validate_response(decode(output))
    except (ValueError, RecursionError, OverflowError):
        raise ProviderError("invalid provider response") from None


def evaluate_checkpoint_bounded(projection, api_key, timeout=15.0):
    from jev_checkpoint import validate_checkpoint_projection
    validate_checkpoint_projection(projection)
    if type(timeout) not in (int, float) or not 0 < timeout <= 30 or not math.isfinite(timeout):
        raise ProviderError("invalid timeout")
    env = {key: os.environ[key] for key in ("PATH", "HOME", "LANG", "LC_ALL", "IMG2_HOME") if key in os.environ}
    env["TYPESAFE_API_KEY"] = api_key
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    output = _run_worker([sys.executable, str(Path(__file__).resolve()), "--checkpoint-worker", str(timeout)], env, canonical(projection), timeout)
    try:
        return validate_checkpoint_response(decode(output))
    except (ValueError, RecursionError, OverflowError):
        raise ProviderError("invalid checkpoint response") from None


def worker():
    try:
        if len(sys.argv) != 3 or sys.argv[1] not in {"--worker", "--checkpoint-worker"}:
            return 2
        incoming = decode(sys.stdin.buffer.read(131073))
        if sys.argv[1] == "--checkpoint-worker":
            from jev_checkpoint import validate_checkpoint_projection
            validate_checkpoint_projection(incoming)
            result = evaluate_checkpoint(incoming, os.environ.get("TYPESAFE_API_KEY", ""), timeout=float(sys.argv[2]))
            result = validate_checkpoint_response(result)
        else:
            state = validate_state(incoming)
            result = evaluate(state, os.environ.get("TYPESAFE_API_KEY", ""), timeout=float(sys.argv[2]))
        sys.stdout.buffer.write(canonical(result) + b"\n")
        return 0
    except Exception:
        # Parent exposes a stable error code, never stderr or provider response text.
        return 2


if __name__ == "__main__":
    raise SystemExit(worker())
