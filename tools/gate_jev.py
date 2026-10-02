import os, sys
root = os.environ.get("IMG2_HOME")
if root: sys.path.insert(0, os.path.join(root, "harness"))
else:
    try: import _img2_local; sys.path.insert(0, _img2_local.CORE)
    except ImportError: sys.exit("img2: core not linked - run `img2 sync`")
from img2_core import require_core_api
require_core_api(1)

import argparse
from img2_core.paths import resolve_workspace
from jev import REPORT_PATH, emit, validate_report
from jev_contracts import ContractError, read_json
from jev_client import ProviderError
from jev_consent import ConsentError


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify Jev recommendation integrity, never scene quality.")
    parser.add_argument("--workspace", default=None)
    args = parser.parse_args(argv)
    evidence = {"artifact": REPORT_PATH, "verification": "artifact-integrity-only", "acceptanceAuthority": False}
    try:
        workspace = resolve_workspace(args.workspace)
        report = read_json(workspace, REPORT_PATH)
        validate_report(workspace, report)
        evidence.update(recommendationId=report["id"], mode=report["mode"], providerStatus=report["provider"]["status"])
        status, code, reasons = "pass", 0, []
    except FileNotFoundError:
        status, code, reasons = "fail", 1, ["recommendation or bound evidence is missing"]
    except (ContractError, ProviderError, ConsentError):
        status, code, reasons = "fail", 1, ["recommendation is stale, malformed or violates advisory policy"]
    except (OSError, ValueError, RuntimeError, TypeError, KeyError, OverflowError):
        status, code, reasons = "error", 2, ["could not verify local recommendation artifact"]
    emit({"kind": "img2.gate-verdict", "version": 1, "gate": "jev-recommendation-integrity", "plugin": "jev", "status": status, "reasons": reasons, "evidence": evidence})
    return code


if __name__ == "__main__":
    raise SystemExit(main())
