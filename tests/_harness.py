"""Link source imports without changing another test's paths, modules or HOME."""
from contextlib import contextmanager
import importlib
import os
from pathlib import Path
import sys
import tempfile
from unittest import mock


@contextmanager
def linked_harness():
    plugin = Path(__file__).resolve().parents[1]
    harness = Path(os.environ.get("IMG2_HARNESS_DIR", plugin.parent / "img2")).resolve()
    with tempfile.TemporaryDirectory(prefix="jev-test-import-") as temporary:
        home = Path(temporary)
        (home / "harness").symlink_to(harness, target_is_directory=True)
        # Replace the path list object for this import scope; never delete
        # shared modules or remove a peer's path entry by value/position.
        with mock.patch.object(sys, "path", [str(plugin / "tools"), str(harness), *sys.path]), \
                mock.patch.dict(os.environ, {"IMG2_HOME": str(home)}):
            # Import the package from its canonical path before production's
            # legacy bootstrap prepends the disposable home symlink. Its lazy
            # submodule __path__ must remain valid after this scope ends.
            importlib.import_module("img2_core")
            yield
