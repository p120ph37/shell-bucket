"""Live cross-implementation interop: the Python backhaul transport vs native `sb`.

Runs both in one Linux container (the host may be macOS, and `sb` is a static
musl Linux binary), driving the Python ARQ/punch against `sb __arqrecv`/
`__punchrecv` over real UDP. The capstone proof that the two transports are
byte-for-byte wire-compatible. See cross_impl_driver.py for the driver.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

_REPO = Path(__file__).resolve().parents[2]
_ARCH = "arm64" if platform.machine() in ("arm64", "aarch64") else "amd64"
# The instrumented binary (dist-test/, SB_TEST=1): the `__arqrecv`/`__punchrecv`
# hooks this driver needs exist ONLY there — production (dist/) strips them.
_SB = _REPO / f"native/sb/dist-test/linux_{_ARCH}/sb"


def _docker_ok() -> bool:
    return shutil.which("docker") is not None and (
        subprocess.run(["docker", "info"], capture_output=True).returncode == 0
    )


def test_python_sb_wire_compatible() -> None:
    if not _docker_ok():
        pytest.skip("Docker not available")
    if not _SB.exists():
        pytest.skip(f"no {_SB}; run native/sb/check.sh")
    r = subprocess.run(
        [
            "docker", "run", "--rm", "--platform", f"linux/{_ARCH}",
            "-v", f"{_REPO}:/work:ro",
            "-v", f"{_SB}:/b/sb:ro",
            "python:3.12-alpine", "sh", "-c",
            "pip install --quiet --break-system-packages cryptography && "
            "python3 /work/tests/integration/cross_impl_driver.py",
        ],
        capture_output=True,
        text=True,
        timeout=420,
    )
    assert "CROSS-IMPL: all OK" in r.stdout, (
        f"rc={r.returncode}\nstdout={r.stdout!r}\nstderr={r.stderr[-1000:]!r}"
    )
