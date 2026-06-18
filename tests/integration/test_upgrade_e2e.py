"""End-to-end UDP-backhaul UPGRADE: wrapper-side ↔ a real `sb` mux upgrade.

Runs the wrapper-side driver and a real `sb __upgradeserve` in one Linux container
(loopback UDP, so the punch trivially succeeds and no Docker host↔container UDP is
needed), exercising the full in-band-signaled offer→answer→punch→frames-over-UDP
path. See upgrade_e2e_driver.py.
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
# The instrumented binary (dist-test/, SB_TEST=1): `__upgradeserve` lives only
# there — production (dist/) strips the self-test hooks.
_SB = _REPO / f"native/sb/dist-test/linux_{_ARCH}/sb"


def _docker_ok() -> bool:
    return shutil.which("docker") is not None and (
        subprocess.run(["docker", "info"], capture_output=True).returncode == 0
    )


def test_udp_backhaul_upgrade_e2e() -> None:
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
            "python3 /work/tests/integration/upgrade_e2e_driver.py",
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert "UPGRADE-E2E: OK" in r.stdout, (
        f"rc={r.returncode}\nstdout={r.stdout!r}\nstderr={r.stderr[-1200:]!r}"
    )
