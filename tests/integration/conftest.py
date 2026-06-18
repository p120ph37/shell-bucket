"""Docker-backed integration test fixtures.

Starts a session-scoped `linuxserver/openssh-server` container; tests reach it
by wrapping the system `ssh` (via `sshpass` for the password) under the generic
PTY transport — exactly as `shell-bucket wrap -- ssh …` would. Skips cleanly if
Docker (or sshpass) isn't available.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass

import pytest

_IMAGE = "linuxserver/openssh-server:latest"
_USER = "testuser"
_PASSWORD = "testpw123"
_READY_TIMEOUT_S = 90.0


@dataclass(frozen=True)
class SSHServer:
    host: str
    port: int
    user: str
    password: str


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    result = subprocess.run(["docker", "info"], capture_output=True)
    return result.returncode == 0


def _wait_ready(host: str, port: int) -> None:
    """Poll until sshd answers with an SSH banner (no asyncssh needed)."""
    deadline = time.monotonic() + _READY_TIMEOUT_S
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2) as s:
                s.settimeout(2)
                banner = s.recv(64)
                if banner.startswith(b"SSH-"):
                    return
        except OSError as e:
            last_err = e
        time.sleep(1.0)
    raise TimeoutError(
        f"SSH server at {host}:{port} did not become ready in {_READY_TIMEOUT_S}s "
        f"(last error: {last_err!r})"
    )


@pytest.fixture(scope="session")
def ssh_server() -> Iterator[SSHServer]:
    if not _docker_available():
        pytest.skip("Docker not available (run `docker info` to diagnose)")

    port = _free_port()
    run = subprocess.run(
        [
            "docker", "run", "-d", "--rm",
            "-e", f"USER_NAME={_USER}",
            "-e", f"USER_PASSWORD={_PASSWORD}",
            "-e", "PASSWORD_ACCESS=true",
            "-p", f"{port}:2222",
            _IMAGE,
        ],
        capture_output=True,
        text=True,
    )
    if run.returncode != 0:
        pytest.fail(f"docker run failed: {run.stderr.strip()}")
    container_id = run.stdout.strip()

    try:
        _wait_ready("127.0.0.1", port)
        yield SSHServer(host="127.0.0.1", port=port, user=_USER, password=_PASSWORD)
    finally:
        subprocess.run(["docker", "kill", container_id], capture_output=True)
