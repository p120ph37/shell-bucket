"""TOFU (trust-on-first-use) host-key store for shell-bucket."""

from __future__ import annotations

from pathlib import Path

import asyncssh


class TOFUStore:
    """OpenSSH-format host-key file with trust-on-first-use semantics."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def _read_entries(self) -> list[tuple[str, asyncssh.SSHKey]]:
        if not self.path.exists():
            return []
        entries: list[tuple[str, asyncssh.SSHKey]] = []
        for raw in self.path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                host, key_type, key_b64 = line.split(maxsplit=2)
                key = asyncssh.import_public_key(f"{key_type} {key_b64}".encode())
            except (ValueError, asyncssh.KeyImportError):
                continue
            entries.append((host, key))
        return entries

    def lookup(self, host: str) -> list[asyncssh.SSHKey]:
        return [k for h, k in self._read_entries() if h == host]

    def add(self, host: str, key: asyncssh.SSHKey) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = key.export_public_key().decode().strip()
        with self.path.open("a") as f:
            f.write(f"{host} {line}\n")

    def validate(self, host: str, key: asyncssh.SSHKey) -> bool:
        """TOFU policy.

        - Host unknown: record and accept.
        - Host known + key matches: accept.
        - Host known + key mismatch: reject.
        """
        known = self.lookup(host)
        if not known:
            self.add(host, key)
            return True
        return any(k == key for k in known)
