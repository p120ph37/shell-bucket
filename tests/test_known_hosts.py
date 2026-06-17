"""Unit tests for the TOFU known-hosts store."""

from __future__ import annotations

from pathlib import Path

import asyncssh
import pytest

from shell_bucket.known_hosts import TOFUStore


def _pubkey() -> asyncssh.SSHKey:
    """Fresh public-only SSHKey for tests."""
    priv = asyncssh.generate_private_key("ssh-ed25519")
    return asyncssh.import_public_key(priv.export_public_key())


def test_unknown_host_is_accepted_and_recorded(tmp_path: Path) -> None:
    store = TOFUStore(tmp_path / "known_hosts")
    key = _pubkey()
    assert store.validate("alpha.example.com", key) is True
    assert (tmp_path / "known_hosts").exists()


def test_known_matching_host_accepts_on_second_call(tmp_path: Path) -> None:
    store = TOFUStore(tmp_path / "known_hosts")
    key = _pubkey()
    store.validate("alpha.example.com", key)
    assert store.validate("alpha.example.com", key) is True


def test_known_host_with_mismatched_key_rejects(tmp_path: Path) -> None:
    store = TOFUStore(tmp_path / "known_hosts")
    first = _pubkey()
    second = _pubkey()
    assert store.validate("alpha.example.com", first) is True
    assert store.validate("alpha.example.com", second) is False


def test_entries_persist_across_store_instances(tmp_path: Path) -> None:
    path = tmp_path / "known_hosts"
    store1 = TOFUStore(path)
    key = _pubkey()
    store1.validate("alpha.example.com", key)

    store2 = TOFUStore(path)
    found = store2.lookup("alpha.example.com")
    assert len(found) == 1
    assert found[0] == key


def test_lookup_unknown_host_returns_empty(tmp_path: Path) -> None:
    store = TOFUStore(tmp_path / "known_hosts")
    assert store.lookup("nonexistent.example.com") == []


def test_add_creates_missing_parent_dirs(tmp_path: Path) -> None:
    nested = tmp_path / "a" / "b" / "c" / "known_hosts"
    store = TOFUStore(nested)
    store.add("h", _pubkey())
    assert nested.exists()


def test_multiple_hosts_coexist_in_file(tmp_path: Path) -> None:
    store = TOFUStore(tmp_path / "known_hosts")
    k1 = _pubkey()
    k2 = _pubkey()
    store.validate("alpha.example.com", k1)
    store.validate("beta.example.com", k2)
    assert store.lookup("alpha.example.com") == [k1]
    assert store.lookup("beta.example.com") == [k2]


def test_blank_and_comment_lines_are_ignored(tmp_path: Path) -> None:
    path = tmp_path / "known_hosts"
    key = _pubkey()
    line = key.export_public_key().decode().strip()
    path.write_text(f"\n# a comment\nalpha {line}\n\n# trailing\n")
    store = TOFUStore(path)
    found = store.lookup("alpha")
    assert len(found) == 1
    assert found[0] == key


def test_malformed_lines_are_skipped(tmp_path: Path) -> None:
    path = tmp_path / "known_hosts"
    path.write_text("not enough fields\nalso bad\n")
    store = TOFUStore(path)
    # Should not raise and should lookup as empty.
    assert store.lookup("anything") == []
