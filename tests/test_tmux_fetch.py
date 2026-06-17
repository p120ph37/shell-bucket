"""Unit tests for the upstream static-tmux fetcher (network injected)."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from shell_bucket.tmux_fetch import (
    PLATFORMS,
    asset_name,
    asset_url,
    extract_tmux,
    fetch_tmux,
    install_tmux,
    latest_version,
)

_ELF = b"\x7fELF" + b"\x00" * 60  # minimal ELF-magic stand-in


def _tarball(member_name: str = "tmux", body: bytes = _ELF) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(member_name)
        info.size = len(body)
        info.mode = 0o755
        tf.addfile(info, io.BytesIO(body))
    return buf.getvalue()


# ───── naming / mapping ──────────────────────────────────────────────────────

def test_platform_map_matches_bucket_subdirs() -> None:
    assert PLATFORMS["linux-x86_64"] == "linux_amd64"
    assert PLATFORMS["linux-arm64"] == "linux_arm64"
    assert PLATFORMS["macos-arm64"] == "darwin_arm64"


def test_asset_name_strips_v_prefix() -> None:
    # tag is v-prefixed, asset filename is not.
    assert asset_name("v3.6b", "linux-arm64") == "tmux-3.6b-linux-arm64.tar.gz"
    assert asset_name("3.6b", "linux-arm64") == "tmux-3.6b-linux-arm64.tar.gz"


def test_asset_url_keeps_tag_in_path() -> None:
    assert asset_url("tmux/tmux-builds", "v3.6b", "linux-arm64") == (
        "https://github.com/tmux/tmux-builds/releases/download/"
        "v3.6b/tmux-3.6b-linux-arm64.tar.gz"
    )


# ───── extract ────────────────────────────────────────────────────────────────

def test_extract_tmux_pulls_binary() -> None:
    assert extract_tmux(_tarball()) == _ELF


def test_extract_tmux_missing_member() -> None:
    with pytest.raises(ValueError, match="no `tmux` member"):
        extract_tmux(_tarball(member_name="something-else"))


def test_extract_tmux_rejects_non_executable() -> None:
    with pytest.raises(ValueError, match="not a recognized executable"):
        extract_tmux(_tarball(body=b"<html>404</html>"))


# ───── install ────────────────────────────────────────────────────────────────

def test_install_tmux_writes_executable(tmp_path: Path) -> None:
    dest = install_tmux(tmp_path, "linux_arm64", _ELF)
    assert dest == tmp_path / "linux_arm64" / "tmux"
    assert dest.read_bytes() == _ELF
    assert dest.stat().st_mode & 0o111  # executable
    assert not (tmp_path / "linux_arm64" / "tmux.partial").exists()  # atomic move


# ───── fetch_tmux (download injected) ────────────────────────────────────────

def test_fetch_tmux_all_platforms(tmp_path: Path) -> None:
    def fake_download(url: str) -> bytes:
        return _tarball()

    installed = fetch_tmux(tmp_path, version="v3.6b", download=fake_download)
    assert {p for p, _ in installed} == set(PLATFORMS)
    for _, path in installed:
        assert path.read_bytes() == _ELF


def test_fetch_tmux_specific_platform_uses_right_url(tmp_path: Path) -> None:
    seen: list[str] = []

    def fake_download(url: str) -> bytes:
        seen.append(url)
        return _tarball()

    fetch_tmux(tmp_path, version="v3.6b", platforms=["linux-arm64"], download=fake_download)
    assert seen == [asset_url("tmux/tmux-builds", "v3.6b", "linux-arm64")]
    assert (tmp_path / "linux_arm64" / "tmux").is_file()


def test_fetch_tmux_unknown_platform(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown platform"):
        fetch_tmux(tmp_path, version="v1", platforms=["solaris-sparc"], download=lambda u: b"")


def test_fetch_tmux_default_version_queries_latest(tmp_path: Path) -> None:
    def fake_download(url: str) -> bytes:
        if url.endswith("/releases/latest"):
            return json.dumps({"tag_name": "v9.9z"}).encode()
        assert "v9.9z" in url  # the resolved tag flows into the asset URL
        return _tarball()

    fetch_tmux(tmp_path, platforms=["linux-arm64"], download=fake_download)
    assert (tmp_path / "linux_arm64" / "tmux").is_file()


def test_latest_version_reads_tag() -> None:
    data = json.dumps({"tag_name": "v3.6b"}).encode()
    assert latest_version(download=lambda u: data) == "v3.6b"
