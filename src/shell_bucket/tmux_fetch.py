"""Populate the bucket with upstream static tmux binaries for in-band delivery.

The official ``tmux/tmux-builds`` GitHub releases ship a single statically-linked
``tmux`` per platform tarball (``tmux-<ver>-<os>-<arch>.tar.gz``). This module
downloads the ones you ask for and drops them into the bucket's os/arch subtree
(``bucket/<os>_<arch>/tmux``), where a ``--tmux`` session fetches them on demand
when the remote lacks its own tmux.

Run on the wrapper host via ``shell-bucket fetch-tmux`` (see cli). The network
boundary is a single injectable ``download(url) -> bytes`` callable, so the
extract/install logic is unit-tested without touching the network.
"""

from __future__ import annotations

import io
import json
import tarfile
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path

# Default upstream: the official builds repo.
DEFAULT_SOURCE = "tmux/tmux-builds"

# Release-asset platform token -> bucket os_arch subdir. The release uses
# `linux/macos` + `x86_64/arm64`; the bucket uses `linux/darwin` + `amd64/arm64`.
PLATFORMS: dict[str, str] = {
    "linux-x86_64": "linux_amd64",
    "linux-arm64": "linux_arm64",
    "macos-x86_64": "darwin_amd64",
    "macos-arm64": "darwin_arm64",
}

# Executable magic numbers -- a sanity gate so a 404/HTML body can't masquerade
# as a binary (the tarball would usually fail to parse first, but be explicit).
_EXEC_MAGICS = (
    b"\x7fELF",          # ELF (Linux)
    b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit little-endian (macOS)
    b"\xca\xfe\xba\xbe",  # Mach-O universal (fat)
)

Download = Callable[[str], bytes]


def _urlopen_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "shell-bucket"})
    with urllib.request.urlopen(req) as resp:  # noqa: S310 (https release URLs)
        return resp.read()


def asset_name(tag: str, platform: str) -> str:
    """The release asset filename, e.g. `tmux-3.6b-linux-arm64.tar.gz`.

    The asset uses the bare version (no `v`), while the release/tag is `v3.6b`;
    strip a leading `v` so a `v`-prefixed tag still names the right file.
    """
    version = tag[1:] if tag.startswith("v") else tag
    return f"tmux-{version}-{platform}.tar.gz"


def asset_url(source: str, tag: str, platform: str) -> str:
    """Browser-download URL for a release asset on `source` (`owner/repo`). The
    download path uses the tag verbatim (`v3.6b`); the filename uses the bare
    version (`tmux-3.6b-...`)."""
    return (
        f"https://github.com/{source}/releases/download/"
        f"{tag}/{asset_name(tag, platform)}"
    )


def latest_version(source: str = DEFAULT_SOURCE, *, download: Download = _urlopen_bytes) -> str:
    """The latest release tag (e.g. `v3.6b`) of `source`, via the GitHub API."""
    data = json.loads(download(f"https://api.github.com/repos/{source}/releases/latest"))
    tag = data.get("tag_name")
    if not tag:
        raise ValueError(f"no tag_name in latest release of {source}")
    return tag


def extract_tmux(tarball: bytes) -> bytes:
    """Pull the `tmux` binary out of a release tarball's bytes.

    Raises ValueError if the archive has no `tmux` member or the member isn't a
    recognizable executable (guards against a downloaded error page).
    """
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as tf:
        member = next((m for m in tf.getmembers() if Path(m.name).name == "tmux"), None)
        if member is None:
            raise ValueError("no `tmux` member in tarball")
        f = tf.extractfile(member)
        data = f.read() if f is not None else b""
    if not data.startswith(_EXEC_MAGICS):
        raise ValueError("extracted `tmux` is not a recognized executable")
    return data


def install_tmux(bucket: Path, subdir: str, data: bytes) -> Path:
    """Write `data` to `bucket/<subdir>/tmux` (0755), atomically. Returns the path."""
    dest_dir = bucket / subdir
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / "tmux"
    tmp = dest.with_suffix(".partial")
    tmp.write_bytes(data)
    tmp.chmod(0o755)
    tmp.replace(dest)
    return dest


def fetch_tmux(
    bucket: Path,
    *,
    version: str | None = None,
    platforms: Sequence[str] | None = None,
    source: str = DEFAULT_SOURCE,
    download: Download = _urlopen_bytes,
) -> list[tuple[str, Path]]:
    """Fetch tmux for each platform into the bucket; return [(platform, path), ...].

    `version` defaults to the source's latest release; `platforms` to all known
    (`PLATFORMS`). Unknown platform tokens raise ValueError.
    """
    ver = version or latest_version(source, download=download)
    wanted = list(platforms) if platforms else list(PLATFORMS)
    unknown = [p for p in wanted if p not in PLATFORMS]
    if unknown:
        raise ValueError(f"unknown platform(s): {', '.join(unknown)}; known: {', '.join(PLATFORMS)}")

    installed: list[tuple[str, Path]] = []
    for platform in wanted:
        data = extract_tmux(download(asset_url(source, ver, platform)))
        path = install_tmux(bucket, PLATFORMS[platform], data)
        installed.append((platform, path))
    return installed
