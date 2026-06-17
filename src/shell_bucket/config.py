"""Wrapper-host paths for shell-bucket.

Everything lives under a single user-visible tree, ``~/.shell-bucket/`` (like
``~/.ssh/``), not an XDG split — users prefer one tree. Override the root with
``$SHELL_BUCKET_HOME`` (used by tests).

  ~/.shell-bucket/
    config.toml      wrapper defaults — local-only, never served
    known_hosts      TOFU trust store — local-only (0600)
    bucket/          THE SERVED TREE (the FILEREQ namespace; path-confined)

The served *bucket* is deliberately a subdirectory: the wrapper resolves every
FILEREQ path within it, so wrapper-local files (config, trust store) must sit
*outside* it and can never be fetched.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path


def root_dir() -> Path:
    """The single wrapper-host tree (``$SHELL_BUCKET_HOME`` or ``~/.shell-bucket``)."""
    env = os.environ.get("SHELL_BUCKET_HOME")
    if env:
        return Path(env)
    return Path(os.path.expanduser("~/.shell-bucket"))


def bucket_dir() -> Path:
    """The served tree: portable files in os/os_arch subdirs + agnostic root."""
    return root_dir() / "bucket"


def known_hosts_path() -> Path:
    """TOFU-managed known_hosts (local-only, 0600)."""
    return root_dir() / "known_hosts"


def config_path() -> Path:
    """Wrapper defaults (local-only, never served)."""
    return root_dir() / "config.toml"


def load_config() -> dict:
    """Parse ``config.toml`` into a dict (``{}`` if absent or unparseable).

    Config is optional — a missing or malformed file falls back to built-in
    defaults rather than failing a connection.
    """
    path = config_path()
    if not path.is_file():
        return {}
    try:
        with path.open("rb") as f:
            return tomllib.load(f)
    except (tomllib.TOMLDecodeError, OSError):
        return {}


@dataclass(frozen=True)
class ClipConfig:
    """Whether to allow clipboard access over the in-band channel.

      [clip]
      enabled = true   # allow sb clip to read/write the local clipboard

    Clipboard integration is enabled by default. Set ``enabled = false`` to
    disable all CLIP:GET / CLIP:SET requests (e.g. on shared / kiosk wrappers).
    """

    enabled: bool = True

    @classmethod
    def from_config(cls, config: dict | None = None) -> ClipConfig:
        """Build from a parsed config dict (or load it)."""
        cfg = config if config is not None else load_config()
        section = cfg.get("clip", {})
        if not isinstance(section, dict):
            section = {}
        v = section.get("enabled", cls.enabled)
        return cls(enabled=v if isinstance(v, bool) else cls.enabled)


@dataclass(frozen=True)
class TmuxConfig:
    """How a ``--tmux`` session resolves a tmux binary on the remote.

      [tmux]
      prefer_system    = true   # use the remote's own tmux if present
      fetch_if_missing = true   # else fetch the bucket's tmux in-band (FILEREQ)
      fallback_without = true   # if still none, run a plain shell (vs. erroring)

    Defaults prefer the system tmux but fetch the bucket binary when absent, and
    degrade to a plain (non-tmux) shell rather than refusing the session.
    """

    prefer_system: bool = True
    fetch_if_missing: bool = True
    fallback_without: bool = True

    @classmethod
    def from_config(cls, config: dict | None = None) -> TmuxConfig:
        """Build from a parsed config dict (or load it). Unknown keys ignored;
        wrong-typed values fall back to the default for that field."""
        cfg = config if config is not None else load_config()
        section = cfg.get("tmux", {})
        if not isinstance(section, dict):
            section = {}

        def flag(key: str, default: bool) -> bool:
            v = section.get(key, default)
            return v if isinstance(v, bool) else default

        return cls(
            prefer_system=flag("prefer_system", cls.prefer_system),
            fetch_if_missing=flag("fetch_if_missing", cls.fetch_if_missing),
            fallback_without=flag("fallback_without", cls.fallback_without),
        )
