"""Unit tests for wrapper-host config (paths + tmux options)."""

from __future__ import annotations

from pathlib import Path

import pytest

from shell_bucket import config
from shell_bucket.config import TmuxConfig, bucket_dir, config_path, load_config, root_dir


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("SHELL_BUCKET_HOME", str(tmp_path))
    return tmp_path


# ----- paths ----------------------------------------------------------------

def test_paths_under_env_root(home: Path) -> None:
    assert root_dir() == home
    assert bucket_dir() == home / "bucket"
    assert config_path() == home / "config.toml"


# ----- load_config -----------------------------------------------------------

def test_load_config_missing_is_empty(home: Path) -> None:
    assert load_config() == {}


def test_load_config_parses_toml(home: Path) -> None:
    config_path().write_text('[tmux]\nprefer_system = false\n')
    assert load_config() == {"tmux": {"prefer_system": False}}


def test_load_config_malformed_is_empty(home: Path) -> None:
    config_path().write_text("this is = = not toml [")
    assert load_config() == {}


# ----- TmuxConfig -------------------------------------------------------------

def test_tmux_config_defaults() -> None:
    cfg = TmuxConfig()
    assert cfg.prefer_system and cfg.fetch_if_missing and cfg.fallback_without


def test_tmux_config_from_empty_is_defaults() -> None:
    assert TmuxConfig.from_config({}) == TmuxConfig()


def test_tmux_config_reads_flags() -> None:
    cfg = TmuxConfig.from_config(
        {"tmux": {"prefer_system": False, "fetch_if_missing": False, "fallback_without": False}}
    )
    assert cfg == TmuxConfig(False, False, False)


def test_tmux_config_wrong_type_falls_back_per_field() -> None:
    cfg = TmuxConfig.from_config({"tmux": {"prefer_system": "yes", "fetch_if_missing": 0}})
    # Non-bool values ignored; defaults kept.
    assert cfg.prefer_system is True and cfg.fetch_if_missing is True


def test_tmux_config_non_dict_section_is_defaults() -> None:
    assert TmuxConfig.from_config({"tmux": "nope"}) == TmuxConfig()


def test_tmux_config_from_disk(home: Path) -> None:
    config_path().write_text("[tmux]\nfallback_without = false\n")
    cfg = TmuxConfig.from_config()  # loads from SHELL_BUCKET_HOME
    assert cfg.fallback_without is False and cfg.prefer_system is True
    assert config.load_config()  # sanity: it actually read the file
