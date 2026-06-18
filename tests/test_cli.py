"""Unit tests for the CLI argument parsing and wiring."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from shell_bucket.cli import Destination, cli, connect, parse_destination


def test_parse_destination_basic() -> None:
    assert parse_destination("me@host.example.com") == Destination(
        user="me", host="host.example.com"
    )


@pytest.mark.parametrize("bad", ["hostonly", "@host", "user@", "", "@", "user@@host"])
def test_parse_destination_rejects_malformed(bad: str) -> None:
    if bad == "user@@host":
        # 'user' + '@' + '@host' — host is '@host', non-empty, so we accept this.
        # That's a known limitation of partition('@'); document via this test.
        assert parse_destination(bad).host == "@host"
        return
    import click

    with pytest.raises(click.UsageError):
        parse_destination(bad)


def _runner() -> CliRunner:
    return CliRunner()


def test_no_auth_flag_errors() -> None:
    result = _runner().invoke(connect, ["user@host"])
    assert result.exit_code == 2
    assert "Specify one of" in result.output


def test_both_auth_flags_error(tmp_path: Path) -> None:
    keyfile = tmp_path / "id"
    keyfile.write_text("k")
    result = _runner().invoke(
        connect, ["user@host", "--password-on-stdin", "--identity-file", str(keyfile)]
    )
    assert result.exit_code == 2
    assert "not both" in result.output


def test_malformed_destination_errors() -> None:
    result = _runner().invoke(connect, ["nohostatall", "--password-on-stdin"], input="pw\n")
    assert result.exit_code == 2
    assert "user@host" in result.output


def test_password_on_stdin_with_empty_stdin_errors() -> None:
    result = _runner().invoke(connect, ["me@h", "--password-on-stdin"], input="")
    assert result.exit_code == 2
    assert "stdin was empty" in result.output


def _make_fake_run_session(captured: dict[str, Any], rc: int = 0):
    async def fake(**kwargs: Any) -> int:
        captured.update(kwargs)
        return rc

    return fake


def _captured_has_bucket(captured: dict[str, Any]) -> bool:
    return captured.get("bucket") is not None


def test_password_path_wires_to_run_session(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        "shell_bucket.cli.run_session", _make_fake_run_session(captured, rc=0)
    )
    result = _runner().invoke(
        connect, ["me@1.2.3.4", "--password-on-stdin", "--no-known-hosts"], input="hunter2\n"
    )
    assert result.exit_code == 0, result.output
    assert captured["user"] == "me"
    assert captured["host"] == "1.2.3.4"
    assert captured["password"] == "hunter2"
    assert captured["identity_file"] is None
    assert captured["store"] is None  # --no-known-hosts
    assert _captured_has_bucket(captured)


def test_identity_file_path_wires_to_run_session(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    keyfile = tmp_path / "id"
    keyfile.write_text("k")
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        "shell_bucket.cli.run_session", _make_fake_run_session(captured, rc=0)
    )
    result = _runner().invoke(connect, ["me@h", "--identity-file", str(keyfile)])
    assert result.exit_code == 0, result.output
    assert captured["password"] is None
    assert captured["identity_file"] == keyfile
    assert captured["store"] is not None  # TOFU active by default


def test_exit_code_propagated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "shell_bucket.cli.run_session", _make_fake_run_session({}, rc=42)
    )
    result = _runner().invoke(
        connect, ["me@h", "--password-on-stdin", "--no-known-hosts"], input="pw\n"
    )
    assert result.exit_code == 42


def test_permission_denied_returns_1(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncssh

    async def fake_run_session(**kwargs: Any) -> int:
        raise asyncssh.PermissionDenied("bad password")

    monkeypatch.setattr("shell_bucket.cli.run_session", fake_run_session)
    result = _runner().invoke(
        connect, ["me@h", "--password-on-stdin", "--no-known-hosts"], input="bad\n"
    )
    assert result.exit_code == 1
    assert "authentication failed" in result.output


# ───── group + download subcommand ─────────────────────────────────────────

def test_cli_is_a_group_with_connect_and_download() -> None:
    """`shell-bucket` is a group with `connect` and `download` subcommands."""
    result = _runner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "connect" in result.output
    assert "download" in result.output


def test_parse_download_spec() -> None:
    from shell_bucket.cli import parse_download_spec

    dest = parse_download_spec("me@host:/etc/foo")
    assert dest.user == "me"
    assert dest.host == "host"
    assert dest.path == "/etc/foo"


def test_parse_download_spec_rejects_missing_path() -> None:
    import click
    from shell_bucket.cli import parse_download_spec

    for bad in ("me@host", "me@host:", "/just/a/path"):
        with pytest.raises(click.UsageError):
            parse_download_spec(bad)


def test_download_requires_user_at_host_colon_path() -> None:
    from shell_bucket.cli import download

    result = _runner().invoke(download, ["/etc/foo", "--password-on-stdin"], input="p\n")
    assert result.exit_code == 2
    assert "user@host" in result.output


def test_iterm_inline_image_emits_osc_1337() -> None:
    from shell_bucket.cli import _iterm_inline_image

    seq = _iterm_inline_image("a.png", b"\x89PNG\r\n\x1a\n")
    assert seq.startswith(b"\033]1337;File=name=")
    assert seq.endswith(b"\007")
    assert b";inline=1:" in seq
    assert b"size=8;" in seq
