"""Unit tests for the CLI argument parsing and wiring."""

from __future__ import annotations

from typing import Any

import pytest
from click.testing import CliRunner

from shell_bucket.cli import cli, wrap


def _runner() -> CliRunner:
    return CliRunner()


# ----- group shape ----------------------------------------------------------


def test_cli_is_a_group_with_wrap_and_fetch_tmux() -> None:
    """`shell-bucket` is a group whose connect-like verb is now `wrap`."""
    result = _runner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "wrap" in result.output
    assert "fetch-tmux" in result.output
    # The SSH-specific verbs are gone -- it's a generic tty wrapper now.
    assert "connect" not in result.output
    assert "download" not in result.output


# ----- wrap: argv handling ----------------------------------------------------


def test_wrap_requires_a_command() -> None:
    result = _runner().invoke(wrap, [])
    assert result.exit_code == 2
    assert "Provide a command to wrap" in result.output


def _capture_session(monkeypatch: pytest.MonkeyPatch, rc: int = 0) -> dict[str, Any]:
    """Patch run_session + CommandTransport, returning a dict that records both."""
    captured: dict[str, Any] = {}

    class FakeTransport:
        def __init__(self, argv: list[str], **kw: Any) -> None:
            captured["argv"] = argv
            captured["transport_kwargs"] = kw

    async def fake_run_session(transport: Any, **kwargs: Any) -> int:
        captured["transport"] = transport
        captured.update(kwargs)
        return rc

    monkeypatch.setattr("shell_bucket.cli.CommandTransport", FakeTransport)
    monkeypatch.setattr("shell_bucket.cli.run_session", fake_run_session)
    return captured


def test_wrap_passes_command_through_to_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _capture_session(monkeypatch)
    result = _runner().invoke(wrap, ["--", "ssh", "user@host"])
    assert result.exit_code == 0, result.output
    assert captured["argv"] == ["ssh", "user@host"]
    assert isinstance(captured["transport"], object)
    assert captured["shell"] == "bash"
    assert captured["tmux_session"] is None
    assert captured["bucket"] is not None


def test_wrap_passes_tool_flags_after_double_dash(monkeypatch: pytest.MonkeyPatch) -> None:
    # A tool's own --flags must reach the tool, not be parsed as wrap options.
    captured = _capture_session(monkeypatch)
    result = _runner().invoke(
        wrap,
        ["--shell", "zsh", "--", "aws", "ecs", "execute-command", "--cluster", "c"],
    )
    assert result.exit_code == 0, result.output
    assert captured["argv"] == ["aws", "ecs", "execute-command", "--cluster", "c"]
    assert captured["shell"] == "zsh"


def test_wrap_tmux_option_wires_through(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _capture_session(monkeypatch)
    result = _runner().invoke(wrap, ["--tmux", "proj", "--", "bash"])
    assert result.exit_code == 0, result.output
    assert captured["argv"] == ["bash"]
    assert captured["tmux_session"] == "proj"


def test_wrap_exit_code_propagated(monkeypatch: pytest.MonkeyPatch) -> None:
    _capture_session(monkeypatch, rc=42)
    result = _runner().invoke(wrap, ["--", "bash"])
    assert result.exit_code == 42


def test_wrap_oserror_reports_and_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shell_bucket.cli.CommandTransport", lambda *a, **k: object())

    async def boom(*a: Any, **k: Any) -> int:
        raise OSError("no such tool")

    monkeypatch.setattr("shell_bucket.cli.run_session", boom)
    result = _runner().invoke(wrap, ["--", "nope"])
    assert result.exit_code == 1
    assert "could not run" in result.output
