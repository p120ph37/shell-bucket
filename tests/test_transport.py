"""Unit tests for the generic PTY command transport.

These spawn real, tiny POSIX commands under a local pseudo-terminal — the same
machinery `shell-bucket wrap` uses for ssh / ECS / bash / screen / anything that
hands you a shell over a tty.
"""

from __future__ import annotations

import asyncio

import pytest

from shell_bucket.transport import CommandTransport, terminal_size


async def _drain(proc, timeout: float = 5.0) -> bytes:
    out = bytearray()

    async def loop() -> None:
        while True:
            data = await proc.stdout.read(65536)
            if not data:
                return
            out.extend(data)

    await asyncio.wait_for(loop(), timeout)
    return bytes(out)


def test_terminal_size_defaults_off_a_tty() -> None:
    # Under pytest stdout isn't a tty → the documented 80x24 fallback.
    cols, rows = terminal_size()
    assert cols >= 1 and rows >= 1


async def test_runs_command_and_captures_output() -> None:
    async with CommandTransport(["printf", "hello-tty"]) as proc:
        out = await _drain(proc)
    assert b"hello-tty" in out
    assert proc.returncode == 0


async def test_returncode_reflects_child_exit() -> None:
    async with CommandTransport(["sh", "-c", "exit 7"]) as proc:
        await _drain(proc)
    assert proc.returncode == 7


async def test_writes_reach_the_child() -> None:
    # The child reads a line from its tty stdin and echoes it back tagged.
    async with CommandTransport(["sh", "-c", 'read x; printf "GOT:%s" "$x"']) as proc:
        proc.stdin.write(b"ping\n")
        out = await _drain(proc)
    assert b"GOT:ping" in out


async def test_write_eof_signals_end_of_input() -> None:
    # `cat` copies stdin→stdout until EOF; write_eof sends the tty's VEOF.
    async with CommandTransport(["cat"]) as proc:
        proc.stdin.write(b"abc\n")
        proc.stdin.write_eof()
        out = await _drain(proc)
    assert b"abc" in out
    assert proc.returncode == 0


async def test_initial_winsize_propagates_to_child() -> None:
    # The slave starts at the wrapper's terminal size (80x24 off a tty) — stty
    # reports "rows cols".
    async with CommandTransport(["sh", "-c", "stty size"]) as proc:
        out = await _drain(proc)
    assert b"24 80" in out


async def test_change_terminal_size_reaches_child() -> None:
    # Resize right after spawn; the (slightly delayed) stty sees the new size.
    async with CommandTransport(["sh", "-c", "sleep 0.3; stty size"]) as proc:
        proc.change_terminal_size(100, 30)
        out = await _drain(proc)
    assert b"30 100" in out


async def test_exec_failure_exits_127() -> None:
    async with CommandTransport(["this-command-does-not-exist-xyz"]) as proc:
        await _drain(proc)
    assert proc.returncode == 127


def test_empty_argv_rejected() -> None:
    with pytest.raises(ValueError):
        CommandTransport([])
