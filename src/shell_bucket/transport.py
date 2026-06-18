"""Generic tty transport: spawn any command under a local PTY and bridge it.

shell-bucket is about generic ttys, not SSH specifically. The wrapper bridges a
byte stream to/from *some* process that owns a terminal at the other end; how
that process is produced is this module's concern. The user names the tool —
``ssh user@host``, ``aws ecs execute-command …``, ``bash``, ``screen``,
``it2-ssh``, anything that gives a shell over a tty — and `CommandTransport`
runs it under a local pseudo-terminal so it behaves exactly as it would if you
had typed it yourself.

The transport exposes the minimal surface `wrapper._bridge_stdio` needs (the
same shape asyncssh's process gave before): a `stdin` you can `write`/`write_eof`
to, an awaitable `stdout.read(n)`, `change_terminal_size`, and a `returncode`.
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import os
import pty
import signal
import struct
import termios
from typing import Any, Protocol


def terminal_size() -> tuple[int, int]:
    """Local terminal (cols, rows), or a sane default off a tty."""
    try:
        s = os.get_terminal_size()
        return s.columns, s.lines
    except OSError:
        return 80, 24


def _set_winsize(fd: int, cols: int, rows: int) -> None:
    with contextlib.suppress(OSError):
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


class Process(Protocol):
    """What `wrapper._bridge_stdio` / `_feed_and_sync` drive a session through."""

    stdin: Any
    stdout: Any
    returncode: int | None

    def change_terminal_size(self, cols: int, rows: int) -> None: ...


class _Stdin:
    """The write half of a `_PtyProcess` (mirrors asyncssh's `proc.stdin`)."""

    def __init__(self, proc: _PtyProcess) -> None:
        self._proc = proc

    def write(self, data: bytes) -> None:
        self._proc._write(data)

    def write_eof(self) -> None:
        self._proc._write_eof()


class _Stdout:
    """The read half of a `_PtyProcess` (mirrors asyncssh's `proc.stdout`)."""

    def __init__(self, proc: _PtyProcess) -> None:
        self._proc = proc

    async def read(self, n: int) -> bytes:
        return await self._proc._read(n)


class _PtyProcess:
    """A child process attached to a local PTY, pumped through the asyncio loop.

    Reads are buffered off a `loop.add_reader` on the master fd; writes are
    buffered and drained via `loop.add_writer` so a child that is briefly not
    reading applies backpressure without blocking the event loop (file delivery
    pushes multi-megabyte payloads down this same stream).
    """

    def __init__(self, pid: int, master_fd: int, loop: asyncio.AbstractEventLoop) -> None:
        self._pid = pid
        self._fd = master_fd
        self._loop = loop
        os.set_blocking(master_fd, False)

        self._rbuf = bytearray()
        self._reof = False
        self._rwaiter: asyncio.Future[None] | None = None
        loop.add_reader(master_fd, self._on_readable)

        self._wbuf = bytearray()
        self._writer_armed = False
        self._eof_pending = False
        self._closed = False

        self.returncode: int | None = None
        self.stdin = _Stdin(self)
        self.stdout = _Stdout(self)

    # ── read side ──────────────────────────────────────────────────────────
    def _on_readable(self) -> None:
        try:
            data = os.read(self._fd, 65536)
        except BlockingIOError:
            return
        except OSError:
            data = b""  # master EOF / slave hung up → child is gone
        if data:
            self._rbuf.extend(data)
        else:
            self._reof = True
            with contextlib.suppress(Exception):
                self._loop.remove_reader(self._fd)
        if self._rwaiter is not None and not self._rwaiter.done():
            self._rwaiter.set_result(None)

    async def _read(self, n: int) -> bytes:
        while not self._rbuf and not self._reof:
            self._rwaiter = self._loop.create_future()
            try:
                await self._rwaiter
            finally:
                self._rwaiter = None
        if self._rbuf:
            chunk = bytes(self._rbuf[:n])
            del self._rbuf[:n]
            return chunk
        return b""

    # ── write side ─────────────────────────────────────────────────────────
    def _write(self, data: bytes) -> None:
        if self._closed or not data:
            return
        self._wbuf.extend(data)
        self._flush()

    def _flush(self) -> None:
        if self._wbuf:
            try:
                n = os.write(self._fd, self._wbuf)
            except BlockingIOError:
                n = 0
            except OSError:
                self._wbuf.clear()
                self._eof_pending = False
                self._disarm_writer()
                return
            if n:
                del self._wbuf[:n]
        if self._wbuf:
            self._arm_writer()
            return
        self._disarm_writer()
        if self._eof_pending:
            self._eof_pending = False
            self._send_eof()

    def _arm_writer(self) -> None:
        if not self._writer_armed:
            self._loop.add_writer(self._fd, self._flush)
            self._writer_armed = True

    def _disarm_writer(self) -> None:
        if self._writer_armed:
            with contextlib.suppress(Exception):
                self._loop.remove_writer(self._fd)
            self._writer_armed = False

    def _write_eof(self) -> None:
        # No half-close on a PTY: signal end-of-input by writing the line
        # discipline's EOF char (Ctrl-D by default) once any buffered output has
        # drained. A raw-mode child ignores it; the session ends when the child
        # exits and the master read returns EOF either way.
        self._eof_pending = True
        if not self._wbuf:
            self._eof_pending = False
            self._send_eof()

    def _send_eof(self) -> None:
        veof = b"\x04"
        with contextlib.suppress(Exception):
            veof = bytes([termios.tcgetattr(self._fd)[6][termios.VEOF]])
        with contextlib.suppress(OSError):
            os.write(self._fd, veof)

    # ── control ──────────────────────────────────────────────────────────────
    def change_terminal_size(self, cols: int, rows: int) -> None:
        _set_winsize(self._fd, cols, rows)

    def _reap(self, *, blocking: bool) -> None:
        if self.returncode is not None:
            return
        flags = 0 if blocking else os.WNOHANG
        try:
            pid, status = os.waitpid(self._pid, flags)
        except ChildProcessError:
            self.returncode = 0
            return
        if pid == 0:
            return  # not exited yet (non-blocking)
        self.returncode = os.waitstatus_to_exitcode(status)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._disarm_writer()
        with contextlib.suppress(Exception):
            self._loop.remove_reader(self._fd)
        # Child usually exited already (its slave hung up → our master read EOF).
        # If not, hang it up, then reap so `returncode` is real.
        self._reap(blocking=False)
        if self.returncode is None:
            with contextlib.suppress(ProcessLookupError, OSError):
                os.kill(self._pid, signal.SIGHUP)
            self._reap(blocking=True)
        with contextlib.suppress(OSError):
            os.close(self._fd)


class CommandTransport:
    """Run an arbitrary argv under a local PTY and bridge it as a `Process`.

    Use as an async context manager::

        async with CommandTransport(["ssh", "user@host"]) as proc:
            ...  # proc.stdin.write / await proc.stdout.read / proc.returncode

    The child's stdin/stdout/stderr are the PTY slave (so it is a real terminal
    to the tool), and the slave is its controlling tty (window-size changes reach
    it as SIGWINCH). `term`/`env` seed the child's environment before exec.
    """

    def __init__(
        self,
        argv: list[str],
        *,
        term: str | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        if not argv:
            raise ValueError("CommandTransport needs a non-empty argv")
        self._argv = list(argv)
        self._term = term or os.environ.get("TERM", "xterm-256color")
        self._env = env
        self._proc: _PtyProcess | None = None

    async def __aenter__(self) -> _PtyProcess:
        cols, rows = terminal_size()
        pid, master_fd = pty.fork()
        if pid == 0:  # child: slave is already fds 0/1/2 and our controlling tty
            os.environ["TERM"] = self._term
            if self._env:
                os.environ.update(self._env)
            try:
                os.execvp(self._argv[0], self._argv)
            except OSError:
                os._exit(127)  # exec failure → conventional "command not found"
        # Set the window size from the parent only. Doing it in the child too
        # would race a later `change_terminal_size` (the child's set could land
        # after a resize and clobber it back). The master-side set propagates to
        # the slave before the child finishes exec.
        _set_winsize(master_fd, cols, rows)
        self._proc = _PtyProcess(pid, master_fd, asyncio.get_running_loop())
        return self._proc

    async def __aexit__(self, *exc: object) -> bool:
        if self._proc is not None:
            self._proc.close()
        return False
