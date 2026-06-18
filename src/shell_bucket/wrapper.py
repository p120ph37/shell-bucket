"""asyncssh-based SSH wrapper with pty bridging."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import os
import shutil
import signal
import socket
import subprocess
import sys
import termios
import tty
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import asyncssh

from shell_bucket.apc_filter import APCFilter, apc_envelope
from shell_bucket.backhaul import (
    SALT_MUX_TX,
    SALT_WRAPPER_TX,
    UdpBackhaul,
    decode_answer,
    encode_offer,
    local_ip,
    stun_query,
)
from shell_bucket.config import ClipConfig, TmuxConfig
from shell_bucket.file_delivery import Bucket, encode_for_delivery, parse_filereq
from shell_bucket.known_hosts import TOFUStore
from shell_bucket.lazy_alias import (
    SHELL_FAMILIES,
    build_bootstrap,
    build_tmux_prologue,
    rc_basename,
    render_rc_file,
)
from shell_bucket.mux_frame import (
    build_push,
    build_route,
    build_survey,
    parse_pushreply,
    parse_route,
    parse_surveyreply,
)
from shell_bucket.topology import Topology

# A `SURVEY:<id>` reply (`SURVEYR:...`) is recorded into the topology, never replied to.


def regenerate_runtimes(bucket: Bucket) -> None:
    """(Re)generate `sb-<family>.rc` for every family in the bucket root.

    Preserves each file's head (the user's pre-extension customizations, above
    the marker) and rewrites the generated body from the current bucket contents
    (rc.d fetch/source stubs). Helpers are not baked into the runtime --
    `sb mux` discovers them from the manifest and exposes them as PATH symlinks.
    Creates the file (with a preamble) if absent. Done at connect, before serving.
    """
    if not bucket.path.exists():
        bucket.path.mkdir(parents=True, exist_ok=True)
    rcd = bucket.rcd_fragments()
    for family in SHELL_FAMILIES:
        path = bucket.path / rc_basename(family)
        existing = path.read_text() if path.is_file() else None
        path.write_text(
            render_rc_file(family, existing=existing, rcd_fragments=rcd)
        )
    # Manifest LAST, so it captures the freshly-written runtimes' mtimes.
    bucket.write_manifest()


class _ShellBucketSSHClient(asyncssh.SSHClient):
    """SSHClient that delegates host-key validation to a TOFUStore (or accepts all)."""

    def __init__(self, store: TOFUStore | None) -> None:
        super().__init__()
        self._store = store

    def validate_host_public_key(
        self, host: str, addr: str, port: int, key: asyncssh.SSHKey
    ) -> bool:
        if self._store is None:
            # --no-known-hosts: accept anything, record nothing.
            return True
        return self._store.validate(host, key)


def build_connect_kwargs(
    *,
    host: str,
    user: str,
    password: str | None,
    identity_file: Path | None,
    store: TOFUStore | None,
    port: int | None = None,
) -> dict[str, Any]:
    """Pure construction of asyncssh.connect kwargs -- extracted for unit testing."""
    kwargs: dict[str, Any] = {
        "host": host,
        "username": user,
        "client_factory": lambda: _ShellBucketSSHClient(store),
        # Prefer zlib over none -- asyncssh defaults offer both but list `none`
        # first, which makes the server pick no compression. SSH negotiation
        # is client-order-wins, so put compression first explicitly. Falls back
        # to `none` if the server doesn't accept zlib.
        "compression_algs": ("zlib@openssh.com", "zlib", "none"),
    }
    if store is None:
        # --no-known-hosts: asyncssh skips host-key validation entirely.
        kwargs["known_hosts"] = None
    else:
        # TOFU: empty trusted/CA/revoked sets force asyncssh to consult our
        # _ShellBucketSSHClient.validate_host_public_key callback.
        kwargs["known_hosts"] = ([], [], [])
    if port is not None:
        kwargs["port"] = port
    if password is not None:
        kwargs["password"] = password
    if identity_file is not None:
        kwargs["client_keys"] = [str(identity_file)]
    return kwargs


@contextmanager
def _raw_terminal_mode(fd: int) -> Iterator[None]:
    if not os.isatty(fd):
        yield
        return
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        yield
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _terminal_size() -> tuple[int, int]:
    try:
        s = os.get_terminal_size()
        return s.columns, s.lines
    except OSError:
        return 80, 24


def _session_script(
    shell: str,
    tmux_session: str | None = None,
    tmux_config: TmuxConfig | None = None,
) -> str:
    """The begin-script the wrapper **feeds** at hop 1 (see `_feed_and_sync`): the
    plain bootstrap, or -- for `--tmux` -- the same bootstrap whose `exec sb mux` runs the
    fetchable `sb-tmux.sh` launcher (`--exec=sb-tmux.sh <session>`, with `tmux_config`
    carried as launcher flags). Both bake the shell and emit a BEGIN sync APC; the
    per-host token is minted by `sb mux` itself, not here. Nothing is written to the
    remote filesystem; delivery is by feed.
    """
    if tmux_session is not None:
        cfg = tmux_config or TmuxConfig()
        return build_tmux_prologue(
            tmux_session,
            shell,
            begin=True,
            prefer_system=cfg.prefer_system,
            fetch_if_missing=cfg.fetch_if_missing,
            fallback_without=cfg.fallback_without,
        )
    return build_bootstrap(shell, begin=True)


def _clipboard_get() -> bytes | None:
    """Read the local clipboard. Returns None if no clipboard tool is available."""
    for cmd in (
        ["pbpaste"],
        ["xclip", "-selection", "clipboard", "-o"],
        ["xsel", "--clipboard", "--output"],
    ):
        if shutil.which(cmd[0]):
            r = subprocess.run(cmd, capture_output=True)
            return r.stdout if r.returncode == 0 else None
    return None


def _clipboard_set(data: bytes) -> bool:
    """Write to the local clipboard. Returns True on success."""
    for cmd in (
        ["pbcopy"],
        ["xclip", "-selection", "clipboard", "-i"],
        ["xsel", "--clipboard", "--input"],
    ):
        if shutil.which(cmd[0]):
            r = subprocess.run(cmd, input=data, capture_output=True)
            return r.returncode == 0
    return False


@dataclass
class BootstrapServer:
    """Serves the in-band bootstrap requests for one session.

    All commands arrive already prefix-stripped by the APC filter, so this only
    routes by command. A socket-relayed request arrives **label-swap framed** as
    `R<id>:<inner>`: the wrapper is the routing *terminus*, so it serves
    `<inner>` and echoes the **same** id in an APC envelope (`R<id>:<response>`) --
    the relabelling lives in the muxes, the wrapper stays stateless. An unframed
    command (the bootstrap, or a mux's own pre-pump `mux_setup` fetch --
    single-in-flight, pre-socket) is served + replied raw.

    The wrapper holds no token -- the wire is token-free (trust is
    structural; see `apc_filter`) and each `sb mux` mints its own per-host socket
    token. The only non-file request is `BOOT` (the bootstrap `sb inject` feeds
    into the command it injects, baked with the shell); everything else is a
    `FILEREQ` resolved as a path in the one bucket tree -- `sb` and the
    `sb-<family>.rc` runtimes are just files there (regenerated at connect; see
    `regenerate_runtimes`).
    """

    bucket: Bucket
    topology: Topology = field(default_factory=Topology)
    pushes: dict[int, bytes] = field(default_factory=dict)  # push-id -> reply body
    clip: ClipConfig = field(default_factory=ClipConfig)

    def serve(self, command: bytes) -> bytes | None:
        """Return the wire response for one command, or None to drop it.

        `R<id>:<inner>` -> serve `<inner>` and echo the id as a RAW frame
        `R<id>:<resp>` (the caller frames it for transport: APC in-band, or raw
        over the UDP backhaul). A `SURVEYR:...` reply is recorded into the topology,
        a `PUSHR:...` reply into `pushes` -- both dropped (fire-and-forget;
        wrapper-initiated). A raw (unframed) command (the bootstrap / mux startup)
        -> raw reply bytes the deeper component reads literally, no framing.
        """
        sr = parse_surveyreply(command)
        if sr is not None:
            _sid, route, identity = sr
            self.topology.record(route, identity)
            return None
        pr = parse_pushreply(command)
        if pr is not None:
            pid, resp = pr
            self.pushes[pid] = resp
            return None
        framed = parse_route(command)
        if framed is not None:
            rid, inner = framed
            resp = self._serve_inner(inner)
            if resp is None:
                return None
            return build_route(rid, resp)
        return self._serve_inner(command)

    def survey_apc(self, sid: int = 1) -> bytes:
        """The `SURVEY:<id>` APC to write down the byte stream to kick off a survey;
        replies arrive as `SURVEYR` and land in `self.topology`."""
        return apc_envelope(build_survey(sid))

    def push_apc(self, pid: int, route: tuple[int, ...], cmd: bytes) -> bytes:
        """The `PUSH:<pid>:<route>:<cmd>` APC to write down the byte stream to address
        a node by its surveyed `route`; the reply arrives as `PUSHR` into `pushes`."""
        return apc_envelope(build_push(pid, route, cmd))

    def _serve_inner(self, command: bytes) -> bytes | None:
        """Route one unframed command to its response (or None to drop it)."""
        if command.startswith(b"BOOT:"):
            # The injector (`sb inject`) asks for the bootstrap to feed into the
            # command it drives -- baked with the given shell, emitting a BEGIN sync
            # APC so the injector knows it's live (the deeper mux mints its own token).
            shell = command[len(b"BOOT:") :].decode("utf-8", "replace")
            return encode_for_delivery(
                build_bootstrap(shell, begin=True).encode("utf-8")
            )
        if command == b"CLIP:GET":
            if not self.clip.enabled:
                return b"ERR:clipboard-disabled"
            data = _clipboard_get()
            if data is None:
                return b"ERR:clipboard-unavailable"
            return base64.b64encode(data)
        if command.startswith(b"CLIP:SET:"):
            if not self.clip.enabled:
                return b"ERR:clipboard-disabled"
            try:
                data = base64.b64decode(command[9:])
            except Exception:
                return b"ERR:bad-base64"
            return b"OK" if _clipboard_set(data) else b"ERR:clipboard-unavailable"
        req = parse_filereq(command)
        if req is None:
            return None
        return self.bucket.serve(req)


def dispatch_apc_events(
    events: list[bytes],
    server: BootstrapServer | None,
    write: Callable[[bytes], None],
) -> None:
    """Route APC events (already prefix-stripped) to the server.

    Extracted from `_bridge_stdio` for unit-testing without a live process.
    Events the server doesn't recognize (returns None) are dropped.
    """
    if server is None:
        return
    for event in events:
        response = server.serve(event)
        if response is not None:
            # serve() returns raw frames; APC-frame a framed reply for in-band.
            write(apc_envelope(response) if parse_route(event) is not None else response)


class _TunnelConn:
    """One connection of a tunnel: an asyncio stream to the wrapper-side socket, pumped
    both ways as `D`/`H`/`C` frames. The socket is `attach`ed once it's dialed/accepted;
    `D`/`H` frames that arrive before then are buffered (the open is async, so the first
    data often races ahead of the connect). `send(frame)` writes one frame down."""

    def __init__(
        self, conn: int, send: Callable[[bytes], None],
        on_close: Callable[[], None] | None = None,
    ) -> None:
        self._conn = conn
        self._send = send
        self._on_close = on_close
        self._writer: asyncio.StreamWriter | None = None
        self._pending = bytearray()  # bytes received before the socket attached
        self._eof = False
        self._closed = False
        self._finished = False
        self._task: asyncio.Task | None = None

    def attach(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._closed:
            with contextlib.suppress(Exception):
                writer.close()
            self._finish()
            return
        self._writer = writer
        if self._pending:
            with contextlib.suppress(Exception):
                writer.write(bytes(self._pending))
            self._pending.clear()
        if self._eof:
            with contextlib.suppress(Exception):
                writer.write_eof()
        self._task = asyncio.create_task(self._pump(reader, writer))

    async def _pump(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    self._send(b"C:%d" % self._conn)  # socket closed -> close the conn
                    return
                self._send(b"D:%d:" % self._conn + base64.b64encode(data))
        except (OSError, asyncio.CancelledError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()
            self._finish()

    def _finish(self) -> None:
        if self._finished:
            return
        self._finished = True
        if self._on_close is not None:
            self._on_close()

    def write(self, data: bytes) -> None:
        if self._writer is None:
            self._pending += data
        else:
            with contextlib.suppress(Exception):
                self._writer.write(data)

    def write_eof(self) -> None:
        if self._writer is None:
            self._eof = True  # flushed on attach
        else:
            with contextlib.suppress(Exception):
                self._writer.write_eof()  # half-close: the peer hit EOF

    def close(self) -> None:
        self._closed = True
        if self._task is not None:
            self._task.cancel()  # pump's `finally` runs _finish
        else:
            if self._writer is not None:
                with contextlib.suppress(Exception):
                    self._writer.close()
            self._finish()


class _DialTunnel:
    """A `TUN:dial:<dest>` tunnel: per `O:<conn>` the wrapper dials <dest> and pumps.
    Used by `sb tunnel import` (remote's listener originates conns) and `connect`
    (remote's stdin/stdout is the single conn)."""

    def __init__(self, dest: str, send: Callable[[bytes], None]) -> None:
        self._dest = dest
        self._send = send
        self._conns: dict[int, _TunnelConn] = {}

    async def _dial(self, conn: int, c: _TunnelConn) -> None:
        host, _, port = self._dest.rpartition(":")
        try:
            reader, writer = await asyncio.open_connection(host or "127.0.0.1", int(port))
        except (OSError, ValueError):
            self._send(b"C:%d" % conn)  # dial failed -> close the conn back
            self._conns.pop(conn, None)
            return
        c.attach(reader, writer)

    def handle(self, frame: bytes) -> None:
        kind = frame[:1]
        if kind == b"O":
            conn = int(frame[2:])
            c = _TunnelConn(conn, self._send, on_close=lambda: self._conns.pop(conn, None))
            self._conns[conn] = c  # register synchronously so racing D/H frames buffer
            asyncio.create_task(self._dial(conn, c))
        elif kind == b"D":
            _, conn_s, b64 = frame.split(b":", 2)
            c = self._conns.get(int(conn_s))
            if c is not None:
                c.write(base64.b64decode(b64))
        elif kind == b"H":
            c = self._conns.get(int(frame[2:]))
            if c is not None:
                c.write_eof()
        elif kind == b"C":
            c = self._conns.get(int(frame[2:]))
            if c is not None:
                c.close()  # on_close pops it

    def close(self) -> None:
        for c in list(self._conns.values()):
            c.close()
        self._conns.clear()


class _BindTunnel:
    """A `TUN:bind:<listen>:<all|one>` tunnel: the WRAPPER binds <listen> and accepts.
    Per accepted conn it assigns an id, sends `O:<conn>` down (the remote dials its dest
    or services via stdio), and pumps. `all` accepts concurrently (export); `one` serves
    one at a time, gated until the prior closes (listen)."""

    def __init__(self, listen: str, accept_all: bool, send: Callable[[bytes], None]) -> None:
        self._listen = listen
        self._all = accept_all
        self._send = send
        self._conns: dict[int, _TunnelConn] = {}
        self._next = 1
        self._server: asyncio.AbstractServer | None = None
        self._gate = asyncio.Semaphore(1)  # `one`: one active conn at a time

    async def start(self) -> bytes:
        host, _, port = self._listen.rpartition(":")
        try:
            self._server = await asyncio.start_server(
                self._on_accept, host or "127.0.0.1", int(port)
            )
        except (OSError, ValueError, OverflowError):
            return b"TUN-ERR:cannot bind " + self._listen.encode()
        return b"TUN-OK"

    async def _on_accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if not self._all:
            await self._gate.acquire()  # serialize: the remote services one at a time
        conn = self._next
        self._next += 1

        def on_close() -> None:
            self._conns.pop(conn, None)
            if not self._all:
                self._gate.release()

        c = _TunnelConn(conn, self._send, on_close=on_close)
        self._conns[conn] = c
        self._send(b"O:%d" % conn)
        c.attach(reader, writer)

    def handle(self, frame: bytes) -> None:
        # The wrapper originates `O`; from the remote we only see D/H/C.
        kind = frame[:1]
        if kind == b"D":
            _, conn_s, b64 = frame.split(b":", 2)
            c = self._conns.get(int(conn_s))
            if c is not None:
                c.write(base64.b64decode(b64))
        elif kind == b"H":
            c = self._conns.get(int(frame[2:]))
            if c is not None:
                c.write_eof()
        elif kind == b"C":
            c = self._conns.get(int(frame[2:]))
            if c is not None:
                c.close()

    def close(self) -> None:
        if self._server is not None:
            self._server.close()
        for c in list(self._conns.values()):
            c.close()
        self._conns.clear()


class TunnelManager:
    """Wrapper-side endpoint for `sb tunnel`. Each tunnel is a persistent route id; the
    manager does the wrapper-side socket work and pumps bytes as O/D/H/C frames. Frames
    out go via `write_apc(payload)` -- one `R<id>:<frame>\\n` APC down the byte stream."""

    def __init__(self, write_apc: Callable[[bytes], None]) -> None:
        self._write_apc = write_apc
        self._tunnels: dict[int, _DialTunnel | _BindTunnel] = {}

    def __contains__(self, rid: int) -> bool:
        return rid in self._tunnels

    def handle(self, rid: int, frame: bytes) -> None:
        if frame.startswith(b"TUN:"):
            self._open(rid, frame)
            return
        t = self._tunnels.get(rid)
        if t is None:
            return
        if frame == b"TUN-CLOSE":
            t.close()
            self._tunnels.pop(rid, None)
            return
        t.handle(frame)

    def _open(self, rid: int, frame: bytes) -> None:
        def send(f: bytes) -> None:
            self._write_apc(b"R%d:" % rid + f + b"\n")

        parts = frame.split(b":", 2)  # TUN, mode, rest
        mode = parts[1] if len(parts) > 1 else b""
        rest = parts[2].decode("utf-8", "replace") if len(parts) > 2 else ""
        if mode == b"dial":
            self._tunnels[rid] = _DialTunnel(rest, send)
            send(b"TUN-OK")
        elif mode == b"bind":
            spec, _, acc = rest.rpartition(":")  # <listen>, all|one
            t = _BindTunnel(spec, acc != "one", send)
            self._tunnels[rid] = t
            asyncio.create_task(self._start_bind(rid, t, send))
        else:
            send(b"TUN-ERR:bad mode")

    async def _start_bind(self, rid: int, t: _BindTunnel, send: Callable[[bytes], None]) -> None:
        ok = await t.start()  # binds the listener; TUN-OK or TUN-ERR
        send(ok)
        if not ok.startswith(b"TUN-OK"):
            self._tunnels.pop(rid, None)

    def close_all(self) -> None:
        for t in self._tunnels.values():
            t.close()
        self._tunnels.clear()


# Default public STUN observers (wrapper resolves these to IPs for the offer).
DEFAULT_STUN: list[tuple[str, int]] = [
    ("stun.cloudflare.com", 3478),
    ("stun.l.google.com", 19302),
]


class TransportManager:
    """Wrapper side of the optional UDP backhaul. Mints the PSK, gathers the
    wrapper's candidates, offers the upgrade in-band, and on the mux's `UP:A:`
    answer establishes a `UdpBackhaul`. Once up, down-frames route over UDP."""

    def __init__(self, write_raw: Callable[[bytes], None], stun: list[tuple[str, int]]) -> None:
        self._write_raw = write_raw
        self._stun = stun
        self.psk = os.urandom(32)
        self.nonce = os.urandom(8)
        self.sock: socket.socket | None = None
        self.bh: UdpBackhaul | None = None
        self._on_frame: Callable[[bytes], None] | None = None
        self._reneg_used = False  # one renegotiation attempt per session, then in-band
        self._tasks: set[asyncio.Task] = set()

    def start(self) -> None:
        """Kick off the initial upgrade offer (the session is bridging; the mux is
        at its pump and will answer `UP:A:`)."""
        self._spawn_offer()

    def _spawn_offer(self) -> None:
        t = asyncio.get_running_loop().create_task(self.offer())
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    async def offer(self) -> None:
        """Gather candidates (off-loop -- STUN blocks briefly) and send `UP:O:`.
        Mints a fresh PSK/nonce each call so a renegotiation offer is independent."""
        self.psk = os.urandom(32)
        self.nonce = os.urandom(8)
        loop = asyncio.get_running_loop()
        try:
            stun_ips, cands, sock = await loop.run_in_executor(None, self._gather)
        except Exception:
            return
        if sock is None:
            return
        self.sock = sock
        b64 = encode_offer(self.psk, self.nonce, stun_ips, cands)
        self._write_raw(apc_envelope(b"UP:O:" + b64))

    def _gather(self) -> tuple[list[tuple[str, int]], list[tuple[str, int]], socket.socket | None]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("0.0.0.0", 0))
        except OSError:
            sock.close()
            return [], [], None
        cands = [(local_ip(), sock.getsockname()[1])]  # host candidate
        stun_ips: list[tuple[str, int]] = []
        for host, port in self._stun:
            try:
                ip = socket.gethostbyname(host)
            except OSError:
                continue
            stun_ips.append((ip, port))
            srflx = stun_query(sock, (ip, port))  # srflx on the SAME socket the channel uses
            if srflx is not None and srflx not in cands:
                cands.append(srflx)
        return stun_ips, cands, sock

    def on_answer(self, b64: bytes, on_frame: Callable[[bytes], None]) -> None:
        if self.bh is not None or self.sock is None:
            return
        res = decode_answer(b64)
        if res is None:
            return
        self._on_frame = on_frame
        _nonce, mux_cands = res
        self.bh = UdpBackhaul(
            self.psk,
            SALT_WRAPPER_TX,
            SALT_MUX_TX,
            mux_cands,
            on_frame,
            on_inband=lambda f: self._write_raw(apc_envelope(f)),
            on_closed=self._on_bh_closed,
        )
        self.bh.start(self.sock)

    def on_peer_revert(self, n: int) -> None:
        """The mux is reverting (it told us how many of our down-frames it has).
        Drive the lossless handoff: re-send the undelivered tail in-band."""
        if self.bh is not None:
            self.bh.peer_revert(n)

    def _on_bh_closed(self) -> None:
        """A backhaul that had been up finished its lossless revert. Make one
        attempt to renegotiate a fresh path (roaming / NAT-rebind); else stay in-band."""
        self.bh = None
        self.sock = None
        if self._reneg_used:
            return
        self._reneg_used = True
        self._spawn_offer()

    def up(self) -> bool:
        return self.bh is not None and self.bh.state == "up"

    def active(self) -> bool:
        # Owns the down-frame stream while up OR draining (so reverting frames are
        # held in the FIFO and re-sent in order, not raced out-of-band).
        return self.bh is not None and self.bh.state in ("up", "reverting")

    def close(self) -> None:
        for t in self._tasks:
            t.cancel()
        self._tasks.clear()
        if self.bh is not None:
            self.bh.close()
        elif self.sock is not None:
            self.sock.close()


async def _bridge_stdio(
    proc: asyncssh.SSHClientProcess,
    server: BootstrapServer | None = None,
    initial: bytes = b"",
    *,
    udp_backhaul: bool = False,
) -> None:
    """Bidirectional raw-byte bridge between local tty and remote process.

    `initial` is any remote output already read past the injector's BEGIN sync
    (see `_feed_bootstrap`); it is processed through the APC filter before the
    read loop so a FILEREQ that trailed BEGIN in the same read isn't lost.
    """
    loop = asyncio.get_running_loop()
    in_fd = sys.stdin.fileno()
    out_fd = sys.stdout.fileno()
    done = asyncio.Event()
    apc_filter = APCFilter()
    tm = TransportManager(proc.stdin.write, DEFAULT_STUN) if udp_backhaul else None

    def send_down(frame: bytes) -> None:
        """Route a down-frame to the mux: raw over the UDP backhaul once up, else
        APC-framed in-band. Framing is a transport concern -- callers pass RAW frames."""
        if tm is not None and tm.active():
            tm.bh.send_frame(frame)
        else:
            proc.stdin.write(apc_envelope(frame))

    tunnels = TunnelManager(send_down)

    # `sb survey` RPC. A framed `R<id>:SURVEY` request rides the ordinary mux-socket
    # relay up; the wrapper answers it asynchronously: broadcast a fresh-id SURVEY
    # down, let the normal dispatch path record SURVEYR replies into the topology
    # for a short collection window, then route the formatted table back as the
    # request's `R<id>` reply. A monotonic survey id per run keeps overlapping
    # surveys from cross-recording.
    survey_seq = 0
    survey_tasks: set[asyncio.Task] = set()
    SURVEY_WINDOW = 1.0  # seconds to gather SURVEYR replies before answering

    async def run_survey(rid: int) -> None:
        nonlocal survey_seq
        if server is None:
            return
        survey_seq += 1
        server.topology = Topology()  # fresh snapshot for this run
        send_down(build_survey(survey_seq))
        await asyncio.sleep(SURVEY_WINDOW)  # SURVEYR replies land via dispatch_frame
        # `~END\n` sentinel terminates the reply (the mux relays the route bytes to
        # the `sb survey` client raw, with no EOF), mirroring the `ctl` STATUS wire.
        table = server.topology.format_table().encode("utf-8") + b"~END\n"
        send_down(build_route(rid, table))

    # Preempt the tty during the mux's pre-pump setup: hold user keystrokes until it
    # signals MUXUP (ready to demux), so tty bytes never interlace the mux_setup
    # fetch exchange -- the same channel-separation the conduit relay enforces deeper
    # in the tree. The mux emits MUXUP right after setup, so input releases promptly.
    mux_ready = False
    held_input = bytearray()

    def on_stdin_readable() -> None:
        try:
            data = os.read(in_fd, 4096)
        except OSError:
            done.set()
            return
        if not data:
            proc.stdin.write_eof()
            done.set()
            return
        if mux_ready:
            proc.stdin.write(data)
        else:
            held_input.extend(data)  # held until MUXUP

    def release_gate() -> None:
        """Release held keystrokes -- on the mux's MUXUP, or via the grace fallback
        if it never starts -- so input can never hang indefinitely."""
        nonlocal mux_ready
        if not mux_ready:
            mux_ready = True
            if held_input:
                proc.stdin.write(bytes(held_input))
                held_input.clear()

    def dispatch_frame(ev: bytes) -> None:
        """Route one up-frame from the mux -- arriving in-band (APC) OR over the UDP
        backhaul; both land here so the transport is transparent to dispatch.

        `sb tunnel` frames (a persistent route) go to the TunnelManager; a framed
        request (`R<id>:...`) is served and its reply routed down as a frame; an
        unframed (bootstrap) reply is written raw (pre-pump, in-band only)."""
        if ev == b"MUXUP":
            release_gate()  # mux finished setup and can demux now
            return
        if tm is not None and ev.startswith(b"UP:A:"):
            tm.on_answer(ev[5:], dispatch_frame)  # the mux's answer -> establish the backhaul
            return
        if tm is not None and ev.startswith(b"UP:RX:"):
            with contextlib.suppress(ValueError):
                tm.on_peer_revert(int(ev[6:]))  # mux reverting -> lossless in-band handoff
            return
        if tm is not None and ev == b"UP:RENEG":
            # Mux-initiated renegotiation (e.g. `sb ctl up`): force a fresh offer
            # regardless of the one-shot auto-reneg guard so the operator can always
            # restore the UDP path manually.
            tm._reneg_used = False
            tm._spawn_offer()
            return
        framed = parse_route(ev)
        if framed is not None:
            rid, inner = framed
            if rid in tunnels or inner.startswith(b"TUN:"):
                tunnels.handle(rid, inner)
                return
            if inner == b"SURVEY":  # `sb survey` RPC -> async broadcast + collect + reply
                survey_tasks.add(t := asyncio.create_task(run_survey(rid)))
                t.add_done_callback(survey_tasks.discard)
                return
        if server is None:
            return
        resp = server.serve(ev)
        if resp is None:
            return
        if framed is not None:
            send_down(resp)  # raw frame -> transport-framed (UDP or in-band APC)
        else:
            proc.stdin.write(resp)  # raw, unframed pre-pump reply (in-band only)

    def consume(data: bytes) -> None:
        forwarded, events = apc_filter.feed(data)
        if forwarded:
            os.write(out_fd, forwarded)
        for ev in events:
            dispatch_frame(ev)

    async def remote_to_local() -> None:
        try:
            if initial:
                consume(initial)
            while True:
                data = await proc.stdout.read(4096)
                if not data:
                    break
                consume(data)
        finally:
            done.set()

    def on_sigwinch() -> None:
        cols, rows = _terminal_size()
        with contextlib.suppress(Exception):
            proc.change_terminal_size(cols, rows)

    with _raw_terminal_mode(in_fd):
        loop.add_reader(in_fd, on_stdin_readable)
        try:
            loop.add_signal_handler(signal.SIGWINCH, on_sigwinch)
        except (NotImplementedError, ValueError):
            # Non-tty / Windows-ish environments.
            pass
        r2l = asyncio.create_task(remote_to_local())
        # Grace fallback: if the mux never signals MUXUP (e.g. it failed to start),
        # release held input anyway so keystrokes can't hang forever.
        gate_timer = loop.call_later(20.0, release_gate)
        # Offer the UDP-backhaul upgrade once the session is bridging (the mux is at
        # its pump and will answer with `UP:A:`); failure just leaves us in-band.
        if tm is not None:
            tm.start()
        try:
            await done.wait()
        finally:
            loop.remove_reader(in_fd)
            gate_timer.cancel()
            with contextlib.suppress(NotImplementedError, ValueError):
                loop.remove_signal_handler(signal.SIGWINCH)
            tunnels.close_all()
            for t in survey_tasks:
                t.cancel()
            if tm is not None:
                tm.close()  # cancels any in-flight offer/reneg tasks too
            r2l.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await r2l


async def _feed_and_sync(
    proc: asyncssh.SSHClientProcess,
    script: str,
    *,
    timeout: float = 30.0,
) -> bytes:
    """Inject hop 1: feed `script` (a begin-emitting bootstrap or tmux prologue)
    into the remote shell over its stdin, then swallow that shell's output (its
    prompt, motd, the echo of the fed line) up to the BEGIN sync APC. Returns the
    post-BEGIN remainder (the first bytes of real session traffic) to prime the
    bridge.

    The script rides as one `eval "$(... base64 -d)"` line: POSIX, no heredoc or
    continuation prompt, and nothing the transport must escape -- the same shape
    `sb inject` feeds for deeper hops. BEGIN is matched at the byte level (real
    ESC), so the echoed *source* of the fed line can't false-trigger it.
    """
    b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
    proc.stdin.write(f'eval "$(printf %s {b64}|base64 -d)"\n'.encode("ascii"))
    marker = b"\x1b_shell-bucket:BEGIN\x1b\\"
    acc = bytearray()

    async def scan() -> bytes:
        while True:
            data = await proc.stdout.read(4096)
            if not data:
                raise RuntimeError("remote shell exited before BEGIN sync")
            acc.extend(data)
            idx = acc.find(marker)
            if idx >= 0:
                return bytes(acc[idx + len(marker) :])
            if len(acc) > 65536:  # BEGIN comes early; keep a marker-spanning tail
                del acc[: -(len(marker) - 1)]

    return await asyncio.wait_for(scan(), timeout)


async def run_session(
    *,
    user: str,
    host: str,
    password: str | None,
    identity_file: Path | None,
    store: TOFUStore | None,
    bucket: Bucket | None = None,
    shell: str = "bash",
    tmux_session: str | None = None,
    tmux_config: TmuxConfig | None = None,
    clip_config: ClipConfig | None = None,
    port: int | None = None,
) -> int:
    """Connect, run interactive shell, bridge stdio, return remote exit code.

    Brings `shell` up under the multiplexer by **injecting** hop 1: it opens an
    ordinary login shell and feeds the session script over its stdin
    (transport-agnostic, POSIX -- no `<(...)`/argv escaping), exactly as `sb inject`
    does for deeper hops. The script is the plain bootstrap, or -- for `--tmux` -- the
    tmux-resolving prologue (which brings tmux up with `sb mux` as the pane command).
    It fetches the sb binary and `exec`s the multiplexer (or tmux), whose in-band
    requests a `BootstrapServer` answers from the `bucket`. If `bucket` is None, a
    plain interactive shell runs.

    The wire is token-free: the wrapper mints nothing -- each `sb mux` mints
    its own per-host socket token.
    """
    server: BootstrapServer | None = None
    if bucket is not None:
        regenerate_runtimes(bucket)
        server = BootstrapServer(bucket=bucket, clip=clip_config or ClipConfig())
    kwargs = build_connect_kwargs(
        host=host,
        user=user,
        password=password,
        identity_file=identity_file,
        store=store,
        port=port,
    )
    script = _session_script(shell, tmux_session, tmux_config) if server else None
    async with asyncssh.connect(**kwargs) as conn:
        cols, rows = _terminal_size()
        # Always an interactive login shell (command=None); we feed the script.
        async with conn.create_process(
            None,
            term_type=os.environ.get("TERM", "xterm-256color"),
            term_size=(cols, rows),
            encoding=None,
        ) as proc:
            initial = await _feed_and_sync(proc, script) if script else b""
            # The UDP backhaul is opt-in (SB_UDP_BACKHAUL=1) until it has soaked;
            # off -> identical in-band behavior.
            udp = os.environ.get("SB_UDP_BACKHAUL") == "1"
            await _bridge_stdio(proc, server=server, initial=initial, udp_backhaul=udp)
            return proc.returncode or 0
