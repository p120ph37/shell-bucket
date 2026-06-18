"""Live SSH integration tests against a Docker-hosted openssh-server.

The bootstrap tests exercise the full flow end-to-end, building a real bucket
(with the cross-built sb binary), serving it to the container, and letting the
multiplexer come up and tool the shell.
"""

from __future__ import annotations

import asyncio
import contextlib
import shutil
from pathlib import Path

import asyncssh
import pytest

from shell_bucket.apc_filter import APCFilter, apc_envelope
from shell_bucket.config import TmuxConfig
from shell_bucket.file_delivery import Bucket
from shell_bucket.known_hosts import TOFUStore
from shell_bucket.mux_frame import parse_route
from shell_bucket.tmux_fetch import fetch_tmux
from shell_bucket.wrapper import (
    BootstrapServer,
    TunnelManager,
    _feed_and_sync,
    _session_script,
    build_connect_kwargs,
    regenerate_runtimes,
)

pytestmark = pytest.mark.integration

# The colima builder is arm64, so the container runs the linux_arm64 binary.
# Integration tests run against the INSTRUMENTED binary (dist-test/, built with
# SB_TEST=1 — see native/sb/check.sh). It's a faithful superset of production:
# identical session behavior plus the `__xxx` hooks the cross-impl/e2e drivers
# need. Production (dist/) omits those hooks by design, so it can't drive them.
_DIST = Path(__file__).resolve().parents[2] / "native" / "sb" / "dist-test" / "linux_arm64"
_SB = _DIST / "sb"
_TMUX = _DIST / "tmux"  # cached static tmux (fetched on first need)
# The static tmux launcher: shipped in the package, dropped into the bucket so
# `sb mux --exec=sb-tmux.sh` autovivifies + runs it. sb itself stays tmux-agnostic.
_SB_TMUX_SH = Path(__file__).resolve().parents[2] / "src" / "shell_bucket" / "assets" / "sb-tmux.sh"


def _make_bucket(
    tmp_path: Path, helpers: dict[str, bytes], *, with_tmux: bool = False
) -> Bucket:
    """Build a bucket containing the real sb (under linux_arm64/), the given
    helpers (executable, at root), and freshly regenerated runtimes. With
    `with_tmux`, also drop the static tmux at linux_arm64/tmux."""
    if not _SB.is_file():
        pytest.skip("no native/sb/dist-test/linux_arm64/sb; run native/sb/check.sh")
    root = tmp_path / "bucket"
    (root / "linux_arm64").mkdir(parents=True)
    shutil.copy2(_SB, root / "linux_arm64" / "sb")
    (root / "linux_arm64" / "sb").chmod(0o755)
    if with_tmux:
        shutil.copy2(_ensure_tmux(), root / "linux_arm64" / "tmux")
        (root / "linux_arm64" / "tmux").chmod(0o755)
        shutil.copy2(_SB_TMUX_SH, root / "sb-tmux.sh")  # the launcher (autoviv'd via --exec)
        (root / "sb-tmux.sh").chmod(0o755)
    for name, body in helpers.items():
        p = root / name
        p.write_bytes(body)
        p.chmod(0o755)
    bucket = Bucket(root)
    regenerate_runtimes(bucket)
    return bucket


def _ensure_tmux() -> Path:
    """Path to a cached linux_arm64 static tmux, fetched (once) into dist if
    absent. Skips the test if it can't be obtained (e.g. offline)."""
    if _TMUX.is_file():
        return _TMUX
    try:
        fetch_tmux(_DIST.parent, platforms=["linux-arm64"])  # → dist/linux_arm64/tmux
    except (OSError, ValueError) as e:  # network / release issues
        pytest.skip(f"could not obtain static tmux: {e}")
    return _TMUX


# ───── connection-level (no bootstrap) ─────────────────────────────────────

async def test_password_auth_happy_path(ssh_server) -> None:
    kwargs = build_connect_kwargs(
        host=ssh_server.host, user=ssh_server.user, password=ssh_server.password,
        identity_file=None, store=None, port=ssh_server.port,
    )
    async with asyncssh.connect(**kwargs) as conn:
        assert (await conn.run("echo hello-from-test", check=True)).stdout.strip() == "hello-from-test"


async def test_tofu_records_then_matches(ssh_server, tmp_path: Path) -> None:
    store = TOFUStore(tmp_path / "known_hosts")
    assert store.lookup(ssh_server.host) == []

    def kwargs() -> dict:
        return build_connect_kwargs(
            host=ssh_server.host, user=ssh_server.user, password=ssh_server.password,
            identity_file=None, store=store, port=ssh_server.port,
        )

    async with asyncssh.connect(**kwargs()):
        pass
    assert len(store.lookup(ssh_server.host)) == 1
    async with asyncssh.connect(**kwargs()) as conn:
        assert (await conn.run("echo second", check=True)).stdout.strip() == "second"
    assert len(store.lookup(ssh_server.host)) == 1


async def test_tofu_rejects_after_tampering(ssh_server, tmp_path: Path) -> None:
    kh = tmp_path / "known_hosts"
    store = TOFUStore(kh)
    kwargs = build_connect_kwargs(
        host=ssh_server.host, user=ssh_server.user, password=ssh_server.password,
        identity_file=None, store=store, port=ssh_server.port,
    )
    async with asyncssh.connect(**kwargs):
        pass
    fake = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    kh.write_text(f"{ssh_server.host} {fake}\n")
    with pytest.raises(asyncssh.Error):
        async with asyncssh.connect(**kwargs):
            pass


async def test_wrong_password_raises(ssh_server) -> None:
    kwargs = build_connect_kwargs(
        host=ssh_server.host, user=ssh_server.user, password="nope",
        identity_file=None, store=None, port=ssh_server.port,
    )
    with pytest.raises(asyncssh.PermissionDenied):
        async with asyncssh.connect(**kwargs):
            pass


async def test_compression_negotiates_non_none(ssh_server) -> None:
    kwargs = build_connect_kwargs(
        host=ssh_server.host, user=ssh_server.user, password=ssh_server.password,
        identity_file=None, store=None, port=ssh_server.port,
    )
    async with asyncssh.connect(**kwargs) as conn:
        assert conn._cmp_alg_cs != b"none" and conn._cmp_alg_sc != b"none"


# ───── bootstrap + sb end-to-end ──────────────────────────────────────────

async def _drive(
    proc: asyncssh.SSHClientProcess,
    server: BootstrapServer,
    *,
    expect: bytes,
    send_after_rc: bytes,
    timeout: float = 45.0,
    initial: bytes = b"",
) -> tuple[bytes, list[bytes]]:
    """Pump the session through a real BootstrapServer until `expect` appears;
    return (output, served-events).

    Once the runtime (sb-bash.rc) is served — the shell is coming up under sb —
    sends `send_after_rc`. `initial` is any output already read past an injector's
    BEGIN sync (the injected-hop-1 path) and is processed before the read loop.
    """
    apc = APCFilter()
    out = bytearray()
    seen: list[bytes] = []
    sent = False

    async def pump() -> None:
        nonlocal sent
        pending = initial
        while True:
            if pending:
                data, pending = pending, b""
            else:
                data = await proc.stdout.read(4096)
                if not data:
                    return
            forwarded, events = apc.feed(data)
            out.extend(forwarded)
            for ev in events:
                seen.append(ev[:48])
                resp = server.serve(ev)
                if resp is not None:
                    proc.stdin.write(apc_envelope(resp) if parse_route(ev) else resp)
                if ev.startswith(b"FILEREQ:sb-bash.rc") and not sent:
                    sent = True
                    proc.stdin.write(send_after_rc)
            if expect in bytes(out):
                return

    try:
        await asyncio.wait_for(pump(), timeout)
    except TimeoutError:
        print(f"\n[drive] TIMEOUT. events: {seen}")
        print(f"[drive] tail: {bytes(out)[-600:]!r}")
        raise
    finally:
        with contextlib.suppress(Exception):
            proc.stdin.write(b"exit\n")
    return bytes(out), seen


async def _run_bootstrap(
    ssh_server, bucket: Bucket, *, expect: bytes, send: bytes
) -> tuple[bytes, list[bytes]]:
    server = BootstrapServer(bucket=bucket)
    kwargs = build_connect_kwargs(
        host=ssh_server.host, user=ssh_server.user, password=ssh_server.password,
        identity_file=None, store=None, port=ssh_server.port,
    )
    async with asyncssh.connect(**kwargs) as conn:
        # The ssh_server fixture is session-scoped, so tests share $HOME and thus
        # ~/.cache/shell-bucket. Clear it so each test starts like a fresh host —
        # otherwise a same-second sb.rc mtime can make If-Modified-Since reuse a
        # prior test's cached runtime (mtime-granularity collision).
        await conn.run('rm -rf "$HOME/.cache/shell-bucket"')
        # Inject hop 1: open a plain login shell and feed the bootstrap (no embed
        # launch, no `<(…)`), exactly as the wrapper does in production.
        async with conn.create_process(
            None, term_type="xterm", term_size=(80, 24), encoding=None
        ) as proc:
            initial = await _feed_and_sync(proc, _session_script("bash"))
            return await _drive(
                proc, server, expect=expect, send_after_rc=send, initial=initial
            )


async def test_sb_bootstrap_runs_lazy_helper_end_to_end(ssh_server, tmp_path: Path) -> None:
    """The wrapper injects hop 1 (feeds the bootstrap over a plain login shell);
    the bootstrap fetches the real sb + runtime → `sb mux` launches the shell → a
    lazy alias fetches+runs through the multiplexer. The whole feed→fetch→mux flow,
    end to end, with no embed."""
    bucket = _make_bucket(tmp_path, {"sbhello": b'#!/bin/sh\necho "HELLO_FROM[$1]"\n'})
    out, seen = await _run_bootstrap(
        ssh_server, bucket, expect=b"HELLO_FROM[world]", send=b"sbhello world\n"
    )
    assert b"HELLO_FROM[world]" in out
    # the child's lazy-alias fetch went over the mux SOCKET — `sbhello` arrives
    # label-swap framed (`R<id>:FILEREQ:sbhello`), never a raw tty `FILEREQ:sbhello`.
    # (The bootstrap's own sb/manifest/runtime fetches stay raw on the byte stream —
    # those happen in/under the mux, pre-socket.)
    assert any(ev.startswith(b"R") and b":FILEREQ:sbhello" in ev for ev in seen), seen
    assert not any(ev.startswith(b"FILEREQ:sbhello") for ev in seen), seen
    # The freshness window dedups the manifest transfer: `sb fetch sb` (bootstrap)
    # fetches it once, and `sb mux` reuses that <60s-old cache rather than refetching.
    assert sum(1 for ev in seen if ev.startswith(b"FILEREQ:sb-manifest")) == 1, seen


async def test_lazy_alias_for_root_helper(ssh_server, tmp_path: Path) -> None:
    """A second end-to-end: an agnostic root-of-bucket helper resolves and runs.

    (Forged-request defense is now structural — the mux strips our-prefix APCs out
    of its child stream — and is covered by `test_strip_at_source_blocks_child_forged_apc`
    plus the APC-filter unit tests.)
    """
    bucket = _make_bucket(tmp_path, {"sbsecret": b"#!/bin/sh\necho SECRET_OK\n"})
    out, _seen = await _run_bootstrap(ssh_server, bucket, expect=b"SECRET_OK", send=b"sbsecret\n")
    assert b"SECRET_OK" in out


async def test_busybox_applet_symlink_dedup_end_to_end(ssh_server, tmp_path: Path) -> None:
    """Busybox-style dedup, end to end: the bucket holds a multi-call helper
    (`sbbox`, dispatching on `$0`) plus an applet symlink (`sbls → sbbox`). The
    wrapper flattens the link in the manifest (4th column); running the applet on
    the target fetches the real helper ONCE and materializes a local symlink, so
    the applet dispatches with no second copy. We then assert the cache holds the
    real `sbbox` and a `sbls` SYMLINK (the dedup), not two copies."""
    box = (
        b'#!/bin/sh\n'
        b'case "${0##*/}" in\n'
        b'  sbls) echo "APPLET_LS_OK" ;;\n'
        b'  *) echo "APPLET_BOX[${0##*/}]" ;;\n'
        b'esac\n'
    )
    bucket = _make_bucket(tmp_path, {"sbbox": box})
    # The applet symlink lives in the bucket root → sbbox (relative, in-bucket).
    (bucket.path / "sbls").symlink_to("sbbox")
    regenerate_runtimes(bucket)  # rewrite the manifest with the link entry

    # Run the applet, then inspect the on-target cache. The gate marker `RES:<…>`
    # is COMPUTED on the target (real-copy count + link flag), so it can't false-
    # match the echoed command line the way a literal `LINK=` would; we wait for it.
    probe = (
        b"sbls; "
        b'echo "RES:$(find "$SB_CACHE" -maxdepth 1 -type f -name sbbox | wc -l | tr -d " ")'
        b'$([ -L "$SB_CACHE/sbls" ] && echo L || echo X)"\n'
    )
    out, seen = await _run_bootstrap(
        ssh_server, bucket, expect=b"RES:1L", send=probe
    )
    assert b"APPLET_LS_OK" in out          # the applet ran (dispatched on $0)
    assert b"RES:1L" in out                # one real copy + sbls is a symlink (dedup)
    # The applet fetch rode the socket as a FILEREQ for the TERMINAL (sbbox), never
    # for sbls — no link bytes cross the wire.
    assert any(ev.startswith(b"R") and b":FILEREQ:sbbox" in ev for ev in seen), seen
    assert not any(b":FILEREQ:sbls" in ev for ev in seen), seen


async def test_strip_at_source_blocks_child_forged_apc(ssh_server, tmp_path: Path) -> None:
    """Strip-at-source: the wire is token-free, so trust is *structural* — any
    child that emits an our-prefix APC has it STRIPPED by the mux before it can reach
    the wrapper. (This is what makes the token-free wire safe: a malicious child can't
    climb a forged request, because the mux eats our-prefix APCs out of its own forkpty
    child.) The surrounding terminal text passes through, so the command demonstrably
    ran but the forged FILEREQ never escaped the host."""
    bucket = _make_bucket(tmp_path, {})
    # printf a real our-prefix APC (ESC _ shell-bucket:FILEREQ:EVIL ESC \) from the
    # child, bracketed by plain text; the APC must be dropped, the text relayed.
    send = b"printf '\\033_shell-bucket:FILEREQ:EVIL\\033\\\\'; echo STRIP_AFTER\n"
    out, seen = await _run_bootstrap(ssh_server, bucket, expect=b"STRIP_AFTER", send=send)
    assert b"STRIP_AFTER" in out  # terminal passed through → the command ran
    # The discriminator: the *real* APC (printf's output, with real ESC bytes) is
    # stripped, so it never becomes a parsed event at the wrapper. (`out` does contain
    # the literal `…FILEREQ:EVIL` — that's the shell ECHOING the typed command line,
    # `\033` as source text not a real ESC, which no parser treats as an APC.)
    assert not any(b"FILEREQ:EVIL" in ev for ev in seen), seen


async def test_subshell_tool_uses_socket_no_nested_mux(ssh_server, tmp_path: Path) -> None:
    """Subshell zero-magic: a plain subshell of the session — NOT a nested
    `sb mux` — runs a lazy alias that fetches over the host mux's mux socket,
    needing only the inherited `SB_TOKEN` + PATH. Proves the side-band collapses
    intra-host tooling to one mux per host (a grandchild process is tooled with no
    multiplexer of its own)."""
    bucket = _make_bucket(tmp_path, {"sbsub": b'#!/bin/sh\necho "SUB_OK[$1]"\n'})
    out, seen = await _run_bootstrap(
        ssh_server, bucket, expect=b"SUB_OK[deep]", send=b"sh -c 'sbsub deep'\n"
    )
    assert b"SUB_OK[deep]" in out
    # The subshell's fetch still rode the host socket (label-swap `R<id>:` framed) —
    # no extra mux was spawned for it; it reused the one host mux.
    assert any(ev.startswith(b"R") and b":FILEREQ:sbsub" in ev for ev in seen), seen


async def test_mux_socket_fetch_through_byte_stream(ssh_server, tmp_path: Path) -> None:
    """The request-id relay: `sb __muxfetch` sends a request over the
    mux socket → the mux tags it with a request-id and frames it up the byte
    stream → the wrapper serves it and echoes the id → the mux routes the response
    back to that client → the client decodes the base64 body. So a socket client
    fetches a real file *through* the byte-stream relay, end to end."""
    bucket = _make_bucket(tmp_path, {"sbmark": b"MARK_THROUGH_SOCKET\n"})
    out, seen = await _run_bootstrap(
        ssh_server, bucket,
        expect=b"MARK_THROUGH_SOCKET", send=b"sb __muxfetch FILEREQ:sbmark\n",
    )
    assert b"MARK_THROUGH_SOCKET" in out
    # The request reached the wrapper label-swap framed (`R<id>:FILEREQ:sbmark`), not
    # a raw/plain FILEREQ — the mux assigned its own id and the wrapper echoed it.
    assert any(ev.startswith(b"R") and b":FILEREQ:sbmark" in ev for ev in seen), seen


async def test_mux_socket_framed_origin_reframes(ssh_server, tmp_path: Path) -> None:
    """The FRAMED-origin routing branch: a socket client sends an already-`R<inner>:`
    tagged request (exactly what an `sb inject` conduit forwards when a deeper mux
    relays its child's fetch). The host mux must record `inner`, relay up under its
    OWN id, and re-frame the reply `R<inner>:<resp>` back as an APC. `__conduitfetch`
    sends `R9:FILEREQ:sbmark`, reads that APC, verifies its id is 9, and prints the
    decoded body. Covers `run_mux_pump`'s `inner_id >= 0` re-framing (the conduit
    response path the multi-hop bootstrap test doesn't reach)."""
    bucket = _make_bucket(tmp_path, {"sbmark": b"FRAMED_ORIGIN_OK\n"})
    out, seen = await _run_bootstrap(
        ssh_server, bucket,
        expect=b"FRAMED_ORIGIN_OK", send=b"sb __conduitfetch 9 FILEREQ:sbmark\n",
    )
    # The client only prints (and exits 0) if the reply came back re-framed to its
    # inner id 9 — so FRAMED_ORIGIN_OK appearing proves the re-frame happened.
    assert b"FRAMED_ORIGIN_OK" in out
    # And the host mux relayed it up under its OWN id (label-swap), not R9.
    assert any(ev.startswith(b"R") and b":FILEREQ:sbmark" in ev and not ev.startswith(b"R9:") for ev in seen), seen


# ───── SURVEY → topology ───────────────────────────────────────────────

async def _drive_survey(
    proc: asyncssh.SSHClientProcess,
    server: BootstrapServer,
    *,
    want_routes: int,
    initial: bytes = b"",
    deeper_send: bytes | None = None,
    timeout: float = 120.0,
) -> None:
    """Bring the session up, (optionally) `sb inject` a deeper mux, then send a
    SURVEY down and pump until the topology has `want_routes` nodes. SURVEYR replies
    record into `server.topology`. The survey is sent once the relevant mux is up:
    on hop-1's rc fetch (raw), and — if `deeper_send` is given — after opening the
    deeper hop and seeing its conduit-relayed rc fetch (`R<id>:…sb-bash.rc`)."""
    apc = APCFilter()
    sent_deeper = False
    surveyed = False

    async def pump() -> None:
        nonlocal sent_deeper, surveyed
        pending = initial
        while True:
            if pending:
                data, pending = pending, b""
            else:
                data = await proc.stdout.read(4096)
                if not data:
                    return
            _forwarded, events = apc.feed(data)
            for ev in events:
                resp = server.serve(ev)
                if resp is not None:
                    proc.stdin.write(apc_envelope(resp) if parse_route(ev) else resp)
                if deeper_send is not None and not sent_deeper and ev.startswith(b"FILEREQ:sb-bash.rc"):
                    sent_deeper = True
                    proc.stdin.write(deeper_send)
                elif not surveyed and (
                    (deeper_send is None and ev.startswith(b"FILEREQ:sb-bash.rc"))
                    or (deeper_send is not None and ev.startswith(b"R") and b"FILEREQ:sb-bash.rc" in ev)
                ):
                    surveyed = True
                    proc.stdin.write(server.survey_apc())
            if len(server.topology.routes()) >= want_routes:
                return

    try:
        await asyncio.wait_for(pump(), timeout)
    except TimeoutError:
        print(f"\n[survey] TIMEOUT. routes: {server.topology.routes()}")
        raise
    finally:
        with contextlib.suppress(Exception):
            proc.stdin.write(b"exit\nexit\n")


async def test_survey_single_hop(ssh_server, tmp_path: Path) -> None:
    """The wrapper sends `SURVEY` down; the (single) host mux self-replies `SURVEYR`
    with its identity and an empty route, which the wrapper records into the topology.
    Proves the SURVEY round-trip + topology rebuild on a one-node tree."""
    bucket = _make_bucket(tmp_path, {})
    server = BootstrapServer(bucket=bucket)
    kwargs = build_connect_kwargs(
        host=ssh_server.host, user=ssh_server.user, password=ssh_server.password,
        identity_file=None, store=None, port=ssh_server.port,
    )
    async with asyncssh.connect(**kwargs) as conn:
        await conn.run('rm -rf "$HOME/.cache/shell-bucket"')
        async with conn.create_process(
            None, term_type="xterm", term_size=(80, 24), encoding=None
        ) as proc:
            initial = await _feed_and_sync(proc, _session_script("bash"))
            await _drive_survey(proc, server, want_routes=1, initial=initial)
    assert server.topology.routes() == [()]  # one node, the top mux, empty route
    node = server.topology.nodes()[0]
    assert node.depth == 1 and node.fields.get("arch")  # identity came back


async def test_survey_two_hop_routes(ssh_server, tmp_path: Path) -> None:
    """With a deeper mux opened via `sb inject` (conduit), SURVEY fans out down the
    conduit and BOTH muxes reply: the host mux with an empty route,
    the deeper mux with a one-element route (the host mux prepended its conduit's
    cid as it relayed the reply up). Proves fan-out + route accumulation."""
    bucket = _make_bucket(tmp_path, {})
    server = BootstrapServer(bucket=bucket)
    kwargs = build_connect_kwargs(
        host=ssh_server.host, user=ssh_server.user, password=ssh_server.password,
        identity_file=None, store=None, port=ssh_server.port,
    )
    deeper = (
        b"mkdir -p /tmp/sbsurv && "
        b"sb inject env SB_CACHE=/tmp/sbsurv/cache bash\n"
    )
    async with asyncssh.connect(**kwargs) as conn:
        await conn.run('rm -rf "$HOME/.cache/shell-bucket" /tmp/sbsurv')
        async with conn.create_process(
            None, term_type="xterm", term_size=(80, 24), encoding=None
        ) as proc:
            initial = await _feed_and_sync(proc, _session_script("bash"))
            await _drive_survey(
                proc, server, want_routes=2, initial=initial, deeper_send=deeper
            )
    routes = server.topology.routes()
    assert () in routes, routes  # the host mux
    assert any(len(r) == 1 for r in routes), routes  # the deeper mux, via one conduit cid
    assert server.topology.depths() == [1, 2], server.topology.nodes()


async def test_push_single_hop_ping(ssh_server, tmp_path: Path) -> None:
    """A source-routed PUSH addressed to the top mux (empty route) — it acts locally
    (PING → PONG:<identity>) and replies up. Proves the wrapper→node push + the
    local-act + the PUSHR return, on a one-node tree."""
    bucket = _make_bucket(tmp_path, {})
    server = BootstrapServer(bucket=bucket)
    kwargs = build_connect_kwargs(
        host=ssh_server.host, user=ssh_server.user, password=ssh_server.password,
        identity_file=None, store=None, port=ssh_server.port,
    )
    apc = APCFilter()
    pushed = False

    async def pump(proc) -> None:
        nonlocal pushed
        pending = b""
        while True:
            if pending:
                data, pending = pending, b""
            else:
                data = await proc.stdout.read(4096)
                if not data:
                    return
            _f, events = apc.feed(data)
            for ev in events:
                r = server.serve(ev)
                if r is not None:
                    proc.stdin.write(apc_envelope(r) if parse_route(ev) else r)
                if not pushed and ev.startswith(b"FILEREQ:sb-bash.rc"):
                    pushed = True
                    proc.stdin.write(server.push_apc(1, (), b"PING"))
            if 1 in server.pushes:
                return

    async with asyncssh.connect(**kwargs) as conn:
        await conn.run('rm -rf "$HOME/.cache/shell-bucket"')
        async with conn.create_process(
            None, term_type="xterm", term_size=(80, 24), encoding=None
        ) as proc:
            initial = await _feed_and_sync(proc, _session_script("bash"))
            apc.feed(initial)  # process any post-BEGIN remainder first
            try:
                await asyncio.wait_for(pump(proc), 45.0)
            finally:
                with contextlib.suppress(Exception):
                    proc.stdin.write(b"exit\n")
    assert server.pushes.get(1, b"").startswith(b"PONG:host="), server.pushes


async def test_push_two_hop_addresses_deeper(ssh_server, tmp_path: Path) -> None:
    """Source-route a PUSH to the DEEPER mux (reached via the conduit): survey first to
    learn its route, then `PUSH` PING along it — the host mux pops the head cid and
    forwards to the conduit, the deeper mux acts locally, and PUSHR returns. The PONG
    identity is the DEEPER node's (different pid than the host mux), proving the push
    addressed the right node down the tree."""
    bucket = _make_bucket(tmp_path, {})
    server = BootstrapServer(bucket=bucket)
    kwargs = build_connect_kwargs(
        host=ssh_server.host, user=ssh_server.user, password=ssh_server.password,
        identity_file=None, store=None, port=ssh_server.port,
    )
    deeper = (
        b"mkdir -p /tmp/sbpush && "
        b"sb inject env SB_CACHE=/tmp/sbpush/cache bash\n"
    )
    sent_deeper = False
    surveyed = False
    pushed = False
    apc = APCFilter()

    def deeper_node():
        for n in server.topology.nodes():
            if len(n.route) == 1:
                return n
        return None

    async def pump(proc) -> None:
        nonlocal sent_deeper, surveyed, pushed
        pending = b""
        while True:
            if pending:
                data, pending = pending, b""
            else:
                data = await proc.stdout.read(4096)
                if not data:
                    return
            _f, events = apc.feed(data)
            for ev in events:
                r = server.serve(ev)
                if r is not None:
                    proc.stdin.write(apc_envelope(r) if parse_route(ev) else r)
                if not sent_deeper and ev.startswith(b"FILEREQ:sb-bash.rc"):
                    sent_deeper = True
                    proc.stdin.write(deeper)
                elif not surveyed and ev.startswith(b"R") and b"FILEREQ:sb-bash.rc" in ev:
                    surveyed = True
                    proc.stdin.write(server.survey_apc())
            if not pushed and deeper_node() is not None:
                pushed = True
                proc.stdin.write(server.push_apc(2, deeper_node().route, b"PING"))
            if 2 in server.pushes:
                return

    async with asyncssh.connect(**kwargs) as conn:
        await conn.run('rm -rf "$HOME/.cache/shell-bucket" /tmp/sbpush')
        async with conn.create_process(
            None, term_type="xterm", term_size=(80, 24), encoding=None
        ) as proc:
            initial = await _feed_and_sync(proc, _session_script("bash"))
            apc.feed(initial)
            try:
                await asyncio.wait_for(pump(proc), 120.0)
            finally:
                with contextlib.suppress(Exception):
                    proc.stdin.write(b"exit\nexit\n")
    reply = server.pushes.get(2, b"")
    assert reply.startswith(b"PONG:"), (reply, server.pushes)
    # The reply identity is the DEEPER node's, not the host mux's (distinct pid).
    deep_pid = deeper_node().fields["pid"]
    top_pid = server.topology.nodes()[0].fields["pid"]
    assert f"pid={deep_pid}".encode() in reply and deep_pid != top_pid, (reply, deep_pid, top_pid)


# ───── multi-hop (sb inject conduit) ───────────────────────────────────────
#
# A host has ONE mux/socket, and deeper hosts are reached via the `sb inject` CONDUIT —
# a label-swap edge to a DIFFERENT host's socket. A real deeper host = a different
# `/tmp` (e.g. `sb inject docker run …`); for a deterministic single-container proof we
# give the deeper mux only a fresh `$SB_CACHE` (so it bootstraps fresh over the conduit,
# which is what the assertions prove). It needs no distinct `$TMPDIR` — each mux mints
# its own token, so its socket name is unique on the shared `/tmp` by construction. Same
# conduit code: separate mux process, real backhaul, and the host mux's `inner_id`
# re-framing.


async def _drive_conduit(
    proc: asyncssh.SSHClientProcess,
    server: BootstrapServer,
    *,
    deeper_send: bytes,
    timeout: float = 120.0,
    initial: bytes = b"",
) -> list[bytes]:
    """Inject hop 1, then `sb inject` a deeper mux (fresh `$SB_CACHE`; its socket name
    is unique by minting). The deeper host then bootstraps ENTIRELY over the conduit: its
    `sb` binary, manifest, and runtime fetches all backhaul up the host mux socket and
    arrive at the wrapper label-swap re-framed by the host mux (`R<id>:FILEREQ:…`, the
    deeper side's raw/`R` request swapped to the host mux's id). Returns when the
    deeper runtime fetch (the last bootstrap step) arrives conduit-relayed — proving
    the full bidirectional edge (the deeper host couldn't have reached that step
    unless every prior response was routed back through the conduit)."""
    apc = APCFilter()
    out = bytearray()
    seen: list[bytes] = []
    sent_deeper = False

    async def pump() -> None:
        nonlocal sent_deeper
        pending = initial
        while True:
            if pending:
                data, pending = pending, b""
            else:
                data = await proc.stdout.read(4096)
                if not data:
                    return
            forwarded, events = apc.feed(data)
            out.extend(forwarded)
            for ev in events:
                seen.append(ev[:64])
                resp = server.serve(ev)
                if resp is not None:
                    proc.stdin.write(apc_envelope(resp) if parse_route(ev) else resp)
                if not sent_deeper and ev.startswith(b"FILEREQ:sb-bash.rc"):
                    sent_deeper = True  # hop-1 shell up → open the deeper hop
                    proc.stdin.write(deeper_send)
                elif sent_deeper and ev.startswith(b"R") and b"FILEREQ:sb-bash.rc" in ev:
                    return  # deeper runtime fetched THROUGH the conduit — proven
    try:
        await asyncio.wait_for(pump(), timeout)
    except TimeoutError:
        print(f"\n[conduit] TIMEOUT. events: {seen}")
        print(f"[conduit] tail: {bytes(out)[-600:]!r}")
        raise
    finally:
        with contextlib.suppress(Exception):
            proc.stdin.write(b"\x03exit\nexit\n")  # interrupt sb inject, then exit both
    return seen


async def test_conduit_multi_hop_label_swap(ssh_server, tmp_path: Path) -> None:
    """`sb inject` opens a deeper mux (fresh `$SB_CACHE`; its own minted socket) and
    BACKHAULS its protocol over the host mux socket — the conduit. With a fresh deeper
    cache, the deeper host fetches its whole bootstrap (sb binary, manifest, runtime)
    through the chain: deeper side → conduit → host mux → wrapper, each reply routed
    back down. So the deeper runtime fetch arriving label-swap re-framed
    (`R<id>:FILEREQ:sb-bash.rc`) proves the conduit edge end to end — the multi-hop path
    now a label-swap edge. (A real deeper host — `sb inject docker
    run …` — is the same code; the fresh `$SB_CACHE` makes the fetches deterministic.)"""
    bucket = _make_bucket(tmp_path, {})
    server = BootstrapServer(bucket=bucket)
    kwargs = build_connect_kwargs(
        host=ssh_server.host, user=ssh_server.user, password=ssh_server.password,
        identity_file=None, store=None, port=ssh_server.port,
    )
    deeper = (
        b"mkdir -p /tmp/sbdeep && "
        b"sb inject env SB_CACHE=/tmp/sbdeep/cache bash\n"
    )
    async with asyncssh.connect(**kwargs) as conn:
        await conn.run('rm -rf "$HOME/.cache/shell-bucket" /tmp/sbdeep')
        async with conn.create_process(
            None, term_type="xterm", term_size=(80, 24), encoding=None
        ) as proc:
            initial = await _feed_and_sync(proc, _session_script("bash"))
            seen = await _drive_conduit(proc, server, deeper_send=deeper, initial=initial)
    # The deeper host's sb-binary AND runtime fetches both arrived conduit-relayed,
    # label-swap re-framed by the host mux (`R<id>:…`). Each prior response had to
    # route back through the conduit for the deeper bootstrap to reach the next step,
    # so this proves the full bidirectional label-swap edge.
    assert any(ev.startswith(b"R") and b"FILEREQ:sb:" in ev for ev in seen), seen
    assert any(ev.startswith(b"R") and b"FILEREQ:sb-bash.rc" in ev for ev in seen), seen


# ───── in-band tmux delivery ────────────────────────────────────────

async def test_tmux_fetched_in_band_then_launches(ssh_server, tmp_path: Path) -> None:
    """With `prefer_system=False` + `fallback_without=False` and an empty cache, the
    only way a tmux session can come up is `sb mux --tmux=sbtest` fetching the bucket's
    static tmux IN-BAND (FILEREQ:tmux over the byte stream) and forkpty'ing a
    `tmux new -A` client (sb mux is the parent that owns the pty + socket; tmux's
    server daemonizes; panes are tooled shells reaching it over the socket). So the
    session's status line (`[sbtest]`) appearing proves the ~2MB binary was delivered
    and the client launched under sb mux — all via the fed prologue, no embed.
    """
    bucket = _make_bucket(tmp_path, {}, with_tmux=True)
    server = BootstrapServer(bucket=bucket)
    cfg = TmuxConfig(prefer_system=False, fetch_if_missing=True, fallback_without=False)
    script = _session_script("bash", tmux_session="sbtest", tmux_config=cfg)
    kwargs = build_connect_kwargs(
        host=ssh_server.host, user=ssh_server.user, password=ssh_server.password,
        identity_file=None, store=None, port=ssh_server.port,
    )
    apc = APCFilter()
    out = bytearray()
    seen: list[bytes] = []
    initial = b""

    async def pump() -> None:
        pending = initial
        while True:
            if pending:
                data, pending = pending, b""
            else:
                data = await proc.stdout.read(4096)
                if not data:
                    return
            forwarded, events = apc.feed(data)
            out.extend(forwarded)
            for ev in events:
                seen.append(ev)
                resp = server.serve(ev)
                if resp is not None:
                    proc.stdin.write(apc_envelope(resp) if parse_route(ev) else resp)
            if b"[sbtest]" in bytes(out):  # tmux status line → session is up
                return

    async with asyncssh.connect(**kwargs) as conn:
        await conn.run('rm -rf "$HOME/.cache/shell-bucket"')
        async with conn.create_process(
            None, term_type="xterm", term_size=(80, 24), encoding=None
        ) as proc:
            initial = await _feed_and_sync(proc, script)
            try:
                await asyncio.wait_for(pump(), 120.0)
            finally:
                with contextlib.suppress(Exception):
                    proc.stdin.write(b"\x02d")  # C-b d: detach, let the session exit cleanly

    # sb-tmux.sh resolved tmux via the bucket autoviv symlink (FILEREQ over the socket,
    # R-framed) and the manifest was already warm from mux startup.
    assert any(b"sb-manifest" in ev for ev in seen), seen
    assert any(b"linux_arm64/tmux" in ev for ev in seen), seen
    assert b"[sbtest]" in bytes(out)  # …and the session launched under the fetched tmux


async def _tmux_serve(proc, server, initial, *, until, on_marker=None, send=b"", timeout=120.0):
    """Pump one tmux phase: serve bootstrap/fetch events; once `on_marker` shows in the
    output, send `send` (e.g. a pane command); return (out, seen) when `until` appears."""
    apc = APCFilter()
    out = bytearray()
    seen: list[bytes] = []
    sent = False

    async def pump() -> None:
        nonlocal sent
        pending = initial
        while True:
            if pending:
                data, pending = pending, b""
            else:
                data = await proc.stdout.read(4096)
                if not data:
                    return
            forwarded, events = apc.feed(data)
            out.extend(forwarded)
            for ev in events:
                seen.append(ev[:64])
                resp = server.serve(ev)
                if resp is not None:
                    proc.stdin.write(apc_envelope(resp) if parse_route(ev) else resp)
            if on_marker and not sent and on_marker in bytes(out):
                sent = True
                proc.stdin.write(send)
            if until in bytes(out):
                return

    try:
        await asyncio.wait_for(pump(), timeout)
    except TimeoutError:
        print(f"\n[recon] TIMEOUT until={until!r}; tail={bytes(out)[-400:]!r}; seen={seen[-12:]}")
        raise
    return bytes(out), seen


async def test_tmux_reconnect_recovers_token(ssh_server, tmp_path: Path) -> None:
    """Reconnect end-to-end. A session's tmux server outlives its ephemeral
    driver+mux. A FRESH connection (new mux, fresh random token) re-runs sb-tmux.sh,
    which finds the surviving server, recovers its saved `@sb-token`, and
    `sb token --token=`s the new mux onto the socket the surviving panes still cache —
    so a tool run in a re-attached pane (carrying the ORIGINAL token) fetches
    successfully over the rebound socket. `RECON_OK` arriving R-framed proves the whole
    chain: surviving daemon → recovered token → socket rebind → pane tool over socket."""
    bucket = _make_bucket(tmp_path, {"sbrecon": b"#!/bin/sh\necho RECON_OK\n"}, with_tmux=True)
    server = BootstrapServer(bucket=bucket)
    cfg = TmuxConfig(prefer_system=False)  # use the bucket tmux → deterministic
    script = _session_script("bash", tmux_session="sbrecon", tmux_config=cfg)
    kwargs = build_connect_kwargs(
        host=ssh_server.host, user=ssh_server.user, password=ssh_server.password,
        identity_file=None, store=None, port=ssh_server.port,
    )
    async with asyncssh.connect(**kwargs) as conn:
        await conn.run('rm -rf "$HOME/.cache/shell-bucket"')
        # Phase 1 — bring the session up, then detach (the tmux server daemonizes and
        # survives; this mux exits with the connection).
        async with conn.create_process(
            None, term_type="xterm", term_size=(80, 24), encoding=None
        ) as proc:
            initial = await _feed_and_sync(proc, script)
            await _tmux_serve(proc, server, initial, until=b"[sbrecon]")
            with contextlib.suppress(Exception):
                proc.stdin.write(b"\x02d")  # C-b d detach
        # Phase 2 — reconnect: a brand-new mux (fresh token) re-runs sb-tmux.sh, which
        # recovers @sb-token and rebinds; then a pane tool must work over that socket.
        async with conn.create_process(
            None, term_type="xterm", term_size=(80, 24), encoding=None
        ) as proc2:
            initial2 = await _feed_and_sync(proc2, script)
            out2, seen2 = await _tmux_serve(
                proc2, server, initial2,
                until=b"RECON_OK", on_marker=b"[sbrecon]", send=b"sbrecon\n",
            )
            with contextlib.suppress(Exception):
                proc2.stdin.write(b"\x02d")
    assert b"RECON_OK" in out2  # a re-attached pane's tool ran…
    # …and it rode the rebound socket (R-framed = relayed up by the reconnected mux),
    # which is only possible if the new mux adopted the recovered token.
    assert any(ev.startswith(b"R") and b":FILEREQ:sbrecon" in ev for ev in seen2), seen2


# ───── sb tunnel ────────────────────────────────────────────────────────────

async def test_tunnel_connect_roundtrips(ssh_server, tmp_path: Path) -> None:
    """`sb tunnel connect <wrapper-dest>` (netcat-style): the wrapper dials a
    wrapper-side dest and `sb tunnel`'s stdin/stdout is the single connection. Driving
    `echo TUNPING | sb tunnel connect 127.0.0.1:<port>` in the pane → the wrapper dials
    a local line server that answers `GOT:TUNPING` → that arrives on the pane's stdout.
    Proves the whole in-band tunnel data plane (open → O → D both ways → H → C)."""
    bucket = _make_bucket(tmp_path, {})
    server = BootstrapServer(bucket=bucket)

    async def dest_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        line = await reader.readline()  # gets "TUNPING\n" then EOF (half-close from H)
        writer.write(b"GOT:" + line.strip() + b"\n")
        await writer.drain()
        writer.close()

    dest = await asyncio.start_server(dest_handler, "127.0.0.1", 0)
    port = dest.sockets[0].getsockname()[1]
    kwargs = build_connect_kwargs(
        host=ssh_server.host, user=ssh_server.user, password=ssh_server.password,
        identity_file=None, store=None, port=ssh_server.port,
    )
    async with dest:
        async with asyncssh.connect(**kwargs) as conn:
            await conn.run('rm -rf "$HOME/.cache/shell-bucket"')
            async with conn.create_process(
                None, term_type="xterm", term_size=(80, 24), encoding=None
            ) as proc:
                initial = await _feed_and_sync(proc, _session_script("bash"))
                apc = APCFilter()
                out = bytearray()
                tunnels = TunnelManager(lambda p: proc.stdin.write(apc_envelope(p)))
                sent = False

                async def pump() -> None:
                    nonlocal sent
                    pending = initial
                    while True:
                        if pending:
                            data, pending = pending, b""
                        else:
                            data = await proc.stdout.read(4096)
                            if not data:
                                return
                        forwarded, events = apc.feed(data)
                        out.extend(forwarded)
                        for ev in events:
                            framed = parse_route(ev)
                            if framed is not None and (
                                framed[0] in tunnels or framed[1].startswith(b"TUN:")
                            ):
                                tunnels.handle(*framed)
                                continue
                            resp = server.serve(ev)
                            if resp is not None:
                                proc.stdin.write(apc_envelope(resp) if parse_route(ev) else resp)
                            if ev.startswith(b"FILEREQ:sb-bash.rc") and not sent:
                                sent = True
                                proc.stdin.write(
                                    b"echo TUNPING | sb tunnel connect 127.0.0.1:%d\n" % port
                                )
                        if b"GOT:TUNPING" in bytes(out):
                            return

                try:
                    await asyncio.wait_for(pump(), 60.0)
                finally:
                    tunnels.close_all()
                    with contextlib.suppress(Exception):
                        proc.stdin.write(b"exit\n")
    assert b"GOT:TUNPING" in bytes(out), bytes(out)[-400:]


async def test_tunnel_listen_roundtrips(ssh_server, tmp_path: Path) -> None:
    """`sb tunnel listen <wrapper-listen>` (netcat-style): the WRAPPER binds the port;
    `sb tunnel`'s stdin/stdout services one accepted connection. `printf TUNRESP |
    sb tunnel listen <port>` → a client connecting to the wrapper's port sends PING (→
    appears on the pane) and receives TUNRESP (sb-tunnel's stdin → the conn). Proves
    bind:one + accept + O + D both ways."""
    import socket as _socket

    bucket = _make_bucket(tmp_path, {})
    server = BootstrapServer(bucket=bucket)
    probe = _socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()  # the wrapper (this process) will bind it via the bind tunnel
    kwargs = build_connect_kwargs(
        host=ssh_server.host, user=ssh_server.user, password=ssh_server.password,
        identity_file=None, store=None, port=ssh_server.port,
    )
    async with asyncssh.connect(**kwargs) as conn:
        await conn.run('rm -rf "$HOME/.cache/shell-bucket"')
        async with conn.create_process(
            None, term_type="xterm", term_size=(80, 24), encoding=None
        ) as proc:
            initial = await _feed_and_sync(proc, _session_script("bash"))
            apc = APCFilter()
            out = bytearray()
            tunnels = TunnelManager(lambda p: proc.stdin.write(apc_envelope(p)))
            done = asyncio.Event()
            result: dict[str, bytes] = {}
            sent = False

            async def pump() -> None:
                nonlocal sent
                pending = initial
                while not done.is_set():
                    if pending:
                        data, pending = pending, b""
                    else:
                        data = await proc.stdout.read(4096)
                        if not data:
                            return
                    forwarded, events = apc.feed(data)
                    out.extend(forwarded)
                    for ev in events:
                        framed = parse_route(ev)
                        if framed is not None and (
                            framed[0] in tunnels or framed[1].startswith(b"TUN:")
                        ):
                            tunnels.handle(*framed)
                            continue
                        resp = server.serve(ev)
                        if resp is not None:
                            proc.stdin.write(apc_envelope(resp) if parse_route(ev) else resp)
                        if ev.startswith(b"FILEREQ:sb-bash.rc") and not sent:
                            sent = True
                            proc.stdin.write(
                                b"printf TUNRESP | sb tunnel listen %d\n" % port
                            )

            async def client() -> None:
                for _ in range(300):  # wait for the wrapper to bind the listener
                    if done.is_set():
                        return
                    try:
                        reader, writer = await asyncio.open_connection("127.0.0.1", port)
                    except OSError:
                        await asyncio.sleep(0.05)
                        continue
                    writer.write(b"PING\n")
                    await writer.drain()
                    result["recv"] = await asyncio.wait_for(reader.read(100), 15)
                    writer.close()
                    done.set()
                    return

            pt = asyncio.create_task(pump())
            try:
                await asyncio.wait_for(client(), 70)
            finally:
                done.set()
                tunnels.close_all()
                pt.cancel()
                with contextlib.suppress(Exception, asyncio.CancelledError):
                    await pt
                with contextlib.suppress(Exception):
                    proc.stdin.write(b"\x03")  # interrupt sb tunnel
    assert result.get("recv", b"").startswith(b"TUNRESP"), (result, bytes(out)[-200:])


async def test_tunnel_export_roundtrips(ssh_server, tmp_path: Path) -> None:
    """`sb tunnel export <wrapper-listen> <remote-dest>`: the WRAPPER binds the port on
    this host; each connection it accepts makes `sb tunnel` (remote) dial <remote-dest> —
    here the container's own sshd at 127.0.0.1:2222. A client connecting to the wrapper's
    port receives the SSH banner tunneled back from the remote. Proves bind:all +
    run_tunnel_sock's dial path + multiplexed D relay."""
    import socket as _socket

    bucket = _make_bucket(tmp_path, {})
    server = BootstrapServer(bucket=bucket)
    probe = _socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()  # the wrapper (this process) will bind it via the export tunnel
    kwargs = build_connect_kwargs(
        host=ssh_server.host, user=ssh_server.user, password=ssh_server.password,
        identity_file=None, store=None, port=ssh_server.port,
    )
    async with asyncssh.connect(**kwargs) as conn:
        await conn.run('rm -rf "$HOME/.cache/shell-bucket"')
        async with conn.create_process(
            None, term_type="xterm", term_size=(80, 24), encoding=None
        ) as proc:
            initial = await _feed_and_sync(proc, _session_script("bash"))
            apc = APCFilter()
            out = bytearray()
            tunnels = TunnelManager(lambda p: proc.stdin.write(apc_envelope(p)))
            done = asyncio.Event()
            result: dict[str, bytes] = {}
            sent = False

            async def pump() -> None:
                nonlocal sent
                pending = initial
                while not done.is_set():
                    if pending:
                        data, pending = pending, b""
                    else:
                        data = await proc.stdout.read(4096)
                        if not data:
                            return
                    forwarded, events = apc.feed(data)
                    out.extend(forwarded)
                    for ev in events:
                        framed = parse_route(ev)
                        if framed is not None and (
                            framed[0] in tunnels or framed[1].startswith(b"TUN:")
                        ):
                            tunnels.handle(*framed)
                            continue
                        resp = server.serve(ev)
                        if resp is not None:
                            proc.stdin.write(apc_envelope(resp) if parse_route(ev) else resp)
                        if ev.startswith(b"FILEREQ:sb-bash.rc") and not sent:
                            sent = True
                            proc.stdin.write(
                                b"sb tunnel export %d 127.0.0.1:2222\n" % port
                            )

            async def client() -> None:
                for _ in range(300):  # wait for the wrapper to bind the listener
                    if done.is_set():
                        return
                    try:
                        reader, writer = await asyncio.open_connection("127.0.0.1", port)
                    except OSError:
                        await asyncio.sleep(0.05)
                        continue
                    result["recv"] = await asyncio.wait_for(reader.read(100), 15)
                    writer.close()
                    done.set()
                    return

            pt = asyncio.create_task(pump())
            try:
                await asyncio.wait_for(client(), 70)
            finally:
                done.set()
                tunnels.close_all()
                pt.cancel()
                with contextlib.suppress(Exception, asyncio.CancelledError):
                    await pt
                with contextlib.suppress(Exception):
                    proc.stdin.write(b"\x03")  # interrupt sb tunnel
    assert result.get("recv", b"").startswith(b"SSH-"), (result, bytes(out)[-200:])


async def test_tunnel_import_roundtrips(ssh_server, tmp_path: Path) -> None:
    """`sb tunnel import <local-listen> <wrapper-dest>`: the REMOTE binds the port; each
    connection it accepts makes the WRAPPER dial <wrapper-dest> (a host-side line server).
    An in-container client (bash `/dev/tcp`) connects to the remote's listener, sends
    TUNPING, and the host dest answers `GOT:TUNPING` back through the tunnel onto the
    pane. Proves run_tunnel_sock's listen/accept path + O-up + _DialTunnel multi-conn."""
    bucket = _make_bucket(tmp_path, {})
    server = BootstrapServer(bucket=bucket)

    async def dest_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        line = await reader.readline()  # "TUNPING\n"
        writer.write(b"GOT:" + line.strip() + b"\n")
        await writer.drain()
        writer.close()

    dest = await asyncio.start_server(dest_handler, "127.0.0.1", 0)
    hport = dest.sockets[0].getsockname()[1]
    cport = 29137  # the remote's listener (fresh container, no conflict)
    kwargs = build_connect_kwargs(
        host=ssh_server.host, user=ssh_server.user, password=ssh_server.password,
        identity_file=None, store=None, port=ssh_server.port,
    )
    async with dest:
        async with asyncssh.connect(**kwargs) as conn:
            await conn.run('rm -rf "$HOME/.cache/shell-bucket"')
            async with conn.create_process(
                None, term_type="xterm", term_size=(80, 24), encoding=None
            ) as proc:
                initial = await _feed_and_sync(proc, _session_script("bash"))
                apc = APCFilter()
                out = bytearray()
                tunnels = TunnelManager(lambda p: proc.stdin.write(apc_envelope(p)))
                sent = False

                async def pump() -> None:
                    nonlocal sent
                    pending = initial
                    while True:
                        if pending:
                            data, pending = pending, b""
                        else:
                            data = await proc.stdout.read(4096)
                            if not data:
                                return
                        forwarded, events = apc.feed(data)
                        out.extend(forwarded)
                        for ev in events:
                            framed = parse_route(ev)
                            if framed is not None and (
                                framed[0] in tunnels or framed[1].startswith(b"TUN:")
                            ):
                                tunnels.handle(*framed)
                                continue
                            resp = server.serve(ev)
                            if resp is not None:
                                proc.stdin.write(apc_envelope(resp) if parse_route(ev) else resp)
                            if ev.startswith(b"FILEREQ:sb-bash.rc") and not sent:
                                sent = True
                                # remote binds cport; wrapper dials the host line server.
                                # `& sleep` lets the listener come up before the client.
                                proc.stdin.write(
                                    b"sb tunnel import %d 127.0.0.1:%d & sleep 0.5; "
                                    b"exec 3<>/dev/tcp/127.0.0.1/%d; "
                                    b"printf 'TUNPING\\n' >&3; cat <&3\n"
                                    % (cport, hport, cport)
                                )
                        if b"GOT:TUNPING" in bytes(out):
                            return

                try:
                    await asyncio.wait_for(pump(), 60.0)
                finally:
                    tunnels.close_all()
                    with contextlib.suppress(Exception):
                        proc.stdin.write(b"\x03")
                        proc.stdin.write(b"exit\n")
    assert b"GOT:TUNPING" in bytes(out), bytes(out)[-400:]


async def test_tunnel_connect_two_hop(ssh_server, tmp_path: Path) -> None:
    """A tunnel established on a DEEPER mux (reached via an `sb inject` conduit) reuses
    ONE route id per hop: the deeper mux relays `R<dtid>:TUN…` up its conduit, the host
    mux label-swaps it to a single persistent id and reuses that id for every O/D/H/C
    frame (rather than minting a fresh id per frame). Running `sb tunnel connect` on the
    deeper host still round-trips `GOT:TUNPING`, proving the multi-hop reuse-lookup."""
    bucket = _make_bucket(tmp_path, {})
    server = BootstrapServer(bucket=bucket)

    async def dest_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        line = await reader.readline()
        writer.write(b"GOT:" + line.strip() + b"\n")
        await writer.drain()
        writer.close()

    dest = await asyncio.start_server(dest_handler, "127.0.0.1", 0)
    port = dest.sockets[0].getsockname()[1]
    kwargs = build_connect_kwargs(
        host=ssh_server.host, user=ssh_server.user, password=ssh_server.password,
        identity_file=None, store=None, port=ssh_server.port,
    )
    async with dest:
        async with asyncssh.connect(**kwargs) as conn:
            await conn.run('rm -rf "$HOME/.cache/shell-bucket" /tmp/sbtun')
            async with conn.create_process(
                None, term_type="xterm", term_size=(80, 24), encoding=None
            ) as proc:
                initial = await _feed_and_sync(proc, _session_script("bash"))
                apc = APCFilter()
                out = bytearray()
                tunnels = TunnelManager(lambda p: proc.stdin.write(apc_envelope(p)))
                injected = False
                tunneled = False

                async def pump() -> None:
                    nonlocal injected, tunneled
                    pending = initial
                    while True:
                        if pending:
                            data, pending = pending, b""
                        else:
                            data = await proc.stdout.read(4096)
                            if not data:
                                return
                        forwarded, events = apc.feed(data)
                        out.extend(forwarded)
                        for ev in events:
                            framed = parse_route(ev)
                            if framed is not None and (
                                framed[0] in tunnels or framed[1].startswith(b"TUN:")
                            ):
                                tunnels.handle(*framed)
                                continue
                            resp = server.serve(ev)
                            if resp is not None:
                                proc.stdin.write(apc_envelope(resp) if parse_route(ev) else resp)
                            if not injected and ev.startswith(b"FILEREQ:sb-bash.rc"):
                                injected = True  # open the deeper mux via a conduit
                                proc.stdin.write(
                                    b"mkdir -p /tmp/sbtun && "
                                    b"sb inject env SB_CACHE=/tmp/sbtun/cache bash\n"
                                )
                            elif (
                                not tunneled
                                and ev.startswith(b"R")
                                and b"FILEREQ:sb-bash.rc" in ev
                            ):
                                tunneled = True  # deeper mux is up → tunnel from it
                                proc.stdin.write(
                                    b"echo TUNPING | sb tunnel connect 127.0.0.1:%d\n" % port
                                )
                        if b"GOT:TUNPING" in bytes(out):
                            return

                try:
                    await asyncio.wait_for(pump(), 120.0)
                finally:
                    tunnels.close_all()
                    with contextlib.suppress(Exception):
                        proc.stdin.write(b"exit\nexit\n")
    assert b"GOT:TUNPING" in bytes(out), bytes(out)[-400:]
