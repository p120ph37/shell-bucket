"""Unit tests for the transport-agnostic wrapper (testable bits)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from shell_bucket.file_delivery import Bucket, encode_for_delivery, err_delivery
from shell_bucket.lazy_alias import RC_MARKER, build_bootstrap, build_tmux_prologue
from shell_bucket.config import TmuxConfig
from shell_bucket.wrapper import (
    BootstrapServer,
    TransportManager,
    _session_script,
    dispatch_apc_events,
    regenerate_runtimes,
)

# The wire is token-free: the wrapper holds no token and the builders /
# envelope take none -- each `sb mux` mints its own per-host socket token.


# ----- BootstrapServer -----------------------------------------------------

def _put(root: Path, rel: str, body: bytes = b"x", *, execu: bool = False) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(body)
    if execu:
        p.chmod(0o755)
    return p


def _server(bucket_path: Path) -> BootstrapServer:
    return BootstrapServer(bucket=Bucket(bucket_path))


def test_serve_legacy_verbs_are_gone(tmp_path: Path) -> None:
    # S2/S1/S1Q (the embed era) are no longer served -> dropped, not answered.
    srv = _server(tmp_path)
    assert srv.serve(b"S2:/usr/bin/bash") is None
    assert srv.serve(b"S1:/bin/bash") is None
    assert srv.serve(b"S1Q:/bin/bash") is None


def test_serve_boot_returns_begin_bootstrap(tmp_path: Path) -> None:
    # `sb hop`'s `BOOT:<shell>` -> the bootstrap to feed, with the BEGIN sync.
    out = _server(tmp_path).serve(b"BOOT:/usr/bin/bash")
    assert out == encode_for_delivery(
        build_bootstrap("/usr/bin/bash", begin=True).encode("utf-8")
    )


def test_serve_boot_route_framed_echoes_id_as_raw_frame(tmp_path: Path) -> None:
    # A BOOT relayed over a socket arrives R<id>-framed; the reply is a RAW frame
    # echoing the id (the transport frames it -- APC in-band or raw over UDP).
    out = _server(tmp_path).serve(b"R0:BOOT:bash")
    assert out is not None and out.startswith(b"R0:") and not out.startswith(b"\x1b_")


def test_serve_filereq_resolves_in_bucket(tmp_path: Path) -> None:
    p = _put(tmp_path, "linux_arm64/sb", body=b"\x7fELF", execu=True)
    out = _server(tmp_path).serve(b"FILEREQ:sb:os=Linux:arch=aarch64")
    mtime = int(p.stat().st_mtime)
    assert out == encode_for_delivery(b"\x7fELF", flags=("chmod=+x", f"mtime={mtime}"))


def test_serve_missing_is_not_found(tmp_path: Path) -> None:
    assert _server(tmp_path).serve(b"FILEREQ:nope:os=linux:arch=amd64") == err_delivery("NOT_FOUND")


def test_serve_unrecognized_returns_none(tmp_path: Path) -> None:
    srv = _server(tmp_path)
    assert srv.serve(b"garbage") is None and srv.serve(b"") is None


# ----- R<id> request-id frame (label-swap mux socket relay) -----------

def test_serve_route_echoes_request_id_as_raw_frame(tmp_path: Path) -> None:
    from shell_bucket.mux_frame import build_route

    a = _put(tmp_path, "alpha", body=b"A", execu=True)
    raw = encode_for_delivery(b"A", flags=("chmod=+x", f"mtime={int(a.stat().st_mtime)}"))
    # A socket request relayed up as R7:... -> reply re-tagged with the same id, as a
    # RAW frame (the transport -- APC in-band or UDP backhaul -- frames it).
    out = _server(tmp_path).serve(b"R7:FILEREQ:alpha")
    assert out == build_route(7, raw)


def test_serve_route_drop_stays_dropped(tmp_path: Path) -> None:
    # An inner command the server drops -> the whole R-frame is dropped (no reply).
    assert _server(tmp_path).serve(b"R3:garbage") is None


def test_serve_route_raw_filereq_unframed(tmp_path: Path) -> None:
    # A raw (unframed) FILEREQ -- the bootstrap / mux-startup path -- gets a raw,
    # un-enveloped reply (the requester reads raw `~EOF` lines).
    p = _put(tmp_path, "linux_arm64/sb", body=b"\x7fELF", execu=True)
    out = _server(tmp_path).serve(b"FILEREQ:sb:os=Linux:arch=aarch64")
    mtime = int(p.stat().st_mtime)
    assert out == encode_for_delivery(b"\x7fELF", flags=("chmod=+x", f"mtime={mtime}"))
    assert not out.startswith(b"\x1b_")  # no APC envelope


# ----- dispatch_apc_events -------------------------------------------------

def test_dispatch_routes_through_server(tmp_path: Path) -> None:
    a = _put(tmp_path, "alpha", body=b"A", execu=True)
    written: list[bytes] = []
    dispatch_apc_events([b"FILEREQ:alpha"], _server(tmp_path), written.append)
    assert written == [encode_for_delivery(b"A", flags=("chmod=+x", f"mtime={int(a.stat().st_mtime)}"))]


def test_dispatch_drops_unrecognized(tmp_path: Path) -> None:
    written: list[bytes] = []
    dispatch_apc_events([b"OTHER:x", b"garbage"], _server(tmp_path), written.append)
    assert written == []


def test_dispatch_no_server_is_silent() -> None:
    written: list[bytes] = []
    dispatch_apc_events([b"FILEREQ:x", b"S2:bash"], None, written.append)
    assert written == []


# ----- SURVEY -> topology -----------------------------------------------

def test_serve_surveyreply_records_topology_no_reply(tmp_path: Path) -> None:
    srv = _server(tmp_path)
    # top mux (empty route) and a deeper one (route 3); both fire-and-forget.
    assert srv.serve(b"SURVEYR:1::host=top:os=Linux:arch=aarch64:pid=1") is None
    assert srv.serve(b"SURVEYR:1:3:host=deep:pid=2") is None
    assert srv.topology.routes() == [(), (3,)]
    assert srv.topology.nodes()[0].host == "top"
    assert srv.topology.nodes()[1].route == (3,) and srv.topology.depths() == [1, 2]


def test_survey_apc_is_enveloped_survey(tmp_path: Path) -> None:
    from shell_bucket.apc_filter import apc_envelope
    from shell_bucket.mux_frame import build_survey

    srv = _server(tmp_path)
    assert srv.survey_apc(5) == apc_envelope(build_survey(5))


# ----- regenerate_runtimes --------------------------------------------------

def test_regenerate_creates_runtimes(tmp_path: Path) -> None:
    bucket = Bucket(tmp_path / "bucket")
    bucket.path.mkdir()
    _put(bucket.path, "imgcat", execu=True)
    _put(bucket.path, "rc.d/00-x.sh")
    regenerate_runtimes(bucket)
    bash_rc = (bucket.path / "sb-bash.rc").read_text()
    assert RC_MARKER in bash_rc
    # Helpers are PATH symlinks now (not baked into the runtime); only the rc.d
    # fragment gets a fetch+source stub, via the `sb` binary on PATH.
    assert "imgcat()" not in bash_rc
    assert 'command sb fetch "rc.d/00-x.sh"' in bash_rc
    # The manifest the wrapper regenerates lists the helper for `sb mux`.
    assert "imgcat\t" in (bucket.path / "sb-manifest").read_text()
    # ksh/zsh runtimes exist too (stubs).
    assert "not yet implemented" in (bucket.path / "sb-ksh.rc").read_text()


def test_regenerate_preserves_user_head(tmp_path: Path) -> None:
    bucket = Bucket(tmp_path / "bucket")
    bucket.path.mkdir()
    (bucket.path / "sb-bash.rc").write_text(f"# MY CUSTOM\nexport X=1\n{RC_MARKER}\nstale\n")
    regenerate_runtimes(bucket)
    rc = (bucket.path / "sb-bash.rc").read_text()
    assert "# MY CUSTOM" in rc and "export X=1" in rc and "stale" not in rc


# ----- _session_script (the script the wrapper feeds at hop 1) --------------

def test_session_script_plain_is_begin_bootstrap() -> None:
    assert _session_script("bash") == build_bootstrap("bash", begin=True)


def test_session_script_tmux_is_begin_prologue() -> None:
    s = _session_script("bash", tmux_session="proj")
    assert s == build_tmux_prologue("proj", "bash", begin=True)
    # the hop-1 script execs the fetchable `sb-tmux.sh` launcher via --exec; sb
    # itself is tmux-agnostic and nothing is embedded.
    assert 'exec "$SB_CACHE/sb" mux --exec=sb-tmux.sh proj' in s
    assert "<(" not in s and "<<<" not in s


def test_session_script_tmux_honors_config() -> None:
    # prefer_system off + fetch off -> those policies ride as launcher `--no-*` flags.
    cfg = TmuxConfig(prefer_system=False, fetch_if_missing=False)
    s = _session_script("bash", tmux_session="proj", tmux_config=cfg)
    assert 'exec "$SB_CACHE/sb" mux --exec=sb-tmux.sh proj --no-system --no-fetch' in s


# ----- BootstrapServer: clipboard (CLIP:GET / CLIP:SET) -----------------------

def test_clip_get_serves_apc_safe_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The wrapper returns b64-encoded clipboard bytes so the APC frame is binary-safe.
    # The mux decodes b64 -> raw before writing to the socket client (transparent to user).
    import shell_bucket.wrapper as _w
    monkeypatch.setattr(_w, "_clipboard_get", lambda: b"hello clipboard")
    srv = _server(tmp_path)
    resp = srv.serve(b"R5:CLIP:GET")
    assert resp is not None
    from shell_bucket.mux_frame import build_route
    import base64
    assert resp == build_route(5, base64.b64encode(b"hello clipboard"))


def test_clip_get_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import shell_bucket.wrapper as _w
    monkeypatch.setattr(_w, "_clipboard_get", lambda: None)
    srv = _server(tmp_path)
    resp = srv.serve(b"R2:CLIP:GET")
    from shell_bucket.mux_frame import build_route
    assert resp == build_route(2, b"ERR:clipboard-unavailable")


def test_clip_get_disabled(tmp_path: Path) -> None:
    from shell_bucket.config import ClipConfig
    srv = BootstrapServer(bucket=Bucket(tmp_path), clip=ClipConfig(enabled=False))
    resp = srv.serve(b"R1:CLIP:GET")
    from shell_bucket.mux_frame import build_route
    assert resp == build_route(1, b"ERR:clipboard-disabled")


def test_clip_set_calls_clipboard(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The mux b64-encodes the raw socket payload before sending CLIP:SET:<b64> upstream.
    # The wrapper decodes it and writes the raw bytes to the clipboard.
    import base64
    import shell_bucket.wrapper as _w
    received: list[bytes] = []
    monkeypatch.setattr(_w, "_clipboard_set", lambda d: received.append(d) or True)
    srv = _server(tmp_path)
    payload = base64.b64encode(b"copy this")
    resp = srv.serve(b"R3:CLIP:SET:" + payload)
    from shell_bucket.mux_frame import build_route
    assert resp == build_route(3, b"OK")
    assert received == [b"copy this"]


def test_clip_set_disabled(tmp_path: Path) -> None:
    import base64
    from shell_bucket.config import ClipConfig
    srv = BootstrapServer(bucket=Bucket(tmp_path), clip=ClipConfig(enabled=False))
    payload = base64.b64encode(b"data")
    resp = srv.serve(b"R4:CLIP:SET:" + payload)
    from shell_bucket.mux_frame import build_route
    assert resp == build_route(4, b"ERR:clipboard-disabled")


def test_clip_set_bad_base64(tmp_path: Path) -> None:
    srv = _server(tmp_path)
    resp = srv.serve(b"R6:CLIP:SET:!!!not-base64!!!")
    from shell_bucket.mux_frame import build_route
    assert resp == build_route(6, b"ERR:bad-base64")


# ----- TransportManager: one-shot renegotiation on backhaul death -----------


def _offers(writes: list[bytes]) -> list[bytes]:
    return [w for w in writes if b"UP:O:" in w]


@pytest.mark.asyncio
async def test_transport_manager_one_shot_renegotiation() -> None:
    # A backhaul that had been up dies (roaming / NAT-rebind). The wrapper makes
    # exactly ONE attempt to renegotiate a fresh path, then falls back to in-band:
    # a second death does not offer again. No STUN servers -> _gather just binds a
    # host candidate locally (fast, no network).
    writes: list[bytes] = []
    tm = TransportManager(write_raw=writes.append, stun=[])

    await tm.offer()  # initial upgrade offer
    assert len(_offers(writes)) == 1
    assert tm.sock is not None
    first_psk = tm.psk

    # First death -> one renegotiation offer, with a freshly minted PSK.
    tm.bh = object()  # truthy stand-in for an up backhaul
    tm._on_bh_closed()
    await asyncio.gather(*list(tm._tasks))
    assert tm._reneg_used is True
    assert len(_offers(writes)) == 2
    assert tm.psk != first_psk  # offers are independent

    # Second death -> no further renegotiation; stay in-band.
    tm.bh = object()
    tm._on_bh_closed()
    await asyncio.gather(*list(tm._tasks))
    assert len(_offers(writes)) == 2

    tm.close()


@pytest.mark.asyncio
async def test_up_reneg_forces_offer_past_one_shot_guard() -> None:
    # `UP:RENEG` from the mux (e.g. `sb ctl udpup`) forces a fresh offer regardless
    # of how many times the one-shot auto-reneg guard has already fired.
    writes: list[bytes] = []
    tm = TransportManager(write_raw=writes.append, stun=[])
    await tm.offer()
    assert len(_offers(writes)) == 1

    # Exhaust the one-shot guard via auto-reneg.
    tm._on_bh_closed()
    await asyncio.gather(*list(tm._tasks))
    assert tm._reneg_used is True
    assert len(_offers(writes)) == 2

    # Now feed UP:RENEG (as dispatch_frame would) -- must bypass the guard.
    tm._reneg_used = False   # simulates what dispatch_frame does on UP:RENEG
    tm._spawn_offer()
    await asyncio.gather(*list(tm._tasks))
    assert len(_offers(writes)) == 3

    # Confirm the guard is resetable: a second UP:RENEG works too.
    tm._reneg_used = False
    tm._spawn_offer()
    await asyncio.gather(*list(tm._tasks))
    assert len(_offers(writes)) == 4

    tm.close()
