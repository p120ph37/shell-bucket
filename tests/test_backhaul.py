"""Unit tests for the Python UDP-backhaul transport (mirror of the V self-tests).

Wire-compatibility with the native `sb` side rests on (a) identical AES-GCM —
proven by the same NIST KAT `sb`/BearSSL pass — and (b) the by-spec packet/ARQ/
frame formats. The lossy-reorder ARQ sim is the port of `test/arq.sh`. A live
Python<->`sb` cross-impl test needs a Linux container (see task #26) and is
covered separately.
"""

import asyncio
import base64
import os
import socket

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from shell_bucket.backhaul import (
    Arq,
    FrameStream,
    UdpBackhaul,
    _put_ipport,
    decode_answer,
    encode_offer,
    now_ms,
    stun_parse,
    stun_request,
    udp_open,
    udp_seal,
)


def encode_answer(nonce: bytes, cands: list[tuple[str, int]]) -> bytes:
    """Mux-side UP:A encoder. The wrapper only ever *decodes* answers (the mux
    answers), so this lives here as a test helper — the inverse of the production
    `decode_answer` it round-trips against. Mirror of the V `encode_answer`."""
    import base64

    blob = bytes([0x01]) + b"A" + nonce[:8]
    blob += bytes([len(cands)]) + b"".join(_put_ipport(ip, p) for ip, p in cands)
    return base64.b64encode(blob)


def test_nist_aesgcm_kat():
    # NIST GCM test case 2 — identical to what BearSSL/`sb __cryptotest` produces,
    # so the AEAD (hence every packet) is wire-compatible.
    key, iv, pt = b"\x00" * 16, b"\x00" * 12, b"\x00" * 16
    out = AESGCM(key).encrypt(iv, pt, b"")
    assert out[:16].hex() == "0388dace60b6a392f328c2b971b2fe78"
    assert out[16:].hex() == "ab6e47d42cec13bdf53a67b21257bddf"


def test_packet_codec_roundtrip():
    key = bytes((i * 7 + 1) & 0xFF for i in range(32))
    pkt = udp_seal(key, 1, 0x0102030405060708, b"hello frame")
    res = udp_open(key, 1, pkt)
    assert res == (0x0102030405060708, b"hello frame")
    assert udp_open(key, 2, pkt) is None  # wrong direction salt → tag fails
    bad = bytearray(pkt)
    bad[10] ^= 0xFF
    assert udp_open(key, 1, bytes(bad)) is None  # tamper → tag fails
    assert udp_open(key, 1, pkt[:-1]) is None  # truncation


def _run_arq_sim(loss_pct: int) -> tuple[bytes, bytes]:
    """128KB A→B over a seeded lossy/reordering channel on a virtual clock."""
    key = bytes((i * 7 + 9) & 0xFF for i in range(32))
    a, b = Arq(key, 1, 2), Arq(key, 2, 1)
    n = 128 * 1024
    msg = bytes((i * 131 + 7) & 0xFF for i in range(n))
    clock = 0
    a.app_send(msg, clock)
    got = bytearray()
    flight: list[tuple[int, bool, bytes]] = []
    rng = 0x1234ABCD
    steps = 0
    while len(got) < n and steps < 4_000_000:
        steps += 1
        for src, to_b in ((a, True), (b, False)):
            for p in src.poll_out():
                rng = (rng * 1103515245 + 12345) & 0xFFFFFFFF
                if (rng >> 16) % 100 < loss_pct:
                    continue
                rng = (rng * 1103515245 + 12345) & 0xFFFFFFFF
                flight.append((clock + 8 + (rng >> 16) % 25, to_b, p))
        nxt = min(
            [clock + 50, clock + a.next_timeout(clock), clock + b.next_timeout(clock)]
            + [due for due, _, _ in flight]
        )
        clock = clock + 1 if nxt <= clock else nxt
        still = []
        for due, to_b, data in flight:
            if due <= clock:
                (b if to_b else a).on_packet(data, clock)
            else:
                still.append((due, to_b, data))
        flight = still
        a.tick(clock)
        b.tick(clock)
        got += b.take_inbox()
    return bytes(got), msg


def test_arq_lossy_reorder():
    got, msg = _run_arq_sim(15)
    assert got == msg


def test_frame_stream_reassembles_across_feeds():
    fs = FrameStream()
    wire = FrameStream.wrap(b"R7:D:3:abc") + FrameStream.wrap(b"SURVEY:1")
    frames = fs.feed(wire[:3]) + fs.feed(wire[3:7]) + fs.feed(wire[7:])
    assert frames == [b"R7:D:3:abc", b"SURVEY:1"]


def test_stun_codec_roundtrip():
    # Build a request, synthesize a Success Response with XOR-MAPPED-ADDRESS, decode it.
    txid = bytes(range(12))
    req = stun_request(txid)
    assert len(req) == 20 and req[4:8] == bytes([0x21, 0x12, 0xA4, 0x42]) and req[8:20] == txid
    ip, port = "203.0.113.7", 54321
    octets = bytes(int(x) ^ c for x, c in zip(ip.split("."), [0x21, 0x12, 0xA4, 0x42]))
    body = bytes([0, 0x20, 0, 8, 0, 1, (port >> 8) ^ 0x21, (port & 0xFF) ^ 0x12]) + octets
    resp = bytes([1, 1, 0, len(body)]) + bytes([0x21, 0x12, 0xA4, 0x42]) + txid + body
    assert stun_parse(resp, txid) == (ip, port)
    assert stun_parse(resp, bytes(12)) is None  # txid mismatch


async def _await_state(bh: UdpBackhaul, target: str, tries: int = 250) -> bool:
    for _ in range(tries):
        if bh.state == target:
            return True
        await asyncio.sleep(0.02)
    return False


@pytest.mark.asyncio
async def test_udp_backhaul_punch_and_transfer_loopback():
    key = bytes((i * 7 + 5) & 0xFF for i in range(32))
    sa = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sb = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sa.bind(("127.0.0.1", 0))
    sb.bind(("127.0.0.1", 0))
    pa, pb = sa.getsockname()[1], sb.getsockname()[1]
    got_b: list[bytes] = []
    bh_a = UdpBackhaul(key, 1, 2, [("127.0.0.1", pb)], lambda f: None)
    bh_b = UdpBackhaul(key, 2, 1, [("127.0.0.1", pa)], got_b.append)
    bh_a.start(sa)
    bh_b.start(sb)
    try:
        assert await _await_state(bh_a, "up") and await _await_state(bh_b, "up")
        frames = [f"R{i}:D:1:{'x' * i}".encode() for i in range(60)]
        for f in frames:
            bh_a.send_frame(f)
        for _ in range(250):
            if len(got_b) >= len(frames):
                break
            await asyncio.sleep(0.02)
        assert got_b == frames
    finally:
        bh_a.close()
        bh_b.close()


@pytest.mark.asyncio
async def test_udp_backhaul_liveness_death_detection(monkeypatch):
    # Two backhauls punch and stay up via heartbeats; when one dies, the other
    # detects the silence and begins the lossless revert ("reverting" — it then
    # waits for the peer's in-band UP:RX to finish the handoff). Timeouts shrunk.
    import shell_bucket.backhaul as m

    monkeypatch.setattr(m, "BH_HB_MS", 30)
    monkeypatch.setattr(m, "BH_DEAD_MS", 200)
    key = bytes((i * 7 + 11) & 0xFF for i in range(32))
    sa = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sb = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sa.bind(("127.0.0.1", 0))
    sb.bind(("127.0.0.1", 0))
    pa, pb = sa.getsockname()[1], sb.getsockname()[1]
    bh_a = UdpBackhaul(key, 1, 2, [("127.0.0.1", pb)], lambda f: None)
    bh_b = UdpBackhaul(key, 2, 1, [("127.0.0.1", pa)], lambda f: None)
    bh_a.start(sa)
    bh_b.start(sb)
    try:
        assert await _await_state(bh_a, "up") and await _await_state(bh_b, "up")
        # Heartbeats keep it alive: still up well past one heartbeat interval.
        await asyncio.sleep(0.1)
        assert bh_a.state == "up"
        # Peer dies → A sees no more packets → begins revert within ~BH_DEAD_MS.
        bh_b.close()
        assert await _await_state(bh_a, "reverting", tries=100)
    finally:
        bh_a.close()
        bh_b.close()


class _FakeSock:
    """A non-networked stand-in: outbound packets land in `out` for manual shuttle."""

    def __init__(self) -> None:
        self.out: list[bytes] = []

    def send(self, pkt: bytes) -> None:
        self.out.append(pkt)

    def sendto(self, pkt: bytes, _addr) -> None:
        self.out.append(pkt)

    def fileno(self) -> int:
        return -1

    def setblocking(self, _b: bool) -> None:
        pass

    def close(self) -> None:
        pass


class _FakeLoop:
    def add_reader(self, *_a) -> None:
        pass

    def remove_reader(self, *_a) -> None:
        pass


def _wire_inband(a: UdpBackhaul, b: UdpBackhaul, got_a: list, got_b: list):
    """Model the durable in-band channel between two backhauls as a deferred queue
    (no synchronous re-entrancy — mirrors the real APC wire). Returns a drain fn."""
    q: list = []

    def inband_for(dst: UdpBackhaul, sink: list):
        def emit(frame: bytes) -> None:
            q.append((dst, sink, frame))

        return emit

    a.on_inband = inband_for(b, got_b)  # a's in-band frames are consumed by b
    b.on_inband = inband_for(a, got_a)

    def drain() -> None:
        while q:
            dst, sink, frame = q.pop(0)
            if frame.startswith(b"UP:RX:"):
                dst.peer_revert(int(frame[6:]))
            else:
                sink.append(frame)  # re-sent data frame, delivered as if it arrived in-band

    return drain


@pytest.mark.parametrize("prune_acks", [True, False])
def test_udp_backhaul_lossless_revert_exactly_once(prune_acks):
    # a streams frames to b; the UDP path dies after only a PREFIX is delivered.
    # The lossless revert must hand off the undelivered tail in-band so b ends up
    # with every frame exactly once, in order — whether or not a's send FIFO was
    # pruned by acks (prune_acks=False proves the peer's count, not the ARQ ack,
    # is authoritative, so no already-delivered frame is duplicated).
    key = bytes((i * 7 + 13) & 0xFF for i in range(32))
    got_a: list[bytes] = []
    got_b: list[bytes] = []
    a = UdpBackhaul(key, 1, 2, [], got_a.append)
    b = UdpBackhaul(key, 2, 1, [], got_b.append)
    for x in (a, b):
        x.sock = _FakeSock()
        x._loop = _FakeLoop()
        x.state = "up"
    drain = _wire_inband(a, b, got_a, got_b)

    # Random ~2 KB frames so DEFLATE can't collapse them to a single segment —
    # the stream spans many packets, making a partial (prefix) delivery realistic.
    frames = [f"R{i}:".encode() + os.urandom(2000) for i in range(24)]
    for f in frames:
        a.send_frame(f)

    # Deliver only the first half of a's packets to b (a contiguous prefix → b
    # cleanly consumes a prefix of frames; the rest are the undelivered tail).
    pkts = a.sock.out
    a.sock.out = []
    for p in pkts[: len(pkts) // 2]:
        b.arq.on_packet(p, now_ms())
    b._prune()
    b._deliver()
    assert 0 < b.rx_frames < len(frames)  # genuine partial delivery
    if prune_acks:
        b.arq.tick(now_ms())  # emit b's cumulative ack
        b._flush()
        for p in b.sock.out:
            a.arq.on_packet(p, now_ms())
        a._prune()
        assert a.tx_base == b.rx_frames  # FIFO pruned to exactly the acked prefix

    # The UDP path dies → a begins the in-band handoff; the queue cascade completes it.
    a._begin_revert()
    drain()

    assert a.state == "failed" and b.state == "failed"
    assert got_b == frames  # every frame, exactly once, in order
    assert got_a == []  # b never sent anything, so nothing to recover the other way


def test_signaling_offer_structure_and_answer_roundtrip():
    psk, nonce = bytes(range(32)), bytes(range(8))
    stun = [("162.159.207.0", 3478), ("74.125.250.129", 19302)]
    cands = [("192.168.1.5", 50000)]
    blob = base64.b64decode(encode_offer(psk, nonce, stun, cands))
    assert blob[0] == 0x01 and blob[1:2] == b"O"
    assert blob[2:34] == psk and blob[34:42] == nonce
    assert blob[42] == len(stun)  # stun count byte
    nonce2, cands2 = decode_answer(encode_answer(nonce, cands))
    assert nonce2 == nonce and cands2 == cands
