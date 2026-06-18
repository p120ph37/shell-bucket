"""The UDP backhaul transport -- the wrapper's peer to the native `sb` Backhaul.

A faithful port of the V implementation (native/sb/src/main.v); the wire must
match byte-for-byte. AES-256-GCM packets carry a TCP-lite ARQ that delivers a
reliable, ordered byte stream over hole-punched UDP; the stream carries
length-prefixed raw frames (no APC) dispatched directly by each side.

Wire (V-authoritative):
  packet  = [seq:8 BE][ AESGCM(key).encrypt(nonce, payload) = ct||tag(16) ]
            nonce = [salt:4 BE][seq:8 BE]; salt is a per-direction constant.
  ARQ payload = [flags:1][ack:8 BE] then if flags & DATA: [offset:8 BE][data]
  control     = flags bit7 set; 1-byte payload ctl_ping(0x80)/ctl_pong(0x81)
  frame strm  = [u32 BE len][frame]...   raw-DEFLATE'd onto the reliable ARQ stream
A persistent raw-deflate compressor pair (wbits=-15, sync-flush per chunk) sits
between the frame stream and the ARQ -- order is guaranteed, so the dictionary is
valid for the whole session. PSK (32 random bytes) is the AES-256 key -- no KDF.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import struct
import time
import zlib
from collections.abc import Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TAG_LEN = 16
SEG_MAX = 1200
ARQ_WINDOW = 65536
RTO_MIN_MS = 100
RTO_MAX_MS = 8000
F_DATA = 0x01
CTL_PING = 0x80
CTL_PONG = 0x81
BH_HB_MS = 5000  # heartbeat cadence once up -- refreshes NAT mappings + proves liveness
BH_DEAD_MS = 20000  # no packet received for this long once up -> path dead -> revert in-band

# Direction salts (must match V): wrapper sends with 1, mux sends with 2.
SALT_WRAPPER_TX = 1
SALT_MUX_TX = 2


def now_ms() -> int:
    return int(time.monotonic() * 1000)


def aead_nonce(salt: int, seq: int) -> bytes:
    return struct.pack(">IQ", salt, seq)  # 4-byte salt || 8-byte seq = 12 bytes


def udp_seal(key: bytes, salt: int, seq: int, payload: bytes) -> bytes:
    return struct.pack(">Q", seq) + AESGCM(key).encrypt(aead_nonce(salt, seq), payload, b"")


def udp_open(key: bytes, salt: int, pkt: bytes) -> tuple[int, bytes] | None:
    """Returns (seq, payload) or None if too short / tag fails."""
    if len(pkt) < 8 + TAG_LEN:
        return None
    seq = struct.unpack(">Q", pkt[:8])[0]
    try:
        payload = AESGCM(key).decrypt(aead_nonce(salt, seq), pkt[8:], b"")
    except Exception:
        return None
    return seq, payload


class Arq:
    """Reliable, ordered byte stream over the AEAD packet codec -- a transport-
    agnostic state machine driven by app_send / on_packet / tick / poll_out, with
    an injected `now` clock (ms). Mirror of the V `Arq`."""

    def __init__(self, key: bytes, tx_salt: int, rx_salt: int) -> None:
        self._aes = AESGCM(key)
        self.tx_salt = tx_salt
        self.rx_salt = rx_salt
        self.pkt_seq = 0
        # sender
        self.pending = bytearray()
        self.unacked: list[dict] = []  # {off, data, sent_ms, xmits}
        self.snd_nxt = 0
        self.last_ack = 0
        self.dup_acks = 0
        self.srtt = 0
        self.rttvar = 0
        self.rto = RTO_MIN_MS
        # receiver
        self.rcv_nxt = 0
        self.reorder: list[tuple[int, bytes]] = []
        self.inbox = bytearray()
        self.needack = False
        # outbound sealed datagrams
        self.outq: list[bytes] = []

    # -- packet codec (cached AESGCM) --
    def _seal(self, payload: bytes) -> bytes:
        seq = self.pkt_seq
        self.pkt_seq += 1
        return struct.pack(">Q", seq) + self._aes.encrypt(aead_nonce(self.tx_salt, seq), payload, b"")

    def _open(self, pkt: bytes) -> tuple[int, bytes] | None:
        if len(pkt) < 8 + TAG_LEN:
            return None
        seq = struct.unpack(">Q", pkt[:8])[0]
        try:
            return seq, self._aes.decrypt(aead_nonce(self.rx_salt, seq), pkt[8:], b"")
        except Exception:
            return None

    def _snd_una(self) -> int:
        return self.unacked[0]["off"] if self.unacked else self.snd_nxt

    def _seal_out(self, flags: int, off: int, data: bytes) -> None:
        body = bytes([flags]) + struct.pack(">Q", self.rcv_nxt)  # piggyback cumulative ack
        if flags & F_DATA:
            body += struct.pack(">Q", off) + data
        self.outq.append(self._seal(body))
        self.needack = False

    def _fill_window(self, now: int) -> None:
        while self.pending and (self.snd_nxt - self._snd_una()) < ARQ_WINDOW:
            chunk = bytes(self.pending[:SEG_MAX])
            del self.pending[: len(chunk)]
            self.unacked.append({"off": self.snd_nxt, "data": chunk, "sent_ms": now, "xmits": 1})
            self.snd_nxt += len(chunk)
            self._seal_out(F_DATA, self.unacked[-1]["off"], chunk)

    def app_send(self, data: bytes, now: int) -> None:
        self.pending += data
        self._fill_window(now)

    def take_inbox(self) -> bytes:
        r = bytes(self.inbox)
        self.inbox = bytearray()
        return r

    def _rtt_update(self, sample: int) -> None:
        s = max(sample, 1)
        if self.srtt == 0:
            self.srtt, self.rttvar = s, s // 2
        else:
            self.rttvar = (3 * self.rttvar + abs(self.srtt - s)) // 4
            self.srtt = (7 * self.srtt + s) // 8
        self.rto = max(RTO_MIN_MS, min(RTO_MAX_MS, self.srtt + 4 * self.rttvar))

    def _retransmit_first(self, now: int) -> None:
        if not self.unacked:
            return
        seg = self.unacked[0]
        seg["xmits"] += 1
        seg["sent_ms"] = now
        self._seal_out(F_DATA, seg["off"], seg["data"])

    def _process_ack(self, ack: int, now: int) -> None:
        while self.unacked and self.unacked[0]["off"] + len(self.unacked[0]["data"]) <= ack:
            seg = self.unacked.pop(0)
            if seg["xmits"] == 1:  # Karn: don't sample a retransmitted segment
                self._rtt_update(now - seg["sent_ms"])
        if ack > self.last_ack:
            self.last_ack, self.dup_acks = ack, 0
        elif ack == self.last_ack and self.unacked:
            self.dup_acks += 1
            if self.dup_acks == 3:
                self._retransmit_first(now)  # fast retransmit

    def _deliver(self, off: int, data: bytes) -> None:
        if off + len(data) <= self.rcv_nxt:
            return  # wholly old / duplicate
        if off > self.rcv_nxt:
            if off - self.rcv_nxt > ARQ_WINDOW or any(o == off for o, _ in self.reorder):
                return
            self.reorder.append((off, data))
            return
        d = data[self.rcv_nxt - off :]
        self.inbox += d
        self.rcv_nxt += len(d)
        self._drain_reorder()

    def _drain_reorder(self) -> None:
        progressed = True
        while progressed:
            progressed = False
            for i, (o, dt) in enumerate(self.reorder):
                if o <= self.rcv_nxt < o + len(dt):
                    self.inbox += dt[self.rcv_nxt - o :]
                    self.rcv_nxt = o + len(dt)
                    self.reorder.pop(i)
                    progressed = True
                    break

    def on_packet(self, pkt: bytes, now: int) -> None:
        opened = self._open(pkt)
        if opened is None:
            return
        _seq, body = opened
        if len(body) < 9 or (body[0] & 0x80):  # too short, or a control packet
            return
        self._process_ack(struct.unpack(">Q", body[1:9])[0], now)
        if (body[0] & F_DATA) and len(body) >= 17:
            self._deliver(struct.unpack(">Q", body[9:17])[0], body[17:])
            self.needack = True
        self._fill_window(now)

    def tick(self, now: int) -> None:
        if self.unacked and now - self.unacked[0]["sent_ms"] >= self.rto:
            self.rto = min(RTO_MAX_MS, self.rto * 2)  # Karn backoff
            self._retransmit_first(now)
        self._fill_window(now)
        if self.needack:
            self._seal_out(0, 0, b"")  # pure ack

    def poll_out(self) -> list[bytes]:
        r, self.outq = self.outq, []
        return r

    def next_timeout(self, now: int) -> int:
        if self.unacked:
            return max(0, self.unacked[0]["sent_ms"] + self.rto - now)
        return 1000


class FrameStream:
    """Length-prefixed framing over the reliable ARQ byte stream: [u32 BE len][frame].
    `wrap` for sending; `feed` reassembles received bytes into whole frames."""

    def __init__(self) -> None:
        self._buf = bytearray()

    @staticmethod
    def wrap(frame: bytes) -> bytes:
        return struct.pack(">I", len(frame)) + frame

    def feed(self, data: bytes) -> list[bytes]:
        self._buf += data
        out: list[bytes] = []
        while len(self._buf) >= 4:
            n = struct.unpack(">I", self._buf[:4])[0]
            if len(self._buf) < 4 + n:
                break
            out.append(bytes(self._buf[4 : 4 + n]))
            del self._buf[: 4 + n]
        return out


# -- UPGRADE signaling codec (offer / answer) -- mirror of the V codec --
def _put_ipport(ip: str, port: int) -> bytes:
    return bytes(int(o) for o in ip.split(".")) + struct.pack(">H", port)


def _read_cands(b: bytes, off: int) -> tuple[list[tuple[str, int]], int] | None:
    if off >= len(b):
        return None
    n = b[off]
    off += 1
    if off + n * 6 > len(b):
        return None
    cands = []
    for _ in range(n):
        ip = ".".join(str(x) for x in b[off : off + 4])
        cands.append((ip, struct.unpack(">H", b[off + 4 : off + 6])[0]))
        off += 6
    return cands, off


def encode_offer(psk: bytes, nonce: bytes, stun: list[tuple[str, int]], cands: list[tuple[str, int]]) -> bytes:
    import base64

    blob = bytes([0x01]) + b"O" + psk[:32] + nonce[:8]
    blob += bytes([len(stun)]) + b"".join(_put_ipport(ip, p) for ip, p in stun)
    blob += bytes([len(cands)]) + b"".join(_put_ipport(ip, p) for ip, p in cands)
    return base64.b64encode(blob)


def local_ip() -> str:
    """This host's primary IPv4 -- the route's source address (no packets sent).
    The wrapper's host candidate."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 53))
        return s.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        s.close()


# -- STUN client (RFC 5389) -- gather the wrapper's srflx candidate --
_STUN_COOKIE = bytes([0x21, 0x12, 0xA4, 0x42])


def stun_request(txid: bytes) -> bytes:
    return bytes([0, 1, 0, 0]) + _STUN_COOKIE + txid[:12]


def stun_parse(resp: bytes, txid: bytes) -> tuple[str, int] | None:
    if len(resp) < 20 or resp[0] != 1 or resp[1] != 1:
        return None
    if resp[4:8] != _STUN_COOKIE or resp[8:20] != txid:
        return None
    end = min(20 + ((resp[2] << 8) | resp[3]), len(resp))
    off = 20
    while off + 4 <= end:
        atype = (resp[off] << 8) | resp[off + 1]
        alen = (resp[off + 2] << 8) | resp[off + 3]
        v = off + 4
        if v + alen > len(resp):
            break
        if atype in (0x0020, 0x0001) and alen >= 8 and resp[v + 1] == 0x01:
            x = atype == 0x0020  # XOR-MAPPED-ADDRESS vs legacy MAPPED-ADDRESS
            port = ((resp[v + 2] ^ (_STUN_COOKIE[0] if x else 0)) << 8) | (
                resp[v + 3] ^ (_STUN_COOKIE[1] if x else 0)
            )
            ip = ".".join(str(resp[v + 4 + i] ^ (_STUN_COOKIE[i] if x else 0)) for i in range(4))
            return ip, port
        off = v + ((alen + 3) // 4) * 4  # 4-byte aligned
    return None


def stun_query(sock: socket.socket, server: tuple[str, int], timeout: float = 1.0) -> tuple[str, int] | None:
    """Discover this socket's reflexive mapping. Sends one Binding Request and
    waits `timeout`s. Done on the SAME socket the channel uses (the mapping is
    per-socket); the caller restores blocking/peer state afterward."""
    txid = os.urandom(12)
    sock.sendto(stun_request(txid), server)
    sock.settimeout(timeout)
    try:
        resp, _ = sock.recvfrom(512)
    except (OSError, socket.timeout):
        return None
    return stun_parse(resp, txid)


class UdpBackhaul:
    """The wrapper's UDP peer: hole punch, then run the Arq over an asyncio-driven
    socket. Mirrors the native `Backhaul` state machine. `on_frame(frame)` is
    called for each length-prefixed frame the peer sends; `send_frame(frame)`
    queues one for reliable delivery."""

    def __init__(
        self,
        key: bytes,
        tx_salt: int,
        rx_salt: int,
        peer_cands: list[tuple[str, int]],
        on_frame: Callable[[bytes], None],
        *,
        budget_ms: int = 8000,
        on_inband: Callable[[bytes], None] | None = None,
        on_closed: Callable[[], None] | None = None,
    ) -> None:
        self.key = key
        self.tx_salt = tx_salt
        self.rx_salt = rx_salt
        self.peer_cands = peer_cands
        self.on_frame = on_frame
        # In-band re-send / completion hooks for the lossless revert handoff.
        self.on_inband = on_inband or (lambda _f: None)
        self.on_closed = on_closed or (lambda: None)
        self.arq = Arq(key, tx_salt, rx_salt)
        self.fs = FrameStream()
        self._tx_comp = zlib.compressobj(6, zlib.DEFLATED, -15)  # raw deflate, persistent
        self._rx_comp = zlib.decompressobj(-15)
        self.state = "punching"  # punching | up | reverting | failed
        self.deadline = now_ms() + budget_ms
        self.pseq = 0
        self.last_rx = 0  # monotonic ms of the last received packet (liveness, once up)
        self.next_hb = 0  # when to send the next heartbeat (once up)
        self.sock: socket.socket | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._timer: asyncio.TimerHandle | None = None
        # Lossless-revert bookkeeping. `sent` is a FIFO of frames submitted to the
        # backhaul but not yet provably consumed by the peer: (compressed_end_off,
        # raw_frame). Pruned as the ARQ acks their byte ranges; on revert the tail
        # the peer never consumed is re-sent in-band. Frame numbering is implicit:
        # sent[i] is frame number tx_base + i. `rx_frames` counts frames delivered
        # from the peer (so we can tell it, in-band, what we already have).
        self.sent: list[tuple[int, bytes]] = []
        self.tx_off = 0  # running compressed-stream byte offset
        self.tx_base = 0  # frame number of sent[0]
        self.rx_frames = 0  # frames delivered up from the peer
        self._resent = False  # re-send of our tail happened exactly once

    def start(self, sock: socket.socket) -> None:
        sock.setblocking(False)
        self.sock = sock
        self._loop = asyncio.get_running_loop()
        self._loop.add_reader(sock.fileno(), self._on_readable)
        self._tick()

    def _ctl(self, flag: int) -> bytes:
        pkt = udp_seal(self.key, self.tx_salt, self.pseq, bytes([flag]))
        self.pseq += 1
        return pkt

    def _flush(self) -> None:
        for pkt in self.arq.poll_out():
            with contextlib.suppress(OSError):
                self.sock.send(pkt)  # connected after nomination

    def _compress(self, data: bytes) -> bytes:
        # sync-flush so the peer can inflate this chunk now; dictionary persists.
        return self._tx_comp.compress(data) + self._tx_comp.flush(zlib.Z_SYNC_FLUSH)

    def _deliver(self) -> None:
        raw = self.arq.take_inbox()
        if raw:
            for frame in self.fs.feed(self._rx_comp.decompress(raw)):
                self.rx_frames += 1  # whole frame consumed -> peer may drop it on revert
                self.on_frame(frame)

    def _prune(self) -> None:
        # Drop sent frames the ARQ has fully acked (a safe lower bound on what the
        # peer received) so the FIFO holds only in-flight frames in steady state.
        una = self.arq._snd_una()
        while self.sent and self.sent[0][0] <= una:
            self.sent.pop(0)
            self.tx_base += 1

    def _on_readable(self) -> None:
        try:
            data, addr = self.sock.recvfrom(2048)
        except (BlockingIOError, OSError):
            return
        now = now_ms()
        if self.state == "up":
            self.last_rx = now  # any packet (data, ack, heartbeat) proves the path is alive
            self.arq.on_packet(data, now)
            self._flush()
            self._prune()  # acks advanced -> drop confirmed frames from the revert FIFO
            self._deliver()
            return
        if self.state != "punching":
            return
        opened = udp_open(self.key, self.rx_salt, data)
        if opened is None or not opened[1] or not (opened[1][0] & 0x80):
            return  # not an authenticated control packet
        if opened[1][0] == CTL_PING:
            self.sock.sendto(self._ctl(CTL_PONG), addr)
        self.sock.connect(addr)  # nominate this pair
        self.state = "up"
        self.last_rx = now
        self.next_hb = now + BH_HB_MS
        self._flush()

    def _tick(self) -> None:
        now = now_ms()
        if self.state == "punching":
            if now >= self.deadline:
                self.state = "failed"
                return
            ping = self._ctl(CTL_PING)
            for c in self.peer_cands:
                with contextlib.suppress(OSError):
                    self.sock.sendto(ping, c)
            delay = 0.2
        elif self.state == "up":
            if now - self.last_rx > BH_DEAD_MS:
                self._begin_revert()  # UDP path went silent -> lossless in-band handoff
                return
            if now >= self.next_hb:
                with contextlib.suppress(OSError):
                    self.sock.send(self._ctl(CTL_PING))  # keepalive (peer's Arq drops it)
                self.next_hb = now + BH_HB_MS
            self.arq.tick(now)
            self._flush()
            self._prune()
            self._deliver()
            delay = max(0.01, min(self.arq.next_timeout(now), self.next_hb - now) / 1000)
        else:
            return
        self._timer = self._loop.call_later(delay, self._tick)

    def send_frame(self, frame: bytes) -> None:
        if self.state == "up":
            comp = self._compress(FrameStream.wrap(frame))
            self.tx_off += len(comp)
            self.sent.append((self.tx_off, frame))  # track for lossless revert
            self.arq.app_send(comp, now_ms())
            self._flush()
        elif self.state == "reverting":
            # Path is dead but draining: hold new frames in the FIFO so they re-send
            # in-band behind the undelivered tail, preserving order.
            self.sent.append((self.tx_off, frame))

    # -- lossless revert handoff (coordinated over the durable in-band channel) --
    def _begin_revert(self) -> None:
        """Enter the draining state and tell the peer, in-band, how many of its
        frames we have consumed so it can re-send only the tail we never got."""
        if self.state != "up":
            return
        self.state = "reverting"
        self._prune()
        self.on_inband(b"UP:RX:" + str(self.rx_frames).encode())
        self.close()  # UDP is dead; the object stays alive for the in-band exchange

    def peer_revert(self, n: int) -> None:
        """The peer is reverting and has consumed `n` of our frames. Re-send frames
        numbered >= n (the tail it never got) in-band, exactly once, then tear down."""
        if self.state == "up":
            self._begin_revert()  # peer noticed first -- mirror into the drain
        if self.state != "reverting" or self._resent:
            return
        self._resent = True
        for _end, frame in self.sent[max(0, n - self.tx_base) :]:
            self.on_inband(frame)
        self.sent.clear()
        self.state = "failed"
        self.close()
        self.on_closed()

    def close(self) -> None:  # idempotent (death calls it, callers may too)
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        if self.sock is not None:
            with contextlib.suppress(OSError, ValueError):
                self._loop.remove_reader(self.sock.fileno())
            self.sock.close()
            self.sock = None


def decode_answer(b64: bytes) -> tuple[bytes, list[tuple[str, int]]] | None:
    import base64

    try:
        b = base64.b64decode(b64)
    except Exception:
        return None
    if len(b) < 10 or b[0] != 0x01 or b[1:2] != b"A":
        return None
    res = _read_cands(b, 10)
    if res is None:
        return None
    return b[2:10], res[0]
