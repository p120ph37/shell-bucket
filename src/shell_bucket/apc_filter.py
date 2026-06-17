"""APC (Application Program Command) stream filter.

Intercepts `ESC _ ... ST` sequences in a byte stream from the remote. Sequences
whose payload is `shell-bucket:<cmd>` are stripped from the forwarded output and
`<cmd>` emitted as an event. The byte-stream APC carries no token: trust is
structural, not bearer-based. The only thing that can put an our-prefix
APC into the stream the wrapper reads is the host `sb mux` — every mux strips
our-prefix APCs out of its own forkpty child (`strip-at-source`), so a malicious
app in the session cannot forge a request by emitting our escape (the mux eats
it before it can climb). The token lives only on the per-host Unix socket,
the one authenticated channel. All other bytes, including foreign APCs (e.g.
Kitty graphics `ESC _ G...`) and OSC/CSI/DCS sequences, pass through.

State persists across `feed()` calls so an APC that spans multiple chunks is
correctly reassembled.
"""

from __future__ import annotations

from enum import Enum, auto

_ESC = 0x1B
_APC_INTRO = 0x5F  # '_'
_ST_BACKSLASH = 0x5C  # '\\'
_BEL = 0x07

PREFIX = b"shell-bucket:"


def apc_envelope(payload: bytes) -> bytes:
    """Wrap `payload` as our APC: `ESC _ shell-bucket:<payload> ST`.

    The inverse of what `APCFilter` extracts. Used by the wrapper to frame mux
    responses (`R<id>:<resp>`) so the downstream scanners in each mux can route
    them. ST-terminated, so `payload` may contain newlines (multi-line responses).
    No token on the wire (see the module docstring).
    """
    return (
        bytes([_ESC, _APC_INTRO])
        + PREFIX
        + payload
        + bytes([_ESC, _ST_BACKSLASH])
    )


class _State(Enum):
    GROUND = auto()
    ESC = auto()
    APC = auto()
    APC_ESC = auto()


class APCFilter:
    """Streaming APC filter.

    `feed(chunk)` returns `(bytes_to_forward, list_of_events)`. Each event is the
    `<cmd>` part of a `shell-bucket:<cmd>` APC (prefix-only recognition; no token
    on the wire). Foreign APCs — anything not `shell-bucket:`-prefixed
    — are forwarded verbatim and never emitted.
    """

    def __init__(self) -> None:
        self._state: _State = _State.GROUND
        self._buf: bytearray = bytearray()

    def feed(self, chunk: bytes) -> tuple[bytes, list[bytes]]:
        out = bytearray()
        events: list[bytes] = []
        for b in chunk:
            self._step(b, out, events)
        return bytes(out), events

    def _step(self, b: int, out: bytearray, events: list[bytes]) -> None:
        s = self._state

        if s is _State.GROUND:
            if b == _ESC:
                self._state = _State.ESC
                self._buf = bytearray([_ESC])
            else:
                out.append(b)
            return

        if s is _State.ESC:
            if b == _APC_INTRO:
                self._state = _State.APC
                self._buf.append(_APC_INTRO)
            else:
                # Not an APC introducer — emit the buffered ESC plus this byte.
                out.extend(self._buf)
                out.append(b)
                self._buf.clear()
                self._state = _State.GROUND
            return

        if s is _State.APC:
            if b == _BEL:
                self._buf.append(_BEL)
                self._finish(out, events)
            elif b == _ESC:
                self._state = _State.APC_ESC
                self._buf.append(_ESC)
            else:
                self._buf.append(b)
            return

        if s is _State.APC_ESC:
            if b == _ST_BACKSLASH:
                self._buf.append(_ST_BACKSLASH)
                self._finish(out, events)
            elif b == _ESC:
                # Treat the previous ESC as data; this is a new candidate ST opener.
                self._buf.append(_ESC)
            else:
                # Previous ESC was data; this byte is data; back to APC payload state.
                self._buf.append(b)
                self._state = _State.APC

    def _finish(self, out: bytearray, events: list[bytes]) -> None:
        buf = bytes(self._buf)
        # Extract payload between `ESC _` (2 bytes) and the terminator.
        if buf.endswith(b"\x1b\\"):
            payload = buf[2:-2]
        elif buf.endswith(b"\x07"):
            payload = buf[2:-1]
        else:
            payload = buf[2:]  # unreachable in normal operation

        if payload.startswith(PREFIX):
            events.append(payload[len(PREFIX):])
        else:
            out.extend(buf)

        self._buf.clear()
        self._state = _State.GROUND
