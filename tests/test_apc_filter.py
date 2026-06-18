"""Unit tests for the APC stream filter (prefix-only, token-free)."""

from __future__ import annotations

import pytest

from shell_bucket.apc_filter import PREFIX, APCFilter, apc_envelope

ESC = b"\x1b"
APC_START = ESC + b"_"
ST = ESC + b"\\"
BEL = b"\x07"


def _apc(payload: bytes, terminator: bytes = ST) -> bytes:
    return APC_START + payload + terminator


def _ours(cmd: bytes, terminator: bytes = ST) -> bytes:
    """One of our APCs: ESC _ shell-bucket:<cmd> ST (no token on the wire)."""
    return _apc(PREFIX + cmd, terminator=terminator)


def _filter() -> APCFilter:
    return APCFilter()


# ----- Basic pass-through ---------------------------------------------------

def test_empty_input() -> None:
    out, events = _filter().feed(b"")
    assert out == b""
    assert events == []


def test_plain_ascii_passes_through() -> None:
    out, events = _filter().feed(b"hello world\n")
    assert out == b"hello world\n"
    assert events == []


def test_binary_bytes_pass_through() -> None:
    chunk = bytes(range(0x20)) + bytes(range(0x80, 0xFF))
    out, events = _filter().feed(chunk)
    assert out == chunk
    assert events == []


# ----- Our APC (prefix match): capture, prefix stripped ---------------------

def test_our_apc_is_stripped_and_cmd_emitted() -> None:
    out, events = _filter().feed(_ours(b"FILEREQ:imgcat:0"))
    assert out == b""
    assert events == [b"FILEREQ:imgcat:0"]


def test_our_framed_reply_emits_cmd() -> None:
    out, events = _filter().feed(_ours(b"R7:FILEREQ:cat:0"))
    assert out == b""
    assert events == [b"R7:FILEREQ:cat:0"]


def test_our_apc_with_bel_terminator() -> None:
    out, events = _filter().feed(_ours(b"FILEREQ:foo:1", terminator=BEL))
    assert out == b""
    assert events == [b"FILEREQ:foo:1"]


def test_multiple_apcs_in_one_chunk() -> None:
    chunk = _ours(b"BEGIN") + b"middle" + _ours(b"FILEREQ:cat:0")
    out, events = _filter().feed(chunk)
    assert out == b"middle"
    assert events == [b"BEGIN", b"FILEREQ:cat:0"]


# ----- Prefix recognition: anything `shell-bucket:`-prefixed is ours --------

def test_bare_prefix_emits_empty_command() -> None:
    """`shell-bucket:` with nothing after -> ours, an empty command."""
    out, events = _filter().feed(_apc(PREFIX))
    assert out == b""
    assert events == [b""]


def test_payload_with_colons_kept_intact() -> None:
    """Only `shell-bucket:` is stripped; the rest (colons and all) is the command."""
    out, events = _filter().feed(_ours(b"FILEREQ:x:mtime=0:os=Linux"))
    assert out == b""
    assert events == [b"FILEREQ:x:mtime=0:os=Linux"]


# ----- Foreign sequences: pass-through --------------------------------------

def test_foreign_prefix_apc_passes_through() -> None:
    """A `shell-bucket`-lookalike without the exact `shell-bucket:` prefix is foreign."""
    seq = _apc(b"shell-bucketX:FILEREQ:x")
    out, events = _filter().feed(seq)
    assert out == seq
    assert events == []


def test_foreign_apc_kitty_graphics_passes_through() -> None:
    seq = _apc(b"Ga=T,f=24,i=1,m=1;ABCD==")
    out, events = _filter().feed(seq)
    assert out == seq
    assert events == []


def test_osc_1337_imgcat_announce_passes_through() -> None:
    seq = b"\x1b]1337;File=name=Zm9v;inline=1:AAAA\x07"
    out, events = _filter().feed(seq)
    assert out == seq
    assert events == []


def test_csi_color_sequence_passes_through() -> None:
    seq = b"\x1b[31mred\x1b[0m"
    out, events = _filter().feed(seq)
    assert out == seq
    assert events == []


def test_dcs_2000_announce_passes_through() -> None:
    seq = b"\x1bP2000p" + b"uniqueid - sshargs\n" + b"\x1b\\"
    out, events = _filter().feed(seq)
    assert out == seq
    assert events == []


def test_lone_esc_followed_by_non_apc_byte_passes_through() -> None:
    out, events = _filter().feed(b"\x1bX")
    assert out == b"\x1bX"
    assert events == []


# ----- Mixed streams --------------------------------------------------------

def test_mixed_stream_strips_only_ours() -> None:
    chunk = (
        b"prefix-"
        + _apc(b"Ga=T,foreign")
        + b"-mid-"
        + _ours(b"FILEREQ:x:0")
        + b"-tail"
    )
    out, events = _filter().feed(chunk)
    assert out == b"prefix-" + _apc(b"Ga=T,foreign") + b"-mid--tail"
    assert events == [b"FILEREQ:x:0"]


# ----- Cross-chunk reassembly -----------------------------------------------

def test_our_apc_split_in_half_across_chunks() -> None:
    full = _ours(b"FILEREQ:imgcat:9")
    mid = len(full) // 2
    f = _filter()
    out1, ev1 = f.feed(full[:mid])
    out2, ev2 = f.feed(full[mid:])
    assert out1 + out2 == b""
    assert ev1 + ev2 == [b"FILEREQ:imgcat:9"]


def test_our_apc_split_byte_by_byte() -> None:
    full = b"prefix-" + _ours(b"BEGIN") + b"-suffix"
    f = _filter()
    out_total = bytearray()
    events_total: list[bytes] = []
    for b in full:
        o, e = f.feed(bytes([b]))
        out_total.extend(o)
        events_total.extend(e)
    assert bytes(out_total) == b"prefix--suffix"
    assert events_total == [b"BEGIN"]


def test_foreign_apc_split_byte_by_byte_reassembles_correctly() -> None:
    full = _apc(b"Garbage123")
    f = _filter()
    out_total = bytearray()
    for b in full:
        o, _ = f.feed(bytes([b]))
        out_total.extend(o)
    assert bytes(out_total) == full


def test_lone_trailing_esc_is_buffered_until_next_byte() -> None:
    f = _filter()
    out1, ev1 = f.feed(b"hello\x1b")
    assert out1 == b"hello"
    assert ev1 == []
    out2, ev2 = f.feed(b"[31m")
    assert out2 == b"\x1b[31m"
    assert ev2 == []


def test_esc_underscore_at_boundary_then_payload_in_next_chunk() -> None:
    f = _filter()
    out1, ev1 = f.feed(b"text" + APC_START)
    assert out1 == b"text"
    assert ev1 == []
    out2, ev2 = f.feed(PREFIX + b"BEGIN" + ST)
    assert out2 == b""
    assert ev2 == [b"BEGIN"]


# ----- Payload edge cases ---------------------------------------------------

def test_esc_inside_payload_treated_as_data_when_not_followed_by_backslash() -> None:
    body = b"FILEREQ:a\x1bXb:0"
    seq = APC_START + PREFIX + body + ST
    out, events = _filter().feed(seq)
    assert out == b""
    assert events == [b"FILEREQ:a\x1bXb:0"]


def test_foreign_apc_with_bel_terminator_passes_through() -> None:
    seq = _apc(b"Gfoo,bar", terminator=BEL)
    out, events = _filter().feed(seq)
    assert out == seq
    assert events == []


# ----- State persistence across feeds ---------------------------------------

@pytest.mark.parametrize("split", [1, 2, 5, 10, 20])
def test_payload_split_at_arbitrary_offsets(split: int) -> None:
    f = _filter()
    full = b"A" * 5 + _ours(b"FILEREQ:p:0") + b"B" * 5
    out1, ev1 = f.feed(full[:split])
    out2, ev2 = f.feed(full[split:])
    assert out1 + out2 == b"A" * 5 + b"B" * 5
    assert ev1 + ev2 == [b"FILEREQ:p:0"]


# ----- apc_envelope (the inverse of the filter) -----------------------------

def test_apc_envelope_format() -> None:
    assert apc_envelope(b"R0:hi") == _ours(b"R0:hi")


def test_apc_envelope_round_trips_through_filter() -> None:
    # A multi-line payload (e.g. a base64+~EOF response) survives intact.
    payload = b"R2:abc\ndef\n~EOF mtime=5\n"
    out, events = _filter().feed(apc_envelope(payload))
    assert out == b"" and events == [payload]
