"""Unit tests for label-swap request-id framing."""

from __future__ import annotations

import pytest

from shell_bucket.mux_frame import build_route, parse_route


def test_build_roundtrip() -> None:
    assert parse_route(build_route(0, b"FILEREQ:imgcat")) == (0, b"FILEREQ:imgcat")
    assert parse_route(build_route(37, b"BOOT:bash")) == (37, b"BOOT:bash")


def test_inner_may_contain_colons_and_newlines() -> None:
    inner = b"FILEREQ:x:mtime=5:os=linux:arch=amd64"
    assert parse_route(build_route(2, inner)) == (2, inner)
    blob = b"AAAA\nBBBB\n~EOF chmod=+x mtime=9\n"  # a multi-line response body
    assert parse_route(build_route(1, blob)) == (1, blob)


def test_parse_rejects_non_route() -> None:
    assert parse_route(b"FILEREQ:imgcat") is None
    assert parse_route(b"BOOT:bash") is None
    assert parse_route(b"R") is None
    assert parse_route(b"Rnotanum:x") is None
    assert parse_route(b"R5") is None  # no colon


def test_build_rejects_negative_id() -> None:
    with pytest.raises(ValueError):
        build_route(-1, b"x")


def test_id_is_a_label_not_a_hop() -> None:
    # Each request carries one local id; there's no hop arithmetic — the response
    # echoes the same id and the originating mux routes it by its table.
    frame = build_route(7, b"FILEREQ:imgcat:os=linux:arch=arm64")
    rid, inner = parse_route(frame)
    assert rid == 7 and inner == b"FILEREQ:imgcat:os=linux:arch=arm64"
