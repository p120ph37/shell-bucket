"""Unit tests for in-band file delivery + the bucket."""

from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest

from shell_bucket.file_delivery import (
    EOF_TOKEN,
    ERR_NOT_CHANGED,
    ERR_NOT_FOUND,
    ERR_TOKEN,
    NO_CACHE_MTIME,
    SYM_TOKEN,
    Bucket,
    FileRequest,
    encode_for_delivery,
    err_delivery,
    normalize_arch,
    normalize_os,
    parse_filereq,
    sym_delivery,
)


# ───── parse_filereq (name + k/v flags) ─────────────────────────────────────

def test_parse_bare_name() -> None:
    assert parse_filereq(b"FILEREQ:imgcat") == FileRequest(name="imgcat")


def test_parse_flags_mtime_os_arch() -> None:
    r = parse_filereq(b"FILEREQ:imgcat:mtime=1700000000:os=Linux:arch=aarch64")
    assert r == FileRequest(
        name="imgcat", cached_mtime=1700000000, os="Linux", arch="aarch64"
    )


def test_parse_flag_order_independent() -> None:
    r = parse_filereq(b"FILEREQ:x:arch=amd64:os=linux:mtime=5")
    assert (r.cached_mtime, r.os, r.arch) == (5, "linux", "amd64")


def test_parse_path_name_allowed() -> None:
    r = parse_filereq(b"FILEREQ:linux_arm64/sb:os=linux:arch=arm64")
    assert r.name == "linux_arm64/sb"


def test_parse_unknown_flags_ignored() -> None:
    r = parse_filereq(b"FILEREQ:x:future=1:mtime=2")
    assert r.cached_mtime == 2 and r.os is None and r.arch is None


def test_parse_rejects_non_filereq() -> None:
    assert parse_filereq(b"S2:bash") is None


def test_parse_rejects_unsafe_names() -> None:
    for bad in (b"FILEREQ:../etc/passwd", b"FILEREQ:/abs", b"FILEREQ:a//b",
                b"FILEREQ:./x", b"FILEREQ:", b"FILEREQ:a/../b"):
        assert parse_filereq(bad) is None, bad


def test_parse_rejects_bad_mtime() -> None:
    assert parse_filereq(b"FILEREQ:x:mtime=-1") is None
    assert parse_filereq(b"FILEREQ:x:mtime=abc") is None


def test_parse_non_ascii() -> None:
    assert parse_filereq(b"FILEREQ:\xff") is None


# ───── normalization ────────────────────────────────────────────────────────

def test_normalize_arch() -> None:
    assert normalize_arch("aarch64") == "arm64"
    assert normalize_arch("arm64") == "arm64"
    assert normalize_arch("x86_64") == "amd64"
    assert normalize_arch("sparc64") == "sparc64"  # passthrough


def test_normalize_os() -> None:
    assert normalize_os("Linux") == "linux"
    assert normalize_os("Darwin") == "darwin"


# ───── encode / err / sym (unchanged API) ───────────────────────────────────

def test_encode_roundtrip() -> None:
    data = b"some \x00\x01\xff bytes"
    encoded = encode_for_delivery(data)
    assert encoded.endswith(b"\n~EOF\n")
    body = encoded[: -len(b"\n~EOF\n")]
    assert base64.b64decode(body.replace(b"\n", b"")) == data


def test_encode_empty_is_eof_alone() -> None:
    assert encode_for_delivery(b"") == b"~EOF\n"


def test_encode_with_flags() -> None:
    assert encode_for_delivery(b"hi", flags=("chmod=+x", "mtime=5")).endswith(
        b"\n~EOF chmod=+x mtime=5\n"
    )


def test_encode_body_only_base64() -> None:
    body = encode_for_delivery(b"\x00\xff" * 50)[: -len(b"\n~EOF\n")]
    assert b"~" not in body


def test_token_constants() -> None:
    assert EOF_TOKEN == b"~EOF" and ERR_TOKEN == b"~ERR" and SYM_TOKEN == b"~SYM"
    assert ERR_NOT_FOUND == "NOT_FOUND" and ERR_NOT_CHANGED == "NOT_CHANGED"


def test_err_delivery() -> None:
    assert err_delivery("NOT_FOUND") == b"~ERR NOT_FOUND\n"
    assert err_delivery("X", "y") == b"~ERR X y\n"


def test_sym_delivery() -> None:
    assert sym_delivery("busybox") == b"~SYM busybox\n"
    with pytest.raises(ValueError):
        sym_delivery("a\nb")


# ───── Bucket resolution ────────────────────────────────────────────────────

def _put(root: Path, rel: str, body: bytes = b"x", *, execu: bool = False) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(body)
    if execu:
        p.chmod(0o755)
    return p


def test_resolve_os_arch_specific_wins(tmp_path: Path) -> None:
    _put(tmp_path, "tool")
    _put(tmp_path, "linux/tool")
    target = _put(tmp_path, "linux_arm64/tool", body=b"ARMSPECIFIC")
    b = Bucket(tmp_path)
    req = FileRequest(name="tool", os="Linux", arch="aarch64")  # → linux_arm64
    assert b.resolve(req) == target.resolve()


def test_resolve_falls_back_to_os_then_root(tmp_path: Path) -> None:
    osfile = _put(tmp_path, "linux/tool", body=b"OS")
    b = Bucket(tmp_path)
    assert b.resolve(FileRequest(name="tool", os="Linux", arch="aarch64")) == osfile.resolve()
    rootfile = _put(tmp_path, "other")
    assert b.resolve(FileRequest(name="other", os="Linux", arch="aarch64")) == rootfile.resolve()


def test_resolve_explicit_path_falls_through_to_root(tmp_path: Path) -> None:
    # Cross-platform fetch: a linux_amd64 host asks for linux_arm64/myfile.
    target = _put(tmp_path, "linux_arm64/myfile", body=b"ARM")
    b = Bucket(tmp_path)
    req = FileRequest(name="linux_arm64/myfile", os="linux", arch="amd64")
    assert b.resolve(req) == target.resolve()


def test_resolve_miss(tmp_path: Path) -> None:
    assert Bucket(tmp_path).resolve(FileRequest(name="nope", os="linux", arch="amd64")) is None


def test_resolve_confined_to_bucket(tmp_path: Path) -> None:
    # Even if a symlink points outside, resolution must refuse it.
    outside = tmp_path / "secret"
    outside.write_bytes(b"SECRET")
    bucket = tmp_path / "bucket"
    bucket.mkdir()
    (bucket / "escape").symlink_to(outside)
    assert Bucket(bucket).resolve(FileRequest(name="escape")) is None


# ───── Bucket serve ─────────────────────────────────────────────────────────

def test_serve_missing_not_found(tmp_path: Path) -> None:
    assert Bucket(tmp_path).serve(FileRequest(name="x")) == err_delivery(ERR_NOT_FOUND)


def test_serve_executable_sends_chmod(tmp_path: Path) -> None:
    p = _put(tmp_path, "imgcat", body=b"\x7fELF", execu=True)
    out = Bucket(tmp_path).serve(FileRequest(name="imgcat", cached_mtime=NO_CACHE_MTIME))
    assert out == encode_for_delivery(b"\x7fELF", flags=("chmod=+x", f"mtime={int(p.stat().st_mtime)}"))


def test_serve_nonexec_no_chmod(tmp_path: Path) -> None:
    p = _put(tmp_path, "myenvvars.sh", body=b"export A=1\n")  # not executable
    out = Bucket(tmp_path).serve(FileRequest(name="myenvvars.sh"))
    assert out == encode_for_delivery(b"export A=1\n", flags=(f"mtime={int(p.stat().st_mtime)}",))


def test_serve_mtime_match_not_changed(tmp_path: Path) -> None:
    p = _put(tmp_path, "imgcat", execu=True)
    m = int(p.stat().st_mtime)
    assert Bucket(tmp_path).serve(FileRequest(name="imgcat", cached_mtime=m)) == err_delivery(ERR_NOT_CHANGED)


# ───── Bucket scanning ──────────────────────────────────────────────────────

def test_alias_names_executables_across_tree(tmp_path: Path) -> None:
    _put(tmp_path, "imgcat", execu=True)
    _put(tmp_path, "linux_arm64/sb", execu=True)     # reserved → excluded
    _put(tmp_path, "linux/it2copy", execu=True)
    _put(tmp_path, "notexec", execu=False)             # not executable → excluded
    _put(tmp_path, "rc.d/00-x.sh", execu=True)         # rc.d → excluded
    _put(tmp_path, "sb-bash.rc", execu=False)          # .rc runtime → excluded
    _put(tmp_path, "sb-tmux.sh", execu=True)           # executable sb-* launcher → dispatchable
    assert Bucket(tmp_path).alias_names() == ["imgcat", "it2copy", "sb-tmux.sh"]


def test_manifest_text_format(tmp_path: Path) -> None:
    p1 = _put(tmp_path, "imgcat", execu=True)
    p2 = _put(tmp_path, "linux_arm64/sb", execu=True)
    p3 = _put(tmp_path, "myenvvars.sh", execu=False)
    lines = Bucket(tmp_path).manifest_text().splitlines()
    assert f"imgcat\t{int(p1.stat().st_mtime)}\tx" in lines
    assert f"linux_arm64/sb\t{int(p2.stat().st_mtime)}\tx" in lines
    assert f"myenvvars.sh\t{int(p3.stat().st_mtime)}\t" in lines  # non-exec → empty flags


def test_manifest_excludes_itself(tmp_path: Path) -> None:
    _put(tmp_path, "imgcat", execu=True)
    b = Bucket(tmp_path)
    b.write_manifest()
    assert (tmp_path / "sb-manifest").is_file()
    # The manifest must not list itself.
    assert "sb-manifest\t" not in b.manifest_text()


def test_manifest_round_trips_resolution(tmp_path: Path) -> None:
    """The wrapper's manifest_text feeds the V resolver — spot-check the path/mtime
    a `sb run imgcat` on linux/arm64 would pick is present verbatim."""
    p = _put(tmp_path, "linux_arm64/imgcat", body=b"ARM", execu=True)
    text = Bucket(tmp_path).manifest_text()
    assert f"linux_arm64/imgcat\t{int(p.stat().st_mtime)}\tx" in text.splitlines()


def test_rcd_fragments_sorted(tmp_path: Path) -> None:
    _put(tmp_path, "rc.d/50-b.sh")
    _put(tmp_path, "rc.d/00-a.sh")
    assert Bucket(tmp_path).rcd_fragments() == ["rc.d/00-a.sh", "rc.d/50-b.sh"]


def test_scanning_empty_bucket(tmp_path: Path) -> None:
    b = Bucket(tmp_path / "nope")
    assert b.alias_names() == [] and b.rcd_fragments() == []
