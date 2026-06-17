"""In-band file delivery from the bucket.

The bucket is one local tree of portable files served over the byte stream. A
request names a path; `os`/`arch` ride as flags and select a subtree:

    FILEREQ:<name>(:<key>=<value>)*

e.g. `FILEREQ:imgcat:mtime=1700000000:os=Linux:arch=aarch64`. The `<name>` may
itself be a path (e.g. `linux_arm64/sb`). Recognized flags: `mtime`, `os`,
`arch` (unknown flags are ignored, forward-compatibly).

Resolution (os/arch normalized — `Darwin→darwin`, `aarch64→arm64`, …), first
hit wins, all confined to the bucket root:

    <bucket>/<os>_<arch>/<name>     os + arch specific
    <bucket>/<os>/<name>            os specific, arch agnostic
    <bucket>/<name>                 fully agnostic (also where an explicit
                                    `<os>_<arch>/path` name resolves)

Response framing — base64 body lines then exactly one `~` control token line:

  ~EOF [flags...]    Success. Flags are `key=value`, space-separated:
                       chmod=<spec>  pass to `chmod` (only when the source file
                                     is itself executable — the bucket holds
                                     non-exec files too, e.g. sb-bash.rc).
                       mtime=<N>     source mtime; the stub `touch -d @N`s the
                                     cache so a later same-mtime FILEREQ → NOT_CHANGED.
  ~ERR <CODE> [detail]  NOT_FOUND | NOT_CHANGED (more may be added).
  ~SYM <target>      symlink (busybox-style multi-call; see chase protocol).

`~` is in neither base64 alphabet, so a token line can't collide with the body.
"""

from __future__ import annotations

import base64
import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

# Control tokens — always `~`-prefixed; never collide with base64.
EOF_TOKEN = b"~EOF"
ERR_TOKEN = b"~ERR"
SYM_TOKEN = b"~SYM"

# Standard ~ERR codes.
ERR_NOT_FOUND = "NOT_FOUND"
ERR_NOT_CHANGED = "NOT_CHANGED"

# Mtime sentinel meaning "no cached copy yet" — wrapper always sends payload.
NO_CACHE_MTIME = 0

# Column width of base64 lines on the wire (RFC 2045 standard).
_LINE_WIDTH = 76

# uname -m → canonical arch subdir token (passthrough for unknowns).
_ARCH_MAP = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
}

# Reserved bucket names that are not user lazy-alias helpers.
_RESERVED_BASENAMES = {"sb"}

# The on-target freshness oracle the wrapper regenerates on connect.
MANIFEST_NAME = "sb-manifest"


def normalize_arch(arch: str) -> str:
    return _ARCH_MAP.get(arch, arch)


def normalize_os(os_name: str) -> str:
    # uname -s is conventionally mixed-case (Linux, Darwin, FreeBSD); the subdir
    # convention is lowercase.
    return os_name.lower()


@dataclass(frozen=True)
class FileRequest:
    name: str
    cached_mtime: int = NO_CACHE_MTIME
    os: str | None = None
    arch: str | None = None


def _safe_relpath(name: str) -> str | None:
    """A bucket-relative path is safe iff non-empty, not absolute, no `\\`, and
    every component is a normal name (no ``''``/``.``/``..``)."""
    if not name or name.startswith("/") or "\\" in name:
        return None
    parts = name.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return None
    return name


def parse_filereq(payload: bytes) -> FileRequest | None:
    """Parse a token-stripped `FILEREQ:<name>(:<k>=<v>)*` command.

    Returns None if not a FILEREQ or the name is unsafe.
    """
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError:
        return None
    parts = text.split(":")
    if len(parts) < 2 or parts[0] != "FILEREQ":
        return None
    name = _safe_relpath(parts[1])
    if name is None:
        return None
    flags: dict[str, str] = {}
    for p in parts[2:]:
        k, sep, v = p.partition("=")
        if sep:
            flags[k] = v
    try:
        mtime = int(flags.get("mtime", "0") or "0")
    except ValueError:
        return None
    if mtime < 0:
        return None
    return FileRequest(
        name=name,
        cached_mtime=mtime,
        os=flags.get("os") or None,
        arch=flags.get("arch") or None,
    )


def _eof_line(flags: Sequence[str] = ()) -> bytes:
    if not flags:
        return EOF_TOKEN + b"\n"
    return EOF_TOKEN + b" " + b" ".join(f.encode("ascii") for f in flags) + b"\n"


def _err_line(code: str, detail: str = "") -> bytes:
    if detail:
        return ERR_TOKEN + b" " + code.encode("ascii") + b" " + detail.encode("ascii") + b"\n"
    return ERR_TOKEN + b" " + code.encode("ascii") + b"\n"


def encode_for_delivery(data: bytes, *, flags: Sequence[str] = ()) -> bytes:
    """Base64-encode `data`, line-wrap, terminate with `~EOF [flags...]`."""
    if not data:
        return _eof_line(flags)
    b64 = base64.b64encode(data)
    lines = [b64[i:i + _LINE_WIDTH] for i in range(0, len(b64), _LINE_WIDTH)]
    return b"\n".join(lines) + b"\n" + _eof_line(flags)


def err_delivery(code: str, detail: str = "") -> bytes:
    """Build an error/control response (`~ERR <code> [detail]`)."""
    return _err_line(code, detail)


def sym_delivery(target: str) -> bytes:
    """Build a symlink-only response (`~SYM <target>`)."""
    if not target or "\n" in target:
        raise ValueError(f"invalid symlink target: {target!r}")
    return SYM_TOKEN + b" " + target.encode("utf-8") + b"\n"


class Bucket:
    """A local tree of portable files served over the byte stream."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def _within(self, candidate: Path) -> Path | None:
        """Resolve `candidate` and confine it under the bucket (blocks `..` and
        symlink escapes). Returns the real path if it's a file inside, else None."""
        try:
            root = self.path.resolve()
            real = (self.path / candidate).resolve()
        except OSError:
            return None
        if real != root and root not in real.parents:
            return None
        return real if real.is_file() else None

    def resolve(self, req: FileRequest) -> Path | None:
        """First matching path for the request (os_arch → os → root), or None."""
        candidates: list[str] = []
        if req.os and req.arch:
            candidates.append(f"{normalize_os(req.os)}_{normalize_arch(req.arch)}/{req.name}")
        if req.os:
            candidates.append(f"{normalize_os(req.os)}/{req.name}")
        candidates.append(req.name)
        for c in candidates:
            hit = self._within(Path(c))
            if hit is not None:
                return hit
        return None

    def serve(self, req: FileRequest) -> bytes:
        """Build the in-band response for `req`.

        miss → NOT_FOUND; mtime match → NOT_CHANGED; else payload with `mtime=`
        and (only if the source is executable) `chmod=+x`.
        """
        path = self.resolve(req)
        if path is None:
            return err_delivery(ERR_NOT_FOUND)
        mtime = int(path.stat().st_mtime)
        if mtime == req.cached_mtime:
            return err_delivery(ERR_NOT_CHANGED)
        flags = [f"mtime={mtime}"]
        if os.access(path, os.X_OK):
            flags.insert(0, "chmod=+x")
        return encode_for_delivery(path.read_bytes(), flags=tuple(flags))

    def alias_names(self) -> list[str]:
        """Sorted unique basenames of executable files across the tree —
        excluding reserved binaries and the rc.d fragments. This is the dispatch
        set `sb mux` exposes as PATH symlinks; `sb` derives the same selection
        from `sb-manifest` on-target (this is the wrapper-side reference)."""
        if not self.path.is_dir():
            return []
        names: set[str] = set()
        for p in self.path.rglob("*"):
            if not p.is_file() or not os.access(p, os.X_OK):
                continue
            rel = p.relative_to(self.path)
            if rel.parts and rel.parts[0] == "rc.d":
                continue
            # Executable + not rc.d ⇒ dispatchable, with only the `sb` binary reserved
            # (the autoviv self-target). Executable `sb-*` SCRIPTS like the `sb-tmux.sh`
            # launcher ARE dispatchable (autoviv via $PATH). The non-exec runtimes
            # (`sb-*.rc`) / manifest are already excluded by the `os.access(X_OK)` filter
            # above. Mirrors the on-target `populate_bin` selection.
            if p.name in _RESERVED_BASENAMES:
                continue
            names.add(p.name)
        return sorted(names)

    def rcd_fragments(self) -> list[str]:
        """Sorted `rc.d/<frag>` relative paths (shell-agnostic, sourced after the
        runtime)."""
        rcd = self.path / "rc.d"
        if not rcd.is_dir():
            return []
        return sorted(
            f"rc.d/{p.name}" for p in rcd.iterdir() if p.is_file()
        )

    def manifest_text(self) -> str:
        """The `sb-manifest` contents: one TSV line per bucket file —
        `<path>\\t<mtime>\\t<flags>` (flags = `x` if executable). Covers every
        file (helpers, `sb-<family>.rc`, the `sb` binary, rc.d/…) except the
        manifest itself. This is the on-target freshness oracle `sb` parses;
        the format mirrors the V `parse_manifest`.
        """
        if not self.path.is_dir():
            return ""
        lines: list[str] = []
        for p in sorted(self.path.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(self.path).as_posix()
            if rel == MANIFEST_NAME:
                continue
            mtime = int(p.stat().st_mtime)
            flags = "x" if os.access(p, os.X_OK) else ""
            lines.append(f"{rel}\t{mtime}\t{flags}")
        return "".join(line + "\n" for line in lines)

    def write_manifest(self) -> None:
        """(Re)generate `<bucket>/sb-manifest` from the current tree."""
        self.path.mkdir(parents=True, exist_ok=True)
        (self.path / MANIFEST_NAME).write_text(self.manifest_text())
