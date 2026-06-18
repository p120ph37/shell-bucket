"""Label-swap request-id framing for the sb fabric.

Between sb instances and the wrapper, an authenticated request/response rides a
token-bearing **request-id frame** whose command (after the APC filter strips the
token) is ``R<id>:<inner>``:

    APC shell-bucket:<token>:R<id>:<inner> ST

``<id>`` is the **local** request-id the sending mux assigned -- each hop swaps in
its own id and records `id -> source`, so the response carrying that id routes back
to the right downstream source (a local tool, or an `sb inject` conduit to a deeper
host). There is no shared hop counter, so fan-out is disambiguated at every level
by each mux's own table.

``<inner>`` is the original request command (upstream) or the full -- possibly
multi-line -- response blob (downstream), carried verbatim: an APC is terminated by
ST, not newline, so embedded ``\n`` needs no escaping (single-frame responses, no
chunking/reassembly).

The wrapper is the routing *terminus*: it serves ``<inner>`` and echoes the same
``<id>`` on the reply (it relabels nothing -- it is stateless). The bootstrap and a
mux's own startup fetches ride **unframed** (a raw ``FILEREQ`` / ``BOOT`` APC, raw
response) since they are single-in-flight and pre-socket.

This module is the Python source of truth for the frame; the sb binary mirrors
``build_route``/``parse_route`` in V.
"""

from __future__ import annotations


def build_route(rid: int, inner: bytes) -> bytes:
    """`R<id>:<inner>` -- the label-swap request-id frame."""
    if rid < 0:
        raise ValueError(f"request-id must be non-negative: {rid}")
    return b"R" + str(rid).encode("ascii") + b":" + inner


def parse_route(cmd: bytes) -> tuple[int, bytes] | None:
    """Parse `R<id>:<inner>` -> `(id, inner)`, or None if not a request-id frame."""
    if not cmd.startswith(b"R"):
        return None
    id_b, sep, inner = cmd[1:].partition(b":")
    if not sep or not id_b.isdigit():
        return None
    return int(id_b), inner


# ----- SURVEY (wrapper -> tree) ----------------------------------------------

def build_survey(sid: int) -> bytes:
    """`SURVEY:<id>` -- the wrapper-initiated broadcast sent down the byte stream;
    every mux replies (`SURVEYR`) and fans it out to its conduit children."""
    if sid < 0:
        raise ValueError(f"survey id must be non-negative: {sid}")
    return b"SURVEY:" + str(sid).encode("ascii")


def parse_surveyreply(cmd: bytes) -> tuple[int, bytes, bytes] | None:
    """Parse `SURVEYR:<id>:<route>:<identity>` -> `(id, route, identity)`, or None.

    `<route>` is the comma-separated conduit-id path from the wrapper to the node
    (empty for the top mux); `<identity>` is the `host=...:os=...:...` tail (kept whole).
    """
    if not cmd.startswith(b"SURVEYR:"):
        return None
    parts = cmd.split(b":", 3)  # SURVEYR, id, route, identity
    if len(parts) != 4 or not parts[1].isdigit():
        return None
    return int(parts[1]), parts[2], parts[3]


# ----- source-routed push (wrapper -> node) -----------------------------------

def build_push(pid: int, route: tuple[int, ...], cmd: bytes) -> bytes:
    """`PUSH:<pid>:<route>:<cmd>` -- a wrapper-initiated message addressed to one node
    by its `route` (the conduit-id path from a SURVEY). Each mux pops the head cid and
    forwards to that conduit; the node at the empty-route end acts locally and replies
    `PUSHR:<pid>:<resp>`. `<cmd>` is kept whole (may contain `:`)."""
    if pid < 0:
        raise ValueError(f"push id must be non-negative: {pid}")
    route_b = b",".join(str(c).encode("ascii") for c in route)
    return b"PUSH:" + str(pid).encode("ascii") + b":" + route_b + b":" + cmd


def parse_pushreply(cmd: bytes) -> tuple[int, bytes] | None:
    """Parse `PUSHR:<pid>:<resp>` -> `(pid, resp)`, or None. `<resp>` kept whole."""
    if not cmd.startswith(b"PUSHR:"):
        return None
    _, pid_b, resp = cmd.split(b":", 2)
    if not pid_b.isdigit():
        return None
    return int(pid_b), resp
