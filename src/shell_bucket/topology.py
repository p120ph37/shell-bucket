"""Session topology -- the graph of `sb` multiplexers the wrapper learns about.

Rebuilt by **SURVEY**: the wrapper sends a `SURVEY:<id>` APC down the byte
stream; every `sb mux` replies `SURVEYR:<id>:<route>:<identity>` (host/os/arch/pid)
and fans the survey out to its conduit children. A reply's `<route>` is the path
of conduit-ids from the wrapper to that node -- empty at the node itself, with each
mux prepending its conduit's cid as it relays the reply up. So the wrapper ends up
with a `route -> identity` map: the topology graph, *and* the address book for
source-routed pushes (the same route a `PUSH` walks down).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Node:
    """One surveyed multiplexer: its route (conduit-id path from the wrapper) and
    parsed identity fields."""

    route: tuple[int, ...]
    fields: dict[str, str]

    @property
    def host(self) -> str:
        return self.fields.get("host", "?")

    @property
    def pid(self) -> str:
        return self.fields.get("pid", "")

    @property
    def depth(self) -> int:
        """Hops from the wrapper (route length); the top mux is depth 1."""
        return len(self.route) + 1


def parse_route_path(route: bytes) -> tuple[int, ...]:
    """Parse a comma-separated cid route (`3,7`), empty -> ()."""
    s = route.decode("ascii", "replace").strip()
    if not s:
        return ()
    return tuple(int(x) for x in s.split(",") if x)


def _parse_fields(info: bytes) -> dict[str, str]:
    """Parse `host=h:os=o:arch=a:pid=p` (the SURVEYR identity tail)."""
    fields: dict[str, str] = {}
    for part in info.decode("ascii", "replace").split(":"):
        k, sep, v = part.partition("=")
        if sep and k:
            fields[k] = v
    return fields


@dataclass
class Topology:
    """The surveyed nodes, keyed by route so a re-survey updates in place."""

    _nodes: dict[tuple[int, ...], Node] = field(default_factory=dict)

    def record(self, route: bytes, identity: bytes) -> Node:
        """Record (or refresh) the node a `SURVEYR` reported at `route`."""
        r = parse_route_path(route)
        node = Node(route=r, fields=_parse_fields(identity))
        self._nodes[r] = node
        return node

    def nodes(self) -> list[Node]:
        """All known nodes, ordered by route (so by depth then position)."""
        return [self._nodes[k] for k in sorted(self._nodes)]

    def routes(self) -> list[tuple[int, ...]]:
        """Sorted known routes (the address book)."""
        return sorted(self._nodes)

    def depths(self) -> list[int]:
        """Sorted distinct depths present."""
        return sorted({n.depth for n in self._nodes.values()})

    def format_table(self) -> str:
        """A human-readable survey listing (one row per node, ordered by route).
        This is what `sb survey` prints; the wrapper builds it and routes it back
        to the in-session client. Columns: depth, route, host, os, arch, pid."""
        rows = [("DEPTH", "ROUTE", "HOST", "OS", "ARCH", "PID")]
        for n in self.nodes():
            route = ",".join(str(c) for c in n.route) or "-"
            rows.append(
                (
                    str(n.depth),
                    route,
                    n.host,
                    n.fields.get("os", "?"),
                    n.fields.get("arch", "?"),
                    n.pid or "?",
                )
            )
        widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
        lines = ["  ".join(c.ljust(widths[i]) for i, c in enumerate(row)) for row in rows]
        return "\n".join(lines) + "\n"

    def __len__(self) -> int:
        return len(self._nodes)
