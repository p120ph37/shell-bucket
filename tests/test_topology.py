"""Unit tests for the session topology map (route-based, rebuilt by SURVEY)."""

from __future__ import annotations

from shell_bucket.topology import Topology, parse_route_path


def test_parse_route_path() -> None:
    assert parse_route_path(b"") == ()
    assert parse_route_path(b"3") == (3,)
    assert parse_route_path(b"3,7") == (3, 7)


def test_record_parses_fields_and_route() -> None:
    t = Topology()
    node = t.record(b"", b"host=alpha:os=linux:arch=arm64:pid=42")
    assert node.route == () and node.depth == 1  # top mux: empty route, depth 1
    assert node.host == "alpha" and node.pid == "42"
    assert node.fields == {"host": "alpha", "os": "linux", "arch": "arm64", "pid": "42"}


def test_route_gives_depth() -> None:
    assert Topology().record(b"3,7", b"host=c:pid=3").depth == 3  # two hops down


def test_record_ignores_malformed_identity_parts() -> None:
    node = Topology().record(b"2", b"host=h:garbage::os=linux")
    assert node.fields == {"host": "h", "os": "linux"}


def test_re_survey_same_route_updates_in_place() -> None:
    t = Topology()
    t.record(b"3", b"host=h:pid=7")
    t.record(b"3", b"host=h2:pid=7")  # same route -> replace
    assert len(t) == 1
    assert t.nodes()[0].host == "h2"


def test_distinct_routes_coexist_and_sort() -> None:
    t = Topology()
    t.record(b"", b"host=top:pid=1")
    t.record(b"3", b"host=mid:pid=2")
    t.record(b"3,7", b"host=deep:pid=3")
    assert len(t) == 3
    assert t.routes() == [(), (3,), (3, 7)]
    assert t.depths() == [1, 2, 3]
    assert [n.host for n in t.nodes()] == ["top", "mid", "deep"]


def test_format_table_is_what_sb_survey_prints() -> None:
    t = Topology()
    t.record(b"", b"host=top:os=Linux:arch=aarch64:pid=1")
    t.record(b"3,7", b"host=deep:os=Linux:arch=x86_64:pid=99")
    out = t.format_table()
    lines = out.splitlines()
    assert lines[0].split() == ["DEPTH", "ROUTE", "HOST", "OS", "ARCH", "PID"]
    # top mux: depth 1, empty route renders "-"
    assert lines[1].split() == ["1", "-", "top", "Linux", "aarch64", "1"]
    # deep mux: depth = len(route)+1 = 3, route joined by commas
    assert lines[2].split() == ["3", "3,7", "deep", "Linux", "x86_64", "99"]
    assert out.endswith("\n")
