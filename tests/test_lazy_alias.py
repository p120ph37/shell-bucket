"""Unit tests for the bootstrap builders + bash runtime generation."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from shell_bucket.lazy_alias import (
    RC_MARKER,
    SHELL_FAMILIES,
    build_bootstrap,
    build_tmux_prologue,
    generate_runtime_body,
    is_valid_helper_name,
    rc_basename,
    render_rc_file,
    shell_family,
)

# The per-host token is minted by `sb mux` (V) now -- there is no Python token to
# bake, so the builders take only the shell/session. (See native/sb `make_token`.)


def _bash_parse_ok(content: bytes) -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash not available")
    r = subprocess.run([bash, "-n"], input=content, capture_output=True)
    assert r.returncode == 0, r.stderr.decode()


# ----- small helpers --------------------------------------------------------

@pytest.mark.parametrize("name", ["imgcat", "my-tool", "_foo", "a1"])
def test_valid_names(name: str) -> None:
    assert is_valid_helper_name(name)


@pytest.mark.parametrize("name", ["a.b", "a/b", "", "1abc", "a b", "sb-bash.rc"])
def test_invalid_names(name: str) -> None:
    assert not is_valid_helper_name(name)


def test_rc_basename() -> None:
    assert rc_basename("bash") == "sb-bash.rc"
    assert rc_basename("ksh") == "sb-ksh.rc"


@pytest.mark.parametrize(
    "shell,family",
    [("bash", "bash"), ("/usr/bin/bash", "bash"), ("ksh", "ksh"), ("mksh", "ksh"),
     ("zsh", "zsh"), ("fish", "bash")],
)
def test_shell_family(shell: str, family: str) -> None:
    assert shell_family(shell) == family
    assert family in SHELL_FAMILIES


# ----- bootstrap -------------------------------------------------------------

def test_bootstrap_bakes_shell_not_token() -> None:
    b = build_bootstrap("/usr/bin/bash")
    assert "SB_SHELL='/usr/bin/bash'" in b
    # No token anywhere -- the mux mints its own and ignores the env; reuse is
    # the explicit `sb mux --token=...`, never an inherited SB_TOKEN.
    assert "SB_TOKEN" not in b
    assert "uname -s" in b and "uname -m" in b


def test_bootstrap_fetches_sb_then_execs_mux() -> None:
    b = build_bootstrap("bash")
    assert '[ -x "$SB_CACHE/sb" ] || __sb_fetch "sb" "$SB_CACHE/sb"' in b  # gated bootstrap
    assert ":os=%s:arch=%s" in b  # os/arch ride as flags for the binary fetch
    assert '"$SB_CACHE/sb" fetch sb' in b  # reconcile sb BEFORE exec (this session)
    assert 'exec "$SB_CACHE/sb" mux' in b
    # The runtime/manifest are fetched by `sb mux` now, not the bootstrap.
    assert ".rc" not in b and "SB_RC_FILE" not in b
    # No leftover stage-1 indirection.
    assert "S2:" not in b and "eval" not in b


def test_bootstrap_is_family_agnostic() -> None:
    # The bootstrap only lands the binary; it no longer names a per-family runtime.
    for shell in ("/bin/ksh", "zsh", "/usr/bin/bash"):
        assert ".rc" not in build_bootstrap(shell)


def test_bootstrap_rejects_bad_shell() -> None:
    for bad in ("ba:sh", "ba'sh", "ba\nsh"):
        with pytest.raises(ValueError):
            build_bootstrap(bad)


def test_bootstrap_parses() -> None:
    _bash_parse_ok(build_bootstrap("bash").encode() + b"\n")
    _bash_parse_ok(build_bootstrap("/usr/bin/bash").encode() + b"\n")


def test_bootstrap_begin_emits_sync_apc() -> None:
    # Injector path: a token-free BEGIN sync APC up front. Embed path (begin=False)
    # omits it.
    plain = build_bootstrap("bash")
    assert "BEGIN" not in plain
    with_begin = build_bootstrap("bash", begin=True)
    assert r"shell-bucket:BEGIN" in with_begin  # token-free marker
    # BEGIN comes before the shell/arch detection (so the injector syncs early).
    assert with_begin.index("BEGIN") < with_begin.index("uname -s")


def test_bootstrap_begin_still_parses() -> None:
    _bash_parse_ok(build_bootstrap("bash", begin=True).encode() + b"\n")


# ----- tmux prologue (bootstrap + `exec sb mux --tmux=...`) ---------------

def test_tmux_prologue_is_bootstrap_plus_exec_launcher() -> None:
    p = build_tmux_prologue("work", "/bin/bash")
    # It IS the plain bootstrap, only with the sb-tmux.sh launcher on its exec line.
    assert p == build_bootstrap("/bin/bash", mux_args="--exec=sb-tmux.sh work")
    assert "SB_SHELL='/bin/bash'" in p and "SB_TOKEN" not in p
    assert 'exec "$SB_CACHE/sb" mux --exec=sb-tmux.sh work' in p
    # No tmux machinery in the shell -- it all lives in the fetchable launcher now.
    assert "command -v tmux" not in p
    assert "sb run tmux" not in p
    assert "allow-passthrough" not in p
    assert "new -A" not in p
    assert "<(" not in p and "<<<" not in p


def test_tmux_prologue_policy_flags() -> None:
    # Each `[tmux]` policy maps to a launcher `--no-*` flag, present only when it's OFF
    # -- so the all-on default is a clean `--exec=sb-tmux.sh <session>`.
    assert "--no-" not in build_tmux_prologue("w", "bash")
    p = build_tmux_prologue(
        "w", "bash", prefer_system=False, fetch_if_missing=False, fallback_without=False
    )
    assert 'exec "$SB_CACHE/sb" mux --exec=sb-tmux.sh w --no-system --no-fetch --no-fallback' in p


def test_tmux_prologue_begin_emits_sync_apc() -> None:
    assert "BEGIN" not in build_tmux_prologue("work", "bash")
    p = build_tmux_prologue("work", "bash", begin=True)
    assert r"shell-bucket:BEGIN" in p  # token-free marker
    assert p.index("BEGIN") < p.index("uname -s")  # sync before detection


def test_tmux_prologue_bootstraps_sb_not_tmux() -> None:
    # The shell only bootstraps the sb binary; tmux acquisition is sb mux's job.
    p = build_tmux_prologue("work", "bash")
    assert '[ -x "$SB_CACHE/sb" ] || __sb_fetch "sb" "$SB_CACHE/sb"' in p
    assert "__sb_fetch() {" in p and '__sb_fetch "tmux"' not in p


def test_tmux_prologue_rejects_unsafe_session() -> None:
    for bad in ("", "a;b", "a b", "a$b", "../etc", "a\nb"):
        with pytest.raises(ValueError):
            build_tmux_prologue(bad, "bash")


def test_tmux_prologue_rejects_unsafe_shell() -> None:
    with pytest.raises(ValueError):
        build_tmux_prologue("work", "ba'sh")
    with pytest.raises(ValueError):
        build_tmux_prologue("work", "ba:sh")


def test_tmux_prologue_parses() -> None:
    _bash_parse_ok(build_tmux_prologue("work", "bash", begin=True).encode() + b"\n")
    _bash_parse_ok(
        build_tmux_prologue(
            "work", "bash", prefer_system=False, fetch_if_missing=False,
            fallback_without=False,
        ).encode() + b"\n"
    )


# ----- runtime body ---------------------------------------------------------

def test_runtime_body_empty_without_rcd() -> None:
    # No helpers, no fetch client, no sb() function -- those are PATH symlinks /
    # the binary now. With no rc.d fragments the generated body is inert.
    body = generate_runtime_body()
    for absent in ("__sb_fetch", "__sb_run", "sb-refresh", "sb()", "sbssh()",
                   "__SB_STAGE1_TPL", "export -n"):
        assert absent not in body, absent


def test_runtime_body_rcd_via_sb_fetch() -> None:
    body = generate_runtime_body(rcd_fragments=["rc.d/00-x.sh", "rc.d/50-y.sh"])
    # Fetch by side effect (NOT captured -- sb's stdout is the protocol channel),
    # then source the agnostic cache path directly.
    assert 'command sb fetch "rc.d/00-x.sh" 2>/dev/null && . "$SB_CACHE/rc.d/00-x.sh"' in body
    assert 'command sb fetch "rc.d/50-y.sh" 2>/dev/null && . "$SB_CACHE/rc.d/50-y.sh"' in body
    assert "$(command sb fetch" not in body  # never command-substituted


def test_runtime_body_parses() -> None:
    _bash_parse_ok(generate_runtime_body(["rc.d/00-x.sh"]).encode())
    _bash_parse_ok(generate_runtime_body().encode())


# ----- render_rc_file (marker preservation) ---------------------------------

def test_render_missing_uses_preamble() -> None:
    rc = render_rc_file("bash", existing=None, rcd_fragments=["rc.d/00-x.sh"])
    assert rc.startswith("# sb-bash.rc")
    assert RC_MARKER in rc
    assert "rc.d/00-x.sh" in rc
    assert rc.index(RC_MARKER) < rc.index("rc.d/00-x.sh")  # body below marker


def test_render_preserves_head_above_marker() -> None:
    existing = f"# my custom top\nalias x=y\n{RC_MARKER}\nOLD GENERATED BODY\n"
    rc = render_rc_file("bash", existing=existing, rcd_fragments=["rc.d/00-x.sh"])
    assert "# my custom top" in rc and "alias x=y" in rc
    assert "OLD GENERATED BODY" not in rc       # below-marker replaced
    assert "rc.d/00-x.sh" in rc
    assert rc.count(RC_MARKER) == 1


def test_render_no_marker_appends_one() -> None:
    rc = render_rc_file("bash", existing="legacy content\n")
    assert "legacy content" in rc and RC_MARKER in rc
    assert rc.index("legacy content") < rc.index(RC_MARKER)


@pytest.mark.parametrize("family", ["ksh", "zsh"])
def test_render_non_bash_is_stub(family: str) -> None:
    rc = render_rc_file(family, existing=None)
    assert "not yet implemented" in rc and family in rc
    assert "__sb_fetch" not in rc
