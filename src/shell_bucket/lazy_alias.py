"""Bootstrap + runtime (`sb-<family>.rc`) generation.

The **bootstrap** is one POSIX script (token + shell baked in) the wrapper / `sb
inject` **feed** over the pty into a target shell (the injector path). It detects
`uname -s`/`-m`, fetches just the `sb` binary, then `exec`s `sb mux`. `sb mux`
(in V) does the rest:
fetches the `sb-manifest` and the `sb-<family>.rc` runtime, populates a PATH dir
of busybox-style dispatch symlinks (one per helper, plus `sb` itself, all -> the
binary), exports the session env, and launches the shell with the runtime as its
rcfile.

The runtime is a real, user-editable file in the bucket, regenerated on connect
with a preserve-marker: the head (above the marker) is the user's shell-specific
pre-extension setup; everything below is generated. Because helpers and `sb` are
PATH symlinks (not shell functions), the generated body is thin -- it only
fetches + sources the shell-agnostic `rc.d/` fragments (post-extension), each via
the `sb` binary on PATH.

Only the **bash** runtime is implemented; ksh/zsh get a not-implemented stub.
bash is kept bash-3.2 compatible.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

# A lazy-alias name must be a valid shell function name.
_VALID_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")

# Shell families with a known injection mechanism. Only `bash` has a runtime.
SHELL_FAMILIES = ("bash", "ksh", "zsh")

# The per-host mux token is minted by `sb mux` itself (see `make_token` in
# native/sb), never by Python: the wire is token-free and the wrapper holds no
# token, so there is nothing to generate or split here.

# sb-<family>.rc preserve-marker: the head (above, incl. marker) is kept verbatim
# on regeneration; everything below is regenerated.
RC_MARKER = "# >>>> shell-bucket generated runtime -- do not edit below this line >>>>"


def is_valid_helper_name(name: str) -> bool:
    return bool(_VALID_NAME.match(name))


def rc_basename(family: str) -> str:
    """Bucket filename for a family's runtime, e.g. `sb-bash.rc`."""
    return f"sb-{family}.rc"


def shell_family(shell: str) -> str:
    """Map a shell invocation (name or path) to its profile family."""
    base = shell.rsplit("/", 1)[-1]
    if base.endswith("bash"):
        return "bash"
    if base in ("ksh", "ksh93", "pdksh", "mksh", "lksh") or base.endswith("ksh"):
        return "ksh"
    if base.endswith("zsh"):
        return "zsh"
    return "bash"


# ----- shell validation -------------------------------------------------------

def _check_shell(shell: str) -> None:
    if "'" in shell or ":" in shell or "\n" in shell:
        raise ValueError(f"shell contains unsafe characters: {shell!r}")


# ----- in-band fetch (shared shell) ------------------------------------------

# The one piece of the protocol that must live in shell (it runs before any `sb`
# binary exists): a `__sb_fetch <name> <out>` that does one FILEREQ transaction
# over the pty -- emit the (token-free) APC, read the `~EOF`-framed base64 reply
# with echo off, decode it onto the file, `chmod +x`. Deliberately minimal: it's
# only called (gated by `[ -x ]`) to bootstrap the small, always-executable `sb`
# binary, so it needs no `stat` (always a full mtime=0 fetch), no `touch` (sb mux
# reconciles its own mtime against the manifest), and no NOT_CHANGED branch. Once
# sb runs, it fetches everything bigger via its own streaming decoder.
#
# Bounded base64 runs are flushed through `base64 -d` straight onto the partial's
# bytes (no staging .b64, no MB-scale shell var). The wire wraps base64 at 76
# chars/line (a multiple of 4) with only the final line short, so each flushed run
# is group-aligned and decodes to exact bytes (any `=` padding sits at the end).
_INLINE_FETCH_FN = r"""__sb_fetch() {
    _rq="$1"; _out="$2"
    mkdir -p "${_out%/*}"
    : > "$_out.partial"
    _sv=$(stty -g 2>/dev/null); stty -echo 2>/dev/null
    printf '\033_shell-bucket:FILEREQ:%s:mtime=0:os=%s:arch=%s\033\\' "$_rq" "$SB_OS" "$SB_ARCH"
    _buf=; _bn=0; _st=
    while IFS= read -r _l; do
        case "$_l" in
            '~EOF'*) _st=eof; break ;;
            '~ERR '*) _st=err; break ;;
            *)
                _buf="$_buf$_l"; _bn=$((_bn + 1))
                if [ "$_bn" -ge 256 ]; then
                    printf %s "$_buf" | base64 -d >> "$_out.partial" || { _st=err; break; }
                    _buf=; _bn=0
                fi ;;
        esac
    done
    [ -n "$_sv" ] && stty "$_sv" 2>/dev/null
    [ "$_st" = eof ] || { rm -f "$_out.partial"; return 1; }
    { [ -z "$_buf" ] || printf %s "$_buf" | base64 -d >> "$_out.partial"; } || {
        rm -f "$_out.partial"; return 1; }
    mv -f "$_out.partial" "$_out" && chmod +x "$_out"
}"""


# ----- the bootstrap (the single injected script) -------------------------

# The one script the wrapper / `sb inject` feed over the pty into a target shell.
# Minimal by design: detect os/arch (per-hop), FILEREQ the `sb` binary (os/arch as
# flags so the wrapper resolves the os_arch subtree), reconcile it, then `exec sb
# mux`. Everything else -- manifest, runtime, PATH dispatch symlinks -- `sb mux`
# fetches/builds itself (in V). Baked with the shell by whoever feeds it; the
# per-host token is minted by `sb mux`, not baked here.
BOOTSTRAP_TEMPLATE = (
    r"""
@@BEGIN@@
SB_SHELL='@@SHELL@@'
SB_OS=$(uname -s)
SB_ARCH=$(uname -m)
: "${SB_CACHE:=$HOME/.cache/shell-bucket}"
mkdir -p "$SB_CACHE"
@@FETCH_FN@@
[ -x "$SB_CACHE/sb" ] || __sb_fetch "sb" "$SB_CACHE/sb" || {
    printf 'shell-bucket: no sb binary for %s/%s\n' "$SB_OS" "$SB_ARCH" >&2
    return 1 2>/dev/null || exit 1
}
export SB_SHELL
# Let the (possibly slightly-stale) cached sb reconcile itself against the
# manifest FIRST -- if the bucket's sb is newer it re-fetches in place -- so the
# `exec` below launches the up-to-date binary this session. Best-effort: a plain
# shell `;` (not `&&`) so we still exec even if the reconcile can't reach the
# wrapper. Its stdout is the live protocol channel; stderr (path) is suppressed.
"$SB_CACHE/sb" fetch sb 2>/dev/null
exec "$SB_CACHE/sb" mux@@MUXARGS@@
""".strip("\n").replace("@@FETCH_FN@@", _INLINE_FETCH_FN)
)


# The injector's sync marker: the first thing the bootstrap emits, so the injector
# can swallow the pre-bootstrap noise (shell prompt, the echo of the fed line) up to
# here and *then* start relaying. The bootstrap's stdout IS the injected pty (the
# injector's master), so a plain emit reaches it. Token-free.
_BEGIN_EMIT = r"""printf '\033_shell-bucket:BEGIN\033\\' """.strip()


def build_bootstrap(shell: str, *, begin: bool = False, mux_args: str = "") -> str:
    """Concretize BOOTSTRAP_TEMPLATE with the shell (the per-host token is minted by
    `sb mux`, not baked here).

    With `begin=True` the bootstrap emits a `BEGIN` sync APC up front; the injector
    watches the fed shell's output for it to know the bootstrap is live (everything
    before is swallowed). `begin=False` omits it (for callers that only want to
    inspect/compare the script body). `mux_args` is appended to the final `exec sb
    mux` -- e.g. `--tmux=<session>` for the tmux launcher (see `build_tmux_prologue`).
    """
    _check_shell(shell)
    begin_line = _BEGIN_EMIT if begin else ":"
    suffix = f" {mux_args}" if mux_args else ""
    return (
        BOOTSTRAP_TEMPLATE.replace("@@BEGIN@@", begin_line)
        .replace("@@SHELL@@", shell)
        .replace("@@MUXARGS@@", suffix)
    )


# ----- tmux launcher prologue (sb mux owns the pty, forkpty's a tmux client) --

# The `--tmux` prologue is the plain bootstrap whose `exec sb mux` runs the
# fetchable `sb-tmux.sh` launcher via `--exec=sb-tmux.sh <session>` (+ the `[tmux]`
# policy as `--no-*` flags). All tmux work lives in that static launcher script
# (autoviv'd through $PATH), not the sb binary: it resolves a tmux (system, else the
# bucket's static one via `sb run tmux`), writes the pane config (`default-command` =
# the tooled shell, `@sb-token` for reconnect, no `allow-passthrough`), and execs
# `tmux new -A` -- so `sb mux` is the parent that owns the ssh-pty + socket while tmux's
# server daemonizes. `sb` itself is tmux-agnostic; screen/etc. can be peer launchers.
_TMUX_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")


def _check_tmux_session(name: str) -> None:
    if not _TMUX_NAME_RE.match(name):
        raise ValueError(f"invalid tmux session name: {name!r}")


def build_tmux_prologue(
    session: str,
    shell: str,
    *,
    begin: bool = False,
    prefer_system: bool = True,
    fetch_if_missing: bool = True,
    fallback_without: bool = True,
) -> str:
    """The `--tmux` hop-1 script: the plain bootstrap, but its `exec sb mux` runs the
    fetchable `sb-tmux.sh` launcher via `--exec`. `sb` stays tmux-agnostic -- the
    launcher (autoviv'd through $PATH) does all the tmux work.

    `prefer_system` / `fetch_if_missing` / `fallback_without` map to the launcher's
    `--no-system` / `--no-fetch` / `--no-fallback` flags (present only when *off*, so
    the common all-on case is a clean `--exec=sb-tmux.sh <session>`).
    """
    _check_tmux_session(session)
    argv = ["--exec=sb-tmux.sh", session]
    if not prefer_system:
        argv.append("--no-system")
    if not fetch_if_missing:
        argv.append("--no-fetch")
    if not fallback_without:
        argv.append("--no-fallback")
    return build_bootstrap(shell, begin=begin, mux_args=" ".join(argv))


# ----- runtime (the generated body of sb-<family>.rc) ------------------------

# Sourced by the shell `sb mux` launches (as its rcfile). Thin by design: helpers
# and `sb` are PATH symlinks to the `sb` binary that `sb mux` populates, and the
# session env (SB_TOKEN/SB_OS/SB_ARCH/SB_CACHE, PATH) is exported by `sb mux`
# before launch. So the body only fetches + sources the shell-agnostic rc.d
# fragments, via the `sb` binary on PATH.
def generate_runtime_body(rcd_fragments: Sequence[str] = ()) -> str:
    """The below-marker generated body for a runtime: fetch + source the rc.d
    fragments (post-extension), each via the `sb` binary on PATH.

    `sb fetch` ensures the fragment is cached (exit status says whether) but its
    stdout is the live protocol channel -- capturing it (`$(sb fetch ...)`) would
    swallow the FILEREQ and hang. So we fetch by side effect, suppress its stderr
    path print, and source the agnostic cache path (`$SB_CACHE/<frag>`) directly.
    """
    if not rcd_fragments:
        return "# (no rc.d fragments)\n"
    parts = [
        "# rc.d fragments -- shell-agnostic post-extension setup, fetched +",
        "# sourced via the sb binary on PATH.",
    ]
    for frag in rcd_fragments:
        parts.append(f'command sb fetch "{frag}" 2>/dev/null && . "$SB_CACHE/{frag}"')
    return "\n".join(parts) + "\n"


def _preamble(family: str) -> str:
    return (
        f"# sb-{family}.rc -- shell-bucket {family} runtime, in your bucket.\n"
        "# Regenerated on connect: everything BELOW the marker is overwritten;\n"
        "# add your own (shell-specific, pre-extension) customizations ABOVE it.\n"
        f"{RC_MARKER}"
    )


def render_rc_file(
    family: str,
    *,
    existing: str | None,
    rcd_fragments: Sequence[str] = (),
) -> str:
    """Compose a full `sb-<family>.rc`: preserved head (above + incl. marker)
    plus a freshly generated body.

    `existing` is the current file text (None if absent). With a marker present,
    the head up to and including it is kept; without one, any existing content is
    preserved as head and the marker appended; absent -> a default preamble.
    """
    if family != "bash":
        body = (
            f"printf 'shell-bucket: {family} runtime not yet implemented "
            f"(rc.d sourcing only)\\n' >&2\n"
        )
    else:
        body = generate_runtime_body(rcd_fragments)

    if existing is None:
        head = _preamble(family)
    else:
        idx = existing.find(RC_MARKER)
        if idx >= 0:
            head = existing[: idx + len(RC_MARKER)]
        else:
            head = existing.rstrip("\n") + "\n" + RC_MARKER
    return head + "\n" + body
