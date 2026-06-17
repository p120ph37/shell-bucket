#!/bin/sh
# shell-bucket tmux launcher. A STATIC bucket asset: `sb mux
# --exec=sb-tmux.sh <session> [flags]` forkpty's it AFTER mux_setup, so the per-host
# socket is up, `sb` + the bucket dispatch dir are on $PATH, and SB_SHELL / SB_CACHE /
# SB_OS / SB_ARCH / SB_TOKEN are exported.
#
# `sb` itself is session-mechanism-agnostic; ALL tmux logic lives here (screen/etc. can
# be peer launchers). We bring up — or, on reconnect, RE-ATTACH to — a tmux session
# whose panes are the tooled shell reaching the host mux over the SOCKET (no
# allow-passthrough, no pane send-keys).
#
# tmux is resolved through the bucket's AUTOVIVIFICATION symlink: we just run `tmux`,
# and whether that's the system one or the bucket's static one (fetched on first run via
# its dispatch symlink) is decided purely by $PATH ORDER — no explicit fetch, no cache
# path. Flags (mirror the wrapper's [tmux] config):
#   --no-system    put the bucket tmux first (don't prefer a $PATH/system tmux)
#   --no-fetch     system tmux only (drop the bucket dispatch dir → no autoviv)
#   --no-fallback  error out instead of dropping to a plain shell when no tmux

session="$1"
shift 2>/dev/null || true
prefer_system=1
fetch=1
fallback=1
for a in "$@"; do
	case "$a" in
		--no-system) prefer_system=0 ;;
		--no-fetch) fetch=0 ;;
		--no-fallback) fallback=0 ;;
	esac
done

rcfile="$SB_CACHE/sb.rc"
launch_shell() {
	case "$SB_SHELL" in
		*bash) exec "$SB_SHELL" --rcfile "$rcfile" ;;
		*) exec "$SB_SHELL" ;;
	esac
}

# Resolve tmux by PATH ORDER only — the autoviv symlink in the bucket dispatch dir does
# the fetch-on-first-run. `command -v` under a policy-ordered PATH gives us a path to
# exec; we exec it with our NORMAL env, so the tmux server + panes inherit the standard
# bucket-first PATH (full tooling) whatever the resolution order was.
bindir="$SB_CACHE/bin"
rest="${PATH#"$bindir":}" # $PATH minus the leading bucket dispatch dir
if [ "$fetch" = 0 ]; then
	tpath="$rest" # system tmux only (no autoviv)
elif [ "$prefer_system" = 1 ]; then
	tpath="$rest:$bindir" # prefer system; bucket tmux as autoviv fallback
else
	tpath="$bindir:$rest" # prefer the bucket's tmux (autoviv)
fi
tmux_bin=$(PATH="$tpath"; command -v tmux 2>/dev/null)

if [ -z "$tmux_bin" ]; then
	[ "$fallback" = 1 ] && launch_shell
	printf 'shell-bucket: no tmux available\n' >&2
	exit 1
fi

# Reconnect: if a tmux server is already running this session, recover the token it
# saved (@sb-token) and tell THIS mux to adopt it — the mux rebinds its socket to the one
# the surviving panes already cached, so their cached SB_TOKEN "starts working again".
if "$tmux_bin" has-session -t "$session" 2>/dev/null; then
	saved=$("$tmux_bin" show -gv @sb-token 2>/dev/null)
	if [ -n "$saved" ] && [ "$saved" != "$SB_TOKEN" ]; then
		sb token --token="$saved" && export SB_TOKEN="$saved"
	fi
fi

# The pane command (tmux default-command), applied when CREATING the session: the same
# tooled shell the non-tmux mux launches. bash → --rcfile; ksh → $ENV; others plain.
case "$SB_SHELL" in
	*bash) dc="exec '$SB_SHELL' --rcfile '$rcfile'" ;;
	*ksh*) export ENV="$rcfile"; dc="exec '$SB_SHELL'" ;;
	*) dc="exec '$SB_SHELL'" ;;
esac
conf="$SB_CACHE/sb-tmux.conf"
{
	printf 'set -g default-command "%s"\n' "$dc"
	printf 'set -g @sb-token "%s"\n' "$SB_TOKEN"
} > "$conf"

exec "$tmux_bin" -f "$conf" new -A -s "$session"
