# shell-bucket

Generic tty wrapper with in-band multiplexing for transparent delivery of helper
files, lazy aliases, TCP tunnels, and an optional NAT-traversed UDP backhaul —
with iTerm2 integration.

shell-bucket is **not** about SSH. It wraps *any* tty tool that drops you into a
shell — `ssh`, `aws ecs execute-command`, `docker exec -it`, `bash`, `screen`,
a serial console, `it2-ssh` — and makes your local toolbox available at the far
end. You name the command; the wrapper runs it under a local pseudo-terminal and
rides that tty.

## Why

Every remote shell is the same story: `ssh` gets you in, but `jq` isn't there,
your vim config isn't there, your aliases aren't there, and if you need to move
a file you're copy-pasting base64 into the terminal. Multiply that by jump-hosts,
AWS ECS Execute Command, serial consoles, `docker exec -it`, and whatever other
connection path stands between you and the thing you need to fix — and the
friction adds up fast.

shell-bucket wraps any of those connection commands and makes your local toolbox
available at the other end. Drop a static binary or a shell script into your
bucket, and it appears on the remote PATH, downloaded on first use. The manifest
tracks mtimes, so nothing re-sends unless it changed. Pile in as much as you
like — only what you actually invoke crosses the wire.

Everything rides the tty itself via in-band multiplexing. No special network
access, no remote daemon, no extra SSH channel. If you can get a shell there,
shell-bucket works: `sshd` → shell-bucket, jump-host → shell-bucket, ECS Execute
Command → shell-bucket, serial port to a Raspberry Pi → shell-bucket. Hops
compose, so a single session can chain through all of the above at once, with the
full toolbox available at every depth.

The security model follows naturally from the transport: the tunnels and tooling
evaporate when the tty closes, just like SSH port-forwarding — because it *is*
the tty, generalized.

**Practical example:** need `jmap` on an ECS instance without baking it into the
Docker image? Put the static binary in your bucket. The next time you
`shell-bucket wrap -- aws ecs execute-command …` into that instance, `jmap` is on
the path.

## What it does

`shell-bucket wrap -- ssh user@host` runs `ssh user@host` under a local
pseudo-terminal (substitute any tty tool — `wrap -- aws ecs execute-command …`,
`wrap -- bash`, etc.). Once it lands you in a shell, the wrapper silently feeds a
POSIX bootstrap script into that shell over the PTY. The bootstrap fetches the
static `sb` binary for the remote's OS/arch in-band (one FILEREQ exchange), then
`exec`s `sb mux`. `sb mux` takes over the PTY and:

- fetches the manifest and per-shell runtime from the wrapper
- populates a PATH dispatch directory of busybox-style symlinks (one per helper
  in the local bucket)
- exports session environment variables (`SB_SHELL`, `SB_CACHE`, the mux token)
- launches the configured shell with the runtime as its rc file

All ongoing protocol traffic (FILEREQ responses, tunnel frames, backhaul
signaling, topology messages) rides the same PTY byte stream via APC escape
sequences. No extra SSH channel, no remote daemon, no filesystem writes outside
`~/.cache/shell-bucket`.

### Multi-hop composition

`sb mux` works at every depth: a nested SSH hop inside the tooled shell gets its
own `sb mux`, which relays outer APCs inward and wraps inner APCs outward with a
hop counter. The wrapper sees the complete topology as a graph of nodes at known
depths. Source-routed `PUSH` commands reach any specific node by path; `SURVEY`
broadcasts collect all nodes' identities.

From a running remote shell, **`sb survey`** prints that topology: it asks the
wrapper (over the mux socket) to broadcast a `SURVEY`, collect every node's
`SURVEYR` reply, and route back a table of `depth · route · host · os · arch ·
pid` — one row per `sb mux` in the tree. (This is the in-session readout of the
graph the wrapper maintains; richer dashboard tooling can build on the same
wrapper-side topology.)

The `sb inject <cmd>` / `sb i <cmd>` subcommand propagates the tooling to the
next hop without a full `sb mux` — useful for nested `ssh` calls that the tooled
shell doesn't launch itself.

## CLI

```
shell-bucket wrap [--tmux SESSION] [--shell SHELL] -- COMMAND [ARGS...]
```

Runs `COMMAND` under a local pseudo-terminal and brings full shell-bucket
injection up over it. `COMMAND` is any tty tool that lands you in a shell:

```
shell-bucket wrap -- ssh user@host
shell-bucket wrap -- aws ecs execute-command --cluster c --command /bin/bash --interactive …
shell-bucket wrap -- docker exec -it mycontainer bash
shell-bucket wrap -- bash
```

Everything after `--` is the command and its own flags, passed through untouched.
Authentication and host-key handling belong to the wrapped tool, not the wrapper
— shell-bucket assumes the command lands you in a shell with no interactive
preamble (no `password:` prompt). Options:

- `--tmux SESSION` — attach/create a tmux session after injection (requires tmux
  3.3+ on the remote for APC passthrough). `sb mux` forkpty's the fetchable
  `sb-tmux.sh` launcher, which resolves a tmux binary (system or bucket-fetched),
  writes the pane config with `@sb-token` for reconnect, and execs `tmux new -A`.
- `--shell SHELL` — login shell (bash / zsh / ksh; default bash)

```
shell-bucket fetch-tmux [--version VER] [--platform linux/ARCH ...] [--source URL]
```

Pre-downloads a static tmux binary into the local bucket so `sb run tmux` can
deliver it without a network round-trip at connect time.

## Bucket

The local bucket (`~/.local/share/shell-bucket/` on macOS/Linux) is a directory
tree the wrapper serves over the in-band byte stream:

```
bucket/
  sb                        # default platform binary
  linux_arm64/sb            # per-(os,arch) variant wins over plain name
  linux_amd64/sb
  sb-bash.rc                # per-family runtime (auto-generated; user preamble preserved)
  sb-zsh.rc
  rc.d/                     # shell-agnostic fragments sourced after the runtime
    your-aliases.sh
  your-helper               # any executable → lazy PATH alias on every remote
  linux_amd64/your-helper   # per-platform variant
```

Every executable in the bucket (outside `rc.d/`, excluding the reserved `sb`
name) appears on the remote's PATH as an alias that downloads and caches the file
on first use. The manifest records mtimes; files are only re-fetched when stale.

The `sb-<family>.rc` runtime files are auto-regenerated at connect time with a
preserve-marker: everything above the marker line is the user's preamble and is
left untouched; everything below is regenerated from the current `rc.d/` set.
Only `bash` has a full runtime; `zsh`/`ksh` receive a not-implemented stub.

## TCP tunnels

From a running remote shell, `sb tunnel` opens in-band TCP forwarding over the
mux socket. All variants multiplex over the single byte stream — no extra SSH
channel needed.

| command | effect |
|---|---|
| `sb tunnel connect WRAPPER_HOST:PORT` | remote's stdin/stdout bridges to WRAPPER_HOST:PORT (one conn) |
| `sb tunnel listen WRAPPER_HOST:PORT` | wrapper binds; remote's stdin/stdout is the accepted conn (one at a time) |
| `sb tunnel import LOCAL_LISTEN WRAPPER_DEST` | wrapper binds LOCAL_LISTEN; dials WRAPPER_DEST per accepted conn |
| `sb tunnel export WRAPPER_LISTEN REMOTE_DEST` | wrapper binds WRAPPER_LISTEN; remote dials REMOTE_DEST per accepted conn |

Data is base64-framed in-band (`O`/`D`/`H`/`C` frames for Open/Data/Half-close/Close).

## Clipboard (`sb clip`)

From a running remote shell, `sb clip` bridges the remote clipboard to the local
wrapper over the in-band channel:

| command | effect |
|---|---|
| `sb clip` | auto-detect: copy if stdin is a pipe, paste if stdout is a pipe |
| `sb clip --paste` | write the local clipboard to stdout |
| `sb clip --copy` | read stdin and write it to the local clipboard |

Clipboard access is enabled by default. Disable it in `config.toml`:

```toml
[clip]
enabled = false
```

On the wrapper host, `pbpaste`/`pbcopy` (macOS) or `xclip`/`xsel` (Linux) must
be available. If no clipboard tool is found, `sb clip` exits with an error.

## Mux control (`sb ctl`)

From a running remote shell, `sb ctl` (alias: `sb control`) queries and controls the
running mux via its side-band socket (`$SB_TOKEN` must be set):

| command | effect |
|---|---|
| `sb ctl` / `sb ctl status` | print session stats: in-band byte counts, PTY throughput, UDP backhaul state + IPs, relay links |
| `sb ctl down` | force a lossless UDP backhaul revert to in-band |
| `sb ctl up [ip:port,…]` | ask the wrapper to (re)negotiate the UDP backhaul; optional CSV list of manual mux candidates (bypasses STUN) |
| `sb ctl reneg [ip:port,…]` | alias for `up`; also bypasses the one-shot auto-reneg guard |

The `up` / `reneg` commands are useful when roaming caused the UDP path to die and
the automatic one-shot renegotiation has already been used, or when STUN cannot
discover the mux's public address (e.g. symmetric NAT) and you know it manually.

## Optional UDP backhaul

When `SB_UDP_BACKHAUL=1`, the wrapper negotiates a direct encrypted UDP path
alongside the in-band channel:

1. **Offer** — the wrapper mints a 32-byte PSK, queries STUN (Cloudflare
   `stun.cloudflare.com:3478`, Google `stun.l.google.com:19302`) to discover its
   public address, and sends a base64-encoded `UP:O:` offer in-band. The offer
   carries the resolved STUN server IPs so the mux can use them too.
2. **Answer** — `sb mux` binds its punch socket and gathers candidates: its
   host-interface address always, plus — if the offer named STUN servers — a
   server-reflexive (public) candidate discovered by querying those servers *on
   that same socket* (the NAT mapping is per-socket). The STUN query is
   non-blocking: requests are folded into the mux's poll loop so the terminal
   never stalls, and the first reply (authoritative for cone NATs) is answered
   immediately; if none arrives within 750 ms the mux answers host-only. It
   replies `UP:A:` in-band with the candidate list.
3. **Punch** — both sides send authenticated PING packets to all candidate pairs
   simultaneously; the first authenticated reply nominates the working pair.
4. **Up** — all down-frames route over UDP. Heartbeats (every 5 s) keep NAT
   mappings alive.
5. **Lossless revert** — if the path goes silent for 20 s, both sides perform a
   coordinated in-band handoff with no loss and no duplication: each side keeps a
   FIFO of sent-but-unacknowledged frames (pruned as the ARQ's cumulative ack
   advances). On dead-path detection, both sides exchange their receive counts over
   the reliable in-band channel (`UP:RX:<n>`) and each re-sends in-band only the
   tail of frames the peer never received — the exact complement of what the ARQ
   already delivered. Frames sent during the drain are held in the FIFO and
   re-sent in order, so no frames are raced out-of-band.
6. **One-shot renegotiation** — after a lossless revert, the wrapper makes one
   attempt to establish a fresh UDP path (new PSK + STUN gather). This handles
   roaming or NAT-rebind events that would succeed on a new socket; if the fresh
   offer is not answered or the new path also dies, the session stays on the
   in-band SSH channel permanently.

**Wire layering (outermost → innermost):**

```
UDP packet  = [seq: 8B BE] [ AES-256-GCM(nonce, payload) = ciphertext ‖ tag(16B) ]
nonce       = [salt: 4B BE][seq: 8B BE]   (per-direction constant salt)
ARQ stream  = reliable TCP-lite: cumulative ack, reorder buffer, fast-retransmit,
              Jacobson/Karn RTO (100–8000 ms), 64 KB window, 1200 B segment cap
DEFLATE     = raw deflate (wbits=-15), Z_SYNC_FLUSH per chunk, persistent dictionary
frame stream= [u32 BE length][raw frame] …
```

The PSK (32 random bytes) is used directly as the AES-256 key — no KDF. Because
the PSK is generated fresh per session at exactly the right key size (256 bits),
no key-derivation step is needed or used. The STUN query is needed because the
wrapper may be on a workstation behind NAT, and the SSH path itself may be a
non-routable relay (e.g. AWS ECS Execute Command via SSM) with no correspondence
to any directly-reachable IP.

Both ends gather a server-reflexive candidate (the wrapper at offer time, the mux
at answer time), so the path establishes when either or both sit behind a cone
NAT — full-cone, restricted-cone, or port-restricted-cone — which is the class
STUN plus simultaneous hole-punching can traverse. A *symmetric* NAT assigns a
different public mapping per destination, so the reflexive candidate it learns
from a STUN server does not predict the mapping the peer will see; STUN cannot
solve that (it needs a relay/TURN, which is out of scope). In that case the punch
simply times out and the channel stays on the in-band path — no failure, just no
upgrade.

Compression (raw DEFLATE with a persistent cross-session dictionary) sits between
the frame layer and the ARQ — above the ARQ rather than below — because the ARQ
guarantees ordering, making the dictionary valid for the entire session.

## Authentication & host-key verification

These belong to the wrapped tool, not to shell-bucket. `ssh` consults your
`~/.ssh/config`, agent, keys, and `known_hosts`; `aws ecs execute-command` uses
your AWS credentials; and so on. The wrapper just runs the command you give it
and rides the resulting tty — it holds no keys and verifies no hosts.

## Installation

```
pip install shell-bucket     # or: uv add shell-bucket
```

Requires Python 3.13+. The `sb` binaries for linux/amd64 and linux/arm64 are
bundled in the package; the wrapper pushes the correct architecture automatically.
To build `sb` from source, see [`native/sb/README.md`](native/sb/README.md).
