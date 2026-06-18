# sb — shell-bucket demultiplexer

Static binary written in V, compiled to C, cross-compiled to static musl via
`xx-clang`. It is both the **in-band multiplexer** that rides the PTY byte stream
at every hop and the **protocol client** that fetches files, manages tunnels, and
drives the optional UDP backhaul upgrade.

Binary sizes: ~378 KB (amd64) / ~402 KB (arm64), stripped static musl.

## Build

```
./check.sh              # build both arches + run the V self-test suite
./build.sh              # build only (linux/amd64 + linux/arm64 → dist/<os>_<arch>/sb)
```

Requires a Docker buildx builder. No QEMU needed: `xx-clang` cross-compiles the
generated C to each TARGETPLATFORM at the C stage; the final `scratch` stage only
copies the finished binary.

**In-container deps (never committed to the workspace):**

- BearSSL v0.6 (shallow-cloned inside the build container) → AES-256-GCM
  (`csrc/sb_aead.c` shim over the BearSSL AES-CT-GCM stack)
- zlib v1.3.1 (shallow-cloned inside the build container) → raw-DEFLATE stream
  compression (`csrc/sb_deflate.c` shim, wbits=−15)

Both are compiled into single relocatable objects (`build/sbcrypto.o`,
`build/sbzlib.o`) that the V link pulls in via `#flag`. Dead code is stripped by
`-Wl,--gc-sections`.

To cross-build for an extra platform (e.g. armv7):

```
SB_PLATFORMS=linux/arm/v7 ./build.sh
```

---

## Bootstrap flow

The wrapper feeds a short POSIX shell script into the remote PTY. It:

1. Emits a `BEGIN` sync APC so the wrapper knows the script is live (everything
   before it is discarded — shell prompt, echo of the fed line).
2. Detects `uname -s` / `uname -m` (OS and arch).
3. Calls `__sb_fetch sb $SB_CACHE/sb` — an inline function that does one
   FILEREQ over the PTY with echo off, decodes the base64 response, and writes the
   binary to `~/.cache/shell-bucket/sb`. If the binary is already cached and
   up-to-date (mtime match) it is not re-fetched.
4. Runs `"$SB_CACHE/sb" fetch sb` — the newly-arrived binary reconciles its own
   mtime against the manifest (re-fetches in-place if the bucket's copy is newer,
   so the following exec picks up the freshest version).
5. `exec "$SB_CACHE/sb" mux` — hands control to `sb mux`.

`sb mux` then runs `mux_setup`:

- Fetches `sb-manifest` (the bucket's file listing with mtimes) and the
  `sb-<family>.rc` runtime.
- Prunes stale cache entries using the manifest.
- Populates a PATH dispatch directory of busybox-style symlinks (one per
  executable helper in the manifest, plus `sb` itself, all pointing to the binary).
- Exports session env: `SB_SHELL`, `SB_CACHE`, `SB_BIN` (dispatch dir), `SB_TOKEN`
  (the per-session mux token), `PATH` (with the dispatch dir prepended).
- Emits `MUXUP` APC up the byte stream, signaling the wrapper and any conduit
  that the mux is ready and terminal input can flow. (Conduits hold stdin until
  they see `MUXUP` or a 20 s grace timer fires.)
- Launches the configured shell with `--rcfile sb-<family>.rc` (bash) or the
  equivalent for ksh/zsh.

---

## APC wire protocol

All protocol frames ride the PTY byte stream as APC escape sequences:

```
ESC _ shell-bucket:<cmd> ESC \
```

Recognition is **prefix-only** — no token on the wire. The APC is trusted
structurally: each `sb mux` strips our-prefix APCs from its forkpty child
("strip-at-source"), so an our-prefix APC arriving from below has already been
authenticated by the hop that emitted it. Foreign (non-our-prefix) APCs are
forwarded verbatim.

The `sb __muxscan` hook exposes the scanner: reads stdin, writes
`T:<passthru>` then one `P:<payload>` per extracted APC.

**Mux frame routing:**

Frames to/from nested hops are wrapped:

```
M:<hop>:<payload>     # hop = relative depth (1 = direct child mux)
R<id>:<payload>       # label-swap route for persistent channels (tunnels, UDP signaling)
```

Each `sb mux` increments the hop counter going downstream and decrements it going
upstream, so the wrapper always sees depth from its perspective.

**MUXUP gate:**

After `mux_setup`, `sb mux` emits `MUXUP` in-band before entering the pump loop.
The wrapper and `sb hop`/conduit relays hold all terminal input until they see
`MUXUP` (or a 20 s grace deadline), preventing APC/terminal interleaving during
the pre-pump bootstrap fetch.

---

## FILEREQ protocol

File delivery uses a request/response exchange over the in-band byte stream:

```
request:  ESC _ shell-bucket:FILEREQ:<name>:mtime=<m>:os=<os>:arch=<arch> ESC \
response: <base64 lines> ~EOF mtime=<m> [chmod=+x]
       or ~EOF NOT_CHANGED
       or ~ERR NOT_FOUND / PERMISSION_DENIED
```

The wrapper resolves `name` against the bucket tree:
`<os>_<arch>/<name>` → `<os>/<name>` → `<name>` (first hit wins). If the
remote's `mtime` matches the bucket's, it replies `NOT_CHANGED`. The response
base64 is wrapped at 76 chars/line (group-aligned so each full run decodes to
exact bytes). The binary itself is the only file fetched in the bootstrap shell
function; everything else is fetched by `sb fetch <name>` (V, streaming decoder).

---

## Topology: ANNOUNCE, SURVEY, PUSH

Each `sb mux` at startup emits an `ANNOUNCE:<host>:<os>:<arch>:<pid>` APC that
each upstream mux wraps with its depth. The wrapper records the full multi-hop
graph.

`SURVEY:<id>` is broadcast down to all reachable nodes; each node replies
`SURVEYR:<id>::<identity>` upstream. Each intermediate mux prepends its conduit's
depth label so the wrapper can reconstruct the topology.

`PUSH:<pid>:<route>:<cmd>` is source-routed: an empty `<route>` means "act on me
and reply"; a non-empty route pops the head conduit id, forwards to that child
mux, and the reply bubbles back up.

---

## Mux side-band socket

Each `sb mux` binds a Unix domain socket at `$XDG_RUNTIME_DIR/sb.<locator>.sock`
(or `~/.cache/shell-bucket/<locator>.sock`). Authentication is constant-time
bearer-token comparison. The socket carries:

- `FILEREQ` requests from any process on the remote (e.g. `sb fetch <name>`, lazy
  aliases, `sb run <name>`)
- `TUN:dial/bind` commands from `sb tunnel`
- `TOKEN:` rebind commands from `sb token`
- `SURVEY` / `PUSH` fan-out relayed from child `sb hop` sessions

`sb token --token=<tok>` rebinds the socket to a new locator/secret (used for
reconnect). `sb token --randomize` mints a fresh random token, prints it, and
rebinds.

---

## TCP tunnels

`sb tunnel` connects to the mux socket, sends a `TUN:<mode>:<spec>` frame, and
relays its stdin/stdout as `O`/`D`/`H`/`C` (Open/Data/Half-close/Close) frames:

| subcommand | wrapper side | remote side |
|---|---|---|
| `connect DEST` | dials DEST, one conn | stdin/stdout bridge |
| `listen ADDR` | binds ADDR, one conn at a time | stdin/stdout bridge |
| `import LOCAL DEST` | dials DEST per accepted conn at LOCAL | listener originates conns |
| `export WRAPPER_ADDR REMOTE_DEST` | binds WRAPPER_ADDR, accepts all | remote dials REMOTE_DEST per conn |

Data is base64-framed within each `D:<conn>:<b64>` payload. Tunnels are
bidirectional and persistent for the lifetime of the `sb tunnel` process.

---

## Optional UDP backhaul

Opt-in via `SB_UDP_BACKHAUL=1` on the wrapper side. The upgrade handshake is
carried in-band as `UP:O:` (offer) and `UP:A:` (answer) APCs over a persistent
`R<id>:` route. The `sb __upgradeserve` hook drives the mux side of the handshake
in isolation (used by the E2E test).

### Signaling wire

```
UP:O:  = base64 of: [0x01]['O'][psk:32B][nonce:8B][n_stun:1B][stun×6B …][n_cand:1B][cand×6B …]
UP:A:  = base64 of: [0x01]['A'][nonce:8B][n_cand:1B][cand×6B …]
cand   = [IPv4:4B][port:2B BE]
```

The PSK is 32 random bytes = AES-256 key directly (no KDF). The nonce is an 8-byte
random value carried through the answer so the mux can verify the offer it is
answering. The offer's STUN list is the resolved IPs of the wrapper's STUN servers
(the static `sb` binary has no DNS resolver), forwarded so the mux can reach the
same observers.

### Candidate gathering

Both ends advertise a host-interface candidate plus, when possible, a
server-reflexive (public) one — the reflexive mapping must be learned on the *same
socket* that will carry the channel, because a NAT maps per-socket.

- **Wrapper (offer time):** `_gather` binds the channel socket and STUN-queries
  each configured server on it (blocking is fine — it runs off the event loop),
  adding any reflexive result to the offer's candidate list.
- **Mux (answer time):** `start_backhaul` binds the punch socket and, if the offer
  named STUN servers, enters the `.gathering` state instead of answering
  immediately. STUN Binding Requests are sent on the punch socket and **serviced by
  the pump's own poll loop** (`tick`/`on_udp`/`next_timeout`) — never a blocking
  call, so the terminal stays responsive. The requests retransmit every 250 ms; the
  first valid response (authoritative for a cone NAT) is answered at once, and if
  none arrives within 750 ms the mux answers host-only. The wrapper does not begin
  punching until it has the answer, so no punch packets can race the STUN responses
  on that socket. With no STUN servers in the offer, the mux skips `.gathering` and
  answers host-only immediately.

This covers the NAT classes STUN + simultaneous hole-punching can traverse: full-,
restricted-, and port-restricted-cone. A *symmetric* NAT remaps per destination, so
the reflexive candidate does not predict the peer-facing mapping; STUN cannot solve
it (TURN would, and is out of scope). The punch then times out and the session
stays in-band — graceful, not an error.

### Packet wire

```
packet = [seq:8B BE][ AES-256-GCM(key, nonce, payload) = ciphertext ‖ tag(16B) ]
nonce  = [salt:4B BE][seq:8B BE]
salts  = wrapper-tx: 1, wrapper-rx: 2; mux-tx: 2, mux-rx: 1
```

Control packets (heartbeat PING/PONG) have `payload[0] & 0x80` set; the ARQ drops
them as non-data. The mux-side seq space for control packets (heartbeats) is
distinct from the ARQ seq space.

### Reliable-UDP (TCP-lite ARQ)

```
ARQ payload = [flags:1B][ack:8B BE]([offset:8B BE][data] if DATA flag set)
```

- Cumulative acknowledgement + receiver reorder buffer
- Fast-retransmit on 3 duplicate acks
- Jacobson/Karn SRTT/RTTVAR RTO: min 100 ms, max 8000 ms, exponential backoff
- 64 KB send window, 1200 B max segment
- Liveness: PING every 5 s once up; path declared dead after 20 s silence

### Lossless revert + one-shot renegotiation

When the path goes silent, both sides coordinate a **lossless handoff** over the
reliable in-band SSH channel — no frames are lost or duplicated:

1. The side that detects the dead path enters a draining state, prunes its FIFO of
   any frames the ARQ already acknowledged, and sends `UP:RX:<n>` in-band, where
   `n` is the count of down-frames it has actually consumed.
2. On receiving the peer's `UP:RX:<n>`, each side re-sends in-band exactly the
   tail of frames the peer did not receive (`frame# >= n`). New frames submitted
   during the drain are held in the FIFO and re-sent in order behind the tail.
3. After the handoff completes, the wrapper makes **one attempt** to renegotiate a
   fresh UDP path (new PSK + STUN gather, new socket). This handles roaming /
   NAT-rebind — if the fresh offer is answered and the new path survives, traffic
   moves back to UDP; otherwise the session stays in-band permanently.

### Stream compression (above the ARQ)

Raw DEFLATE (wbits=−15, no zlib/gzip header) with `Z_SYNC_FLUSH` per chunk and a
persistent cross-session dictionary sits between the frame layer and the ARQ.
Placing it above the ARQ means ordering is guaranteed, so the dictionary remains
valid for the whole session. The AES-GCM tag authenticates each ARQ packet, so a
container checksum would be dead weight; raw deflate carries zero per-chunk
overhead beyond the compressed data.

### Full layering

```
IP → UDP → AES-256-GCM → ARQ (reliable ordered stream) → raw-DEFLATE → frames
frame stream = [u32 BE length][raw frame] …
```

---

## Self-test suite

`./check.sh` builds both arches then runs the full suite inside an Alpine
container against the freshly-built `linux_arm64` binary. Tests in `test/*.sh`:

| test | what it covers |
|---|---|
| `passthrough.sh` | PTY pass-through pump; env-driven launch; exit-status mirror |
| `muxscan.sh` | APC scanner: passthru vs payload split, multi-APC, foreign APCs |
| `fetch.sh` | FILEREQ client (mtime=0 fetch, NOT_CHANGED, NOT_FOUND, os/arch resolve) |
| `resolve.sh` | manifest parse + os/arch resolution; MISS |
| `dispatch.sh` | `sb fetch` / `sb run` / PATH symlink dispatch |
| `bin.sh` | `sb mux` dispatch-dir population from a manifest |
| `prune.sh` | cache reconciliation at manifest-load |
| `hop.sh` | `sb hop` forkpty relay |
| `muxsock.sh` | side-band socket: bearer-auth, echo roundtrip, sysexits failure codes |
| `token.sh` | `sb token` socket rebind |
| `crypto.sh` | AES-256-GCM AEAD: NIST KAT + round-trip/tamper/AAD-mismatch |
| `deflate.sh` | raw-DEFLATE shim: round-trip + persistent-dictionary shrink |
| `stun.sh` | STUN RFC 5389 codec: Binding Request, XOR-MAPPED-ADDRESS decode, negative cases |
| `udp.sh` | UDP packet codec: seal/open, cross-direction rejection, tamper, truncation |
| `arq.sh` | ARQ: 128 KB over simulated 15% loss+reorder (virtual clock, no sockets) |
| `arqudp.sh` | ARQ over real loopback UDP sockets: 256 KB deterministic stream |
| `punch.sh` | NAT hole-punch establishment + 128 KB transfer over the punched pair |
| `sig.sh` | UPGRADE signaling codec: offer/answer round-trip + rejection of malformed blobs |
| `gather.sh` | mux-side srflx gathering: STUN query on the punch socket → reflexive candidate in the `UP:A` answer set |
| `revert.sh` | lossless revert handoff: FIFO prune + in-band tail re-send (`__revertprobe`) |
| `ctl.sh` | `sb ctl` status + control verbs over the real bearer-auth socket (`__muxserve` stub) |

The Python integration suite (`tests/integration/`) adds:

- **`test_ssh_connection.py`** — end-to-end: real asyncssh + containerized `sb mux`
  including two-hop nested mux tests
- **`test_cross_impl.py`** — Python ARQ ↔ `sb __arqrecv`; Python `UdpBackhaul` ↔
  `sb __punchrecv` (bidirectional, 128 KB, compressed)
- **`test_upgrade_e2e.py`** — full upgrade path: wrapper-side `TransportManager` ↔
  `sb __upgradeserve`, loopback UDP, echo round-trip "E2E-UPGRADE-PING"

---

## Subcommand reference

User-facing (invoked by name or via PATH symlink):

| subcommand | description |
|---|---|
| `sb mux [--token=T] [--exec=CMD [args]]` | start the multiplexer (called by the bootstrap) |
| `sb fetch <name>` | fetch one file from the wrapper into the local cache |
| `sb run <name> [args]` | ensure-cached then exec the named helper |
| `sb token [--token=T \| --randomize]` | manage the side-band socket token |
| `sb tunnel connect\|listen\|import\|export …` | open an in-band TCP tunnel |
| `sb hop <cmd...>` / `sb h <cmd...>` | carry tooling to the next hop |
| `sb ctl [status]` | show mux session stats: byte counts, backhaul state, relay links |
| `sb ctl down` | force a lossless UDP backhaul revert to in-band |
| `sb ctl up [ip:port,…]` | ask the wrapper to (re)negotiate the UDP backhaul; optional manual mux candidates |
| `sb ctl reneg [ip:port,…]` | alias for `up`; bypass the one-shot renegotiation guard |
| `sb control …` | alias for `sb ctl` |

Internal / test hooks (`__` prefix):

| hook | description |
|---|---|
| `__pumptest` | PTY pass-through pump in isolation (no mux_setup) |
| `__muxscan` | APC scanner stdin→stdout |
| `__fetchtest` | FILEREQ client round-trip test |
| `__resolvetest` | manifest resolution test |
| `__bintest` | dispatch-dir population test |
| `__prunetest` | cache prune test |
| `__muxserve / __muxclient / __muxfetch / __conduitfetch` | socket server/client stubs |
| `__cryptotest` | AES-GCM self-test |
| `__stuntest` | STUN codec self-test |
| `__udptest` | UDP packet codec self-test |
| `__deflatetest` | raw-DEFLATE shim self-test |
| `__arqtest` | ARQ simulation self-test |
| `__sigtest` | upgrade signaling codec self-test |
| `__arqsend / __arqrecv` | ARQ live-socket sender/receiver |
| `__punchsend / __punchrecv` | hole-punch + transfer live-socket test |
| `__cands` | print local UDP candidates |
| `__upgradeserve` | mux side of the full backhaul upgrade (for E2E tests) |
| `__stunquery HOST PORT` | live STUN query (prints srflx address) |
| `__stunserver PORT PUB_IP PUB_PORT` | fake STUN observer reporting a fixed mapping (pairs with `__gatherprobe`) |
| `__gatherprobe STUN_IP STUN_PORT WRAP_IP WRAP_PORT` | run the real mux gather path; print the srflx + answer candidate set |
| `__revertprobe` | lossless-revert white-box self-test: FIFO prune + in-band handoff |
| `__ctlprobe` | (exercised via ctl.sh) STATUS wire format round-trip via `__muxserve` stub |
| `__bindprobe` | bind-probe helper |
