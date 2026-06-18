module main

import os
import encoding.base64

// sb -- transparent PTY byte-pump.
//
//   sb -- <command> [args...]
//
// Allocates a pty, forks <command> as its session leader on the slave side,
// puts our own stdin in raw mode, and relays bytes both directions verbatim.
// Window-size changes (SIGWINCH) and child exit (SIGCHLD) are delivered via a
// signalfd folded into the same poll() loop -- no async signal handlers, so the
// relay stays simple and re-entrancy-free. Exit status mirrors the child.
//
// This is pure pass-through: a session run through sb must be byte-identical
// to one without it. The mux/auth/fetch multiplexer logic layers on top.

#include <pty.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <poll.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <time.h>

// AES-GCM AEAD lives behind a flat C shim (csrc/sb_aead.c) over BearSSL's
// constant-time primitives. BearSSL is cloned at a pinned release and compiled
// to build/sbcrypto.o inside the build container (never vendored into the
// workspace); see Dockerfile. The V side only ever sees two byte-pointer calls.
#flag -I@VMODROOT/csrc
#flag @VMODROOT/build/sbcrypto.o
#flag @VMODROOT/build/sbzlib.o
#include "sb_aead.h"
#include "sb_deflate.h"

fn C.forkpty(amaster &int, name charptr, termp voidptr, winp voidptr) int
fn C.execvp(file charptr, argv voidptr) int
fn C.isatty(fd int) int
fn C.tcgetattr(fd int, p voidptr) int
fn C.tcsetattr(fd int, act int, p voidptr) int
fn C.cfmakeraw(p voidptr)
fn C.ioctl(fd int, req u64, arg voidptr) int
fn C.signalfd(fd int, mask voidptr, flags int) int
fn C.sigemptyset(set voidptr) int
fn C.sigaddset(set voidptr, signo int) int
fn C.sigprocmask(how int, set voidptr, old voidptr) int
fn C.poll(fds voidptr, n u64, timeout int) int
fn C.read(fd int, buf voidptr, n usize) i64
fn C.write(fd int, buf voidptr, n usize) i64
fn C.waitpid(pid int, status &int, opt int) int
fn C.setenv(name charptr, value charptr, overwrite int) int
fn C.utime(file charptr, times voidptr) int
fn C.getpid() int
fn C.time(t voidptr) i64
fn C.open(path charptr, flags int) int
fn C.close(fd int) int
fn C.pipe(fds &int) int
fn C.dup(fd int) int
fn C.dup2(oldfd int, newfd int) int

// AF_UNIX stream sockets for the mux side-band: one mux per host
// exposes a socket, intra-host `sb` clients connect + bearer-auth over it.
fn C.socket(domain int, typ int, protocol int) int
fn C.bind(fd int, addr voidptr, len u32) int
fn C.listen(fd int, backlog int) int
fn C.accept(fd int, addr voidptr, len voidptr) int
fn C.connect(fd int, addr voidptr, len u32) int
fn C.unlink(path charptr) int
fn C.chmod(path charptr, mode u32) int
fn C.setsockopt(fd int, level int, optname int, optval voidptr, optlen u32) int
fn C.htons(host u16) u16
fn C.inet_pton(af int, src charptr, dst voidptr) int
fn C.shutdown(fd int, how int) int
fn C.sendto(fd int, buf voidptr, n usize, flags int, addr voidptr, addrlen u32) i64
fn C.recvfrom(fd int, buf voidptr, n usize, flags int, addr voidptr, addrlen voidptr) i64
fn C.getsockname(fd int, addr voidptr, addrlen voidptr) int
fn C.getsockopt(fd int, level int, optname int, optval voidptr, optlen voidptr) int
fn C.kill(pid int, sig int) int

@[noreturn]
fn C._exit(code int)

// Linux asm-generic ioctl/signal constants -- identical on amd64 and arm64.
const tiocgwinsz = u64(0x5413)
const tiocswinsz = u64(0x5414)
const sig_block = 0
const sigwinch = 28
const sigchld = 17
const sfd_cloexec = 0o2000000
const tcsadrain = 1
const tcsaflush = 2
const o_rdwr = 2
const pollin = i16(0x001)
// POLLIN|POLLERR|POLLHUP -- "there is something to read, or the peer is gone".
// HUP/ERR carry no POLLIN bit on their own, so a POLLIN-only test would spin
// forever once the child's slave closes instead of draining + ending.
const readable = i16(0x001 | 0x008 | 0x010)
const af_unix = 1
const af_inet = 2
const sock_stream = 1
const sock_cloexec = 0o2000000 // SOCK_CLOEXEC (== O_CLOEXEC on Linux)
const somaxconn = 128
const sol_socket = 1
const so_reuseaddr = 2
const so_peercred = 17 // getsockopt(SOL_SOCKET, SO_PEERCRED) -> struct ucred (Linux)
const sigterm = 15 // `sb ctl kill` sends SIGTERM (graceful) to session components
const shut_wr = 1 // shutdown(fd, SHUT_WR) -- half-close the write side
const sock_mode = u32(0o600)
// sysexits.h codes the mux socket clients return so cron-style consumers can
// trap a closed/unreachable channel cleanly (vs. a real error).
const ex_unavailable = 69 // no socket / connection closed
const ex_tempfail = 75 // socket present but unresponsive
const ex_noperm = 77 // bearer auth rejected

// C-layout-compatible structs (V structs are unboxed and field-ordered).
struct Winsize {
mut:
	row    u16
	col    u16
	xpixel u16
	ypixel u16
}

struct Pollfd {
mut:
	fd      int
	events  i16
	revents i16
}

// struct sockaddr_un { sa_family_t sun_family; char sun_path[108]; } -- 110 bytes,
// no padding (u16 then a u8 array). Linux sun_path is 108.
struct SockaddrUn {
mut:
	sun_family u16
	sun_path   [108]u8
}

// struct sockaddr_in { u16 sin_family; u16 sin_port (net order); u32 sin_addr (net
// order); u8 sin_zero[8]; } -- 16 bytes, the AF_INET address for `sb tunnel`'s TCP
// listeners (import) and dials (export).
struct SockaddrIn {
mut:
	sin_family u16
	sin_port   u16
	sin_addr   u32
	sin_zero   [8]u8
}

// struct ucred { pid_t pid; uid_t uid; gid_t gid; } -- 12 bytes, what
// getsockopt(SO_PEERCRED) fills in. We only read `pid`: the kernel attests the
// connecting process, so a socket client can never lie about its PID -- that is
// what makes `sb ctl kill` a SAFE kill (only real session components, never an
// arbitrary PID a client names).
struct Ucred {
mut:
	pid u32
	uid u32
	gid u32
}

// One connected mux-socket client in the mux poll loop: its fd, whether it has
// passed bearer-auth yet, and a line-assembly buffer (the loop is non-blocking, so
// a request may arrive in pieces).
struct MuxClient {
mut:
	fd               int
	authed           bool
	conduit          bool // declared `CONDUIT` -> owns a downward byte stream (a tree edge)
	cid              int  // this mux's id for the conduit (the route element addressing it)
	tunnel_id        int = -1 // a tunnel client (`sb tunnel`) relays its lines under this id
	pid              int    // kernel-attested peer PID (SO_PEERCRED); 0 if unknown
	desc             string // component description for `sb ctl -v` (cmdline / port spec / RPC name)
	inbuf            []u8
	clip_set_waiting bool // CLIP:SET received; next bytes are 4-byte-length + raw payload
	clip_set_len     int = -1 // -1 = awaiting 4-byte length; >=0 = payload bytes remaining
}

// Read the kernel-attested peer PID of a connected AF_UNIX socket. 0 if the
// lookup fails (the caller then treats the component as un-killable, never PID 0).
fn peer_pid(fd int) int {
	mut cred := Ucred{}
	mut l := u32(sizeof(Ucred))
	if C.getsockopt(fd, sol_socket, so_peercred, voidptr(&cred), voidptr(&l)) != 0 {
		return 0
	}
	return int(cred.pid)
}

@[noreturn]
fn die(msg string) {
	eprintln('sb: ${msg}')
	C._exit(2)
}

// stat_main_tx accumulates all bytes written to fd 1 (the in-band parent channel)
// across the mux pump's lifetime. It is incremented via write1() instead of
// write_all(1,...) in all pump-path code, so `sb ctl status` can report it.
// This is a process-level counter; the pump is single-threaded, so no atomics needed.
__global (
	stat_main_tx i64
)

// write1 writes to fd 1 (the in-band parent channel) and counts the bytes.
fn write1(buf &u8, n i64) {
	write_all(1, buf, n)
	stat_main_tx += n
}

fn write_all(fd int, buf &u8, n i64) {
	mut off := i64(0)
	for off < n {
		w := C.write(fd, unsafe { voidptr(buf + off) }, usize(n - off))
		if w <= 0 {
			return
		}
		off += w
	}
}

// ----- APC framing ---------------------------------------------------------
//
// Our wire frame is `ESC _ shell-bucket:<cmd> ST`. The Scanner (below) splits a byte
// stream into terminal `passthru` and extracted `<cmd>` payloads; `build_apc` is the
// inverse. State persists across feed() calls so an APC split across reads reassembles.

const esc = u8(0x1b)
const apc_intro = u8(0x5f) // '_'
const st_bs = u8(0x5c) // '\'
const bel = u8(0x07)
const colon = u8(0x3a) // ':'
const prefix = 'shell-bucket:' // our APC payload prefix (string; `bprefix` tests it)
const prefix_bytes = prefix.bytes()

enum MState {
	ground
	esc
	apc
	apc_esc
}

// One label-swap routing entry. When a node relays a downstream request up,
// it assigns its OWN `next_id` and records this entry; the response carrying that id
// is routed back here. `fd` is the socket client (a local tool, or an `sb inject`
// conduit to a deeper host) awaiting the reply. `inner_id` is the caller's own
// request-id when the request arrived already `R<id>`-framed (a deeper host relaying
// through its conduit) -- the reply is re-framed `R<inner_id>:` back to it; or -1 when
// it arrived raw (a local tool fetch, or a deeper host's pre-mux bootstrap), in which
// case the reply goes back unframed. Each hop assigns its own id, so fan-out is
// disambiguated at every level (no shared depth, no ambiguity between sibling conduits).
struct Route {
mut:
	fd         int
	inner_id   int
	persistent bool   // a tunnel route: bidirectional + not deleted on reply
	clip       bool   // CLIP:GET / CLIP:SET: b64<->raw translation at socket boundary
	pid        int    // originating local client's kernel-attested PID (for `sb ctl` rpc inventory)
	desc       string // RPC name (verb before the first ':'); never the args, which may hold secrets
}

// One mux-session component for `sb ctl -v` / `sb ctl kill`: a relay (an `sb inject`
// conduit), a port (an `sb tunnel` client), or an rpc (a one-shot local route). `pid`
// is the kernel-attested peer PID -- the ONLY PIDs `sb ctl kill` will ever signal, so a
// client cannot ask the mux to kill an arbitrary process.
struct Comp {
	pid  int
	cat  string // 'relay' | 'port' | 'rpc'
	desc string
}

// inventory enumerates this mux's DIRECT local components (not deep ones carried over a
// relay -- those are killed by killing the relay, or by `sb ctl` after hopping down).
// relays/ports are socket clients; rpcs are non-persistent routes that a LOCAL client
// (inner_id == -1) originated.
fn inventory(clients []MuxClient, routes map[int]Route) []Comp {
	mut out := []Comp{}
	for cl in clients {
		if cl.conduit {
			out << Comp{
				pid:  cl.pid
				cat:  'relay'
				desc: cl.desc
			}
		} else if cl.tunnel_id >= 0 {
			out << Comp{
				pid:  cl.pid
				cat:  'port'
				desc: cl.desc
			}
		}
	}
	for _, rt in routes {
		if !rt.persistent && rt.inner_id == -1 {
			out << Comp{
				pid:  rt.pid
				cat:  'rpc'
				desc: rt.desc
			}
		}
	}
	return out
}

// select_kills resolves a kill `selector` (all|relays|ports|rpcs|<pid>) against the live
// inventory and returns the PIDs to signal. A non-empty `matchf` further requires the
// component's desc to contain it (a `--match=` filter, and a PID-reuse safeguard for a
// numeric selector). A numeric selector ONLY ever returns a PID that is actually in
// `comps` -- the safety gate that keeps `sb ctl kill` from signalling unlisted processes.
fn select_kills(comps []Comp, selector string, matchf string) []int {
	mut out := []int{}
	for c in comps {
		if c.pid <= 0 {
			continue
		}
		if matchf != '' && !c.desc.contains(matchf) {
			continue
		}
		hit := match selector {
			'all' { true }
			'relays' { c.cat == 'relay' }
			'ports' { c.cat == 'port' }
			'rpcs' { c.cat == 'rpc' }
			else { selector.int() > 0 && c.pid == selector.int() }
		}
		if hit && out.index(c.pid) < 0 {
			out << c.pid
		}
	}
	return out
}

// `R<id>:<rest>` -> (true, id, rest); (false, ...) if not a request-id frame.
fn parse_route(cmd []u8) (bool, int, []u8) {
	if cmd.len < 2 || cmd[0] != u8(0x52) { // 'R'
		return false, 0, []u8{}
	}
	mut i := 1
	mut id := 0
	for i < cmd.len && cmd[i] >= u8(0x30) && cmd[i] <= u8(0x39) {
		id = id * 10 + int(cmd[i] - u8(0x30))
		i++
	}
	if i == 1 || i >= cmd.len || cmd[i] != colon {
		return false, 0, []u8{}
	}
	return true, id, cmd[i + 1..].clone()
}

// Build the full APC `ESC _ shell-bucket:<cmd> ST`. The byte-stream APC carries NO
// token: the wire is trusted structurally (each mux strips our-prefix APCs from its
// forkpty child -- `strip-at-source`), so an our-prefix APC arriving from a mux's child
// is, by construction, one the mux itself emitted. The token lives only on the per-host
// Unix socket (the one authenticated channel).
fn build_apc(cmd []u8) []u8 {
	mut o := []u8{}
	o << esc
	o << apc_intro
	o << prefix_bytes
	o << cmd
	o << esc
	o << st_bs
	return o
}

// A streaming APC scanner. Splits a byte stream into `passthru` (terminal data +
// foreign APCs, forwarded verbatim) and `payloads` (the command part of each complete
// our-prefix APC, with `shell-bucket:` stripped). A node never rewrites a frame in
// place -- it extracts a payload and emits its own -- so a plain scanner is all each
// direction needs. State persists across feeds (an APC split over reads reassembles).
// Recognition is prefix-only: no token on the wire, so any `shell-bucket:`-prefixed
// APC is ours.
struct Scanner {
mut:
	state    MState = .ground
	buf      []u8   // bytes since ESC (candidate APC, incl. ESC _)
	passthru []u8   // non-our bytes (terminal + foreign APCs)
	payloads [][]u8 // extracted our-prefix APC payloads
}

fn (mut s Scanner) finish() {
	mut end := s.buf.len
	if s.buf.len >= 2 && s.buf[s.buf.len - 2] == esc && s.buf[s.buf.len - 1] == st_bs {
		end = s.buf.len - 2
	} else if s.buf.len >= 1 && s.buf[s.buf.len - 1] == bel {
		end = s.buf.len - 1
	}
	payload := s.buf[2..end]
	if bprefix(payload, prefix) {
		s.payloads << payload[prefix.len..].clone()
		s.buf = []u8{}
		s.state = .ground
		return
	}
	s.passthru << s.buf // foreign APC -> verbatim
	s.buf = []u8{}
	s.state = .ground
}

fn (mut s Scanner) feed_byte(b u8) {
	match s.state {
		.ground {
			if b == esc {
				s.state = .esc
				s.buf = [esc]
			} else {
				s.passthru << b
			}
		}
		.esc {
			if b == apc_intro {
				s.state = .apc
				s.buf << b
			} else {
				s.passthru << s.buf
				s.passthru << b
				s.buf = []u8{}
				s.state = .ground
			}
		}
		.apc {
			if b == bel {
				s.buf << b
				s.finish()
			} else if b == esc {
				s.state = .apc_esc
				s.buf << b
			} else {
				s.buf << b
			}
		}
		.apc_esc {
			if b == st_bs {
				s.buf << b
				s.finish()
			} else if b == esc {
				s.buf << b
			} else {
				s.buf << b
				s.state = .apc
			}
		}
	}
}

fn (mut s Scanner) feed_raw(buf &u8, n int) {
	for i in 0 .. n {
		s.feed_byte(unsafe { buf[i] })
	}
}

fn (mut s Scanner) feed(data []u8) {
	for b in data {
		s.feed_byte(b)
	}
}

fn (mut s Scanner) take_passthru() []u8 {
	p := s.passthru
	s.passthru = []u8{}
	return p
}

fn (mut s Scanner) take_payloads() [][]u8 {
	p := s.payloads
	s.payloads = [][]u8{}
	return p
}

fn read_all_fd(fd int) []u8 {
	mut acc := []u8{}
	mut chunk := [4096]u8{}
	for {
		n := C.read(fd, voidptr(&chunk[0]), usize(4096))
		if n <= 0 {
			break
		}
		for i in 0 .. int(n) {
			acc << chunk[i]
		}
	}
	return acc
}

// `sb __muxscan`: read stdin through the APC Scanner, write the split it produced --
// `T:<passthru>` then one `P:<payload>` per extracted our-prefix APC. A deterministic,
// pty-free hook for unit-testing the scanner.
@[noreturn]
fn run_muxscan() {
	mut s := Scanner{}
	s.feed(read_all_fd(0))
	mut out := []u8{}
	pt := s.take_passthru()
	if pt.len > 0 {
		out << 'T:'.bytes()
		out << pt
		out << u8(0x0a)
	}
	for pl in s.take_payloads() {
		out << 'P:'.bytes()
		out << pl
		out << u8(0x0a)
	}
	if out.len > 0 {
		write_all(1, unsafe { &out[0] }, i64(out.len))
	}
	C._exit(0)
}

// ----- FILEREQ client ----------------------------------------------------
//
// The protocol transaction, in V (replacing the bash __sb_fetch / __s2_fetch):
// emit `APC shell-bucket:<token>:FILEREQ:<name>:mtime=<m>:os=<o>:arch=<a> ST`
// to stdout (the upstream byte stream -- the parent mux wraps it M:0), read the
// `~EOF`-terminated base64 response from stdin (echo off), decode, and write the
// cache file (chmod + mtime). Used by `sb fetch`/`run`, symlink dispatch, and
// `sb mux`'s own manifest/runtime fetch.

const fr_eof = 0
const fr_notchanged = 1
const fr_err = 2

// Toggle terminal ECHO (c_lflag bit 0x8, at termios offset 12 -- stable across
// Linux arches) so the response bytes aren't echoed during the read.
fn set_echo(fd int, on bool) {
	if C.isatty(fd) != 1 {
		return
	}
	mut t := [64]u8{}
	if C.tcgetattr(fd, voidptr(&t[0])) != 0 {
		return
	}
	unsafe {
		p := &u32(voidptr(&t[12]))
		if on {
			*p = *p | u32(8)
		} else {
			*p = *p & ~u32(8)
		}
	}
	C.tcsetattr(fd, 0, voidptr(&t[0])) // TCSANOW
}

// Read one '\n'-terminated line from fd (byte-by-byte, so we never over-read
// past the response into the user's subsequent input). Returns (line, ok);
// ok=false only at EOF with nothing buffered.
fn read_line(fd int) (string, bool) {
	mut acc := []u8{}
	mut c := [1]u8{}
	for {
		n := C.read(fd, voidptr(&c[0]), usize(1))
		if n <= 0 {
			if acc.len == 0 {
				return '', false
			}
			break
		}
		if c[0] == u8(0x0a) {
			break
		}
		acc << c[0]
	}
	return acc.bytestr(), true
}

fn apply_chmod(path string, spec string) {
	if spec.contains('x') && !spec[0].is_digit() {
		os.chmod(path, 0o755) or {}
	} else if spec.len > 0 && spec[0].is_digit() {
		os.chmod(path, int(('0o' + spec).u32())) or {}
	}
}

fn set_mtime(path string, mtime i64) {
	mut tv := [2]i64{}
	tv[0] = mtime
	tv[1] = mtime
	C.utime(path.str, voidptr(&tv[0]))
}

// Emit `APC shell-bucket:<cmd> ST` to `out_fd` (the upstream byte stream; the parent
// mux wraps it). Usually stdout (fd 1); bare `sb` uses /dev/tty so the request isn't
// swallowed by `$(sb)`'s stdout capture. `cmd` is the full command after the prefix.
fn emit_request(out_fd int, cmd string) {
	req := build_apc(cmd.bytes())
	write_all(out_fd, unsafe { &req[0] }, i64(req.len))
}

// Read a `~EOF`-terminated response from `fd`, returning (status, base64-body).
// The socket variant of the FILEREQ response read (no tty echo handling) -- used by
// `sb inject` to fetch the bootstrap (`BOOT`) over the mux socket. Accumulates into
// a []u8 (amortized O(1)), not a `string +=` (O(n2) on MB payloads).
fn read_resp_b64(fd int) (int, string) {
	mut b64 := []u8{}
	mut status := -1
	for {
		line, ok := read_line(fd)
		if !ok {
			break
		}
		if line.starts_with('~EOF') {
			status = fr_eof
			break
		} else if line.starts_with('~ERR') {
			status = fr_err
			break
		} else {
			b64 << line.bytes()
		}
	}
	return status, b64.bytestr()
}

// Read a FILEREQ response from `fd` -- each base64 body line decoded + appended to
// `f` as it arrives (O(1) memory regardless of payload size; per-line decode is
// exact because the wire wraps base64 at 76 chars, a multiple of 4) -- until a
// control token. Returns (status, chmod_spec, mtime). Transport-agnostic: `fd` is
// the byte stream (fd 0) or an mux socket.
fn read_fileresp(fd int, mut f os.File) (int, string, i64) {
	mut chmod_spec := ''
	mut new_mtime := i64(0)
	mut status := -1
	for {
		line, ok := read_line(fd)
		if !ok {
			break
		}
		if line.starts_with('~EOF') {
			for fl in line.all_after('~EOF').trim_space().split(' ') {
				if fl.starts_with('chmod=') {
					chmod_spec = fl.all_after('chmod=')
				} else if fl.starts_with('mtime=') {
					new_mtime = fl.all_after('mtime=').i64()
				}
			}
			status = fr_eof
			break
		} else if line.starts_with('~ERR NOT_CHANGED') {
			status = fr_notchanged
			break
		} else if line.starts_with('~ERR') {
			status = fr_err
			break
		} else {
			// A malformed body line means the stream desynced (e.g. terminal input
			// raced a pre-pump fetch) -- fail the fetch cleanly rather than crash.
			decoded := b64_decode(line) or {
				status = fr_err
				break
			}
			f.write(decoded) or {
				status = fr_err
				break
			}
		}
	}
	return status, chmod_spec, new_mtime
}

// b64_decode wraps base64.decode SAFELY. V's stdlib indexes a 123-entry table by
// the raw input byte with no bounds check, so any byte >= 123 (`{` `|` `}` `~`,
// UTF-8, ...) -- or other non-base64 input from a desynced/malformed stream -- panics
// the whole process. We validate first and return none, so a protocol reader can
// reject a bad frame instead of crashing. (Valid base64 only uses `A`-`Z`/`a`-`z`/
// `0`-`9`/`+`/`/`/`=`, all <= 122, so this never rejects well-formed input.)
fn b64_decode(s string) ?[]u8 {
	for c in s {
		if !((c >= `A` && c <= `Z`) || (c >= `a` && c <= `z`)
			|| (c >= `0` && c <= `9`) || c == `+` || c == `/` || c == `=`) {
			return none
		}
	}
	return base64.decode(s)
}

// Run one FILEREQ transaction, streaming the response to `outpath.partial` then
// atomically renaming. `prefer_socket` (the `sb fetch`/`run`/symlink tools) routes
// the request over the per-host **mux socket** when one is up -- the mux relays
// it up the byte stream with a request-id and routes the reply back -- falling back
// to the tty protocol (emit the APC to fd 1, read fd 0) when there's no socket. The
// mux's own pre-pump fetches pass `prefer_socket=false` (they ARE the byte stream).
fn filereq(token string, name string, cached_mtime i64, os_name string, arch string, outpath string, prefer_socket bool) int {
	mut cmd := 'FILEREQ:${name}:mtime=${cached_mtime}'
	if os_name != '' {
		cmd += ':os=${os_name}'
	}
	if arch != '' {
		cmd += ':arch=${arch}'
	}

	dir := os.dir(outpath)
	if dir != '' {
		os.mkdir_all(dir) or {}
	}
	part := outpath + '.partial'
	mut f := os.create(part) or { return fr_err }

	mut status := -1
	mut chmod_spec := ''
	mut new_mtime := i64(0)
	sockfd := if prefer_socket { mux_sock_request(token, cmd) } else { -1 }
	if sockfd >= 0 {
		status, chmod_spec, new_mtime = read_fileresp(sockfd, mut f)
		C.close(sockfd)
	} else {
		emit_request(1, cmd)
		set_echo(0, false)
		status, chmod_spec, new_mtime = read_fileresp(0, mut f)
		set_echo(0, true)
	}
	f.close()

	if status == fr_eof {
		if chmod_spec != '' {
			apply_chmod(part, chmod_spec)
		}
		os.mv(part, outpath) or { return fr_err }
		if new_mtime > 0 {
			set_mtime(outpath, new_mtime)
		}
		return fr_eof
	}
	os.rm(part) or {}
	return status
}

// ----- manifest + os/arch resolution -------------------------------------
//
// `sb-manifest` is a bucket file the wrapper regenerates on connect: one TSV
// line per bucket file -- `<path>\t<mtime>\t<flags>` (flags carries `x` for
// executable). `sb mux` fetches it once at startup; `sb run/fetch` then resolves
// a name against the cached manifest entirely on-target (no wire mtime
// negotiation): the manifest mtime is the version id.

struct ManifestEntry {
	mtime i64
	exec  bool
	link  string // non-empty: this path is an in-bucket symlink -> this terminal path
	// (busybox-style dedup; the wrapper pre-flattened the chain). mtime/exec
	// describe the terminal. We fetch the terminal once and materialize the
	// link locally -- never fetch the link's own bytes.
}

fn norm_os(s string) string {
	return s.to_lower()
}

fn norm_arch(s string) string {
	return match s {
		'x86_64', 'amd64' { 'amd64' }
		'aarch64', 'arm64' { 'arm64' }
		else { s }
	}
}

fn parse_manifest(text string) map[string]ManifestEntry {
	mut m := map[string]ManifestEntry{}
	for line in text.split_into_lines() {
		if line.trim_space() == '' {
			continue
		}
		parts := line.split('\t')
		if parts.len < 2 {
			continue
		}
		m[parts[0]] = ManifestEntry{
			mtime: parts[1].i64()
			exec:  parts.len >= 3 && parts[2].contains('x')
			link:  if parts.len >= 4 { parts[3] } else { '' }
		}
	}
	return m
}

// Resolve `name` (for this host's os/arch) to a bucket path present in the
// manifest, most-specific first: <os>_<arch>/name -> <os>/name -> name. Returns
// (ok, path, entry).
fn resolve_manifest(m map[string]ManifestEntry, name string, os_name string, arch string) (bool, string, ManifestEntry) {
	mut cands := []string{}
	if os_name != '' && arch != '' {
		cands << '${norm_os(os_name)}_${norm_arch(arch)}/${name}'
	}
	if os_name != '' {
		cands << '${norm_os(os_name)}/${name}'
	}
	cands << name
	for c in cands {
		if c in m {
			return true, c, m[c]
		}
	}
	return false, '', ManifestEntry{}
}

// ----- fetch / run / dispatch --------------------------------------------
//
// `sb run <name>` / `sb fetch <name>` / symlink-dispatch all resolve `<name>`
// against the cached manifest (for this host's os/arch), use the cache if its
// mtime matches the manifest's, else fetch the exact resolved path. Env carries
// the session context the mux exported: SB_TOKEN, SB_CACHE, SB_OS, SB_ARCH.

fn sb_cache() string {
	c := os.getenv('SB_CACHE')
	if c != '' {
		return c
	}
	return os.getenv('HOME') + '/.cache/shell-bucket'
}

fn host_os() string {
	e := os.getenv('SB_OS')
	return if e != '' { e } else { os.uname().sysname }
}

fn host_arch() string {
	e := os.getenv('SB_ARCH')
	return if e != '' { e } else { os.uname().machine }
}

// This mux's identity for a SURVEY reply -- host/os/arch/pid (colons OK; it's the
// tail field of the `SURVEYR` frame).
fn node_identity() string {
	host := os.hostname() or { 'unknown' }
	return 'host=${host}:os=${host_os()}:arch=${host_arch()}:pid=${C.getpid()}'
}

// Handle a source-routed PUSH that reached its target node (this mux) -- a local op the
// mux answers about/on its own host. Returns the response body for `PUSHR`:
//   PING  -> PONG:<identity>   (reachability + identity of the addressed node)
fn push_local(cmd string) string {
	if cmd == 'PING' {
		return 'PONG:${node_identity()}'
	}
	return 'ERR:unknown push cmd: ${cmd}'
}

// `sb mux` reuses a cached manifest this recent (seconds) rather than refetching
// -- deduping the bootstrap burst (`sb fetch sb` / `sb run tmux` just fetched it)
// into a single transfer. Uses ctime (the target-local write time, updated by our
// own write/set_mtime) -- NOT mtime, which carries the wrapper's clock and is
// meaningless across hosts.
const manifest_max_age = i64(60)

// True if a cached manifest exists and is younger than `manifest_max_age`.
fn manifest_fresh(mpath string) bool {
	if st := os.stat(mpath) {
		return C.time(unsafe { nil }) - st.ctime <= manifest_max_age
	}
	return false
}

// The cached manifest text, fetching it first if it isn't present. `sb mux`
// fetches it (subject to the freshness window) at startup, so at session time
// this just reads the cache; before that (e.g. the tmux prologue's `sb run tmux`,
// which runs pre-mux) it populates the manifest on demand -- so resolution is
// ALWAYS manifest-driven, with the manifest as the single authority. '' on failure.
fn ensure_manifest(prefer_socket bool) string {
	mpath := '${sb_cache()}/sb-manifest'
	return os.read_file(mpath) or {
		st := filereq(os.getenv('SB_TOKEN'), 'sb-manifest', 0, '', '', mpath, prefer_socket)
		if st == fr_eof || st == fr_notchanged {
			os.read_file(mpath) or { '' }
		} else {
			eprintln('sb: manifest unavailable')
			''
		}
	}
}

// Fetch the exact bucket `path` into `cp` if absent or older than `mtime` (the
// manifest version id), and stamp it. Returns true on a present+current file.
// Unlike ensure_cached this takes an ALREADY-RESOLVED path (no os/arch fallback)
// -- used to materialize a symlink's terminal, which the wrapper pre-resolved.
fn ensure_terminal(path string, cp string, mtime i64, prefer_socket bool) bool {
	local := if !os.is_link(cp) && os.exists(cp) { i64(os.file_last_mod_unix(cp)) } else { i64(-1) }
	if local >= mtime {
		if local != mtime {
			set_mtime(cp, mtime)
		}
		return true
	}
	st := filereq(os.getenv('SB_TOKEN'), path, 0, '', '', cp, prefer_socket)
	if st == fr_eof || st == fr_notchanged {
		set_mtime(cp, mtime)
		return true
	}
	return false
}

// Ensure the cache file for `name` is present and current; return its path, or
// '' on failure. Resolution is manifest-driven (the manifest is auto-populated
// by ensure_manifest if absent); freshness is the manifest mtime as version id.
fn ensure_cached(name string, prefer_socket bool) string {
	cache := sb_cache()
	mtext := ensure_manifest(prefer_socket)
	if mtext == '' {
		return ''
	}
	ok, path, ent := resolve_manifest(parse_manifest(mtext), name, host_os(), host_arch())
	if !ok {
		eprintln('sb: ${name}: not in manifest')
		return ''
	}
	// Busybox-style symlink: the wrapper flattened the chain to `ent.link` (the
	// terminal bucket path) and stamped this entry with the TERMINAL's mtime/exec.
	// Fetch the terminal ONCE into its own cache slot, then materialize a local
	// symlink (named `path`, so argv[0]'s basename drives the multi-call applet
	// dispatch on exec) -> it. No link bytes ride the wire; N applets share 1 copy.
	if ent.link != '' {
		tcp := '${cache}/${ent.link}'
		if !ensure_terminal(ent.link, tcp, ent.mtime, prefer_socket) {
			eprintln('sb: ${name}: terminal ${ent.link} fetch failed')
			return ''
		}
		cp := '${cache}/${path}'
		// Point cp -> terminal iff it isn't already that exact link (idempotent;
		// re-runs are a no-op). os.symlink can't overwrite, so clear cp first.
		if !(os.is_link(cp) && os.real_path(cp) == os.real_path(tcp)) {
			dir := os.dir(cp)
			if dir != '' {
				os.mkdir_all(dir) or {}
			}
			os.rm(cp) or {}
			os.symlink(tcp, cp) or {
				eprintln('sb: ${name}: cannot link -> ${ent.link}')
				return ''
			}
		}
		return cp
	}
	// The binary itself caches FLAT ($SB_CACHE/sb) -- where the shell bootstrap
	// writes it, `sb mux` execs from, and the dispatch symlink points -- not under
	// the arch subdir like other files. (The manifest still resolves its version.)
	cp := if name == 'sb' { '${cache}/sb' } else { '${cache}/${path}' }
	// A `->sb` placeholder (prune_cache demoted a stale binary) counts as not-present:
	// force a fresh fetch, which atomically renames the real binary over the symlink.
	local := if !os.is_link(cp) && os.exists(cp) { i64(os.file_last_mod_unix(cp)) } else { i64(-1) }
	if local >= ent.mtime {
		// Present and at least as new as the manifest version -> current. A
		// shell-bootstrapped sb has mtime=now (ahead of the manifest, which never
		// set it); align the stamp so later checks are exact equality, and don't
		// re-download. Files sb fetched already carry the manifest mtime, so this
		// fixup only ever fires for the shell-bootstrapped binary.
		if local != ent.mtime {
			set_mtime(cp, ent.mtime)
		}
		return cp
	}
	// Absent (-1) or genuinely older than the manifest version: (re)fetch the
	// resolved arch path INTO cp (flat for the binary).
	st := filereq(os.getenv('SB_TOKEN'), path, 0, '', '', cp, prefer_socket)
	if st == fr_eof || st == fr_notchanged {
		set_mtime(cp, ent.mtime) // align cache mtime to the manifest version id
		return cp
	}
	eprintln('sb: ${name}: fetch failed')
	return ''
}

@[noreturn]
fn run_tool(name string, args []string) {
	cp := ensure_cached(name, true) // child tool -> prefer the mux socket
	if cp == '' {
		C._exit(127)
	}
	mut cargv := []charptr{}
	cargv << cp.str
	for a in args {
		cargv << a.str
	}
	cargv << charptr(0)
	C.execvp(cp.str, voidptr(cargv.data))
	C._exit(127)
}

// `sb fetch <name>`: ensure the file is cached (exit 0/1 says whether), and print
// its cache path. The path goes to STDERR, not stdout: stdout is the live
// protocol channel (the FILEREQ APC rides it up to the wrapper), so a caller that
// captured stdout -- `x=$(sb fetch foo)` -- would swallow the request and hang.
// Scripts use the exit status + the known cache layout instead.
@[noreturn]
fn run_fetch(name string) {
	cp := ensure_cached(name, true) // child tool -> prefer the mux socket
	if cp == '' {
		C._exit(1)
	}
	eprintln(cp)
	C._exit(0)
}

// ----- mux startup wiring -------------------------------------------------
//
// At `sb mux` startup (once per hop) we stand up the on-target session
// environment the rest of the protocol leans on: fetch the freshness oracle
// (`sb-manifest`) and this shell's runtime, populate a PATH dir of busybox-style
// dispatch symlinks (one per helper, plus `sb` itself, all -> the sb binary), and
// export the session context. The bootstrap stays minimal -- it only fetches the
// binary and execs us; everything else happens here, in V, with the FILEREQ client.

fn family_of(shell string) string {
	base := shell.all_after_last('/')
	if base.ends_with('bash') {
		return 'bash'
	}
	if base.contains('ksh') {
		return 'ksh'
	}
	if base.ends_with('zsh') {
		return 'zsh'
	}
	return 'bash'
}

// Populate `bindir` with a symlink per dispatchable helper (+ `sb`) -> `self`,
// pruning links no longer in the manifest. Pure given the manifest text (no
// network): the dispatch set is every executable entry's basename, excluding
// `sb`, the `sb-*` runtimes, and the (sourced, non-exec) rc.d fragments. Mirrors
// the wrapper-side `Bucket.alias_names` selection.
//
// Prune BEFORE create: `os.ls` reliably enumerates the directory as a prior
// session left it, but (a static-musl/`-gc none` quirk) under-reports entries
// created via `os.symlink` earlier in the *same* process -- so we never re-list
// after creating. Reconnects see the previous session's links via os.ls; the
// single mux_setup call per session never lists its own fresh links.
fn populate_bin(bindir string, self string, manifest_text string) {
	os.mkdir_all(bindir) or {}
	mut want := map[string]bool{}
	want['sb'] = true
	for name, ent in parse_manifest(manifest_text) {
		if !ent.exec || name.starts_with('rc.d/') {
			continue
		}
		base := name.all_after_last('/')
		// `sb` is the autoviv TARGET every symlink points to (already in `want`); skip
		// re-adding it. Everything else executable and not under `rc.d/` is a dispatchable
		// command -- including `sb-*` SCRIPTS like the `sb-tmux.sh` launcher, so
		// `sb mux --exec=sb-tmux.sh` needs no special handling. The non-exec runtimes
		// (`sb-*.rc`) and the manifest are already excluded by `!ent.exec` above.
		if base == 'sb' {
			continue
		}
		want[base] = true
	}
	for e in (os.ls(bindir) or { []string{} }) {
		if e !in want {
			os.rm('${bindir}/${e}') or {}
		}
	}
	for base, _ in want {
		link := '${bindir}/${base}'
		os.rm(link) or {}
		os.symlink(self, link) or {}
	}
}

// Collect cache files (+ symlinks) under `dir` as paths relative to `root`. Real
// subdirs are recursed (not symlinked dirs); the `bin/` dispatch dir is skipped --
// `populate_bin` owns it.
fn walk_cache(dir string, root string, mut out []string) {
	for e in (os.ls(dir) or { return }) {
		full := '${dir}/${e}'
		rp := full[root.len + 1..]
		if rp == 'bin' {
			continue
		}
		if os.is_dir(full) && !os.is_link(full) {
			walk_cache(full, root, mut out)
		} else {
			out << rp
		}
	}
}

// Atomically replace the file at `cp` with a symlink -> `self` (the sb binary): make
// the link at a temp name, then rename it over `cp`. The rename is atomic on the
// cache fs, so a local tool reading the path during a mux reconnect never sees it
// absent -- it sees either the old binary or the placeholder, never nothing.
fn demote_to_symlink(cp string, self string) {
	tmp := '${cp}.demote'
	os.rm(tmp) or {}
	os.symlink(self, tmp) or { return }
	os.mv(tmp, cp) or { os.rm(tmp) or {} }
}

// Reconcile the cache against the manifest at manifest-load (mux startup) -- WITHOUT
// fetching anything (binaries refetch lazily, atomically, via `ensure_cached` on
// next use). For each cached entry (excluding the binary/manifest/runtime and the
// `bin/` symlinks):
//   - upstream-deleted (not in manifest) -> remove, binary OR not (it's gone).
//   - in-manifest, executable, and STALE (cache mtime < manifest version) -> demote
//     atomically to a `->sb` placeholder, so it refetches fresh on next use.
//   - already a placeholder, current, or a merely-stale NON-binary -> left alone.
//
// The binary/non-binary asymmetry is the crux, NOT incidental: a stale binary can be
// demoted because it **autovivifies** -- the next dispatch hits the `->sb` placeholder
// and refetches before exec, so demotion can't break an in-flight script. A
// non-binary can't autovivify (nothing re-fetches it on read), so deleting a
// merely-stale one would break the race where a script does `sb fetch <file>`, does
// work, then reads `<file>` -- if a manifest refresh fired during "does work" and we
// yanked it, the read fails. So a stale-but-present non-binary is LEFT on disk; it
// refreshes at the script's next `sb fetch` checkpoint or manually. (Upstream-deleted
// is different: it's gone from the bucket, so removing it is correct either way.)
fn prune_cache(cache string, manifest_text string, self string) {
	m := parse_manifest(manifest_text)
	mut files := []string{}
	walk_cache(cache, cache, mut files)
	for rp in files {
		// `sb` (cached flat, never at the arch path) is the autovivify TARGET every
		// placeholder symlinks to, so it can NEVER itself become a placeholder --
		// demoting it would orphan every other helper. Its own staleness is fixed by
		// a REFETCH, not a demote: the bootstrap runs `sb fetch sb` (-> ensure_cached,
		// which loads the manifest and refetches a stale sb) right before `exec sb
		// mux`, so the fresh binary runs this session. `sb-manifest`/`sb.rc` are the
		// manifest + runtime, managed by mux_setup. All four are skipped here.
		if rp == 'sb' || rp == 'sb-manifest' || rp == 'sb.rc' {
			continue
		}
		cp := '${cache}/${rp}'
		if rp !in m {
			os.rm(cp) or {} // upstream-deleted -> remove (binary or not)
			continue
		}
		if os.is_link(cp) {
			continue // a current placeholder -- refetches on use
		}
		ent := m[rp]
		if ent.exec && i64(os.file_last_mod_unix(cp)) < ent.mtime {
			demote_to_symlink(cp, self) // stale binary -> placeholder
		}
	}
}

// Fetch manifest + runtime, populate the dispatch dir, prepend it to PATH, and
// export the session context for the child shell and dispatched `sb` calls.
// Returns the runtime path to hand the shell as its rcfile ('' if unavailable).
fn mux_setup(shell string) string {
	token := os.getenv('SB_TOKEN')
	cache := sb_cache()
	os.mkdir_all(cache) or {}

	// Resolve os/arch once and export, so dispatched `sb` and children agree
	// (and skip re-running uname); SB_CACHE too, for the same reason.
	o := host_os()
	a := host_arch()
	C.setenv(c'SB_OS', o.str, 1)
	C.setenv(c'SB_ARCH', a.str, 1)
	C.setenv(c'SB_CACHE', cache.str, 1)

	// The freshness oracle. Refetch unless the bootstrap (`sb fetch sb`, or
	// `sb-tmux.sh`'s `sb run tmux`) just fetched it within the freshness window --
	// then reuse, so it transfers once per connect. (Our own binary was already
	// reconciled by `sb fetch sb` BEFORE this mux was exec'd, so the FRESH sb runs
	// as mux this session.)
	mpath := '${cache}/sb-manifest'
	if !manifest_fresh(mpath) {
		filereq(token, 'sb-manifest', 0, '', '', mpath, false) // mux: tty, not socket
	}

	// This shell's runtime, used as its rcfile (agnostic path; resolved exactly).
	rcpath := '${cache}/sb.rc'
	filereq(token, 'sb-${family_of(shell)}.rc', 0, '', '', rcpath, false)

	// Dispatch symlinks + PATH. The binary is where the bootstrap placed us.
	bindir := '${cache}/bin'
	mtext := os.read_file('${cache}/sb-manifest') or { '' }
	populate_bin(bindir, '${cache}/sb', mtext)
	// Reconcile the cache against the (just-loaded) manifest -- demote stale binaries
	// to placeholders, drop upstream-deleted ones. No fetching here; binaries refetch
	// lazily + atomically via ensure_cached on next use.
	prune_cache(cache, mtext, '${cache}/sb')
	oldpath := os.getenv('PATH')
	newpath := if oldpath != '' { '${bindir}:${oldpath}' } else { bindir }
	C.setenv(c'PATH', newpath.str, 1)

	return if os.exists(rcpath) { rcpath } else { '' }
}

// ----- mux side-band: per-host unix socket -------------------------

// Constant-time byte-slice equality -- the standard cryptographic idiom: accumulate
// `diff |= a[i] ^ b[i]` over a fixed length (no early exit, no data-dependent
// branch), then one `diff == 0`. The socket bearer-auth faces a *local* attacker
// who can measure timing, so the secret compare must not early-exit. `@[noinline]`
// keeps a caller from folding the loop; if a toolchain bump ever shortcuts it,
// verify the disassembly / add a volatile barrier. Length mismatch -> not equal
// (the length isn't secret).
@[noinline]
fn ct_eq(a []u8, b []u8) bool {
	if a.len != b.len {
		return false
	}
	mut diff := u8(0)
	for i in 0 .. a.len {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// The mux socket path: $TMPDIR (or /tmp) + `sb-<locator>`, where the locator is the
// token's `:`-delimited prefix (per-host collision-avoidance only; no secrecy).
fn mux_sock_path(token string) string {
	mut tmp := os.getenv('TMPDIR')
	if tmp == '' {
		tmp = '/tmp'
	}
	tmp = tmp.trim_right('/')
	return '${tmp}/sb-${token.all_before(':')}'
}

// The bearer secret: the token's `:`-delimited suffix.
fn token_secret(token string) string {
	return token.all_after(':')
}

// Mint a fresh per-host token: 21 random bytes -> 28 Base64URL chars, of which
// we keep 24, formatted `<locator>:<secret>` -- a 6-char locator, a `:`, and an 18-char
// ~108-bit secret. Each `sb mux` mints its own when none is supplied via arg, so every
// host names a UNIQUE socket and the secret is the sole bearer authenticator. (Base64URL
// never yields `.` or `/`, so the locator is always a valid non-hidden filename
// component for `sb-<locator>`; the `:` is a delimiter only, never inside either part.)
fn make_token() string {
	fd := C.open(c'/dev/urandom', 0) // O_RDONLY
	if fd < 0 {
		die('cannot open /dev/urandom to mint mux token')
	}
	mut b := [21]u8{}
	mut got := 0
	for got < 21 {
		n := C.read(fd, voidptr(&b[got]), usize(21 - got))
		if n <= 0 {
			break
		}
		got += int(n)
	}
	C.close(fd)
	if got < 21 {
		die('short read from /dev/urandom minting mux token')
	}
	enc := base64.url_encode(b[..]) // 21 bytes -> 28 chars, no padding
	return '${enc[..6]}:${enc[6..24]}' // <locator>:<secret>
}

// A well-formed token is `<locator>:<secret>` with both parts non-empty (the `sb
// token` rebind validates the requested token before adopting it).
fn valid_token(t string) bool {
	return t.contains(':') && t.all_before(':') != '' && t.all_after(':') != ''
}

// Create + bind + chmod + listen a 0600 Unix socket at `path` (clearing any stale
// one first). Returns the listen fd, or -1. Shared by the initial bind and the
// `sb token` rebind. SOCK_CLOEXEC so a forkpty child never inherits the listen fd.
fn bind_listen(path string) int {
	fd := C.socket(af_unix, sock_stream | sock_cloexec, 0)
	if fd < 0 {
		return -1
	}
	C.unlink(path.str)
	mut sa := sockaddr_for(path)
	if C.bind(fd, voidptr(&sa), u32(sizeof(SockaddrUn))) != 0 {
		C.close(fd)
		return -1
	}
	C.chmod(path.str, sock_mode)
	if C.listen(fd, somaxconn) != 0 {
		C.close(fd)
		return -1
	}
	return fd
}

// Adopt a new token (the `sb token` command): close + unlink the old listen socket,
// bind the new locator's path, and return the (lfd, path, secret) the mux switches to
// so its socket follows the token. Old `secret` stays valid only until this returns;
// new clients then authenticate against the new one.
fn rebind_socket(old_lfd int, old_path string, newtok string) (int, string, []u8) {
	if old_lfd >= 0 {
		C.close(old_lfd)
		C.unlink(old_path.str)
	}
	newpath := mux_sock_path(newtok)
	return bind_listen(newpath), newpath, token_secret(newtok).bytes()
}

// Fill a sockaddr_un for `path` (nul-terminated, truncated to fit sun_path).
fn sockaddr_for(path string) SockaddrUn {
	mut a := SockaddrUn{
		sun_family: u16(af_unix)
	}
	pb := path.bytes()
	n := if pb.len < 107 { pb.len } else { 107 }
	for i in 0 .. n {
		a.sun_path[i] = pb[i]
	}
	a.sun_path[n] = 0
	return a
}

// Connect to the mux socket; the fd, or -1 if unreachable.
fn mux_sock_connect(path string) int {
	fd := C.socket(af_unix, sock_stream, 0)
	if fd < 0 {
		return -1
	}
	mut a := sockaddr_for(path)
	if C.connect(fd, voidptr(&a), u32(sizeof(SockaddrUn))) != 0 {
		C.close(fd)
		return -1
	}
	return fd
}

// Connect to the per-host mux socket, bearer-auth, and send `cmd` as a request;
// returns the fd ready for the caller to read the response, or -1 if the socket is
// unreachable or rejects auth (the caller falls back to the tty protocol).
fn mux_sock_request(token string, cmd string) int {
	fd := mux_sock_connect(mux_sock_path(token))
	if fd < 0 {
		return -1
	}
	write_str(fd, '${token_secret(token)}\n')
	ok_line, ok := read_line(fd)
	if !ok || ok_line != 'OK' {
		C.close(fd)
		return -1
	}
	write_str(fd, '${cmd}\n')
	return fd
}

fn write_str(fd int, s string) {
	mut b := s.bytes()
	if b.len > 0 {
		write_all(fd, unsafe { &b[0] }, i64(b.len))
	}
}

// `sb __muxserve` (self-test): bring up the mux socket and run a minimal
// auth+echo loop -- accept a client, read its secret line, constant-time-check it,
// then echo subsequent lines (until `__quit`, which unlinks + exits). Exercises the
// socket + bearer-auth + roundtrip (and the `TOKEN:` rebind) in isolation, pty-free.
// (Not marked @[noreturn]: it loops forever / `_exit`s, but V's analyzer doesn't
// recognize the nested accept loop as infinite.)
fn run_mux_serve() {
	token := os.getenv('SB_TOKEN')
	if token == '' {
		die('SB_TOKEN not set')
	}
	mut path := mux_sock_path(token)
	mut secret := token_secret(token).bytes()

	mut fd := bind_listen(path)
	if fd < 0 {
		die('bind ${path} failed')
	}
	for {
		cfd := C.accept(fd, unsafe { nil }, unsafe { nil })
		if cfd < 0 {
			continue
		}
		presented, ok := read_line(cfd) // auth: first line is the presented secret
		if !ok || !ct_eq(presented.bytes(), secret) {
			C.close(cfd) // reject -- no OK
			continue
		}
		write_str(cfd, 'OK\n')
		for {
			line, lok := read_line(cfd)
			if !lok {
				C.close(cfd)
				break
			}
			if line == '__quit' {
				C.close(cfd)
				C.unlink(path.str)
				C._exit(0)
			}
			// `TOKEN:<tok>` (empty -> randomize): rebind the socket to the new token's
			// locator and adopt its secret, then reply `OK:<effective-token>`. Exercises
			// the same rebind the real mux uses for `sb token` (reconnect).
			if line.starts_with('TOKEN:') {
				req := line.all_after('TOKEN:')
				newtok := if req == '' { make_token() } else { req }
				if !valid_token(newtok) {
					write_str(cfd, 'ERR bad-token\n')
					continue
				}
				fd, path, secret = rebind_socket(fd, path, newtok)
				write_str(cfd, 'OK:${newtok}\n')
				continue
			}
			// STATUS: return a minimal canned response (exercises the wire format
			// round-trip via sb ctl without needing a live pump + pty).
			if line == 'STATUS' {
				write_str(cfd, 'depth:0\nuptime_ms:5000\nmain_rx_bytes:100\nmain_tx_bytes:200\npty_rx_bytes:50\npty_tx_bytes:20\nbh_state:inactive\nclients:1\nports:0\nrelays:0\nrpcs:0\n~END\n')
				continue
			}
			// BH:DOWN / BH:UP: just echo OK (real logic lives in the pump).
			if line.starts_with('BH:') {
				write_str(cfd, 'OK\n')
				continue
			}
			// COMPS: canned inventory -- one of each category (exercises the `-v` /
			// `kill` table wire without a live pump). PID 0 -> never actually signalled.
			if line == 'COMPS' {
				write_str(cfd, 'comp\t0\trelay\tssh bastion\ncomp\t0\tport\tbind:127.0.0.1:8080:all\ncomp\t0\trpc\tFILEREQ\n~END\n')
				continue
			}
			// KILL: echo back a canned killed-row table (PID 0 -> no real signal sent).
			if line.starts_with('KILL:') {
				write_str(cfd, 'killed\t0\trpc\tFILEREQ\n~END\n')
				continue
			}
			// CLIP:GET: return "hello" using the binary socket protocol (OK\n + len + raw).
			if line == 'CLIP:GET' {
				payload := 'hello'.bytes()
				dlen := u32(payload.len)
				mut lb := [4]u8{}
				lb[0] = u8(dlen >> 24)
				lb[1] = u8(dlen >> 16)
				lb[2] = u8(dlen >> 8)
				lb[3] = u8(dlen)
				write_str(cfd, 'OK\n')
				write_all(cfd, unsafe { &lb[0] }, 4)
				write_all(cfd, unsafe { &payload[0] }, i64(payload.len))
				continue
			}
			// CLIP:SET: read 4-byte length + raw payload, discard, reply OK.
			if line == 'CLIP:SET' {
				mut lb := [4]u8{}
				mut rem := i64(4)
				mut off := i64(0)
				for rem > 0 {
					n := C.read(cfd, voidptr(unsafe { &lb[off] }), usize(rem))
					if n <= 0 {
						break
					}
					off += n
					rem -= n
				}
				mut dlen2 := i64((u32(lb[0]) << 24) | (u32(lb[1]) << 16) | (u32(lb[2]) << 8) | u32(lb[3]))
				mut disc := [4096]u8{}
				for dlen2 > 0 {
					want := if dlen2 < 4096 { dlen2 } else { i64(4096) }
					n := C.read(cfd, voidptr(&disc[0]), usize(want))
					if n <= 0 {
						break
					}
					dlen2 -= n
				}
				write_str(cfd, 'OK\n')
				continue
			}
			write_str(cfd, '${line}\n') // echo
		}
	}
}

// Collect a `~END`-terminated tab-separated table from the mux socket (the reply to
// COMPS or KILL): each line is `<tag>\t<pid>\t<cat>\t<desc>`. Returns the rows as
// [pid, cat, desc] triples (the tag is dropped). Used by `sb ctl -v` and `kill`.
fn ctl_read_table(fd int) [][]string {
	mut rows := [][]string{}
	for {
		line, lok := read_line(fd)
		if !lok || line == '~END' {
			break
		}
		f := line.split('\t')
		if f.len >= 4 {
			rows << [f[1], f[2], f[3]]
		}
	}
	return rows
}

// Pretty-print a component table (the rows from ctl_read_table) under `title`.
fn print_comp_table(title string, rows [][]string) {
	println(title)
	if rows.len == 0 {
		println('  (none)')
		return
	}
	for r in rows {
		println('  ${r[0]:7}  ${r[1]:-5}  ${r[2]}') // pid, cat, desc
	}
}

// `sb ctl [-v] [status|udpup [ip:port,...]|udpdn|kill <sel> [--match=X]]` -- query or
// control the running mux. No args (or `status`): formatted session stats; add `-v`
// to also list each relay/port/rpc (pid * category * description). `udpup` asks the
// wrapper to (re)negotiate the UDP backhaul (optional `ip:port,...` overrides the mux's
// advertised candidates when STUN can't find a public address); `udpdn`/`udpdown`
// forces a lossless revert to in-band. `kill <sel>` SAFELY stops session components:
// `<sel>` is all|relays|ports|rpcs|<pid>, `--match=X` filters to descriptions
// containing X (and double-guards a numeric pid against PID reuse). Bare `kill` prints
// usage + the `-v` listing. Only kernel-attested session components are ever signalled.
// `sb control` is a canonical alias.
@[noreturn]
fn run_ctl(args []string) {
	// Split switches (`-v`, `--match=...`) from positional args so they may appear anywhere.
	mut pos := []string{}
	mut verbose := false
	mut matchf := ''
	for a in args {
		if a == '-v' || a == '--verbose' {
			verbose = true
		} else if a.starts_with('--match=') {
			matchf = a['--match='.len..]
		} else {
			pos << a
		}
	}
	token := os.getenv('SB_TOKEN')
	if token == '' {
		die('SB_TOKEN not set')
	}
	fd := mux_sock_connect(mux_sock_path(token))
	if fd < 0 {
		eprintln('sb ctl: mux not reachable (is sb mux running with this token?)')
		C._exit(ex_unavailable)
	}
	write_str(fd, '${token_secret(token)}\n')
	ok_line, ok := read_line(fd)
	if !ok || ok_line != 'OK' {
		C.close(fd)
		C._exit(ex_noperm)
	}
	verb := if pos.len > 0 { pos[0] } else { 'status' }
	match verb {
		'status', '' {
			write_str(fd, 'STATUS\n')
			// Read key=value lines until ~END.
			mut kv := map[string]string{}
			mut order := []string{}
			for {
				line, lok := read_line(fd)
				if !lok || line == '~END' {
					break
				}
				idx := line.index(':') or { continue }
				k := line[..idx]
				v := line[idx + 1..]
				kv[k] = v
				order << k
			}
			// NB: socket stays open -- `-v` issues a second COMPS request below.
			// Pretty-print -- extract into locals to avoid escaped-quote issues.
			uptime_ms := kv['uptime_ms'].i64()
			h := uptime_ms / 3600000
			m2 := (uptime_ms % 3600000) / 60000
			s2 := (uptime_ms % 60000) / 1000
			dep := kv['depth']
			main_rx := fmt_bytes(kv['main_rx_bytes'].i64())
			main_tx := fmt_bytes(kv['main_tx_bytes'].i64())
			pty_rx := fmt_bytes(kv['pty_rx_bytes'].i64())
			pty_tx := fmt_bytes(kv['pty_tx_bytes'].i64())
			bh_st := kv['bh_state']
			println('=== sb mux status ===')
			println('depth: ${dep}  uptime: ${h:02}:${m2:02}:${s2:02}')
			println('')
			println('Channel')
			println('  rx: ${main_rx}   tx: ${main_tx}')
			println('')
			println('PTY')
			println('  rx: ${pty_rx}   tx: ${pty_tx}')
			println('')
			if bh_st != 'inactive' {
				bh_srflx := kv['bh_srflx']
				bh_peers := kv['bh_peer_cands']
				bh_txb := fmt_bytes(kv['bh_tx_bytes'].i64())
				bh_txf := kv['bh_tx_frames']
				bh_rxb := fmt_bytes(kv['bh_rx_bytes'].i64())
				bh_rxf := kv['bh_rx_frames']
				rtt := kv['bh_arq_rtt_ms']
				rto := kv['bh_arq_rto_ms']
				inflight_b := fmt_bytes(kv['bh_arq_inflight_bytes'].i64())
				inflight_s := kv['bh_arq_inflight_segs']
				mut hdr := 'Side-channel: ${bh_st}'
				if bh_peers.len > 0 {
					hdr += '   ${bh_peers}'
				}
				if bh_srflx.len > 0 {
					hdr += '   srflx ${bh_srflx}'
				}
				println(hdr)
				println('  tx: ${bh_txb} (${bh_txf} frames)   rx: ${bh_rxb} (${bh_rxf} frames)')
				println('  rtt: ${rtt} ms  rto: ${rto} ms  in-flight: ${inflight_s} segs / ${inflight_b}')
				println('')
			} else {
				println('Side-channel: inactive')
				println('')
			}
			nclients := kv['clients'].int()
			nports := kv['ports'].int()
			nrelays := kv['relays'].int()
			nrpcs := kv['rpcs'].int()
			println('Clients: ${nclients} (${nrelays} relays, ${nports} ports, ${nrpcs} RPCs)')
			if verbose {
				// Second round-trip on the SAME socket: enumerate the components.
				write_str(fd, 'COMPS\n')
				rows := ctl_read_table(fd)
				C.close(fd)
				println('')
				print_comp_table('Components (pid * cat * desc)', rows)
			} else {
				C.close(fd)
			}
			exit(0)
		}
		'udpdn', 'udpdown' {
			write_str(fd, 'BH:DOWN\n')
			resp, rok := read_line(fd)
			C.close(fd)
			if !rok || !resp.starts_with('OK') {
				eprintln('sb ctl: ${resp}')
				C._exit(1)
			}
			println(resp)
			exit(0)
		}
		'udpup' {
			cand_arg := if pos.len > 1 { ':${pos[1..].join(',')}' } else { '' }
			write_str(fd, 'BH:UP${cand_arg}\n')
			resp, rok := read_line(fd)
			C.close(fd)
			if !rok || !resp.starts_with('OK') {
				eprintln('sb ctl: ${resp}')
				C._exit(1)
			}
			println('udp backhaul renegotiation requested')
			exit(0)
		}
		'kill' {
			// Bare `kill` (no selector): print usage + the `-v` component listing so the
			// user can see what's killable, then exit non-zero (nothing was killed).
			if pos.len < 2 {
				write_str(fd, 'COMPS\n')
				rows := ctl_read_table(fd)
				C.close(fd)
				eprintln('usage: sb ctl kill {all|relays|ports|rpcs|<pid>} [--match=<substr>]')
				eprintln('')
				print_comp_table('Killable components (pid * cat * desc):', rows)
				C._exit(2)
			}
			selector := pos[1]
			req := if matchf != '' { 'KILL:${selector}:${matchf}\n' } else { 'KILL:${selector}\n' }
			write_str(fd, req)
			rows := ctl_read_table(fd)
			C.close(fd)
			if rows.len == 0 {
				eprintln('sb ctl: no matching session components')
				C._exit(1)
			}
			print_comp_table('Killed (pid * cat * desc):', rows)
			exit(0)
		}
		else {
			C.close(fd)
			die('usage: sb ctl [-v] [status | udpup [ip:port,...] | udpdn | kill {all|relays|ports|rpcs|<pid>} [--match=X]]')
		}
	}
	C._exit(0) // unreachable; satisfies @[noreturn] checker
}

// `sb survey` -- ask the WRAPPER to enumerate the multiplexer tree and print the
// result. Rides the ordinary mux-socket relay: we send `SURVEY` as a one-shot
// request; the host mux frames it `R<id>:SURVEY` up the byte stream, the wrapper
// broadcasts a SURVEY down the tree, gathers every mux's `SURVEYR` reply for a
// short window, and routes the formatted node table back (raw, `~END`-terminated)
// to us. No new mux machinery -- the wrapper owns the topology; this is its readout.
@[noreturn]
fn run_survey() {
	token := os.getenv('SB_TOKEN')
	if token == '' {
		die('SB_TOKEN not set')
	}
	fd := mux_sock_connect(mux_sock_path(token))
	if fd < 0 {
		eprintln('sb survey: mux not reachable (is sb mux running with this token?)')
		C._exit(ex_unavailable)
	}
	write_str(fd, '${token_secret(token)}\n')
	ok_line, ok := read_line(fd)
	if !ok || ok_line != 'OK' {
		C.close(fd)
		C._exit(ex_noperm)
	}
	write_str(fd, 'SURVEY\n')
	// Read the relayed table line-by-line until the `~END` sentinel (the route
	// bytes arrive raw -- no EOF, since the mux socket stays open).
	for {
		line, lok := read_line(fd)
		if !lok || line == '~END' {
			break
		}
		println(line)
	}
	C.close(fd)
	C._exit(0)
}

// fmt_bytes formats a byte count as a human-readable string (B / KB / MB).
fn fmt_bytes(n i64) string {
	if n < 1024 {
		return '${n} B'
	}
	if n < 1024 * 1024 {
		return '${n / 1024}.${(n % 1024) * 10 / 1024} KB'
	}
	return '${n / (1024 * 1024)}.${(n % (1024 * 1024)) * 10 / (1024 * 1024)} MB'
}

// `sb clip [--copy | --paste]` -- transparent clipboard bridge over the mux socket.
// User-facing I/O is raw binary; the mux handles b64 encode/decode at the APC
// transport boundary so the wire is safe for in-band relay without escaping issues.
// Mode is inferred from tty state when no flag is given:
//   stdin not a tty  -> copy (data is being piped in)
//   stdout not a tty -> paste (output is being captured)
//   both or neither  -> print help
@[noreturn]
fn run_clip(args []string) {
	mut mode := ''
	for a in args {
		if a == '--copy' {
			mode = 'copy'
		}
		if a == '--paste' {
			mode = 'paste'
		}
	}
	if mode == '' {
		stdin_tty := C.isatty(0) == 1
		stdout_tty := C.isatty(1) == 1
		if !stdin_tty && stdout_tty {
			mode = 'copy'
		} else if stdin_tty && !stdout_tty {
			mode = 'paste'
		} else {
			println('usage: sb clip [--copy | --paste]')
			println('  --copy   read stdin -> clipboard')
			println('  --paste  write clipboard -> stdout')
			C._exit(0)
		}
	}
	token := os.getenv('SB_TOKEN')
	if token == '' {
		die('SB_TOKEN not set')
	}
	fd := mux_sock_connect(mux_sock_path(token))
	if fd < 0 {
		eprintln('sb clip: mux not reachable')
		C._exit(ex_unavailable)
	}
	write_str(fd, '${token_secret(token)}\n')
	ok_line, ok := read_line(fd)
	if !ok || ok_line != 'OK' {
		C.close(fd)
		C._exit(ex_noperm)
	}
	if mode == 'paste' {
		write_str(fd, 'CLIP:GET\n')
		status, sok := read_line(fd)
		if !sok {
			C.close(fd)
			C._exit(1)
		}
		if status.starts_with('ERR:') {
			C.close(fd)
			emsg := status[4..]
			eprintln('sb clip: ${emsg}')
			C._exit(1)
		}
		// Read 4-byte BE length then stream raw bytes to stdout.
		mut lenb := [4]u8{}
		mut lrem := i64(4)
		mut loff := i64(0)
		for lrem > 0 {
			n := C.read(fd, voidptr(unsafe { &lenb[loff] }), usize(lrem))
			if n <= 0 {
				C.close(fd)
				C._exit(1)
			}
			loff += n
			lrem -= n
		}
		mut dlen := i64((u32(lenb[0]) << 24) | (u32(lenb[1]) << 16) | (u32(lenb[2]) << 8) | u32(lenb[3]))
		mut cbuf := [65536]u8{}
		for dlen > 0 {
			want := if dlen < 65536 { dlen } else { i64(65536) }
			n := C.read(fd, voidptr(&cbuf[0]), usize(want))
			if n <= 0 {
				break
			}
			write_all(1, unsafe { &cbuf[0] }, i64(n))
			dlen -= n
		}
		C.close(fd)
	} else {
		// Copy: buffer stdin, send CLIP:SET + 4-byte length + raw bytes.
		mut chunks := []u8{}
		mut tmp := [65536]u8{}
		for {
			n := C.read(0, voidptr(&tmp[0]), 65536)
			if n <= 0 {
				break
			}
			for i in 0 .. int(n) {
				chunks << tmp[i]
			}
		}
		dlen := u32(chunks.len)
		mut lenb := [4]u8{}
		lenb[0] = u8(dlen >> 24)
		lenb[1] = u8(dlen >> 16)
		lenb[2] = u8(dlen >> 8)
		lenb[3] = u8(dlen)
		write_str(fd, 'CLIP:SET\n')
		write_all(fd, unsafe { &lenb[0] }, 4)
		if chunks.len > 0 {
			write_all(fd, unsafe { &chunks[0] }, i64(chunks.len))
		}
		resp, rok := read_line(fd)
		C.close(fd)
		if !rok || resp != 'OK' {
			emsg := if resp.starts_with('ERR:') { resp[4..] } else { resp }
			eprintln('sb clip: ${emsg}')
			C._exit(1)
		}
	}
	C._exit(0)
}

// `sb token --token=<tok>` / `sb token --randomize`: ask the running mux (over its
// socket, authed with the CURRENT SB_TOKEN) to adopt a new token -- it rebinds its
// socket to the new locator and swaps its auth secret. `--token` sets a specific token
// (reconnect: the one surviving panes cached); `--randomize` lets the mux mint a fresh
// one and prints it on stdout. Updating SB_TOKEN in already-running shells is the
// caller's job (e.g. a launcher `export`s it before `exec`). This is the agnostic
// primitive session-recovery scripts build on.
@[noreturn]
fn run_token(args []string) {
	mut newtok := ''
	mut randomize := false
	for a in args {
		if a.starts_with('--token=') {
			newtok = a['--token='.len..]
		} else if a == '--randomize' {
			randomize = true
		}
	}
	if newtok == '' && !randomize {
		die('usage: sb token --token=<tok> | --randomize')
	}
	if newtok != '' && !valid_token(newtok) {
		die('sb token: token must be <locator>:<secret>')
	}
	token := os.getenv('SB_TOKEN')
	if token == '' {
		die('SB_TOKEN not set')
	}
	fd := mux_sock_connect(mux_sock_path(token))
	if fd < 0 {
		C._exit(ex_unavailable)
	}
	write_str(fd, '${token_secret(token)}\n')
	status, sok := read_line(fd)
	if !sok || status != 'OK' {
		C.close(fd)
		C._exit(ex_noperm)
	}
	write_str(fd, 'TOKEN:${newtok}\n') // empty payload => the mux randomizes
	resp, rok := read_line(fd)
	C.close(fd)
	if !rok || !resp.starts_with('OK:') {
		C._exit(ex_tempfail)
	}
	if randomize {
		println(resp.all_after('OK:')) // the freshly-minted token
	}
	C._exit(0)
}

// ----- sb tunnel: in-band TCP forwarding + netcat-style stdio ----------------
//
// `sb tunnel` opens a TUNNEL over the mux socket: a persistent bidirectional route to
// the wrapper carrying per-connection `O`/`D`/`H`/`C` frames. The wrapper does the
// wrapper-side socket work (dial a dest, or bind a listener); this process does the
// remote-side (a local listener/dial for import/export, or stdin/stdout for the
// netcat-style connect/listen). When this process exits -- or the mux dies (socket EOF)
// -- the tunnel tears down. Frames are `\n`-delimited; data is standard base64.

// `sb tunnel connect <wrapper-dest>`: the wrapper dials <wrapper-dest>; OUR stdin/stdout
// is the single connection (netcat client). stdin EOF half-closes (`H`); the wrapper's
// `C` (dest closed) or socket EOF ends us.
@[noreturn]
fn run_tunnel_connect(sock int) {
	write_str(sock, 'O:1\n') // one conn; the wrapper dials its dest on seeing it
	mut fds := [2]Pollfd{}
	fds[0] = Pollfd{
		fd:     sock
		events: pollin
	}
	mut inbuf := []u8{}
	bufsz := usize(65536)
	buf := unsafe { &u8(malloc(isize(bufsz))) }
	mut stdin_open := true
	for {
		fds[1] = Pollfd{
			fd:     if stdin_open { 0 } else { -1 }
			events: pollin
		}
		if C.poll(voidptr(&fds[0]), 2, -1) < 0 {
			break
		}
		// frames from the wrapper (down the tunnel).
		if (fds[0].revents & readable) != 0 {
			n := C.read(sock, voidptr(buf), bufsz)
			if n <= 0 {
				break // mux/wrapper gone -> tear down
			}
			for k in 0 .. int(n) {
				inbuf << unsafe { buf[k] }
			}
			for {
				nl := index_of(inbuf, u8(0x0a))
				if nl < 0 {
					break
				}
				line := inbuf[..nl].bytestr()
				inbuf = inbuf[nl + 1..].clone()
				if line.starts_with('D:1:') {
					data := b64_decode(line.all_after('D:1:')) or { []u8{} }
					if data.len > 0 {
						write_all(1, unsafe { &data[0] }, i64(data.len))
					}
				} else if line.starts_with('C:1') {
					C._exit(0) // dest closed -> done
				} else if line.starts_with('TUN-ERR') {
					eprintln('sb tunnel: ${line}')
					C._exit(1)
				}
			}
		}
		// our stdin -> the wrapper's dest.
		if stdin_open && (fds[1].revents & readable) != 0 {
			n := C.read(0, voidptr(buf), bufsz)
			if n <= 0 {
				write_str(sock, 'H:1\n') // half-close: no more from us
				stdin_open = false
			} else {
				data := unsafe { buf.vbytes(int(n)) }
				write_str(sock, 'D:1:${base64.encode(data)}\n')
			}
		}
	}
	C._exit(0)
}

// `sb tunnel listen <wrapper-listen> [--multi]` (netcat-style): the WRAPPER binds the
// port and accepts ONE connection at a time; OUR stdin/stdout services it. One-shot
// (default) exits after the first; `--multi` emits a `\0` separator after each and
// serves the next. (The wrapper paces accepts to one-at-a-time for `bind:one`.)
@[noreturn]
fn run_tunnel_listen(sock int, multi bool) {
	mut fds := [2]Pollfd{}
	fds[0] = Pollfd{
		fd:     sock
		events: pollin
	}
	mut inbuf := []u8{}
	bufsz := usize(65536)
	buf := unsafe { &u8(malloc(isize(bufsz))) }
	mut active := -1 // current conn id, or -1 when between connections
	mut stdin_eof := false
	for {
		fds[1] = Pollfd{
			fd:     if active >= 0 && !stdin_eof { 0 } else { -1 }
			events: pollin
		}
		if C.poll(voidptr(&fds[0]), 2, -1) < 0 {
			break
		}
		if (fds[0].revents & readable) != 0 {
			n := C.read(sock, voidptr(buf), bufsz)
			if n <= 0 {
				break // mux/wrapper gone -> tear down
			}
			for k in 0 .. int(n) {
				inbuf << unsafe { buf[k] }
			}
			for {
				nl := index_of(inbuf, u8(0x0a))
				if nl < 0 {
					break
				}
				line := inbuf[..nl].bytestr()
				inbuf = inbuf[nl + 1..].clone()
				if line.starts_with('O:') {
					active = line.all_after('O:').int() // a new accepted connection
					stdin_eof = false
				} else if line.starts_with('D:') {
					data := b64_decode(line.all_after('D:').all_after(':')) or { []u8{} }
					if data.len > 0 {
						write_all(1, unsafe { &data[0] }, i64(data.len))
					}
				} else if line.starts_with('C:') {
					if multi {
						sep := [u8(0)]
						write_all(1, unsafe { &sep[0] }, 1) // \0 between connections
						active = -1
					} else {
						C._exit(0)
					}
				} else if line.starts_with('TUN-ERR') {
					eprintln('sb tunnel: ${line}')
					C._exit(1)
				}
			}
		}
		if active >= 0 && !stdin_eof && (fds[1].revents & readable) != 0 {
			n := C.read(0, voidptr(buf), bufsz)
			if n <= 0 {
				write_str(sock, 'H:${active}\n') // our input ended -> half-close
				stdin_eof = true
			} else {
				data := unsafe { buf.vbytes(int(n)) }
				write_str(sock, 'D:${active}:${base64.encode(data)}\n')
			}
		}
	}
	C._exit(0)
}

// One TCP connection of an import/export tunnel: its conn-id, fd, and whether its read
// side has hit EOF (half-closed -> stop reading, keep writing) or it's fully closed.
struct TunConn {
mut:
	id      int
	fd      int
	rclosed bool
	closed  bool
}

// Parse `[addr:]port` -> (addr, port); `default_addr` when only a port is given. addr is
// a dotted IPv4 (or 0.0.0.0); hostnames aren't resolved here (use the wrapper side for
// those, which has full async resolution).
fn parse_hostport(spec string, default_addr string) (string, u16) {
	if spec.contains(':') {
		a := spec.all_before_last(':')
		return if a == '' {
			default_addr
		} else {
			a
		}, u16(spec.all_after_last(':').int())
	}
	return default_addr, u16(spec.int())
}

// Bind+listen a TCP socket on addr:port (SO_REUSEADDR), or -1.
fn tcp_listen(addr string, port u16) int {
	fd := C.socket(af_inet, sock_stream | sock_cloexec, 0)
	if fd < 0 {
		return -1
	}
	one := int(1)
	C.setsockopt(fd, sol_socket, so_reuseaddr, voidptr(&one), u32(sizeof(int)))
	mut sa := SockaddrIn{
		sin_family: u16(af_inet)
		sin_port:   C.htons(port)
	}
	if C.inet_pton(af_inet, addr.str, voidptr(&sa.sin_addr)) != 1 {
		C.close(fd)
		return -1
	}
	if C.bind(fd, voidptr(&sa), u32(sizeof(SockaddrIn))) != 0 || C.listen(fd, somaxconn) != 0 {
		C.close(fd)
		return -1
	}
	return fd
}

// Connect a TCP socket to addr:port (blocking -- the dial target is local/nearby), or -1.
fn tcp_connect(addr string, port u16) int {
	fd := C.socket(af_inet, sock_stream | sock_cloexec, 0)
	if fd < 0 {
		return -1
	}
	mut sa := SockaddrIn{
		sin_family: u16(af_inet)
		sin_port:   C.htons(port)
	}
	if C.inet_pton(af_inet, addr.str, voidptr(&sa.sin_addr)) != 1 {
		C.close(fd)
		return -1
	}
	if C.connect(fd, voidptr(&sa), u32(sizeof(SockaddrIn))) != 0 {
		C.close(fd)
		return -1
	}
	return fd
}

// -- STUN client (RFC 5389) --------------------------------------------------
// Discovers this socket's server-reflexive candidate (its public ip:port as seen
// from outside the NAT) for the UDP backhaul. We implement only the CLIENT; an
// EXTERNAL STUN server is the observer -- required because the ssh path may be a
// non-routable relay (e.g. AWS ECS exec via SSM) with no IP correspondence to a
// real network path, and either peer (including the wrapper) may be behind NAT.
// The mapping is per-socket, so stun_query binds the SAME local port the P2P
// channel will reuse.
const sock_dgram = 2
const stun_cookie = [u8(0x21), 0x12, 0xa4, 0x42] // RFC 5389 magic cookie

// stun_build_request assembles a 20-byte Binding Request carrying `txid` (12 bytes).
fn stun_build_request(txid []u8) []u8 {
	mut m := []u8{cap: 20}
	m << 0x00
	m << 0x01 // message type 0x0001 = Binding Request
	m << 0x00
	m << 0x00 // message length 0 (no attributes)
	m << stun_cookie
	m << txid[..12]
	return m
}

// stun_make_response builds a Binding Success Response echoing `txid` with a
// single XOR-MAPPED-ADDRESS (IPv4) -- the encoder a loopback responder would use,
// and what the self-test decodes.
fn stun_make_response(txid []u8, ip string, port u16) []u8 {
	o := ip.split('.')
	mut body := [u8(0x00), 0x20, 0x00, 0x08, 0x00, 0x01] // XOR-MAPPED-ADDRESS, len 8, IPv4
	body << u8(port >> 8) ^ stun_cookie[0]
	body << u8(port) ^ stun_cookie[1]
	for i in 0 .. 4 {
		body << u8(o[i].int()) ^ stun_cookie[i]
	}
	mut m := [u8(0x01), 0x01] // 0x0101 = Binding Success Response
	m << u8(body.len >> 8)
	m << u8(body.len)
	m << stun_cookie
	m << txid[..12]
	m << body
	return m
}

// stun_parse_response validates a Binding Success Response against `txid` and
// returns its XOR-MAPPED-ADDRESS (IPv4) as (ok, ip, port). MAPPED-ADDRESS (the
// legacy, un-XORed form) is accepted as a fallback.
fn stun_parse_response(r []u8, txid []u8) (bool, string, u16) {
	if r.len < 20 || r[0] != 0x01 || r[1] != 0x01 {
		return false, '', 0
	}
	for i in 0 .. 4 {
		if r[4 + i] != stun_cookie[i] {
			return false, '', 0
		}
	}
	for i in 0 .. 12 {
		if r[8 + i] != txid[i] {
			return false, '', 0
		}
	}
	mlen := int(r[2]) << 8 | int(r[3])
	end := if 20 + mlen <= r.len { 20 + mlen } else { r.len }
	mut off := 20
	for off + 4 <= end {
		atype := int(r[off]) << 8 | int(r[off + 1])
		alen := int(r[off + 2]) << 8 | int(r[off + 3])
		v := off + 4
		if v + alen > r.len {
			break
		}
		if (atype == 0x0020 || atype == 0x0001) && alen >= 8 && r[v + 1] == 0x01 {
			x := atype == 0x0020 // 0x0020 XOR-MAPPED-ADDRESS; 0x0001 MAPPED-ADDRESS (legacy)
			ph := if x { r[v + 2] ^ stun_cookie[0] } else { r[v + 2] }
			pl := if x { r[v + 3] ^ stun_cookie[1] } else { r[v + 3] }
			mut a := [4]u8{}
			for i in 0 .. 4 {
				a[i] = if x { r[v + 4 + i] ^ stun_cookie[i] } else { r[v + 4 + i] }
			}
			return true, '${a[0]}.${a[1]}.${a[2]}.${a[3]}', u16(ph) << 8 | u16(pl)
		}
		off = v + ((alen + 3) / 4) * 4 // attributes are padded to a 4-byte boundary
	}
	return false, '', 0
}

// urandom returns n random bytes from /dev/urandom (zero-padded on a short read).
fn urandom(n int) []u8 {
	mut b := []u8{len: n}
	fd := C.open(c'/dev/urandom', 0)
	if fd < 0 {
		return b
	}
	mut got := 0
	for got < n {
		r := C.read(fd, unsafe { voidptr(&b[got]) }, usize(n - got))
		if r <= 0 {
			break
		}
		got += int(r)
	}
	C.close(fd)
	return b
}

// stun_query binds `bind_port` (0 = ephemeral), asks the STUN server at
// `server_ip`:`port` for this socket's reflexive mapping, and returns (ok, ip,
// port). `server_ip` is a numeric IPv4 -- the WRAPPER resolves STUN hostnames
// and forwards IPs in the offered config (no DNS resolver in the static binary;
// anycast/GeoDNS are don't-care for a request this cheap, and the resolver
// machinery is ~28KB). Best-effort: one request, ~1s wait. The socket is closed
// on return -- establishment re-binds the same port for the live channel.
fn stun_query(server_ip string, port u16, bind_port u16) (bool, string, u16) {
	fd := C.socket(af_inet, sock_dgram, 0)
	if fd < 0 {
		return false, '', 0
	}
	defer {
		C.close(fd)
	}
	if bind_port != 0 {
		one := int(1)
		C.setsockopt(fd, sol_socket, so_reuseaddr, voidptr(&one), u32(sizeof(int)))
		mut la := SockaddrIn{
			sin_family: u16(af_inet)
			sin_port:   C.htons(bind_port)
		}
		if C.bind(fd, voidptr(&la), u32(sizeof(SockaddrIn))) != 0 {
			return false, '', 0
		}
	}
	mut sa := SockaddrIn{
		sin_family: u16(af_inet)
		sin_port:   C.htons(port)
	}
	if C.inet_pton(af_inet, server_ip.str, voidptr(&sa.sin_addr)) != 1 {
		return false, '', 0
	}
	if C.connect(fd, voidptr(&sa), u32(sizeof(SockaddrIn))) != 0 {
		return false, '', 0
	}
	txid := urandom(12)
	req := stun_build_request(txid)
	if C.write(fd, req.data, usize(req.len)) != i64(req.len) {
		return false, '', 0
	}
	mut pfd := Pollfd{
		fd:     fd
		events: pollin
	}
	if C.poll(voidptr(&pfd), 1, 1000) <= 0 {
		return false, '', 0
	}
	mut buf := []u8{len: 512}
	n := C.read(fd, buf.data, usize(buf.len))
	if n < 20 {
		return false, '', 0
	}
	return stun_parse_response(buf[..int(n)], txid)
}

// run_cryptotest's STUN sibling: `sb __stuntest` exercises the codec hermetically
// (build request, decode a synthetic XOR-MAPPED-ADDRESS, reject bad txid/cookie/type).
fn run_stuntest() {
	txid := [u8(0xa1), 0xb2, 0xc3, 0xd4, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
	req := stun_build_request(txid)
	if req.len == 20 && req[0] == 0 && req[1] == 1 && req[4..8] == stun_cookie && req[8..20] == txid {
		println('ok:   binding request encodes (20B header, cookie, txid)')
	} else {
		println('FAIL: binding request encoding')
	}
	ip, port := '203.0.113.7', u16(54321)
	resp := stun_make_response(txid, ip, port)
	ok, gip, gport := stun_parse_response(resp, txid)
	if ok && gip == ip && gport == port {
		println('ok:   XOR-MAPPED-ADDRESS decodes (${gip}:${gport})')
	} else {
		println('FAIL: XOR-MAPPED-ADDRESS decode ok=${ok} got=${gip}:${gport}')
	}
	mut bad_txid := txid.clone()
	bad_txid[0] ^= 0xff
	rt, _, _ := stun_parse_response(resp, bad_txid)
	if rt {
		println('FAIL: mismatched txid accepted')
	} else {
		println('ok:   mismatched txid rejected')
	}
	mut bad_cookie := resp.clone()
	bad_cookie[4] ^= 0xff
	rc, _, _ := stun_parse_response(bad_cookie, txid)
	if rc {
		println('FAIL: bad magic cookie accepted')
	} else {
		println('ok:   bad magic cookie rejected')
	}
	mut bad_type := resp.clone()
	bad_type[0], bad_type[1] = 0x00, 0x01 // a request, not a success response
	rty, _, _ := stun_parse_response(bad_type, txid)
	if rty {
		println('FAIL: non-success type accepted')
	} else {
		println('ok:   non-success message type rejected')
	}
}

// The multiplexed remote side of `import`/`export`: a poll loop over the mux socket, the
// local listener (import only), and N connection fds. `import` binds `local_listen` and
// originates an `O` per accept (the wrapper dials its dest); `export` dials `remote_dest`
// on each `O` the wrapper sends. Bytes relay as `D:<conn>:<b64>`; `H` is a half-close
// (read EOF on one side -> shutdown the other's write); `C` is a full close.
@[noreturn]
fn run_tunnel_sock(sock int, is_import bool, local_listen string, remote_dest string) {
	mut listener := -1
	if is_import {
		addr, port := parse_hostport(local_listen, '127.0.0.1')
		listener = tcp_listen(addr, port)
		if listener < 0 {
			eprintln('sb tunnel: cannot bind ${local_listen}')
			C.close(sock)
			C._exit(1)
		}
	}
	mut conns := []TunConn{}
	mut next_conn := 1
	mut inbuf := []u8{}
	bufsz := usize(65536)
	buf := unsafe { &u8(malloc(isize(bufsz))) }
	for {
		mut fds := []Pollfd{}
		fds << Pollfd{
			fd:     sock
			events: pollin
		}
		fds << Pollfd{
			fd:     listener // -1 for export -> poll ignores it
			events: pollin
		}
		nconns := conns.len
		for c in conns {
			fds << Pollfd{
				fd:     if c.closed || c.rclosed { -1 } else { c.fd }
				events: pollin
			}
		}
		if C.poll(voidptr(unsafe { &fds[0] }), u64(fds.len), -1) < 0 {
			break
		}
		// frames from the wrapper.
		if (fds[0].revents & readable) != 0 {
			n := C.read(sock, voidptr(buf), bufsz)
			if n <= 0 {
				break // mux/wrapper gone -> tear down
			}
			for k in 0 .. int(n) {
				inbuf << unsafe { buf[k] }
			}
			for {
				nl := index_of(inbuf, u8(0x0a))
				if nl < 0 {
					break
				}
				line := inbuf[..nl].bytestr()
				inbuf = inbuf[nl + 1..].clone()
				if line.starts_with('O:') { // export: dial our remote dest for this conn
					conn := line.all_after('O:').int()
					addr, port := parse_hostport(remote_dest, '127.0.0.1')
					cfd := tcp_connect(addr, port)
					if cfd < 0 {
						write_str(sock, 'C:${conn}\n')
					} else {
						conns << TunConn{
							id: conn
							fd: cfd
						}
					}
				} else if line.starts_with('D:') {
					rest := line.all_after('D:')
					cid := rest.all_before(':').int()
					data := b64_decode(rest.all_after(':')) or { []u8{} }
					if data.len > 0 {
						for c in conns {
							if c.id == cid && !c.closed {
								write_all(c.fd, unsafe { &data[0] }, i64(data.len))
							}
						}
					}
				} else if line.starts_with('H:') {
					cid := line.all_after('H:').int()
					for c in conns {
						if c.id == cid && !c.closed {
							C.shutdown(c.fd, shut_wr) // peer done writing -> EOF our local side
						}
					}
				} else if line.starts_with('C:') {
					cid := line.all_after('C:').int()
					for mut c in conns {
						if c.id == cid && !c.closed {
							C.close(c.fd)
							c.closed = true
						}
					}
				} else if line.starts_with('TUN-ERR') {
					eprintln('sb tunnel: ${line}')
					C._exit(1)
				}
			}
		}
		// import: accept a new local connection -> originate an `O` up.
		if listener >= 0 && (fds[1].revents & readable) != 0 {
			cfd := C.accept(listener, unsafe { nil }, unsafe { nil })
			if cfd >= 0 {
				id := next_conn
				next_conn++
				conns << TunConn{
					id: id
					fd: cfd
				}
				write_str(sock, 'O:${id}\n')
			}
		}
		// local conn fds -> `D` up; read EOF -> `H` (half-close).
		for ci, mut c in conns {
			if ci >= nconns || c.closed || c.rclosed || (fds[2 + ci].revents & readable) == 0 {
				continue
			}
			n := C.read(c.fd, voidptr(buf), bufsz)
			if n <= 0 {
				write_str(sock, 'H:${c.id}\n')
				c.rclosed = true
			} else {
				data := unsafe { buf.vbytes(int(n)) }
				write_str(sock, 'D:${c.id}:${base64.encode(data)}\n')
			}
		}
		// compact out fully-closed conns (kept until here so fds[] stayed aligned).
		mut keep := []TunConn{}
		for c in conns {
			if !c.closed {
				keep << c
			}
		}
		conns = keep.clone()
	}
	C.close(sock)
	for c in conns {
		if !c.closed {
			C.close(c.fd)
		}
	}
	C._exit(0)
}

// `sb tunnel <verb> ...`: connect + auth the mux socket, send the tunnel open, and run
// the verb's remote side. `connect`/`listen` use stdin/stdout (netcat); `import`/
// `export` bind/dial local sockets.
@[noreturn]
fn run_tunnel(args []string) {
	if args.len < 2 {
		die('usage: sb tunnel {connect <dest>|listen <listen>|import <listen> <dest>|export <listen> <dest>}')
	}
	verb := args[0]
	token := os.getenv('SB_TOKEN')
	if token == '' {
		die('SB_TOKEN not set')
	}
	sock := mux_sock_connect(mux_sock_path(token))
	if sock < 0 {
		C._exit(ex_unavailable)
	}
	write_str(sock, '${token_secret(token)}\n')
	ok_line, ok := read_line(sock)
	if !ok || ok_line != 'OK' {
		C.close(sock)
		C._exit(ex_noperm)
	}
	match verb {
		'connect' {
			write_str(sock, 'TUN:dial:${args[1]}\n') // wrapper dials args[1]
			rep, rok := read_line(sock)
			if !rok || !rep.starts_with('TUN-OK') {
				eprintln('sb tunnel: ${rep}')
				C._exit(1)
			}
			run_tunnel_connect(sock)
		}
		'listen' {
			mut multi := false
			for a in args[2..] {
				if a == '--multi' {
					multi = true
				}
			}
			write_str(sock, 'TUN:bind:${args[1]}:one\n') // wrapper binds, one conn at a time
			rep, rok := read_line(sock)
			if !rok || !rep.starts_with('TUN-OK') {
				eprintln('sb tunnel: ${rep}')
				C._exit(1)
			}
			run_tunnel_listen(sock, multi)
		}
		'import' {
			if args.len < 3 {
				die('usage: sb tunnel import <local-listen> <wrapper-dest>')
			}
			write_str(sock, 'TUN:dial:${args[2]}\n') // wrapper dials the wrapper-dest
			rep, rok := read_line(sock)
			if !rok || !rep.starts_with('TUN-OK') {
				eprintln('sb tunnel: ${rep}')
				C._exit(1)
			}
			run_tunnel_sock(sock, true, args[1], '')
		}
		'export' {
			if args.len < 3 {
				die('usage: sb tunnel export <wrapper-listen> <remote-dest>')
			}
			write_str(sock, 'TUN:bind:${args[1]}:all\n') // wrapper binds the wrapper-listen
			rep, rok := read_line(sock)
			if !rok || !rep.starts_with('TUN-OK') {
				eprintln('sb tunnel: ${rep}')
				C._exit(1)
			}
			run_tunnel_sock(sock, false, '', args[2])
		}
		else {
			die('sb tunnel: verb ${verb} not yet implemented')
		}
	}
	C._exit(0)
}

// `sb __muxclient <msg>` (self-test): connect, auth, send <msg>, print the echo.
// Exit codes are the sysexits the real clients will use.
@[noreturn]
fn run_mux_client(msg string) {
	token := os.getenv('SB_TOKEN')
	if token == '' {
		die('SB_TOKEN not set')
	}
	fd := mux_sock_connect(mux_sock_path(token))
	if fd < 0 {
		C._exit(ex_unavailable)
	}
	write_str(fd, '${token_secret(token)}\n')
	status, sok := read_line(fd)
	if !sok || status != 'OK' {
		C.close(fd)
		C._exit(ex_noperm)
	}
	write_str(fd, '${msg}\n')
	echo, eok := read_line(fd)
	C.close(fd)
	if !eok {
		C._exit(ex_tempfail)
	}
	println(echo)
	C._exit(0)
}

// `sb __muxfetch <request>` (self-test): connect + auth, send a FILEREQ-style
// request over the socket, read the relayed response (the mux frames the request
// up the byte stream with a request-id and routes the wrapper's reply back), decode
// the base64 body, print it. Proves the full request-id round-trip end to end.
@[noreturn]
fn run_mux_fetch(request string) {
	token := os.getenv('SB_TOKEN')
	if token == '' {
		die('SB_TOKEN not set')
	}
	fd := mux_sock_connect(mux_sock_path(token))
	if fd < 0 {
		C._exit(ex_unavailable)
	}
	write_str(fd, '${token_secret(token)}\n')
	status, sok := read_line(fd)
	if !sok || status != 'OK' {
		C.close(fd)
		C._exit(ex_noperm)
	}
	write_str(fd, '${request}\n')
	mut b64 := []u8{}
	mut st := -1
	for {
		line, ok := read_line(fd)
		if !ok {
			break
		}
		if line.starts_with('~EOF') {
			st = fr_eof
			break
		}
		if line.starts_with('~ERR') {
			st = fr_err
			break
		}
		b64 << line.bytes()
	}
	C.close(fd)
	if st != fr_eof {
		C._exit(1)
	}
	decoded := base64.decode(b64.bytestr())
	if decoded.len > 0 {
		write_all(1, unsafe { &decoded[0] }, i64(decoded.len))
	}
	C._exit(0)
}

// `sb __conduitfetch <inner-id> <request>` (self-test): connect + auth, then send an
// `R<inner-id>:<request>` line -- exactly what an `sb inject` conduit forwards when a
// deeper mux relays its child's R-tagged fetch. This exercises the host mux's
// FRAMED-origin path: it must record inner-id, relay up under its OWN id, and on the
// reply re-frame `R<inner-id>:<resp>` back as an APC (the form a conduit relays into
// the deeper pty). We read that APC, verify its id is the inner-id we sent, and print
// the decoded body. Proves the `inner_id >= 0` re-framing branch end to end.
@[noreturn]
fn run_conduit_fetch(inner int, request string) {
	token := os.getenv('SB_TOKEN')
	if token == '' {
		die('SB_TOKEN not set')
	}
	fd := mux_sock_connect(mux_sock_path(token))
	if fd < 0 {
		C._exit(ex_unavailable)
	}
	write_str(fd, '${token_secret(token)}\n')
	ok_line, ok := read_line(fd)
	if !ok || ok_line != 'OK' {
		C.close(fd)
		C._exit(ex_noperm)
	}
	write_str(fd, 'R${inner}:${request}\n')
	// The framed-origin reply is one APC: `ESC _ shell-bucket:R<inner>:<body> ST`.
	mut sc := Scanner{}
	mut payload := []u8{}
	mut chunk := [4096]u8{}
	for payload.len == 0 {
		n := C.read(fd, voidptr(&chunk[0]), usize(4096))
		if n <= 0 {
			break
		}
		sc.feed_raw(&chunk[0], int(n))
		pls := sc.take_payloads()
		if pls.len > 0 {
			payload = pls[0]
		}
	}
	C.close(fd)
	okr, id, body := parse_route(payload)
	if !okr || id != inner {
		C._exit(1) // reply not re-framed back to our inner id -> fail
	}
	// `body` is the `~EOF`-framed response blob; decode the base64 lines before it.
	mut b64 := []u8{}
	for line in body.bytestr().split_into_lines() {
		if line.starts_with('~EOF') {
			break
		}
		if line.starts_with('~ERR') {
			C._exit(1)
		}
		b64 << line.bytes()
	}
	decoded := base64.decode(b64.bytestr())
	if decoded.len > 0 {
		write_all(1, unsafe { &decoded[0] }, i64(decoded.len))
	}
	C._exit(0)
}

fn C.sb_aesgcm_seal(key &u8, key_len usize, iv &u8, aad &u8, aad_len usize, data &u8, data_len usize, tag &u8) int
fn C.sb_aesgcm_open(key &u8, key_len usize, iv &u8, aad &u8, aad_len usize, data &u8, data_len usize, tag &u8) int

// aead_seal encrypts `data` in place and returns its 16-byte authentication
// tag. `iv` must be 12 bytes; `key` 16/24/32 bytes (AES-128/192/256). `aad` is
// authenticated but not encrypted (may be empty).
fn aead_seal(key []u8, iv []u8, aad []u8, mut data []u8) []u8 {
	mut tag := []u8{len: 16}
	C.sb_aesgcm_seal(key.data, usize(key.len), iv.data, aad.data, usize(aad.len), data.data,
		usize(data.len), tag.data)
	return tag
}

// aead_open decrypts `data` in place and reports whether `tag` authenticates it
// under `key`/`iv`/`aad`. On a false result the caller MUST discard `data`.
fn aead_open(key []u8, iv []u8, aad []u8, mut data []u8, tag []u8) bool {
	return C.sb_aesgcm_open(key.data, usize(key.len), iv.data, aad.data, usize(aad.len),
		data.data, usize(data.len), tag.data) == 0
}

// -- UDP AEAD packet layer ----------------------------------------------------
// Each datagram on the backhaul is `[seq:8 BE][ciphertext][tag:16]`, sealed with
// the shared 32-byte PSK (used DIRECTLY as the AES-256 key -- the PSK is random &
// single-purpose, so no KDF) under a 12-byte nonce = `[salt:4 BE][seq:8 BE]`.
// `salt` is a per-DIRECTION constant, so the two directions never collide on a
// (key,nonce) pair, and `seq` is a per-direction monotonic counter that never
// repeats (64-bit, never wraps in practice). `seq` rides in the clear but is
// bound into the nonce, so tampering it fails the tag. It doubles as the ARQ
// sequence number (increment 2's reliability layer).
const aead_tag_len = 16

fn aead_nonce(salt u32, seq u64) []u8 {
	mut n := []u8{len: 12}
	n[0], n[1], n[2], n[3] = u8(salt >> 24), u8(salt >> 16), u8(salt >> 8), u8(salt)
	for i in 0 .. 8 {
		n[4 + i] = u8(seq >> (8 * (7 - i)))
	}
	return n
}

// udp_seal builds an on-wire packet for `payload` at sequence `seq`.
fn udp_seal(key []u8, salt u32, seq u64, payload []u8) []u8 {
	mut data := payload.clone()
	tag := aead_seal(key, aead_nonce(salt, seq), []u8{}, mut data)
	mut pkt := []u8{cap: 8 + data.len + aead_tag_len}
	for i in 0 .. 8 {
		pkt << u8(seq >> (8 * (7 - i)))
	}
	pkt << data
	pkt << tag
	return pkt
}

// udp_open parses a packet, reconstructs the nonce from `salt` + the wire seq,
// and verifies the tag. Returns (ok, seq, plaintext). Replay/reorder handling
// (a per-direction seq window) is the ARQ layer's job, not the packet codec's.
fn udp_open(key []u8, salt u32, pkt []u8) (bool, u64, []u8) {
	if pkt.len < 8 + aead_tag_len {
		return false, 0, []u8{}
	}
	mut seq := u64(0)
	for i in 0 .. 8 {
		seq = seq << 8 | u64(pkt[i])
	}
	ctend := pkt.len - aead_tag_len
	mut data := pkt[8..ctend].clone()
	tag := pkt[ctend..]
	if !aead_open(key, aead_nonce(salt, seq), []u8{}, mut data, tag) {
		return false, 0, []u8{}
	}
	return true, seq, data
}

// run_udptest (`sb __udptest`): the UDP AEAD packet codec -- seal/open round-trip,
// the clear seq survives, cross-direction (wrong salt) is rejected, and any
// tamper/truncation fails the tag.
fn run_udptest() {
	key := []u8{len: 32, init: u8(index * 7 + 1)}
	salt_a, salt_b := u32(0x00000001), u32(0x00000002)
	payload := 'backhaul frame: R7:D:3:aGVsbG8='.bytes()
	seq := u64(0x0102030405060708)
	pkt := udp_seal(key, salt_a, seq, payload)
	ok, gseq, got := udp_open(key, salt_a, pkt)
	if ok && gseq == seq && got == payload {
		println('ok:   packet seal/open round-trip (seq preserved)')
	} else {
		println('FAIL: packet round-trip ok=${ok} seq=${gseq}')
	}
	// Wrong direction salt -> nonce mismatch -> tag fails (directions are isolated).
	xok, _, _ := udp_open(key, salt_b, pkt)
	if xok {
		println('FAIL: cross-direction packet accepted')
	} else {
		println('ok:   cross-direction (wrong salt) rejected')
	}
	// Flip a ciphertext byte -> tag fails.
	mut tampered := pkt.clone()
	tampered[10] ^= 0xff
	tok, _, _ := udp_open(key, salt_a, tampered)
	if tok {
		println('FAIL: tampered packet accepted')
	} else {
		println('ok:   tampered ciphertext rejected')
	}
	// Truncated packet -> rejected.
	trok, _, _ := udp_open(key, salt_a, pkt[..pkt.len - 1])
	if trok {
		println('FAIL: truncated packet accepted')
	} else {
		println('ok:   truncated packet rejected')
	}
	// Empty-payload packet (a pure ARQ ack/heartbeat) still seals/opens.
	apkt := udp_seal(key, salt_a, seq + 1, []u8{})
	aok, aseq, abody := udp_open(key, salt_a, apkt)
	if aok && aseq == seq + 1 && abody.len == 0 {
		println('ok:   empty-payload packet (ack/heartbeat) round-trips')
	} else {
		println('FAIL: empty-payload packet ok=${aok}')
	}
}

// -- Reliable-UDP (TCP-lite ARQ) ----------------------------------------------
// A transport-agnostic reliable, ordered byte stream over the AEAD packet codec.
// It does NO socket I/O and reads no clock -- the caller injects received packets
// + a monotonic `now` (ms) and drains the packets it wants to send. That keeps
// it a pure state machine: hermetically testable against a simulated lossy /
// reordering channel before it's wired into the live poll loop.
//
// Sealed payload: `[flags:1][ack:8 BE]` (cumulative ack, always piggybacked),
// then `[offset:8 BE][data]` when the DATA flag is set. `offset`/`ack` are
// 64-bit byte-stream positions (never wrap -> no serial-number arithmetic). The
// outer packet `seq` (2a) remains the per-direction nonce counter, distinct from
// `offset` so a retransmit reuses the offset but never the nonce.
const seg_max = 1200 // bytes of stream data per datagram (fits common MTUs)
const arq_window = u64(65536) // max bytes in flight (flow control; no cwnd in v1)
const rto_min = i64(100)
const rto_max = i64(8000)
const arq_fdata = u8(0x01) // flags: a DATA segment follows the ack

fn be64(b []u8, off int) u64 {
	mut v := u64(0)
	for i in 0 .. 8 {
		v = v << 8 | u64(b[off + i])
	}
	return v
}

fn put_be64(mut o []u8, v u64) {
	for i in 0 .. 8 {
		o << u8(v >> (8 * (7 - i)))
	}
}

fn put_be32(mut o []u8, v u32) {
	for i in 0 .. 4 {
		o << u8(v >> (8 * (3 - i)))
	}
}

struct Segment {
mut:
	off     u64
	data    []u8
	sent_ms i64
	xmits   int // transmission count (Karn: RTT-sample only when == 1)
}

struct Arq {
mut:
	key     []u8
	tx_salt u32 // our outbound direction salt
	rx_salt u32 // peer's outbound salt (what we receive under)
	pkt_seq u64 // outbound nonce counter (increments every datagram sent)
	// sender
	pending  []u8 // app bytes not yet segmented
	unacked  []Segment
	snd_nxt  u64
	last_ack u64
	dup_acks int
	srtt     i64
	rttvar   i64
	rto      i64
	// receiver
	rcv_nxt u64
	reorder []Segment // out-of-order segments awaiting a gap fill
	inbox   []u8      // delivered, in-order bytes for the app to read
	needack bool
	// outbound sealed datagrams, drained by poll_out
	outq [][]u8
}

fn new_arq(key []u8, tx_salt u32, rx_salt u32) Arq {
	return Arq{
		key:     key.clone()
		tx_salt: tx_salt
		rx_salt: rx_salt
		rto:     rto_min
	}
}

fn (a &Arq) snd_una() u64 {
	return if a.unacked.len > 0 { a.unacked[0].off } else { a.snd_nxt }
}

fn (a &Arq) outstanding() u64 {
	return a.snd_nxt - a.snd_una()
}

// seal_out builds one outbound datagram (always carrying the current cumulative
// ack); DATA is appended when arq_fdata is set. Clears the ack debt.
fn (mut a Arq) seal_out(flags u8, off u64, data []u8) {
	mut body := [flags]
	put_be64(mut body, a.rcv_nxt)
	if (flags & arq_fdata) != 0 {
		put_be64(mut body, off)
		body << data
	}
	a.outq << udp_seal(a.key, a.tx_salt, a.pkt_seq, body)
	a.pkt_seq++
	a.needack = false
}

// fill_window segments `pending` into DATA datagrams while the flow window allows.
fn (mut a Arq) fill_window(now i64) {
	for a.pending.len > 0 && a.outstanding() < arq_window {
		take := if a.pending.len < seg_max { a.pending.len } else { seg_max }
		chunk := a.pending[..take].clone()
		a.pending = a.pending[take..].clone()
		seg := Segment{
			off:     a.snd_nxt
			data:    chunk
			sent_ms: now
			xmits:   1
		}
		a.snd_nxt += u64(take)
		a.unacked << seg
		a.seal_out(arq_fdata, seg.off, seg.data)
	}
}

// app_send queues `data` for reliable, ordered delivery to the peer.
fn (mut a Arq) app_send(data []u8, now i64) {
	a.pending << data
	a.fill_window(now)
}

// take_inbox drains the in-order bytes delivered so far.
fn (mut a Arq) take_inbox() []u8 {
	r := a.inbox.clone()
	a.inbox = []u8{}
	return r
}

fn (mut a Arq) rtt_update(sample i64) {
	s := if sample < 1 { i64(1) } else { sample }
	if a.srtt == 0 {
		a.srtt = s
		a.rttvar = s / 2
	} else {
		mut d := a.srtt - s
		if d < 0 {
			d = -d
		}
		a.rttvar = (3 * a.rttvar + d) / 4
		a.srtt = (7 * a.srtt + s) / 8
	}
	a.rto = a.srtt + 4 * a.rttvar
	if a.rto < rto_min {
		a.rto = rto_min
	}
	if a.rto > rto_max {
		a.rto = rto_max
	}
}

fn (mut a Arq) retransmit_first(now i64) {
	if a.unacked.len == 0 {
		return
	}
	a.unacked[0].xmits++
	a.unacked[0].sent_ms = now
	a.seal_out(arq_fdata, a.unacked[0].off, a.unacked[0].data)
}

fn (mut a Arq) process_ack(ack u64, now i64) {
	for a.unacked.len > 0 && a.unacked[0].off + u64(a.unacked[0].data.len) <= ack {
		if a.unacked[0].xmits == 1 {
			a.rtt_update(now - a.unacked[0].sent_ms)
		}
		a.unacked.delete(0)
	}
	if ack > a.last_ack {
		a.last_ack = ack
		a.dup_acks = 0
	} else if ack == a.last_ack && a.unacked.len > 0 {
		a.dup_acks++
		if a.dup_acks == 3 {
			a.retransmit_first(now) // fast retransmit
		}
	}
}

// deliver places a received segment in order, buffering out-of-order arrivals.
fn (mut a Arq) deliver(off u64, data []u8) {
	if off + u64(data.len) <= a.rcv_nxt {
		return
	}
	if off > a.rcv_nxt {
		if off - a.rcv_nxt > arq_window {
			return
		}
		for s in a.reorder {
			if s.off == off {
				return
			}
		}
		a.reorder << Segment{
			off:  off
			data: data.clone()
		}
		return
	}
	mut d := data.clone()
	if off < a.rcv_nxt {
		d = data[int(a.rcv_nxt - off)..].clone() // trim the overlap
	}
	a.inbox << d
	a.rcv_nxt += u64(d.len)
	a.drain_reorder()
}

fn (mut a Arq) drain_reorder() {
	for {
		mut hit := -1
		for i, s in a.reorder {
			if s.off <= a.rcv_nxt && s.off + u64(s.data.len) > a.rcv_nxt {
				hit = i
				break
			}
		}
		if hit < 0 {
			break
		}
		s := a.reorder[hit]
		skip := int(a.rcv_nxt - s.off)
		a.inbox << s.data[skip..].clone()
		a.rcv_nxt += u64(s.data.len - skip)
		a.reorder.delete(hit)
	}
}

// on_packet feeds one received datagram into the state machine.
fn (mut a Arq) on_packet(pkt []u8, now i64) {
	ok, _, body := udp_open(a.key, a.rx_salt, pkt)
	if !ok || body.len < 9 {
		return
	}
	if (body[0] & 0x80) != 0 {
		return
	}
	a.process_ack(be64(body, 1), now)
	if (body[0] & arq_fdata) != 0 && body.len >= 17 {
		a.deliver(be64(body, 9), body[17..].clone())
		a.needack = true
	}
	a.fill_window(now)
}

// tick services timers: RTO retransmit (with backoff), window refill, and any
// owed ack with nothing to piggyback on.
fn (mut a Arq) tick(now i64) {
	if a.unacked.len > 0 && now - a.unacked[0].sent_ms >= a.rto {
		a.rto = if a.rto * 2 > rto_max { rto_max } else { a.rto * 2 } // Karn backoff
		a.retransmit_first(now)
	}
	a.fill_window(now)
	if a.needack {
		a.seal_out(0, 0, []u8{}) // pure ack
	}
}

// poll_out drains the datagrams the conn wants to send.
fn (mut a Arq) poll_out() [][]u8 {
	r := a.outq.clone()
	a.outq = [][]u8{}
	return r
}

// next_timeout is how long (ms) until tick must next run (for the poll timeout).
fn (a &Arq) next_timeout(now i64) i64 {
	if a.unacked.len > 0 {
		due := a.unacked[0].sent_ms + a.rto - now
		return if due < 0 { i64(0) } else { due }
	}
	return i64(1000)
}

// One datagram in flight in the ARQ self-test's simulated channel.
struct SimPkt {
mut:
	due  i64
	to_b bool // destined for endpoint B (came from A); else for A
	data []u8
}

// run_arqtest (`sb __arqtest`): drive a 128KB transfer A->B through a simulated
// 15%-loss, reordering channel (acks lossy too) on a virtual clock, and assert
// the bytes arrive intact and in order. Exercises retransmit, flow window, and
// the reorder buffer end to end -- deterministic (seeded LCG), no sockets.
fn run_arqtest() {
	key := []u8{len: 32, init: u8(index + 9)}
	mut a := new_arq(key, u32(1), u32(2))
	mut b := new_arq(key, u32(2), u32(1))
	n := 128 * 1024
	msg := []u8{len: n, init: u8((index * 131 + 7) & 0xff)}
	mut clock := i64(0)
	a.app_send(msg, clock)
	mut got := []u8{}
	mut flight := []SimPkt{}
	mut rng := u32(0x1234abcd)
	mut steps := 0
	for got.len < n && steps < 4_000_000 {
		steps++
		for p in a.poll_out() {
			rng = rng * u32(1103515245) + u32(12345)
			if (rng >> 16) % 100 < 15 {
				continue // 15% loss A->B
			}
			rng = rng * u32(1103515245) + u32(12345)
			flight << SimPkt{
				due:  clock + 8 + i64((rng >> 16) % 25) // 8ms + up to 24ms jitter -> reorder
				to_b: true
				data: p
			}
		}
		for p in b.poll_out() {
			rng = rng * u32(1103515245) + u32(12345)
			if (rng >> 16) % 100 < 15 {
				continue // 15% loss B->A (acks)
			}
			rng = rng * u32(1103515245) + u32(12345)
			flight << SimPkt{
				due:  clock + 8 + i64((rng >> 16) % 25)
				to_b: false
				data: p
			}
		}
		mut next := clock + 50
		for p in flight {
			if p.due < next {
				next = p.due
			}
		}
		for t in [clock + a.next_timeout(clock), clock + b.next_timeout(clock)] {
			if t < next {
				next = t
			}
		}
		clock = if next <= clock { clock + 1 } else { next }
		mut still := []SimPkt{}
		for p in flight {
			if p.due <= clock {
				if p.to_b {
					b.on_packet(p.data, clock)
				} else {
					a.on_packet(p.data, clock)
				}
			} else {
				still << p
			}
		}
		flight = still.clone()
		a.tick(clock)
		b.tick(clock)
		got << b.take_inbox()
	}
	if got.len == n && got == msg {
		println('ok:   ARQ delivers ${n}B intact over 15% loss + reorder (${clock}ms, ${steps} steps)')
	} else {
		println('FAIL: ARQ delivered ${got.len}/${n}B match=${got == msg} steps=${steps}')
	}
}

// -- Reliable-UDP over a real socket ------------------------------------------
// Drives an Arq over an actual connected UDP socket with a monotonic clock -- the
// bridge from the hermetic state machine to live I/O. (NAT hole punching, which
// gathers candidates and survives NAT, layers on top in establishment.)
const clock_monotonic = 1

// Same layout as `struct timespec` on 64-bit musl (time_t + long, both i64), but
// named to avoid colliding with vlib/os's own `C.timespec` declaration; passed
// to clock_gettime as an opaque pointer.
struct MonoTs {
mut:
	tv_sec  i64
	tv_nsec i64
}

fn C.clock_gettime(clk int, ts voidptr) int

fn monotonic_ms() i64 {
	mut ts := MonoTs{}
	C.clock_gettime(clock_monotonic, voidptr(&ts))
	return ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000
}

// udp_socket binds `local_port` and connects to `peer_ip`:`peer_port` so the
// Arq driver can use read/write. (UDP connect just pins the default peer -- no
// handshake -- so packets sent before the peer binds are simply dropped and the
// ARQ retransmits.)
fn udp_socket(local_port u16, peer_ip string, peer_port u16) int {
	fd := C.socket(af_inet, sock_dgram, 0)
	if fd < 0 {
		return -1
	}
	one := int(1)
	C.setsockopt(fd, sol_socket, so_reuseaddr, voidptr(&one), u32(sizeof(int)))
	mut la := SockaddrIn{
		sin_family: u16(af_inet)
		sin_port:   C.htons(local_port)
	}
	if C.bind(fd, voidptr(&la), u32(sizeof(SockaddrIn))) != 0 {
		C.close(fd)
		return -1
	}
	mut pa := SockaddrIn{
		sin_family: u16(af_inet)
		sin_port:   C.htons(peer_port)
	}
	if C.inet_pton(af_inet, peer_ip.str, voidptr(&pa.sin_addr)) != 1
		|| C.connect(fd, voidptr(&pa), u32(sizeof(SockaddrIn))) != 0 {
		C.close(fd)
		return -1
	}
	return fd
}

// arq_flush drains the Arq's outbound queue to the connected socket.
fn arq_flush(fd int, mut a Arq) {
	for pkt in a.poll_out() {
		C.write(fd, pkt.data, usize(pkt.len))
	}
}

// arq_service does one poll/recv/tick cycle on a connected socket.
fn arq_service(fd int, mut a Arq, mut buf []u8) {
	arq_flush(fd, mut a)
	mut pfd := Pollfd{
		fd:     fd
		events: pollin
	}
	C.poll(voidptr(&pfd), 1, int(a.next_timeout(monotonic_ms())))
	if (pfd.revents & pollin) != 0 {
		n := C.read(fd, buf.data, usize(buf.len))
		if n > 0 {
			a.on_packet(buf[..int(n)], monotonic_ms())
		}
	}
	a.tick(monotonic_ms())
}

// arq_pump_send drives an Arq sender over a connected socket until everything is
// acked (or a 30s safety deadline), feeding it the deterministic test stream.
fn arq_pump_send(fd int, mut a Arq, total int) {
	a.app_send([]u8{len: total, init: u8((index * 131 + 7) & 0xff)}, monotonic_ms())
	mut buf := []u8{len: 2048}
	deadline := monotonic_ms() + 30000
	for (a.pending.len > 0 || a.unacked.len > 0) && monotonic_ms() < deadline {
		arq_service(fd, mut a, mut buf)
	}
	arq_flush(fd, mut a) // push final acks/data
}

// arq_pump_recv drives an Arq receiver until `total` bytes arrive, then lingers
// briefly re-acking so the sender learns the final segment landed. Returns
// whether the received bytes matched the deterministic test stream.
fn arq_pump_recv(fd int, mut a Arq, total int) bool {
	expect := []u8{len: total, init: u8((index * 131 + 7) & 0xff)}
	mut got := []u8{}
	mut buf := []u8{len: 2048}
	deadline := monotonic_ms() + 30000
	for got.len < total && monotonic_ms() < deadline {
		arq_service(fd, mut a, mut buf)
		got << a.take_inbox()
	}
	grace := monotonic_ms() + 300
	for monotonic_ms() < grace {
		arq_service(fd, mut a, mut buf)
	}
	return got == expect
}

// `sb __arqsend <peer_ip> <peer_port> <local_port> <total> <seed>` (self-test).
@[noreturn]
fn run_arqsend(peer_ip string, peer_port u16, local_port u16, total int, seed int) {
	fd := udp_socket(local_port, peer_ip, peer_port)
	if fd < 0 {
		die('arqsend: socket')
	}
	mut a := new_arq([]u8{len: 32, init: u8(index * 7 + seed)}, u32(1), u32(2))
	arq_pump_send(fd, mut a, total)
	println('SENT:${total}')
	C.close(fd)
	exit(0)
}

// `sb __arqrecv <local_port> <peer_ip> <peer_port> <total> <seed>` (self-test).
@[noreturn]
fn run_arqrecv(local_port u16, peer_ip string, peer_port u16, total int, seed int) {
	fd := udp_socket(local_port, peer_ip, peer_port)
	if fd < 0 {
		die('arqrecv: socket')
	}
	mut a := new_arq([]u8{len: 32, init: u8(index * 7 + seed)}, u32(2), u32(1))
	ok := arq_pump_recv(fd, mut a, total)
	println(if ok { 'RECV:${total}:OK' } else { 'RECV:?:MISMATCH' })
	C.close(fd)
	exit(0)
}

// -- NAT traversal: candidate gathering + hole punching -----------------------
// Peers exchange candidates via in-band signaling, then send authenticated
// control PINGs to every peer candidate at once. NAT mappings open from the
// outbound sends; the first candidate an authenticated packet returns from is
// nominated and the socket connected to it for the Arq. If no pair completes
// (symmetric NAT on both sides), the peers just stay in-band.
const ctl_ping = u8(0x80) // control flags carry bit7 so the Arq drops them as non-data
const ctl_pong = u8(0x81)

fn make_sa(ip string, port u16) SockaddrIn {
	mut sa := SockaddrIn{
		sin_family: u16(af_inet)
		sin_port:   C.htons(port)
	}
	C.inet_pton(af_inet, ip.str, voidptr(&sa.sin_addr))
	return sa
}

fn sa_ip(sa &SockaddrIn) string {
	mut b := [4]u8{}
	unsafe {
		p := &u8(&sa.sin_addr) // network-order address bytes
		b[0], b[1], b[2], b[3] = p[0], p[1], p[2], p[3]
	}
	return '${b[0]}.${b[1]}.${b[2]}.${b[3]}'
}

// udp_bind binds an UNCONNECTED UDP socket on local_port (0 = ephemeral) for
// hole punching (sendto/recvfrom across multiple peer candidates).
fn udp_bind(local_port u16) int {
	fd := C.socket(af_inet, sock_dgram, 0)
	if fd < 0 {
		return -1
	}
	one := int(1)
	C.setsockopt(fd, sol_socket, so_reuseaddr, voidptr(&one), u32(sizeof(int)))
	mut sa := SockaddrIn{
		sin_family: u16(af_inet)
		sin_port:   C.htons(local_port)
	}
	if C.bind(fd, voidptr(&sa), u32(sizeof(SockaddrIn))) != 0 {
		C.close(fd)
		return -1
	}
	return fd
}

// local_ip returns this host's primary IPv4 -- the route's source address, found
// by connecting a throwaway UDP socket (no packets sent) and reading getsockname.
// This is the host candidate.
fn local_ip() string {
	fd := C.socket(af_inet, sock_dgram, 0)
	if fd < 0 {
		return '0.0.0.0'
	}
	mut dst := make_sa('8.8.8.8', 53)
	C.connect(fd, voidptr(&dst), u32(sizeof(SockaddrIn)))
	mut me := SockaddrIn{}
	mut l := u32(sizeof(SockaddrIn))
	r := C.getsockname(fd, voidptr(&me), voidptr(&l))
	C.close(fd)
	return if r == 0 { sa_ip(&me) } else { '0.0.0.0' }
}

// stun_on_socket runs a STUN Binding query over an EXISTING unconnected socket so
// the reflexive mapping matches the socket the channel will use. The srflx candidate.
fn stun_on_socket(fd int, stun_ip string, stun_port u16) (bool, string, u16) {
	mut srv := make_sa(stun_ip, stun_port)
	txid := urandom(12)
	req := stun_build_request(txid)
	C.sendto(fd, req.data, usize(req.len), 0, voidptr(&srv), u32(sizeof(SockaddrIn)))
	mut pfd := Pollfd{
		fd:     fd
		events: pollin
	}
	if C.poll(voidptr(&pfd), 1, 1000) <= 0 {
		return false, '', 0
	}
	mut from := SockaddrIn{}
	mut flen := u32(sizeof(SockaddrIn))
	mut buf := []u8{len: 512}
	n := C.recvfrom(fd, buf.data, usize(buf.len), 0, voidptr(&from), voidptr(&flen))
	if n < 20 {
		return false, '', 0
	}
	return stun_parse_response(buf[..int(n)], txid)
}

// Backhaul: the NON-BLOCKING UDP backhaul state machine -- hole punch then
// reliable Arq -- that the pump's poll loop steps via tick/on_udp/next_timeout
// (no event loop of its own, so it folds into run_mux_pump's existing poll set).
//   gathering: mux only -- STUN the offered servers on the punch socket to learn a
//              server-reflexive candidate, then emit the UP:A answer -> punching.
//              Skipped (answer host-only) when the offer named no STUN servers.
//   punching: PING every peer candidate ~every 200ms; the first authenticated
//             control reply nominates that source (connect) -> up.
//   up:       the Arq carries the framed byte stream; flush() drains it to the
//             (now-connected) socket.
//   failed:   budget elapsed with no pair -- caller stays in-band.
const bh_hb_ms = i64(5000) // heartbeat cadence once .up -- refreshes both NAT mappings + proves liveness
const bh_dead_ms = i64(20000) // no packet received for this long once .up -> path dead -> revert in-band

enum BhState {
	inactive  // zero value -- no backhaul (Backhaul{} placeholder)
	gathering // mux-side: collecting a STUN srflx on the punch socket before answering
	punching
	up
	reverting // path died while up: draining the lossless in-band handoff (see begin_revert)
	failed
}

const bh_gather_ms = i64(750) // budget to collect a STUN srflx before answering host-only
const bh_stun_rtx_ms = i64(250) // STUN Binding Request retransmit cadence while gathering
const bh_punch_ms = i64(8000) // hole-punch budget once answering -- no pair by then -> fail -> in-band

struct Backhaul {
mut:
	fd        int
	key       []u8
	tx_salt   u32
	rx_salt   u32
	cands     []SockaddrIn
	state     BhState // zero value = .inactive
	deadline  i64
	next_ping i64
	pseq      u64     // control-packet nonce counter (distinct seq space from the Arq)
	last_rx   i64     // monotonic ms of the last received packet (liveness, once .up)
	next_hb   i64     // when to send the next heartbeat (once .up)
	tx_comp   voidptr // streaming raw-DEFLATE compressor (frame layer -> ARQ)
	rx_comp   voidptr // streaming raw-DEFLATE decompressor (ARQ -> frame layer)
	// mux-side srflx gathering (.gathering): query the offered STUN servers on the
	// punch socket itself (the mapping is per-socket) so a NAT'd mux advertises its
	// public address. Non-blocking -- driven by the pump's poll loop, not stun_query.
	stun_servers    []SockaddrIn // STUN observers carried in the offer
	stun_txid       []u8         // transaction id for this gather burst
	stun_req        []u8         // prebuilt 20-byte Binding Request (resent at bh_stun_rtx_ms)
	next_stun       i64          // when to (re)send the STUN burst
	gather_deadline i64          // when to give up waiting for a srflx and answer host-only
	srflx           IpPort       // discovered server-reflexive candidate (empty ip = none yet)
	answer_nonce    []u8         // the offer nonce, echoed in our UP:A once gathering resolves
	override_cands  []IpPort     // non-empty: use instead of auto-computed host+srflx in answer
	arq             Arq
	// Lossless-revert bookkeeping (mirror of the Python UdpBackhaul). `sent` is a
	// FIFO of up-frames submitted to the backhaul but not yet provably consumed by
	// the wrapper, pruned as the ARQ acks their compressed byte ranges; on revert
	// the tail the wrapper never got is re-sent in-band. Frame numbering is implicit:
	// sent[i] is frame number tx_base + i. `rx_frames` counts down-frames delivered
	// from the wrapper (so we can tell it, in-band, what we already have).
	sent      []FrameRec
	tx_off    i64  // running compressed-stream byte offset (compressed bytes sent upstream)
	tx_base   int  // frame number of sent[0]
	rx_frames int  // down-frames delivered up to the handler
	rx_bytes  i64  // raw bytes received from wrapper over UDP (for status reporting)
	resent    bool // our tail was re-sent in-band exactly once
	uframe    []u8 // reassembly buffer for length-prefixed RAW frames off the stream
}

// FrameRec pairs a sent frame with the compressed-stream offset at its end, so the
// ARQ's cumulative ack (a byte offset) prunes whole frames from the revert FIFO.
struct FrameRec {
mut:
	end_off i64
	frame   []u8
}

fn new_backhaul(fd int, key []u8, tx_salt u32, rx_salt u32, cands []SockaddrIn, now i64, budget_ms i64) Backhaul {
	return Backhaul{
		fd:        fd
		key:       key.clone()
		tx_salt:   tx_salt
		rx_salt:   rx_salt
		cands:     cands.clone()
		state:     .punching
		deadline:  now + budget_ms
		next_ping: now
		tx_comp:   C.sb_deflate_new()
		rx_comp:   C.sb_inflate_new()
		arq:       new_arq(key, tx_salt, rx_salt)
	}
}

// close_comp frees the streaming compressor pair (call once, before discarding
// the Backhaul on revert; the test runners just exit and let the OS reclaim).
fn (mut b Backhaul) close_comp() {
	if b.tx_comp != unsafe { nil } {
		C.sb_deflate_close(b.tx_comp)
		b.tx_comp = unsafe { nil }
	}
	if b.rx_comp != unsafe { nil } {
		C.sb_inflate_close(b.rx_comp)
		b.rx_comp = unsafe { nil }
	}
}

fn (mut b Backhaul) flush() {
	for pkt in b.arq.poll_out() {
		C.write(b.fd, pkt.data, usize(pkt.len))
	}
}

fn (mut b Backhaul) tick(now i64) {
	if b.state == .gathering {
		if now >= b.gather_deadline {
			b.emit_answer(now) // no srflx in time -> answer host-only, start punching
			return
		}
		if now >= b.next_stun {
			for s in b.stun_servers {
				mut sa := s
				C.sendto(b.fd, b.stun_req.data, usize(b.stun_req.len), 0, voidptr(&sa),
					u32(sizeof(SockaddrIn)))
			}
			b.next_stun = now + bh_stun_rtx_ms
		}
		return
	}
	if b.state == .punching {
		if now >= b.deadline {
			b.state = .failed
			return
		}
		if now >= b.next_ping {
			ping := udp_seal(b.key, b.tx_salt, b.pseq, [ctl_ping])
			b.pseq++
			for c in b.cands {
				mut ca := c
				C.sendto(b.fd, ping.data, usize(ping.len), 0, voidptr(&ca), u32(sizeof(SockaddrIn)))
			}
			b.next_ping = now + 200
		}
	} else if b.state == .up {
		if now - b.last_rx > bh_dead_ms {
			b.begin_revert(now) // UDP path went silent -> lossless in-band handoff
			return
		}
		if now >= b.next_hb {
			hb := udp_seal(b.key, b.tx_salt, b.pseq, [ctl_ping]) // keepalive (peer's Arq drops it)
			b.pseq++
			C.write(b.fd, hb.data, usize(hb.len)) // socket is connected once .up
			b.next_hb = now + bh_hb_ms
		}
		b.arq.tick(now)
		b.flush()
		b.prune()
	}
}

// on_udp feeds one received datagram + its source address into the machine.
fn (mut b Backhaul) on_udp(pkt []u8, src SockaddrIn, now i64) {
	if b.state == .gathering {
		// STUN responses are unauthenticated (sent before the channel exists); the
		// txid match is the only binding. The wrapper does not punch until it has our
		// answer, so nothing else can arrive on this socket yet -- no ambiguity.
		ok, ip, port := stun_parse_response(pkt, b.stun_txid)
		if ok {
			b.srflx = IpPort{ip, port}
			b.gather_deadline = now // first reply is authoritative -> answer on the next tick
		}
		return
	}
	if b.state == .up {
		b.last_rx = now // any packet (data, ack, heartbeat) proves the path is alive
		b.arq.on_packet(pkt, now)
		b.flush()
		b.prune() // acks advanced -> drop confirmed frames from the revert FIFO
		return
	}
	if b.state != .punching {
		return
	}
	ok, _, body := udp_open(b.key, b.rx_salt, pkt)
	if !ok || body.len < 1 || (body[0] & 0x80) == 0 {
		return
	}
	mut s := src
	if body[0] == ctl_ping {
		pong := udp_seal(b.key, b.tx_salt, b.pseq, [ctl_pong])
		b.pseq++
		C.sendto(b.fd, pong.data, usize(pong.len), 0, voidptr(&s), u32(sizeof(SockaddrIn)))
	}
	C.connect(b.fd, voidptr(&s), u32(sizeof(SockaddrIn))) // nominate this pair
	b.state = .up
	b.last_rx = now
	b.next_hb = now + bh_hb_ms
}

// send compresses framed bytes onto the reliable stream (no-op until up). The
// stream compressor sits above the ARQ: order is guaranteed, so the cross-chunk
// dictionary is valid for the whole session.
fn (mut b Backhaul) send(data []u8, now i64) {
	if b.state == .up && data.len > 0 {
		b.arq.app_send(deflate_chunk(b.tx_comp, data), now)
		b.flush()
	}
}

// recv drains in-order bytes from the peer and inflates them back to frame bytes.
fn (mut b Backhaul) recv() []u8 {
	if b.state != .up {
		return []u8{}
	}
	raw := b.arq.take_inbox()
	return if raw.len > 0 { inflate_chunk(b.rx_comp, raw) } else { []u8{} }
}

// recv_frames reassembles the inflated byte stream into whole RAW down-frames
// ([u32 BE len][frame]...), counting each toward rx_frames so a revert can tell the
// wrapper exactly how many we consumed. The reassembly buffer lives on the Backhaul,
// so it is discarded with it on revert -- a renegotiated backhaul starts clean.
fn (mut b Backhaul) recv_frames() [][]u8 {
	inb := b.recv()
	if inb.len > 0 {
		b.uframe << inb
	}
	mut out := [][]u8{}
	for b.uframe.len >= 4 {
		flen := int(u32(b.uframe[0]) << 24 | u32(b.uframe[1]) << 16 | u32(b.uframe[2]) << 8 | u32(b.uframe[3]))
		if b.uframe.len < 4 + flen {
			break // frame split across datagrams -- wait for the rest
		}
		out << b.uframe[4..4 + flen].clone()
		b.uframe = b.uframe[4 + flen..].clone()
		b.rx_frames++ // whole down-frame consumed -> tell the wrapper on revert
	}
	return out
}

// enqueue_frame sends one up-frame over the backhaul (length-prefixed, compressed
// onto the reliable stream) AND records it in the revert FIFO with its end offset.
fn (mut b Backhaul) enqueue_frame(frame []u8, now i64) {
	mut rec := []u8{cap: 4 + frame.len}
	put_be32(mut rec, u32(frame.len))
	rec << frame
	comp := deflate_chunk(b.tx_comp, rec)
	b.tx_off += i64(comp.len)
	b.sent << FrameRec{b.tx_off, frame.clone()}
	b.arq.app_send(comp, now)
	b.flush()
}

// hold_frame queues a frame produced while the dead path drains (.reverting): it is
// not transmitted now but kept in the FIFO so it re-sends in-band behind the tail.
fn (mut b Backhaul) hold_frame(frame []u8) {
	b.sent << FrameRec{b.tx_off, frame.clone()}
}

// prune drops sent frames the ARQ has fully acked (a safe lower bound on what the
// wrapper received) so the FIFO holds only in-flight frames in steady state.
fn (mut b Backhaul) prune() {
	for b.sent.len > 0 && b.sent[0].end_off <= i64(b.arq.snd_una()) {
		b.sent.delete(0)
		b.tx_base++
	}
}

// begin_revert enters the draining state and tells the wrapper, in-band, how many
// of its down-frames we have consumed so it re-sends only the tail we never got.
// The UDP socket is left open but the pump stops polling it (the fds[4] gate omits
// .reverting); the handoff completes when the wrapper's UP:RX arrives on fd0.
fn (mut b Backhaul) begin_revert(now i64) {
	if b.state != .up {
		return
	}
	b.state = .reverting
	b.prune()
	rx := build_apc('UP:RX:${b.rx_frames}'.bytes())
	write1(unsafe { &rx[0] }, i64(rx.len))
}

// peer_revert handles the wrapper's UP:RX (it is reverting and has consumed `n` of
// our up-frames): re-send frames numbered >= n -- the tail it never got -- in-band,
// exactly once. The caller then tears the backhaul down (back to in-band).
fn (mut b Backhaul) peer_revert(n int, now i64) {
	if b.state == .up {
		b.begin_revert(now) // wrapper noticed first -- mirror into the drain
	}
	if b.state != .reverting || b.resent {
		return
	}
	b.resent = true
	start := if n > b.tx_base { n - b.tx_base } else { 0 }
	for i in start .. b.sent.len {
		out := build_apc(b.sent[i].frame)
		write1(unsafe { &out[0] }, i64(out.len))
	}
}

// next_timeout: ms until tick must next run (drives the pump's poll timeout).
fn (b &Backhaul) next_timeout(now i64) i64 {
	return match b.state {
		.gathering {
			ns := if b.next_stun > now { b.next_stun - now } else { i64(0) }
			gd := if b.gather_deadline > now { b.gather_deadline - now } else { i64(0) }
			if ns < gd {
				ns
			} else {
				gd
			} // wake for the next of: STUN resend, gather deadline
		}
		.punching {
			if b.next_ping > now {
				b.next_ping - now
			} else {
				i64(0)
			}
		}
		.up {
			at := b.arq.next_timeout(now)
			hb := if b.next_hb > now { b.next_hb - now } else { i64(0) }
			if hb < at {
				hb
			} else {
				at
			} // wake for the next of: ARQ timer, heartbeat
		}
		.inactive, .failed, .reverting {
			i64(1000)
		} // .reverting waits on fd0 (in-band UP:RX)
	}
}

// bh_step does one poll/recvfrom cycle on a Backhaul's own socket (the self-test
// driver; the live pump steps tick/on_udp/next_timeout inside its own poll set).
fn bh_step(mut b Backhaul, mut buf []u8) {
	now := monotonic_ms()
	b.tick(now)
	mut pfd := Pollfd{
		fd:     b.fd
		events: pollin
	}
	C.poll(voidptr(&pfd), 1, int(b.next_timeout(now)))
	if (pfd.revents & pollin) != 0 {
		mut sa := SockaddrIn{}
		mut slen := u32(sizeof(SockaddrIn))
		n := C.recvfrom(b.fd, buf.data, usize(buf.len), 0, voidptr(&sa), voidptr(&slen))
		if n > 0 {
			b.on_udp(buf[..int(n)], sa, monotonic_ms())
		}
	}
}

// `sb __punchsend <local_port> <peer_ip> <peer_port> <total> <seed>` (self-test):
// punch to the peer (poll-driven Backhaul), then reliably send `total` bytes.
@[noreturn]
fn run_punchsend(local_port u16, peer_ip string, peer_port u16, total int, seed int) {
	fd := udp_bind(local_port)
	if fd < 0 {
		die('punchsend: bind')
	}
	key := []u8{len: 32, init: u8(index * 7 + seed)}
	mut b := new_backhaul(fd, key, u32(1), u32(2), [make_sa(peer_ip, peer_port)], monotonic_ms(),
		5000)
	mut buf := []u8{len: 2048}
	mut sent := false
	deadline := monotonic_ms() + 30000
	for monotonic_ms() < deadline {
		if b.state == .failed {
			println('PUNCH:FAIL')
			exit(1)
		}
		if b.state == .up && !sent {
			b.send([]u8{len: total, init: u8((index * 131 + 7) & 0xff)}, monotonic_ms())
			sent = true
		}
		if sent && b.arq.pending.len == 0 && b.arq.unacked.len == 0 {
			break
		}
		bh_step(mut b, mut buf)
	}
	b.flush()
	println('SENT:${total}')
	C.close(fd)
	exit(0)
}

// `sb __punchrecv <local_port> <peer_ip> <peer_port> <total> <seed>` (self-test).
@[noreturn]
fn run_punchrecv(local_port u16, peer_ip string, peer_port u16, total int, seed int) {
	fd := udp_bind(local_port)
	if fd < 0 {
		die('punchrecv: bind')
	}
	key := []u8{len: 32, init: u8(index * 7 + seed)}
	mut b := new_backhaul(fd, key, u32(2), u32(1), [make_sa(peer_ip, peer_port)], monotonic_ms(),
		5000)
	expect := []u8{len: total, init: u8((index * 131 + 7) & 0xff)}
	mut got := []u8{}
	mut buf := []u8{len: 2048}
	deadline := monotonic_ms() + 30000
	for got.len < total && monotonic_ms() < deadline {
		if b.state == .failed {
			println('PUNCH:FAIL')
			exit(1)
		}
		bh_step(mut b, mut buf)
		got << b.recv()
	}
	grace := monotonic_ms() + 300 // keep acking so the sender learns the last segment landed
	for monotonic_ms() < grace {
		bh_step(mut b, mut buf)
		got << b.recv()
	}
	println(if got == expect { 'RECV:${total}:OK' } else { 'RECV:?:MISMATCH' })
	C.close(fd)
	exit(0)
}

// `sb __cands <local_port> <stun_ip> <stun_port>` (smoke test): print this
// socket's host + srflx candidates (the latter via a real STUN server).
@[noreturn]
fn run_cands(local_port u16, stun_ip string, stun_port u16) {
	fd := udp_bind(local_port)
	if fd < 0 {
		die('cands: bind')
	}
	println('HOST:${local_ip()}:${local_port}')
	ok, ip, port := stun_on_socket(fd, stun_ip, stun_port)
	line := if ok { 'SRFLX:${ip}:${port}' } else { 'SRFLX:FAIL' }
	println(line)
	C.close(fd)
	exit(0)
}

// -- UPGRADE signaling (offer / answer) ---------------------------------------
// The wrapper offers an upgrade to a capable mux over the in-band APC channel;
// the mux answers with its own candidates; both then hole_punch with the shared
// PSK. Messages are a compact binary blob, base64'd to ride the text APC wire
// (NO raw bytes in-band). The pump (increment 5) frames these as `UP:O:<b64>` /
// `UP:A:<b64>` and triggers gather->punch->Arq; this layer is just the codec.
//
// Offer blob:  [ver:1=0x01][type:1='O'][psk:32][nonce:8][n_stun:1][stun: nx6]
//              [n_cand:1][cands: nx6]   where each ip:port is [ip4:4][port:2 BE]
// Answer blob: [ver:1=0x01][type:1='A'][nonce:8][n_cand:1][cands: nx6]
struct IpPort {
	ip   string
	port u16
}

fn put_ipport(mut o []u8, c IpPort) {
	p := c.ip.split('.')
	o << u8(p[0].int())
	o << u8(p[1].int())
	o << u8(p[2].int())
	o << u8(p[3].int())
	o << u8(c.port >> 8)
	o << u8(c.port)
}

fn read_ipport(b []u8, off int) IpPort {
	return IpPort{
		ip:   '${b[off]}.${b[off + 1]}.${b[off + 2]}.${b[off + 3]}'
		port: u16(b[off + 4]) << 8 | u16(b[off + 5])
	}
}

// read a length-prefixed candidate list at `off`; returns (cands, next_off, ok).
fn read_cands(b []u8, off int) ([]IpPort, int, bool) {
	if off >= b.len {
		return []IpPort{}, off, false
	}
	n := int(b[off])
	mut o := off + 1
	if o + n * 6 > b.len {
		return []IpPort{}, off, false
	}
	mut cs := []IpPort{}
	for _ in 0 .. n {
		cs << read_ipport(b, o)
		o += 6
	}
	return cs, o, true
}

fn encode_offer(psk []u8, nonce []u8, stun []IpPort, cands []IpPort) string {
	mut b := [u8(0x01), `O`]
	b << psk[..32]
	b << nonce[..8]
	b << u8(stun.len)
	for s in stun {
		put_ipport(mut b, s)
	}
	b << u8(cands.len)
	for c in cands {
		put_ipport(mut b, c)
	}
	return base64.encode(b)
}

fn decode_offer(s string) (bool, []u8, []u8, []IpPort, []IpPort) {
	b := b64_decode(s) or { return false, []u8{}, []u8{}, []IpPort{}, []IpPort{} }
	if b.len < 42 || b[0] != 0x01 || b[1] != `O` {
		return false, []u8{}, []u8{}, []IpPort{}, []IpPort{}
	}
	psk := b[2..34].clone()
	nonce := b[34..42].clone()
	stun, off, ok1 := read_cands(b, 42)
	if !ok1 {
		return false, []u8{}, []u8{}, []IpPort{}, []IpPort{}
	}
	cands, _, ok2 := read_cands(b, off)
	if !ok2 {
		return false, []u8{}, []u8{}, []IpPort{}, []IpPort{}
	}
	return true, psk, nonce, stun, cands
}

fn encode_answer(nonce []u8, cands []IpPort) string {
	mut b := [u8(0x01), `A`]
	b << nonce[..8]
	b << u8(cands.len)
	for c in cands {
		put_ipport(mut b, c)
	}
	return base64.encode(b)
}

fn decode_answer(s string) (bool, []u8, []IpPort) {
	b := b64_decode(s) or { return false, []u8{}, []IpPort{} }
	if b.len < 10 || b[0] != 0x01 || b[1] != `A` {
		return false, []u8{}, []IpPort{}
	}
	nonce := b[2..10].clone()
	cands, _, ok := read_cands(b, 10)
	if !ok {
		return false, []u8{}, []IpPort{}
	}
	return true, nonce, cands
}

// run_sigtest (`sb __sigtest`): UPGRADE offer/answer codec round-trip + rejection.
fn run_sigtest() {
	psk := urandom(32)
	nonce := urandom(8)
	stun := [IpPort{'162.159.207.0', 3478}, IpPort{'74.125.250.129', 19302}]
	cands := [IpPort{'192.168.1.5', 50000}, IpPort{'96.248.19.84', 64218}]
	ok, p2, n2, s2, c2 := decode_offer(encode_offer(psk, nonce, stun, cands))
	if ok && p2 == psk && n2 == nonce && s2 == stun && c2 == cands {
		println('ok:   offer round-trips (PSK + nonce + ${s2.len} STUN + ${c2.len} cands)')
	} else {
		println('FAIL: offer round-trip ok=${ok}')
	}
	acands := [IpPort{'10.0.0.7', 40000}]
	aok, an2, ac2 := decode_answer(encode_answer(nonce, acands))
	if aok && an2 == nonce && ac2 == acands {
		println('ok:   answer round-trips (nonce echo + ${ac2.len} cand)')
	} else {
		println('FAIL: answer round-trip aok=${aok}')
	}
	enc := encode_offer(psk, nonce, stun, cands)
	rok, _, _, _, _ := decode_offer(enc[..10]) // truncated
	tok, _, _, _, _ := decode_offer('not-valid-base64!!')
	if !rok && !tok {
		println('ok:   truncated / malformed offers rejected')
	} else {
		println('FAIL: bad offer accepted (trunc=${rok} malformed=${tok})')
	}
}

// -- Stream DEFLATE (raw, persistent dictionary) -- zlib shim csrc/sb_deflate.c --
// One compressor + one decompressor per direction live in the Backhaul; each
// chunk sync-flushes so the peer inflates promptly while the cross-chunk
// dictionary is retained. Sits between the frame layer and the ARQ byte stream.
fn C.sb_deflate_new() voidptr
fn C.sb_inflate_new() voidptr
fn C.sb_deflate_close(h voidptr)
fn C.sb_inflate_close(h voidptr)
fn C.sb_deflate_chunk(h voidptr, src &u8, src_len usize, out_len &usize) &u8
fn C.sb_inflate_chunk(h voidptr, src &u8, src_len usize, out_len &usize) &u8
fn C.sb_zfree(p voidptr)

// deflate_chunk compresses `data` (Z_SYNC_FLUSH) with the streaming compressor `c`.
fn deflate_chunk(c voidptr, data []u8) []u8 {
	if data.len == 0 {
		return []u8{}
	}
	mut olen := usize(0)
	p := C.sb_deflate_chunk(c, data.data, usize(data.len), &olen)
	if p == unsafe { nil } {
		return []u8{}
	}
	res := unsafe { p.vbytes(int(olen)) }.clone()
	C.sb_zfree(p)
	return res
}

// inflate_chunk expands `data` with the streaming decompressor `c`.
fn inflate_chunk(c voidptr, data []u8) []u8 {
	if data.len == 0 {
		return []u8{}
	}
	mut olen := usize(0)
	p := C.sb_inflate_chunk(c, data.data, usize(data.len), &olen)
	if p == unsafe { nil } {
		return []u8{}
	}
	res := unsafe { p.vbytes(int(olen)) }.clone()
	C.sb_zfree(p)
	return res
}

// run_deflatetest (`sb __deflatetest`): a streaming compress->inflate round-trip,
// plus a check that the persistent dictionary shrinks a repeated chunk.
fn run_deflatetest() {
	c := C.sb_deflate_new()
	d := C.sb_inflate_new()
	if c == unsafe { nil } || d == unsafe { nil } {
		println('FAIL: zlib init')
		return
	}
	msg := 'R7:D:3:abcdefgh'.repeat(400).bytes() // repetitive -> compresses well
	comp := deflate_chunk(c, msg)
	back := inflate_chunk(d, comp)
	if back == msg && comp.len < msg.len {
		println('ok:   deflate round-trip (${msg.len}B -> ${comp.len}B -> ${back.len}B)')
	} else {
		println('FAIL: deflate round-trip match=${back == msg} comp=${comp.len} orig=${msg.len}')
	}
	comp2 := deflate_chunk(c, msg) // same chunk again -- the dictionary already has it
	back2 := inflate_chunk(d, comp2)
	if back2 == msg && comp2.len < comp.len {
		println('ok:   persistent dictionary (2nd ${comp2.len}B < 1st ${comp.len}B)')
	} else {
		println('FAIL: dictionary 2nd=${comp2.len} 1st=${comp.len} match=${back2 == msg}')
	}
	C.sb_deflate_close(c)
	C.sb_inflate_close(d)
}

// run_cryptotest (`sb __cryptotest`): a NIST AES-128-GCM known-answer vector
// plus AES-256 round-trip / tamper / AAD-mismatch checks. Prints `ok:`/`FAIL:`
// lines for the self-test harness.
fn run_cryptotest() {
	// NIST GCM test case 2: all-zero 128-bit key, 96-bit zero IV, 16-byte zero PT.
	exp_ct := [u8(0x03), 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71,
		0xb2, 0xfe, 0x78]
	exp_tag := [u8(0xab), 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12,
		0x57, 0xbd, 0xdf]
	mut pt := []u8{len: 16}
	ktag := aead_seal([]u8{len: 16}, []u8{len: 12}, []u8{}, mut pt)
	if pt == exp_ct && ktag == exp_tag {
		println('ok:   AES-128-GCM NIST known-answer vector')
	} else {
		println('FAIL: AES-128-GCM known-answer vector mismatch')
	}
	// AES-256 round-trip with AAD over a non-block-aligned message.
	key := []u8{len: 32, init: u8(index + 1)}
	iv := []u8{len: 12, init: u8(0xa0 + index)}
	aad := 'sb-aead'.bytes()
	msg := 'the quick brown fox jumps over 13 lazy dogs'.bytes()
	mut buf := msg.clone()
	t := aead_seal(key, iv, aad, mut buf)
	if buf == msg {
		println('FAIL: AES-256-GCM ciphertext == plaintext')
	}
	if aead_open(key, iv, aad, mut buf, t) && buf == msg {
		println('ok:   AES-256-GCM round-trip (+AAD, unaligned)')
	} else {
		println('FAIL: AES-256-GCM round-trip did not recover plaintext')
	}
	// A flipped tag byte must fail authentication.
	mut buf2 := msg.clone()
	mut bad := aead_seal(key, iv, aad, mut buf2)
	bad[0] ^= 0xff
	if aead_open(key, iv, aad, mut buf2, bad) {
		println('FAIL: forged tag accepted')
	} else {
		println('ok:   tampered tag rejected')
	}
	// AAD mismatch must also fail.
	mut buf3 := msg.clone()
	t3 := aead_seal(key, iv, aad, mut buf3)
	if aead_open(key, iv, 'wrong-aad'.bytes(), mut buf3, t3) {
		println('FAIL: AAD mismatch accepted')
	} else {
		println('ok:   AAD mismatch rejected')
	}
}

// sb is a multi-call binary. main() routes by argv[0]/argv[1]:
//   sb mux [--token=...] [--exec=...]      -- the persistent per-host multiplexer
//   sb fetch / run / token / inject    -- protocol subcommands
//   <symlink>                          -- busybox-style PATH dispatch (argv[0] != sb)
fn main() {
	// The `__xxx` hooks and their exclusive helpers (the run_*test/probe/serve
	// drivers, plus codecs only they reach -- e.g. blocking `stun_query`, the
	// reverse-direction `encode_offer`/`decode_answer`) exist ONLY for the V
	// self-test suite. Gate the entire dispatch behind `-d sb_test`: a `-prod`
	// build (no flag) makes every test-only fn unreachable, so `-skip-unused` +
	// `--gc-sections` sweep them out of the shipped binary. Every byte rides the
	// wire, so the production `sb` carries no test scaffolding. Build the test
	// binary with `v -d sb_test ...` (see check.sh).
	$if sb_test ? {
		if os.args.len >= 2 && os.args[1] == '__muxscan' {
			run_muxscan()
		}
		// Self-test hook: `sb __fetchtest <token> <name> <outpath> [os] [arch]` runs
		// one FILEREQ transaction (request -> stdout, response <- stdin), writing the
		// cache file; status to stderr. Deterministic, pty-free.
		if os.args.len >= 5 && os.args[1] == '__fetchtest' {
			o := if os.args.len > 5 { os.args[5] } else { '' }
			a := if os.args.len > 6 { os.args[6] } else { '' }
			st := filereq(os.args[2], os.args[3], 0, o, a, os.args[4], false) // tty test
			eprintln('status=${st}')
			C._exit(0)
		}
		// Self-test hook: `sb __resolvetest <manifest> <name> [os] [arch]` prints the
		// resolved `<path>\t<mtime>\t<exec>[\t<link>]` (or `MISS`). The link field is
		// appended only for a symlink entry (the busybox-style dedup terminal).
		if os.args.len >= 4 && os.args[1] == '__resolvetest' {
			text := os.read_file(os.args[2]) or { '' }
			o := if os.args.len > 4 { os.args[4] } else { '' }
			a := if os.args.len > 5 { os.args[5] } else { '' }
			ok, path, ent := resolve_manifest(parse_manifest(text), os.args[3], o, a)
			mut out := '${path}\t${ent.mtime}\t${ent.exec}'
			if ent.link != '' {
				out += '\t${ent.link}'
			}
			println(if ok { out } else { 'MISS' })
			C._exit(0)
		}
		// Self-test hook: `sb __bintest <bindir> <self> <manifest>` populates the
		// dispatch dir from a manifest file. The harness inspects the dir with the
		// shell afterward (not os.ls -- see populate_bin's same-process caveat).
		if os.args.len >= 5 && os.args[1] == '__bintest' {
			populate_bin(os.args[2], os.args[3], os.read_file(os.args[4]) or { '' })
			C._exit(0)
		}
		// Self-test hook: `sb __linktest <name>` exercises ensure_cached's busybox-style
		// symlink branch. SB_CACHE must be pre-staged with a manifest + an already-current
		// terminal file, so NO FILEREQ fires (present-and-current path) and we test only
		// terminal-fetch-skip + local link materialization. Prints `<cp>\t<target>` where
		// target is the link's real path basename, or `ERR`.
		if os.args.len >= 3 && os.args[1] == '__linktest' {
			cp := ensure_cached(os.args[2], false)
			if cp == '' || !os.is_link(cp) {
				println('ERR')
				C._exit(1)
			}
			println('${cp}\t${os.real_path(cp).all_after_last('/')}')
			C._exit(0)
		}
		// Self-test hook: `sb __prunetest <cache> <manifest-file>` reconciles the cache
		// against a manifest (no fetching) -- demote stale binaries, drop deleted ones.
		if os.args.len >= 4 && os.args[1] == '__prunetest' {
			prune_cache(os.args[2], os.read_file(os.args[3]) or { '' }, '${os.args[2]}/sb')
			C._exit(0)
		}
		// Self-test hook: `sb __bindprobe <path>` reports FREE / LIVE / STALE for a socket
		// path -- the run_mux_pump socket-exists guard (concurrent-mux edge case).
		if os.args.len >= 3 && os.args[1] == '__bindprobe' {
			p := os.args[2]
			if !os.exists(p) {
				println('FREE')
				C._exit(0)
			}
			probe := mux_sock_connect(p)
			if probe >= 0 {
				C.close(probe)
				println('LIVE')
				C._exit(0)
			}
			println('STALE')
			C._exit(0)
		}
		// Self-test hook: `sb __pumptest` runs the pure byte-pump (SB_SHELL/SB_RC_FILE
		// driven, no wrapper / no mux_setup) -- the pass-through checks.
		if os.args.len >= 2 && os.args[1] == '__pumptest' {
			sh := os.getenv('SB_SHELL')
			if sh == '' {
				die('SB_SHELL not set')
			}
			run_pump(sh, os.getenv('SB_RC_FILE'))
		}
		// Self-test hooks for the mux socket: a minimal auth+echo server and a
		// client (constant-time bearer-auth + sysexits failure codes).
		if os.args.len >= 2 && os.args[1] == '__muxserve' {
			run_mux_serve()
		}
		if os.args.len >= 3 && os.args[1] == '__muxclient' {
			run_mux_client(os.args[2])
		}
		if os.args.len >= 3 && os.args[1] == '__muxfetch' {
			run_mux_fetch(os.args[2])
		}
		if os.args.len >= 4 && os.args[1] == '__conduitfetch' {
			run_conduit_fetch(os.args[2].int(), os.args[3])
		}
		if os.args.len >= 2 && os.args[1] == '__cryptotest' {
			run_cryptotest()
			exit(0)
		}
		if os.args.len >= 2 && os.args[1] == '__stuntest' {
			run_stuntest()
			exit(0)
		}
		if os.args.len >= 2 && os.args[1] == '__udptest' {
			run_udptest()
			exit(0)
		}
		if os.args.len >= 2 && os.args[1] == '__deflatetest' {
			run_deflatetest()
			exit(0)
		}
		if os.args.len >= 2 && os.args[1] == '__arqtest' {
			run_arqtest()
			exit(0)
		}
		if os.args.len >= 2 && os.args[1] == '__sigtest' {
			run_sigtest()
			exit(0)
		}
		// `sb __killtest <selector> [match]` -- exercise select_kills against a fixed
		// synthetic inventory (no socket/pty). Prints the chosen PIDs space-joined, or
		// `none`. Proves the selector/category/match/PID-reuse-guard logic.
		if os.args.len >= 3 && os.args[1] == '__killtest' {
			comps := [
				Comp{
					pid:  101
					cat:  'relay'
					desc: 'ssh bastion'
				},
				Comp{
					pid:  102
					cat:  'port'
					desc: 'bind:127.0.0.1:8080:all'
				},
				Comp{
					pid:  103
					cat:  'port'
					desc: 'dial:db:5432'
				},
				Comp{
					pid:  104
					cat:  'rpc'
					desc: 'FILEREQ'
				},
				Comp{
					pid:  0
					cat:  'rpc'
					desc: 'unknownpid'
				},
			]
			matchf := if os.args.len >= 4 { os.args[3] } else { '' }
			pids := select_kills(comps, os.args[2], matchf)
			println(if pids.len == 0 { 'none' } else { pids.map(it.str()).join(' ') })
			exit(0)
		}
		if os.args.len >= 7 && os.args[1] == '__arqsend' {
			run_arqsend(os.args[2], u16(os.args[3].int()), u16(os.args[4].int()), os.args[5].int(),
				os.args[6].int())
		}
		if os.args.len >= 7 && os.args[1] == '__arqrecv' {
			run_arqrecv(u16(os.args[2].int()), os.args[3], u16(os.args[4].int()), os.args[5].int(),
				os.args[6].int())
		}
		if os.args.len >= 7 && os.args[1] == '__punchsend' {
			run_punchsend(u16(os.args[2].int()), os.args[3], u16(os.args[4].int()), os.args[5].int(),
				os.args[6].int())
		}
		if os.args.len >= 7 && os.args[1] == '__punchrecv' {
			run_punchrecv(u16(os.args[2].int()), os.args[3], u16(os.args[4].int()), os.args[5].int(),
				os.args[6].int())
		}
		if os.args.len >= 5 && os.args[1] == '__cands' {
			run_cands(u16(os.args[2].int()), os.args[3], u16(os.args[4].int()))
		}
		if os.args.len >= 2 && os.args[1] == '__upgradeserve' {
			run_upgrade_serve()
		}
		if os.args.len >= 4 && os.args[1] == '__stunquery' {
			bindp := if os.args.len >= 5 { u16(os.args[4].int()) } else { u16(0) }
			ok, ip, port := stun_query(os.args[2], u16(os.args[3].int()), bindp)
			println(if ok { 'REFLEX:${ip}:${port}' } else { 'STUN-FAIL' })
			exit(0)
		}
		if os.args.len >= 5 && os.args[1] == '__stunserver' {
			run_stunserver(u16(os.args[2].int()), os.args[3], u16(os.args[4].int()))
		}
		if os.args.len >= 6 && os.args[1] == '__gatherprobe' {
			run_gatherprobe(os.args[2], u16(os.args[3].int()), os.args[4], u16(os.args[5].int()))
		}
		if os.args.len >= 2 && os.args[1] == '__revertprobe' {
			run_revertprobe()
		}
	}
	// $if sb_test
	prog := os.args[0].all_after_last('/')
	if prog == 'sb' {
		if os.args.len >= 2 {
			match os.args[1] {
				'mux' {
					// `sb mux [--token=<tok>] [--exec=<cmd> [args...]]`. `--token` makes
					// reuse INTENTIONAL (reconnect / fixed back-channel token); with none, a
					// fresh per-host token is minted. The token is NEVER read from the env
					// (that made reuse a silent footgun; see run_mux). `--exec=<cmd>` and
					// everything after it is the command the mux forkpty's instead of the
					// default shell (a fetchable launcher script, another shell, ...) -- it's
					// run via $PATH, so bucket scripts autovivify (no special handling).
					mut arg_token := ''
					mut exec_cmd := ''
					mut exec_args := []string{}
					mut i := 2
					for i < os.args.len {
						a := os.args[i]
						if a.starts_with('--exec=') {
							exec_cmd = a['--exec='.len..]
							if i + 1 < os.args.len {
								exec_args = os.args[i + 1..].clone()
							}
							break
						} else if a.starts_with('--token=') {
							arg_token = a['--token='.len..]
						}
						i++
					}
					run_mux(arg_token, exec_cmd, exec_args)
				}
				'fetch' {
					if os.args.len >= 3 {
						run_fetch(os.args[2])
					} else {
						die('usage: sb fetch <name>')
					}
				}
				'token' {
					run_token(os.args[2..].clone())
				}
				'tunnel' {
					run_tunnel(os.args[2..].clone())
				}
				'run' {
					if os.args.len >= 3 {
						run_tool(os.args[2], os.args[3..].clone())
					} else {
						die('usage: sb run <name> [args]')
					}
				}
				'inject', 'i' {
					// `sb inject <cmd...>` / `sb i <cmd...>` -> inject that command.
					run_inject(os.args[2..].clone())
				}
				'control', 'ctl' {
					run_ctl(os.args[2..].clone())
				}
				'clip' {
					run_clip(os.args[2..].clone())
				}
				'survey' {
					run_survey()
				}
				else {
					die('usage: sb {mux|fetch <name>|run <name> [args]|token <opts>|tunnel <spec>|inject <cmd...>|ctl [-v|status|udpup|udpdn|kill]|clip [--copy|--paste]|survey}')
				}
			}
		}
		// Bare `sb` has no action -- `sb inject <cmd>` propagates the tooling to the
		// next hop.
		die('usage: sb {mux|fetch <name>|run <name> [args]|token <opts>|tunnel <spec>|inject <cmd...>|ctl [-v|status|udpup|udpdn|kill]|clip [--copy|--paste]|survey}')
	}
	// Invoked via a PATH symlink (argv[0] != sb): dispatch that tool.
	run_tool(prog, os.args[1..].clone())
}

// The argv to launch the tooled interactive shell: bash takes `--rcfile <rc>`; ksh
// reads `$ENV` (exported here); other shells just run with the inherited env.
fn shell_launch_words(shell string, rc string) []string {
	mut words := [shell]
	if rc != '' {
		base := shell.all_after_last('/')
		if base.ends_with('bash') {
			words << '--rcfile'
			words << rc
		} else if base.contains('ksh') {
			C.setenv(c'ENV', rc.str, 1)
		}
	}
	return words
}

// The persistent in-band multiplexer / PTY byte-pump. SB_SHELL and the rest of the
// session env arrive from the bootstrap; `mux_setup` derives the manifest, runtime,
// and dispatch dir. `arg_token` is the `--token=` value (or '' to mint). With
// `exec_cmd` set, the mux forkpty's THAT command (+ `exec_args`) instead of the
// default tooled shell.
fn run_mux(arg_token string, exec_cmd string, exec_args []string) {
	shell := os.getenv('SB_SHELL')
	if shell == '' {
		die('SB_SHELL not set')
	}
	// Per-host token: the supplied `--token=` (intentional reuse -- reconnect /
	// fixed back-channel token) or a freshly MINTED one -- NEVER silently inherited from
	// the env. We OVERWRITE any inherited SB_TOKEN with the resolved value before the
	// forkpty below, so the child (and every tool it runs) reaches THIS mux's socket and
	// a token leaked across a same-host conduit can't make us reuse the parent's socket.
	token := if arg_token != '' { arg_token } else { make_token() }
	C.setenv(c'SB_TOKEN', token.str, 1)
	// Stand up the session env (manifest, runtime, dispatch symlinks, PATH),
	// then become the byte-pump WITH the mux socket. mux_setup is the only
	// wrapper-coupled step.
	rc := mux_setup(shell)
	mut words := []string{}
	if exec_cmd != '' {
		// `--exec=<cmd> [args]`: forkpty an arbitrary command instead of the default
		// shell -- a fetchable launcher (e.g. sb-tmux.sh), another shell, anything. NOT
		// special-cased: it runs via $PATH, which mux_setup put the bucket dispatch dir
		// on, so an executable bucket file autovivifies through its dispatch symlink.
		words << exec_cmd
		for a in exec_args {
			words << a
		}
	} else {
		words = shell_launch_words(shell, rc)
	}
	run_mux_pump(words, token)
}

// send_up relays a protocol FRAME (the raw payload, NOT APC-wrapped) UP toward
// the wrapper. Over the UDP backhaul it goes as a length-prefixed record (the
// channel carries only frames, so the wrapper dispatches them directly -- no APC
// encode/decode, no merge with the pty stream). In-band it is APC-wrapped onto
// fd1. Length-prefix (not newline) because frame payloads may contain any byte.
// Terminal passthrough is NOT a frame and never routes here -- always fd1.
fn send_up(frame []u8, mut bh Backhaul, now i64) {
	if frame.len == 0 {
		return
	}
	match bh.state {
		.up {
			bh.enqueue_frame(frame, now)
		} // over UDP + tracked for lossless revert
		.reverting {
			bh.hold_frame(frame)
		} // dead path draining -> held, re-sent in-band in order
		else {
			out := build_apc(frame)
			write1(unsafe { &out[0] }, i64(out.len))
		}
	}
}

// handle_down_frame processes one APC frame arriving DOWN from the wrapper --
// identically whether it came in-band (fd0) or over the UDP backhaul. SURVEY /
// PUSH replies route UP via send_up; `R<id>:` replies route DOWN to the
// originating client (unframed) or re-framed into a conduit child.
fn handle_down_frame(pl []u8, mut routes map[int]Route, clients []MuxClient, mut bh Backhaul, now i64) {
	spl := pl.bytestr()
	// SURVEY (wrapper-initiated): reply with our identity (empty route -- a parent
	// prepends its conduit's cid as it relays up), and fan the SURVEY out to every
	// conduit child so the whole tree replies.
	if spl.starts_with('SURVEY:') {
		sid := spl.all_after('SURVEY:')
		send_up('SURVEYR:${sid}::${node_identity()}'.bytes(), mut bh, now)
		fwd := build_apc('SURVEY:${sid}'.bytes())
		for c in clients {
			if c.conduit {
				write_all(c.fd, unsafe { &fwd[0] }, i64(fwd.len))
			}
		}
		return
	}
	// PUSH (wrapper->node, source-routed): `PUSH:<pid>:<route>:<cmd>`. Empty route ->
	// we're the target: act locally, reply `PUSHR` up. Else pop the head cid and
	// forward to that conduit (route shortened).
	if spl.starts_with('PUSH:') {
		parts := spl.all_after('PUSH:').split_nth(':', 3) // pid, route, cmd
		if parts.len == 3 {
			ppid := parts[0]
			route := parts[1]
			pcmd := parts[2]
			if route == '' {
				resp := push_local(pcmd)
				send_up('PUSHR:${ppid}:${resp}'.bytes(), mut bh, now)
			} else {
				rp := route.split_nth(',', 2)
				hcid := rp[0].int()
				newroute := if rp.len > 1 { rp[1] } else { '' }
				fwd := build_apc('PUSH:${ppid}:${newroute}:${pcmd}'.bytes())
				for c in clients {
					if c.conduit && c.cid == hcid {
						write_all(c.fd, unsafe { &fwd[0] }, i64(fwd.len))
					}
				}
			}
		}
		return
	}
	okr, id, resp := parse_route(pl)
	if !okr {
		return
	}
	rt := routes[id] or { return }
	// CLIP routes: translate between the b64-encoded APC wire (safe for the in-band
	// escape sequence) and the raw-binary socket protocol. The socket client never
	// sees base64 -- the mux decodes GET responses and encodes SET payloads.
	if rt.clip {
		sresp := resp.bytestr()
		if sresp.starts_with('ERR:') || sresp == 'OK' {
			// Text response: error or CLIP:SET success -- write as a line.
			write_all(rt.fd, unsafe { &resp[0] }, i64(resp.len))
			write_str(rt.fd, '\n')
		} else {
			// b64-encoded clipboard data (CLIP:GET success) -> decode + length-prefix.
			raw := b64_decode(sresp) or { []u8{} }
			mut lenb := [4]u8{}
			dlen := u32(raw.len)
			lenb[0] = u8(dlen >> 24)
			lenb[1] = u8(dlen >> 16)
			lenb[2] = u8(dlen >> 8)
			lenb[3] = u8(dlen)
			write_str(rt.fd, 'OK\n')
			write_all(rt.fd, unsafe { &lenb[0] }, 4)
			if raw.len > 0 {
				write_all(rt.fd, unsafe { &raw[0] }, i64(raw.len))
			}
		}
		if !rt.persistent {
			routes.delete(id)
		}
		return
	}
	if rt.inner_id < 0 {
		// raw-origin (local tool / deeper bootstrap / tunnel client): reply unframed
		// -- the bytes go straight to the awaiting client fd.
		if resp.len > 0 {
			write_all(rt.fd, unsafe { &resp[0] }, i64(resp.len))
		}
	} else {
		// framed-origin (deeper host via conduit): re-frame R<inner> and APC-wrap so
		// it travels the conduit into the deeper mux.
		mut cmd := 'R${rt.inner_id}:'.bytes()
		cmd << resp
		out := build_apc(cmd)
		write_all(rt.fd, unsafe { &out[0] }, i64(out.len))
	}
	// A tunnel is a PERSISTENT route -- many frames both ways; keep it until the
	// tunnel closes (client drop / TUN-CLOSE). One-shot requests delete.
	if !rt.persistent {
		routes.delete(id)
	}
}

// udp_local_port returns the port a bound socket actually got (for the host candidate).
fn udp_local_port(fd int) u16 {
	mut sa := SockaddrIn{}
	mut l := u32(sizeof(SockaddrIn))
	if C.getsockname(fd, voidptr(&sa), voidptr(&l)) != 0 {
		return 0
	}
	return C.htons(sa.sin_port)
}

// start_backhaul handles an `UP:O:` offer: decode it, bind a UDP socket, start the
// Backhaul punching toward the wrapper's candidates, and reply `UP:A:` in-band with
// our host candidate. Salts: wrapper tx=1/rx=2, mux tx=2/rx=1. The wrapper learns
// our srflx from our punch pings (non-blocking srflx gathering is a later add).
// answer_cands is the candidate list this mux advertises: its host-interface
// address plus the gathered server-reflexive one (if any, and distinct). The
// wrapper punches all of them, so a NAT'd mux is reachable via its srflx.
fn (b &Backhaul) answer_cands() []IpPort {
	if b.override_cands.len > 0 {
		return b.override_cands.clone()
	}
	host := IpPort{local_ip(), udp_local_port(b.fd)}
	mut cs := [host]
	if b.srflx.ip.len > 0 && !(b.srflx.ip == host.ip && b.srflx.port == host.port) {
		cs << b.srflx
	}
	return cs
}

// emit_answer sends the UP:A reply in-band and flips gathering -> punching. Called
// once gathering resolves (a srflx arrived) or its deadline elapses (host-only).
fn (mut b Backhaul) emit_answer(now i64) {
	ans := build_apc('UP:A:${encode_answer(b.answer_nonce, b.answer_cands())}'.bytes())
	write1(unsafe { &ans[0] }, i64(ans.len))
	b.state = .punching
	b.deadline = now + bh_punch_ms // the punch budget starts now, after gathering
	b.next_ping = now
}

// start_backhaul handles the wrapper's UP:O offer: bind the punch socket, then --
// if the offer carried STUN servers -- gather a server-reflexive candidate on that
// socket before answering (so a NAT'd mux is reachable). Gathering is non-blocking:
// the first STUN burst goes out on the next pump tick and responses are serviced by
// the poll loop. With no STUN servers offered, answer host-only immediately.
fn start_backhaul(b64 []u8, mut bh Backhaul) {
	if bh.state != .inactive {
		return
	}
	ok, psk, nonce, stun, wcands := decode_offer(b64.bytestr())
	if !ok || psk.len != 32 || wcands.len == 0 {
		return
	}
	ufd := udp_bind(0)
	if ufd < 0 {
		return
	}
	mut peer := []SockaddrIn{}
	for c in wcands {
		peer << make_sa(c.ip, c.port)
	}
	now := monotonic_ms()
	bh = new_backhaul(ufd, psk, u32(2), u32(1), peer, now, bh_punch_ms)
	bh.answer_nonce = nonce.clone()
	if stun.len == 0 {
		bh.emit_answer(now) // no observers -> can't learn a srflx; answer host-only now
		return
	}
	for s in stun {
		bh.stun_servers << make_sa(s.ip, s.port)
	}
	bh.stun_txid = urandom(12)
	bh.stun_req = stun_build_request(bh.stun_txid)
	bh.state = .gathering
	bh.gather_deadline = now + bh_gather_ms
	bh.next_stun = now // first burst fires on the next tick (poll timeout 0)
}

// `sb __upgradeserve` (E2E test): a minimal mux that does ONLY the UDP-backhaul
// upgrade -- read an `UP:O:` offer (APC) off fd 0, run the REAL start_backhaul
// (gather + answer on fd 1 + punch), then service the Backhaul and ECHO the frame
// byte stream back over it. Pairs with a wrapper-side driver to prove the full
// offer->answer->punch->frames-over-UDP path end to end on loopback.
fn run_upgrade_serve() {
	mut sc := Scanner{}
	mut bh := Backhaul{}
	bufsz := usize(65536)
	buf := unsafe { &u8(malloc(isize(bufsz))) }
	mut udpbuf := []u8{len: 2048}
	for {
		if bh.state == .inactive {
			// Block on fd 0 for the offer (no backhaul to service yet).
			n := C.read(0, voidptr(buf), bufsz)
			if n <= 0 {
				C._exit(1)
			}
			sc.feed_raw(buf, int(n))
			for pl in sc.take_payloads() {
				if bprefix(pl, 'UP:O:') {
					start_backhaul(pl[5..], mut bh) // gather + answer (fd 1) + punch
				}
			}
			continue
		}
		now := monotonic_ms()
		mut pfd := Pollfd{
			fd:     bh.fd
			events: pollin
		}
		C.poll(voidptr(&pfd), 1, int(bh.next_timeout(now)))
		if (pfd.revents & pollin) != 0 {
			mut sa := SockaddrIn{}
			mut slen := u32(sizeof(SockaddrIn))
			n := C.recvfrom(bh.fd, udpbuf.data, usize(udpbuf.len), 0, voidptr(&sa), voidptr(&slen))
			if n > 0 {
				bh.on_udp(udpbuf[..int(n)], sa, now)
			}
		}
		bh.tick(now)
		if bh.state == .failed {
			C._exit(2)
		}
		inb := bh.recv()
		if inb.len > 0 {
			bh.send(inb, monotonic_ms()) // echo the received frame byte stream back
		}
	}
}

// `sb __revertprobe` (self-test): white-box exercise of the lossless-revert FIFO
// and the in-band handoff. Enqueue N up-frames, fake the ARQ acking a prefix and
// check prune advances tx_base by exactly that many, then capture fd 1 across a
// begin_revert + peer_revert and assert the wrapper sees exactly `UP:RX:<rx>`
// followed by the tail of frames it never consumed -- verbatim, in order, once.
@[noreturn]
fn run_revertprobe() {
	now := monotonic_ms()
	mut fail := 0
	mut nfail := fn [mut fail] (cond bool, msg string) {
		if !cond {
			eprintln('FAIL: ${msg}')
			fail++
		}
	}

	key := []u8{len: 32, init: u8(index * 7 + 1)}
	devnull := C.open(c'/dev/null', 1) // O_WRONLY: flush()'s packets go nowhere
	mut b := new_backhaul(devnull, key, 2, 1, []SockaddrIn{}, now, 5000)
	b.state = .up

	// N deterministic, varied-length frames. Production frames are text-safe by
	// construction (base64-structured, e.g. `D:<conn>:<b64...>`) -- the in-band APC
	// envelope carries them verbatim without escaping -- so the probe uses the same
	// safe alphabet rather than arbitrary binary the wire could never produce.
	alpha := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.bytes()
	n := 8
	mut frames := [][]u8{}
	for i in 0 .. n {
		mut f := []u8{}
		f << 'D:${i}:'.bytes()
		for j in 0 .. (16 + i * 5) {
			f << alpha[(i * 37 + j * 11) % alpha.len]
		}
		frames << f
	}
	for f in frames {
		b.enqueue_frame(f, now)
	}
	nfail(b.sent.len == n, 'after enqueue: sent.len ${b.sent.len} != ${n}')
	nfail(b.tx_base == 0, 'after enqueue: tx_base ${b.tx_base} != 0')

	// Fake the ARQ cumulatively acking through frame k's compressed-stream end, then
	// prune: exactly k whole frames should drop from the FIFO (tx_base advances by k).
	k := 3
	target := b.sent[k - 1].end_off
	b.arq.unacked = []Segment{}
	b.arq.snd_nxt = u64(target)
	b.prune()
	nfail(b.tx_base == k, 'after prune: tx_base ${b.tx_base} != ${k}')
	nfail(b.sent.len == n - k, 'after prune: sent.len ${b.sent.len} != ${n - k}')

	// Capture fd 1 across the in-band handoff (begin_revert + peer_revert write there).
	mut fds := [2]int{}
	if C.pipe(&fds[0]) != 0 {
		die('revertprobe: pipe')
	}
	orig := C.dup(1)
	C.dup2(fds[1], 1)
	C.close(fds[1])

	// Wrapper says it consumed m of our up-frames (m > k: it got more than the ARQ
	// proved) -> we re-send only frames m..n-1, the tail it never received.
	m := k + 2
	b.begin_revert(now) // emits UP:RX:<rx_frames>
	b.peer_revert(m, now) // re-sends the tail in-band, exactly once

	C.dup2(orig, 1)
	C.close(orig)

	mut cap_buf := []u8{}
	mut tmp := [4096]u8{}
	for {
		r := C.read(fds[0], &tmp[0], usize(4096))
		if r <= 0 {
			break
		}
		for i in 0 .. int(r) {
			cap_buf << tmp[i]
		}
	}
	C.close(fds[0])

	nfail(b.state == .reverting, 'state ${b.state} != .reverting')
	nfail(b.resent, 'resent flag not set')

	mut sc := Scanner{}
	sc.feed(cap_buf)
	pls := sc.payloads

	mut exp := [][]u8{}
	exp << 'UP:RX:${b.rx_frames}'.bytes() // rx_frames == 0 (no down-frames delivered)
	for i in m .. n {
		exp << frames[i]
	}
	nfail(pls.len == exp.len, 'in-band payloads: got ${pls.len}, want ${exp.len}')
	if pls.len == exp.len {
		for i in 0 .. exp.len {
			nfail(pls[i] == exp[i], 'payload ${i} mismatch')
		}
	}

	if fail == 0 {
		println('ok:   revert FIFO prune + lossless in-band handoff (exactly-once tail)')
		exit(0)
	}
	exit(1)
}

// `sb __stunserver <port> <pub_ip> <pub_port>` (self-test): a minimal STUN
// observer -- bind <port>, answer the first Binding Request with a Success
// Response reporting <pub_ip>:<pub_port> as XOR-MAPPED-ADDRESS, then exit. Pairs
// with __gatherprobe to exercise mux-side srflx gathering on loopback.
@[noreturn]
fn run_stunserver(port u16, pub_ip string, pub_port u16) {
	fd := udp_bind(port)
	if fd < 0 {
		die('stunserver: bind ${port}')
	}
	mut buf := []u8{len: 512}
	deadline := monotonic_ms() + 3000
	for monotonic_ms() < deadline {
		mut pfd := Pollfd{
			fd:     fd
			events: pollin
		}
		if C.poll(voidptr(&pfd), 1, 200) <= 0 {
			continue
		}
		mut sa := SockaddrIn{}
		mut slen := u32(sizeof(SockaddrIn))
		n := C.recvfrom(fd, buf.data, usize(buf.len), 0, voidptr(&sa), voidptr(&slen))
		if n >= 20 && buf[0] == 0x00 && buf[1] == 0x01 { // Binding Request
			resp := stun_make_response(buf[8..20], pub_ip, pub_port)
			C.sendto(fd, resp.data, usize(resp.len), 0, voidptr(&sa), slen)
			C._exit(0) // answered once -- the gather is satisfied
		}
	}
	C._exit(0)
}

// `sb __gatherprobe <stun_ip> <stun_port> <wrap_ip> <wrap_port>` (self-test):
// craft an offer naming that STUN server and one wrapper candidate, run the REAL
// start_backhaul gather path, and print the resolved srflx + answer candidate set.
// Proves the non-blocking on-socket STUN gather feeds the UP:A candidate list.
@[noreturn]
fn run_gatherprobe(stun_ip string, stun_port u16, wrap_ip string, wrap_port u16) {
	off := encode_offer(urandom(32), urandom(8), [IpPort{stun_ip, stun_port}], [
		IpPort{wrap_ip, wrap_port},
	])
	mut bh := Backhaul{}
	start_backhaul(off.bytes(), mut bh)
	if bh.state != .gathering {
		eprintln('gatherprobe: expected .gathering, got ${bh.state}')
		C._exit(1)
	}
	mut buf := []u8{len: 2048}
	deadline := monotonic_ms() + 3000
	// Drive the gather loop until a srflx lands -- stop BEFORE the tick that would
	// emit the answer to fd 1, so stdout carries only our plain-text result.
	for bh.srflx.ip.len == 0 && bh.state == .gathering && monotonic_ms() < deadline {
		now := monotonic_ms()
		mut pfd := Pollfd{
			fd:     bh.fd
			events: pollin
		}
		C.poll(voidptr(&pfd), 1, int(bh.next_timeout(now)))
		if (pfd.revents & pollin) != 0 {
			mut sa := SockaddrIn{}
			mut slen := u32(sizeof(SockaddrIn))
			n := C.recvfrom(bh.fd, buf.data, usize(buf.len), 0, voidptr(&sa), voidptr(&slen))
			if n > 0 {
				bh.on_udp(buf[..int(n)], sa, monotonic_ms())
			}
		}
		if bh.srflx.ip.len > 0 {
			break
		}
		bh.tick(monotonic_ms())
	}
	if bh.srflx.ip.len == 0 {
		eprintln('gatherprobe: no srflx gathered')
		C._exit(2)
	}
	mut cs := []string{}
	for c in bh.answer_cands() {
		cs << '${c.ip}:${c.port}'
	}
	joined := cs.join(' ')
	println('srflx: ${bh.srflx.ip}:${bh.srflx.port}')
	println('cands: ${joined}')
	exit(0) // V exit flushes buffered stdout; C._exit would drop the last line
}

// The mux's PTY pump: forkpty the child + bind the per-host socket, then a poll loop
// bridging three interfaces -- the parent byte stream (down: route `R<id>` replies and
// fan SURVEY / source-route PUSH; up: the child's terminal plus socket requests framed
// as APCs), the child pty (terminal only -- its our-prefix APCs are stripped at the
// source), and the socket (authed local tools + inject conduits). The child tty carries
// no protocol; escapes live only on the byte stream.
@[noreturn]
fn run_mux_pump(argv []string, token string) {
	// The per-host mux socket -- bound + listening BEFORE forkpty so it's ready before
	// any child tool could connect; `bind_listen` uses SOCK_CLOEXEC so the child never
	// inherits the listen fd. One per host, named from the token locator, 0600. If the
	// path already exists, distinguish a LIVE owner (refuse -- another `sb mux` already
	// serves this token) from a stale file left by a dead mux (clear it).
	mut sock_path := mux_sock_path(token)
	mut secret := token_secret(token).bytes()
	if os.exists(sock_path) {
		probe := mux_sock_connect(sock_path)
		if probe >= 0 {
			C.close(probe)
			die('another sb mux already owns ${sock_path} (token in use) -- refusing to start a second')
		}
		C.unlink(sock_path.str) // stale -> clear
	}
	mut lfd := bind_listen(sock_path)

	// Depth in the multi-hop tree: 0 at the first mux, +1 for each nested hop.
	// Read before forkpty, then stamp the child's env so its own `sb mux` sees depth+1.
	depth := os.getenv('SB_MUX_DEPTH').int()
	C.setenv(c'SB_MUX_DEPTH', '${depth + 1}'.str, 1)

	// forkpty the child + raw-mode our tty + block SIGWINCH/SIGCHLD onto a signalfd.
	pid, master, sfd, mut saved, have_saved, mut ws := relay_setup(argv)

	// `down` peels `R<id>:resp` (and SURVEY/PUSH) off the parent byte stream. `child`
	// scans the forkpty child's output and STRIPS our-prefix APCs at the source
	// (strip-at-source): the child's tools use the socket, so it has no business
	// emitting our APCs -- a malicious child (`cat evil.txt`, or one that read the
	// token) thus can't forge into the trusted byte stream; its terminal passes
	// through untouched.
	mut down := Scanner{}
	mut child := Scanner{}
	mut routes := map[int]Route{}
	mut next_id := 1
	mut next_cid := 1 // per-mux id assigned to each conduit child (route element)

	mut clients := []MuxClient{}
	mut stdin_open := true
	// Optional UDP backhaul (increment 5): `bh.state` is .inactive until an `UP:O:`
	// offer arrives. The backhaul carries length-prefixed RAW frames (no APC), which
	// bh.recv_frames reassembles across datagram boundaries -> handle_down_frame.
	mut bh := Backhaul{}
	mut udpbuf := []u8{len: 2048}
	bufsz := usize(65536)
	buf := unsafe { &u8(malloc(isize(bufsz))) }
	// Session byte counters for `sb ctl status`.
	mut stat_main_rx := i64(0) // raw bytes read from fd0 (in-band from wrapper)
	mut stat_pty_rx := i64(0) // raw bytes read from PTY master (child -> us direction)
	mut stat_pty_tx := i64(0) // passthrough bytes written to PTY master (us -> child)
	// bh.tx_off (compressed bytes sent upstream) and bh.rx_bytes (UDP bytes received)
	// live on the Backhaul struct so they survive the above local variables.
	start_ms := monotonic_ms()
	// Manual backhaul candidates set by `sb ctl up <ip:port>...`: used as override_cands
	// in the next start_backhaul call, then cleared. Empty = use auto (STUN).
	mut pending_cands := []IpPort{}

	// Channel-separation handshake: mux_setup's pre-pump fetches are done and the
	// pump (which demuxes APC frames from terminal bytes) is about to run -- emit
	// MUXUP up the byte stream so the relayer above us (a conduit `sb inject`, or
	// the wrapper) stops HOLDING terminal input and releases it now. Until MUXUP,
	// input is preempted, so tty bytes never interlace our raw pre-pump exchange.
	muxup := build_apc('MUXUP'.bytes())
	write1(unsafe { &muxup[0] }, i64(muxup.len))

	for {
		// Rebuild the poll set each pass: fd0, master, sfd, listen, then clients.
		mut fds := []Pollfd{}
		fds << Pollfd{
			fd:     if stdin_open { 0 } else { -1 }
			events: pollin
		}
		fds << Pollfd{
			fd:     master
			events: pollin
		}
		fds << Pollfd{
			fd:     sfd
			events: pollin
		}
		fds << Pollfd{
			fd:     lfd // -1 if the socket couldn't bind -> poll ignores it
			events: pollin
		}
		// fds[4]: the UDP backhaul socket (-1 -> ignored while inactive/failed). Polled
		// during .gathering too, so STUN responses reach on_udp.
		fds << Pollfd{
			fd:     if bh.state in [.gathering, .punching, .up] { bh.fd } else { -1 }
			events: pollin
		}
		nclients := clients.len // fds[5 + ci] aligns with this snapshot
		for c in clients {
			fds << Pollfd{
				fd:     c.fd
				events: pollin
			}
		}
		// Block indefinitely when there's no backhaul; otherwise wake for its timers
		// (ping cadence while punching, RTO/idle while up).
		timeout := if bh.state == .inactive { -1 } else { int(bh.next_timeout(monotonic_ms())) }
		if C.poll(voidptr(unsafe { &fds[0] }), u64(fds.len), timeout) < 0 {
			break
		}
		// fd0 (parent) down: terminal keystrokes -> child; `R<id>:resp` -> its client.
		if (fds[0].revents & readable) != 0 {
			n := C.read(0, voidptr(buf), bufsz)
			if n <= 0 {
				stdin_open = false
			} else {
				stat_main_rx += n
				down.feed_raw(buf, int(n))
				pt := down.take_passthru()
				if pt.len > 0 {
					stat_pty_tx += i64(pt.len)
					write_all(master, unsafe { &pt[0] }, i64(pt.len))
				}
				for pl in down.take_payloads() {
					// `UP:O:<b64>` -- the wrapper's offer to upgrade to a UDP backhaul.
					// Always arrives in-band (the backhaul doesn't exist yet). Handled here
					// (it creates pump-local socket/backhaul state); all other frames go to
					// the shared handler.
					if bprefix(pl, 'UP:O:') {
						start_backhaul(pl[5..], mut bh)
						if pending_cands.len > 0 {
							bh.override_cands = pending_cands.clone()
							pending_cands = []IpPort{}
						}
						continue
					}
					// `UP:RX:<n>` -- the wrapper is reverting the backhaul (it consumed n
					// of our up-frames). Complete the lossless handoff: re-send the tail it
					// never got in-band, then discard the backhaul (back to .inactive) so a
					// renegotiation offer can re-establish. In-band order guarantees any
					// re-sent down-frames and a following UP:O are processed after this.
					if bprefix(pl, 'UP:RX:') {
						if bh.state in [.up, .reverting] {
							bh.peer_revert(pl[6..].bytestr().int(), monotonic_ms())
							C.close(bh.fd)
							bh.close_comp()
							bh = Backhaul{} // discard (incl. its reassembly buffer) -> in-band
						}
						continue
					}
					handle_down_frame(pl, mut routes, clients, mut bh, monotonic_ms())
				}
			}
		}
		// UDP backhaul: ingest a datagram, step timers, and feed any frames the
		// wrapper sent over UDP through the SAME down-frame handler as fd0 (via the
		// separate `udown` scanner). On failure, close it and revert to in-band.
		if bh.state != .inactive {
			now := monotonic_ms()
			if (fds[4].revents & readable) != 0 {
				mut sa := SockaddrIn{}
				mut slen := u32(sizeof(SockaddrIn))
				un := C.recvfrom(bh.fd, udpbuf.data, usize(udpbuf.len), 0, voidptr(&sa),
					voidptr(&slen))
				if un > 0 {
					bh.rx_bytes += un
					bh.on_udp(udpbuf[..int(un)], sa, now)
				}
			}
			bh.tick(now)
			for frame in bh.recv_frames() {
				handle_down_frame(frame, mut routes, clients, mut bh, now)
			}
			if bh.state == .failed {
				C.close(bh.fd)
				bh.close_comp()
				bh = Backhaul{} // revert to in-band (back to .inactive)
			}
		}
		// child up: scan + STRIP our-prefix APCs (the child can't forge into the
		// trusted byte stream); terminal passes through to the parent. EOF = end.
		if (fds[1].revents & readable) != 0 {
			n := C.read(master, voidptr(buf), bufsz)
			if n <= 0 {
				break
			}
			stat_pty_rx += n
			child.feed_raw(buf, int(n))
			pt := child.take_passthru()
			if pt.len > 0 {
				write1(unsafe { &pt[0] }, i64(pt.len))
			}
			_ := child.take_payloads() // DROP: the child has no business emitting our APCs
		}
		// signals
		if (fds[2].revents & pollin) != 0 {
			mut si := [128]u8{}
			C.read(sfd, voidptr(&si[0]), 128)
			signo := unsafe { *(&u32(voidptr(&si[0]))) }
			if signo == u32(sigwinch) {
				if C.ioctl(0, tiocgwinsz, &ws) == 0 {
					C.ioctl(master, tiocswinsz, &ws)
				}
			}
		}
		// socket clients: auth, then per-request label-swap relay up the byte stream.
		mut drop := []int{}
		for ci, mut c in clients {
			if ci >= nclients || (fds[5 + ci].revents & readable) == 0 {
				continue
			}
			n := C.read(c.fd, voidptr(buf), bufsz)
			if n <= 0 {
				// A client went away. Tear down every tunnel routed through it -- a
				// direct tunnel client (`c.tunnel_id`) or, for a conduit child, the
				// multi-hop tunnels carried over it (its persistent routes). Tell the
				// wrapper to close/unbind, then drop the routes.
				mut dead := []int{}
				if c.tunnel_id >= 0 {
					dead << c.tunnel_id
				}
				for rid, rt in routes {
					if rt.persistent && rt.fd == c.fd && rid != c.tunnel_id {
						dead << rid
					}
				}
				for rid in dead {
					send_up('R${rid}:TUN-CLOSE'.bytes(), mut bh, monotonic_ms())
					routes.delete(rid)
				}
				C.close(c.fd)
				drop << ci
				continue
			}
			for k in 0 .. int(n) {
				c.inbuf << unsafe { buf[k] }
			}
			mut closed := false
			for {
				// Binary CLIP:SET payload arrives after the CLIP:SET\n line.
				// Consume the 4-byte length prefix then the raw clipboard bytes,
				// then b64-encode and relay upstream. No newline scanning here.
				if c.clip_set_waiting {
					if c.clip_set_len < 0 {
						if c.inbuf.len < 4 {
							break
						}
						c.clip_set_len = int((u32(c.inbuf[0]) << 24) | (u32(c.inbuf[1]) << 16) | (u32(c.inbuf[2]) << 8) | u32(c.inbuf[3]))
						c.inbuf = c.inbuf[4..]
					}
					if c.inbuf.len < c.clip_set_len {
						break
					}
					raw := c.inbuf[..c.clip_set_len].clone()
					c.inbuf = c.inbuf[c.clip_set_len..]
					c.clip_set_waiting = false
					c.clip_set_len = -1
					enc := base64.encode(raw)
					cid2 := next_id
					next_id++
					routes[cid2] = Route{
						fd:       c.fd
						inner_id: -1
						clip:     true
					}
					send_up('R${cid2}:CLIP:SET:${enc}'.bytes(), mut bh, monotonic_ms())
					continue
				}
				nl := index_of(c.inbuf, u8(0x0a))
				if nl < 0 {
					break
				}
				line := c.inbuf[..nl].clone()
				c.inbuf = c.inbuf[nl + 1..].clone()
				if !c.authed {
					if ct_eq(line, secret) {
						c.authed = true
						write_str(c.fd, 'OK\n')
					} else {
						C.close(c.fd)
						drop << ci
						closed = true
						break
					}
					continue
				}
				sline := line.bytestr()
				// `CONDUIT[:<cmdline>]`: this client (an `sb inject`) owns a downward byte
				// stream -- a tree edge. Tag it + assign a cid so SURVEY fans out to it and
				// its SURVEYR replies get this cid prepended to their route. The optional
				// cmdline is the sub-process it drives, shown by `sb ctl -v`.
				if sline == 'CONDUIT' || sline.starts_with('CONDUIT:') {
					c.conduit = true
					c.cid = next_cid
					next_cid++
					c.desc = if sline.len > 8 { sline[8..] } else { '' }
					continue
				}
				// A SURVEYR coming UP from a conduit child: prepend this conduit's cid
				// to the route (building the wrapper->node path) and relay it up.
				if sline.starts_with('SURVEYR:') {
					parts := sline.split_nth(':', 4) // SURVEYR, sid, route, identity
					if parts.len == 4 {
						route := if parts[2] == '' { '${c.cid}' } else { '${c.cid},${parts[2]}' }
						send_up('SURVEYR:${parts[1]}:${route}:${parts[3]}'.bytes(), mut
							bh, monotonic_ms())
					}
					continue
				}
				// A PUSHR (push reply) coming UP from a conduit child: forward verbatim
				// -- the push-id is wrapper-global, so no per-hop remapping is needed.
				if sline.starts_with('PUSHR:') {
					send_up(line, mut bh, monotonic_ms())
					continue
				}
				// `STATUS` -- `sb ctl` status query. Reply with key=value lines covering
				// session byte counts, backhaul state, relay links, and uptime. `~END`
				// terminates the response. Handled here (inline access to all pump locals).
				if sline == 'STATUS' {
					now_ctl := monotonic_ms()
					uptime := now_ctl - start_ms
					bh_state := bh.state.str()
					mut bh_info := ''
					if bh.state != .inactive {
						mut cstr := ''
						for ca in bh.cands {
							if cstr.len > 0 {
								cstr += ','
							}
							cstr += '${sa_ip(&ca)}:${int(C.htons(ca.sin_port))}'
						}
						srflx_str := if bh.srflx.ip.len > 0 {
							'${bh.srflx.ip}:${int(bh.srflx.port)}'
						} else {
							''
						}
						bh_info = 'bh_peer_cands:${cstr}\nbh_srflx:${srflx_str}\nbh_tx_bytes:${bh.tx_off}\nbh_rx_bytes:${bh.rx_bytes}\nbh_tx_frames:${
							bh.tx_base + bh.sent.len}\nbh_rx_frames:${bh.rx_frames}\nbh_arq_rtt_ms:${bh.arq.srtt}\nbh_arq_rto_ms:${bh.arq.rto}\nbh_arq_inflight_bytes:${bh.arq.outstanding()}\nbh_arq_inflight_segs:${bh.arq.unacked.len}\n'
					}
					mut ntunnels := 0
					mut nconduits := 0
					for cl in clients {
						if cl.tunnel_id >= 0 {
							ntunnels++
						}
						if cl.conduit {
							nconduits++
						}
					}
					mut nrpcs := 0
					for _, rt in routes {
						if !rt.persistent {
							nrpcs++
						}
					}
					write_str(c.fd, 'depth:${depth}\nuptime_ms:${uptime}\nmain_rx_bytes:${stat_main_rx}\nmain_tx_bytes:${stat_main_tx}\npty_rx_bytes:${stat_pty_rx}\npty_tx_bytes:${stat_pty_tx}\nbh_state:${bh_state}\n${bh_info}clients:${clients.len}\nports:${ntunnels}\nrelays:${nconduits}\nrpcs:${nrpcs}\n~END\n')
					continue
				}
				// `COMPS` -- `sb ctl -v` inventory: one `comp\t<pid>\t<cat>\t<desc>` line
				// per DIRECT local component (relay/port/rpc), `~END`-terminated. desc is
				// tab/newline-free by construction, so the wire stays line/field-safe.
				if sline == 'COMPS' {
					mut out := ''
					for cp in inventory(clients, routes) {
						out += 'comp\t${cp.pid}\t${cp.cat}\t${cp.desc}\n'
					}
					write_str(c.fd, '${out}~END\n')
					continue
				}
				// `KILL:<selector>[:<match>]` -- `sb ctl kill`. selector in {all, relays,
				// ports, rpcs, <pid>}; optional `<match>` requires the component's desc to
				// contain it (the `--match=` filter / PID-reuse safeguard). The mux resolves
				// against its OWN inventory and signals ONLY those PIDs -- a client can never
				// name an arbitrary process (PIDs are kernel-attested via SO_PEERCRED).
				// Replies `killed\t<pid>\t<cat>\t<desc>` per signalled component + `~END`.
				if sline.starts_with('KILL:') {
					parts := sline.split_nth(':', 3) // KILL, selector, match
					selector := if parts.len >= 2 { parts[1] } else { '' }
					matchf := if parts.len >= 3 { parts[2] } else { '' }
					comps := inventory(clients, routes)
					pids := select_kills(comps, selector, matchf)
					mut out := ''
					for cp in comps {
						if pids.index(cp.pid) >= 0 && (matchf == '' || cp.desc.contains(matchf)) {
							C.kill(cp.pid, sigterm)
							out += 'killed\t${cp.pid}\t${cp.cat}\t${cp.desc}\n'
						}
					}
					write_str(c.fd, '${out}~END\n')
					continue
				}
				// `BH:DOWN` -- force the backhaul into a lossless revert (no-op if not up).
				if sline == 'BH:DOWN' {
					if bh.state == .up {
						bh.begin_revert(monotonic_ms())
						write_str(c.fd, 'OK\n')
					} else {
						write_str(c.fd, 'OK:already-down\n')
					}
					continue
				}
				// `BH:UP[:<ip>:<port>[,<ip>:<port>...]]` -- ask the wrapper to (re)negotiate
				// a UDP backhaul. Sends UP:RENEG in-band (wrapper forces a fresh UP:O:
				// regardless of its one-shot renegotiation guard). Optional CSV candidate
				// override is stashed in pending_cands and consumed on the next UP:O:.
				if sline.starts_with('BH:UP') {
					rest := sline['BH:UP'.len..]
					pending_cands = []IpPort{}
					if rest.starts_with(':') {
						for tok2 in rest[1..].split(',') {
							cpos := tok2.last_index(':') or { continue }
							p := u16(tok2[cpos + 1..].int())
							if p > 0 {
								pending_cands << IpPort{tok2[..cpos], p}
							}
						}
					}
					reneg := build_apc('UP:RENEG'.bytes())
					write1(unsafe { &reneg[0] }, i64(reneg.len))
					write_str(c.fd, 'OK\n')
					continue
				}
				// `TOKEN:<tok>` (empty => randomize): the `sb token` command. Rebind the
				// listen socket to the new token's locator + adopt its secret, so this mux
				// follows the token (session recovery). The caller is already authed
				// with the OLD secret; new clients use the new one. Reply `OK:<token>`.
				if sline.starts_with('TOKEN:') {
					req := sline.all_after('TOKEN:')
					newtok := if req == '' { make_token() } else { req }
					if !valid_token(newtok) {
						write_str(c.fd, 'ERR bad-token\n')
						continue
					}
					lfd, sock_path, secret = rebind_socket(lfd, sock_path, newtok)
					C.setenv(c'SB_TOKEN', newtok.str, 1)
					write_str(c.fd, 'OK:${newtok}\n')
					continue
				}
				// `CLIP:GET` -- paste: relay upstream, mux decodes the b64 APC response and
				// sends raw bytes (OK\n + 4-byte-len + payload) to the socket client.
				if sline == 'CLIP:GET' {
					cgid := next_id
					next_id++
					routes[cgid] = Route{
						fd:       c.fd
						inner_id: -1
						clip:     true
					}
					send_up('R${cgid}:CLIP:GET'.bytes(), mut bh, monotonic_ms())
					continue
				}
				// `CLIP:SET` -- copy: signal to the binary payload reader above.
				// The payload (4-byte-len + raw bytes) follows immediately after this line.
				if sline == 'CLIP:SET' {
					c.clip_set_waiting = true
					c.clip_set_len = -1
					continue
				}
				// A request line. Assign our own id (label-swap), record the source,
				// and relay `R<id>:<inner>` up. If it arrived `R<inner>:...` (a deeper
				// host relaying through its conduit) we remember the inner id so the
				// reply re-frames back to it; else (a local tool, or a deeper host's
				// pre-mux bootstrap) the reply goes back unframed (inner_id = -1).
				// `TUN:...` opens a tunnel: a PERSISTENT label-swap route bound to this client;
				// its later lines relay under the SAME id (not a fresh one each), so the
				// tunnel's O/D/H/C frames share one route the wrapper demuxes, and frames down
				// route back here (the route is not deleted on reply).
				if sline.starts_with('TUN:') {
					tid := next_id
					next_id++
					routes[tid] = Route{
						fd:         c.fd
						inner_id:   -1
						persistent: true
					}
					c.tunnel_id = tid
					c.desc = sline['TUN:'.len..] // e.g. `dial:host:22` / `bind:127.0.0.1:8080:all`
					send_up('R${tid}:${sline}'.bytes(), mut bh, monotonic_ms())
					continue
				}
				if c.tunnel_id >= 0 {
					send_up('R${c.tunnel_id}:${sline}'.bytes(), mut bh, monotonic_ms())
					continue
				}
				okr, inner_id, inner := parse_route(line)
				if okr {
					// A routed line up from a conduit child (a deeper host relaying through
					// its conduit). If it belongs to an already-established multi-hop tunnel
					// -- a persistent route for this (conduit fd, inner id) pair -- reuse that
					// id so every O/D/H/C frame of the tunnel shares ONE route the whole way
					// up (the wrapper demuxes by route id). Otherwise mint a route, marking it
					// persistent iff it opens a tunnel (`TUN:`); plain requests stay one-shot.
					mut id := -1
					for rid, rt in routes {
						if rt.persistent && rt.fd == c.fd && rt.inner_id == inner_id {
							id = rid
							break
						}
					}
					if id < 0 {
						id = next_id
						next_id++
						routes[id] = Route{
							fd:         c.fd
							inner_id:   inner_id
							persistent: bprefix(inner, 'TUN:')
						}
					} else if bprefix(inner, 'TUN-CLOSE') {
						routes.delete(id) // deep tunnel torn down -> drop the reused route
					}
					mut cmd := 'R${id}:'.bytes()
					cmd << inner
					send_up(cmd, mut bh, monotonic_ms())
				} else {
					id := next_id
					next_id++
					// RPC desc = the verb only (up to the first ':'); args may hold secrets.
					routes[id] = Route{
						fd:       c.fd
						inner_id: -1
						pid:      c.pid
						desc:     sline[..(sline.index(':') or { sline.len })]
					}
					mut cmd := 'R${id}:'.bytes()
					cmd << line
					send_up(cmd, mut bh, monotonic_ms())
				}
			}
			if closed {
				continue
			}
		}
		for di := drop.len - 1; di >= 0; di-- {
			clients.delete(drop[di])
		}
		// accept new clients last (after the fds-aligned client pass above).
		if lfd >= 0 && (fds[3].revents & readable) != 0 {
			cfd := C.accept(lfd, unsafe { nil }, unsafe { nil })
			if cfd >= 0 {
				clients << MuxClient{
					fd:     cfd
					authed: false
					pid:    peer_pid(cfd) // kernel-attested; basis for safe `sb ctl kill`
				}
			}
		}
	}

	if lfd >= 0 {
		C.unlink(sock_path.str) // remove our (possibly rebound) socket on the way out
	}
	relay_finish(pid, have_saved, mut saved)
}

// Index of the first `b` in `buf`, or -1.
fn index_of(buf []u8, b u8) int {
	for i in 0 .. buf.len {
		if buf[i] == b {
			return i
		}
	}
	return -1
}

// True if `buf` starts with the bytes of `s` -- a cheap prefix test that avoids copying
// a (possibly large) frame into a string just to check its leading verb.
fn bprefix(buf []u8, s string) bool {
	if buf.len < s.len {
		return false
	}
	for i in 0 .. s.len {
		if buf[i] != s[i] {
			return false
		}
	}
	return true
}

// Find the first index of `needle` in `hay`, or -1. A short-needle linear scan;
// both the swallow buffer and the BEGIN marker stay small.
fn find_subseq(hay []u8, needle []u8) int {
	if needle.len == 0 || hay.len < needle.len {
		return -1
	}
	for i in 0 .. hay.len - needle.len + 1 {
		mut ok := true
		for j in 0 .. needle.len {
			if hay[i + j] != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

// forkpty `argv`, put our stdin in raw mode, seed the slave window size, and return
// (pid, master_fd, sfd, saved_termios, have_saved). Shared setup for `plain_relay`
// and `conduit_relay`. On forkpty failure it dies.
fn relay_setup(argv []string) (int, int, int, [64]u8, bool, Winsize) {
	mut cargv := []charptr{}
	for w in argv {
		cargv << w.str
	}
	cargv << charptr(0)

	has_tty := C.isatty(0) == 1
	mut ws := Winsize{}
	mut wsp := unsafe { nil }
	if has_tty && C.ioctl(0, tiocgwinsz, &ws) == 0 {
		wsp = voidptr(&ws)
	}
	mut saved := [64]u8{}
	mut have_saved := false
	if has_tty && C.tcgetattr(0, voidptr(&saved[0])) == 0 {
		have_saved = true
		mut raw := [64]u8{}
		C.tcgetattr(0, voidptr(&raw[0]))
		C.cfmakeraw(voidptr(&raw[0]))
		C.tcsetattr(0, tcsadrain, voidptr(&raw[0]))
	}

	mut master := 0
	pid := C.forkpty(&master, charptr(0), unsafe { nil }, wsp)
	if pid < 0 {
		if have_saved {
			C.tcsetattr(0, tcsaflush, voidptr(&saved[0]))
		}
		die('forkpty failed')
	}
	if pid == 0 {
		C.execvp(cargv[0], voidptr(cargv.data))
		C._exit(127)
	}

	mut mask := [128]u8{}
	C.sigemptyset(voidptr(&mask[0]))
	C.sigaddset(voidptr(&mask[0]), sigwinch)
	C.sigaddset(voidptr(&mask[0]), sigchld)
	C.sigprocmask(sig_block, voidptr(&mask[0]), unsafe { nil })
	sfd := C.signalfd(-1, voidptr(&mask[0]), sfd_cloexec)
	return pid, master, sfd, saved, have_saved, ws
}

@[noreturn]
fn relay_finish(pid int, have_saved bool, mut saved [64]u8) {
	mut status := 0
	C.waitpid(pid, &status, 0)
	if have_saved {
		C.tcsetattr(0, tcsaflush, voidptr(&saved[0]))
	}
	code := if status & 0x7f == 0 { (status >> 8) & 0xff } else { 128 + (status & 0x7f) }
	C._exit(code)
}

// A pure PTY byte-pump: forkpty `argv`, raw-relay stdin/master both directions,
// mirror SIGWINCH + exit status. No protocol at all. `run_pump` (local shell /
// `__pumptest`) and `sb inject`'s no-session fallback use it.
@[noreturn]
fn plain_relay(argv []string) {
	pid, master, sfd, mut saved, have_saved, mut ws := relay_setup(argv)
	mut fds := [3]Pollfd{}
	fds[0] = Pollfd{
		fd:     0
		events: pollin
	}
	fds[1] = Pollfd{
		fd:     master
		events: pollin
	}
	fds[2] = Pollfd{
		fd:     sfd
		events: pollin
	}
	bufsz := usize(65536)
	buf := unsafe { &u8(malloc(isize(bufsz))) }
	for {
		if C.poll(voidptr(&fds[0]), 3, -1) < 0 {
			break
		}
		if (fds[0].revents & readable) != 0 {
			n := C.read(0, voidptr(buf), bufsz)
			if n <= 0 {
				fds[0].fd = -1
			} else {
				write_all(master, buf, n)
			}
		}
		if (fds[1].revents & readable) != 0 {
			n := C.read(master, voidptr(buf), bufsz)
			if n <= 0 {
				break
			}
			write_all(1, buf, n)
		}
		if (fds[2].revents & pollin) != 0 {
			mut si := [128]u8{}
			C.read(sfd, voidptr(&si[0]), 128)
			signo := unsafe { *(&u32(voidptr(&si[0]))) }
			if signo == u32(sigwinch) {
				if C.ioctl(0, tiocgwinsz, &ws) == 0 {
					C.ioctl(master, tiocswinsz, &ws)
				}
			}
		}
	}
	relay_finish(pid, have_saved, mut saved)
}

// The pure PTY byte-pump for a local shell (the `__pumptest` self-test path).
@[noreturn]
fn run_pump(shell string, rc string) {
	plain_relay(shell_launch_words(shell, rc))
}

// The injector's sync. After feeding the bootstrap into the injected shell, read +
// DISCARD that shell's output (prompt, the echo of the fed line) until the
// bootstrap's `BEGIN` APC, and RETURN any bytes that trailed it (the first real
// session traffic) for the caller's relay to process. Byte-level marker match, so
// the echoed *source* of the fed line (literal `\033...BEGIN`, never a real ESC byte)
// can't false-trigger.
fn swallow_until_begin(master int) []u8 {
	marker := build_apc('BEGIN'.bytes())
	mut acc := []u8{}
	mut chunk := [4096]u8{}
	for {
		n := C.read(master, voidptr(&chunk[0]), usize(4096))
		if n <= 0 {
			die('sb inject: injected shell exited before bootstrap BEGIN')
		}
		for i in 0 .. int(n) {
			acc << chunk[i]
		}
		idx := find_subseq(acc, marker)
		if idx >= 0 {
			return acc[idx + marker.len..].clone()
		}
		if acc.len > 65536 {
			keep := marker.len - 1
			acc = acc[acc.len - keep..].clone()
		}
	}
	return []u8{} // unreachable (the loop only exits via return/die); satisfies V
}

// Drain an up-scanner: terminal `passthru` -> our stdout (the user's screen); each
// extracted request payload -> the mux socket as a `\n`-terminated line (requests
// are single-line). The host mux relabels + relays it up the byte stream.
// forward_up drains the deeper pty's scanned output: terminal passthru -> our
// stdout, APC payloads -> the conduit socket (newline-framed). Returns true if the
// deeper mux emitted MUXUP (it is ready to demux) -- consumed here, not relayed:
// it's the local gate that releases held terminal input so tty bytes never
// interlace the deeper mux's pre-pump setup exchange.
fn forward_up(mut up Scanner, sockfd int) bool {
	pt := up.take_passthru()
	if pt.len > 0 {
		write_all(1, unsafe { &pt[0] }, i64(pt.len))
	}
	mut muxup := false
	for pl in up.take_payloads() {
		if pl.bytestr() == 'MUXUP' {
			muxup = true
			continue
		}
		mut line := pl.clone()
		line << u8(0x0a)
		write_all(sockfd, unsafe { &line[0] }, i64(line.len))
	}
	return muxup
}

// `sb inject`'s conduit bridge: forkpty the transport, feed the bootstrap,
// sync on BEGIN, then relay -- terminal both ways verbatim -- while the deeper host's
// protocol is BACKHAULED over the mux SOCKET (`sockfd`) instead of up our own tty.
// So the host mux's child tty stays opaque: an `up` Scanner splits the deeper byte
// stream (terminal -> our stdout, request APCs -> socket as lines), and the socket's
// responses (raw APC bytes the host mux re-framed `R<inner>:`) are written straight
// down into the deeper pty, where the deeper mux's own scanner routes them.
@[noreturn]
fn conduit_relay(argv []string, feed []u8, sockfd int, token string) {
	pid, master, sfd, mut saved, have_saved, mut ws := relay_setup(argv)
	mut up := Scanner{}
	// Hold terminal input until the deeper mux signals MUXUP (ready to demux): its
	// pre-pump mux_setup reads fd 0 RAW, so any tty byte that arrived during that
	// window would interlace the fetch exchange and corrupt it. This preemption is
	// the multiplexer's whole job -- keep the tty and APC channels separate.
	mut muxready := false
	mut heldin := []u8{}

	write_all(master, unsafe { &feed[0] }, i64(feed.len))
	trailing := swallow_until_begin(master)
	if trailing.len > 0 {
		up.feed(trailing)
		if forward_up(mut up, sockfd) {
			muxready = true
		}
	}

	mut fds := [4]Pollfd{}
	fds[0] = Pollfd{
		fd:     0
		events: pollin
	}
	fds[1] = Pollfd{
		fd:     master
		events: pollin
	}
	fds[2] = Pollfd{
		fd:     sockfd
		events: pollin
	}
	fds[3] = Pollfd{
		fd:     sfd
		events: pollin
	}
	bufsz := usize(65536)
	buf := unsafe { &u8(malloc(isize(bufsz))) }
	// Safety net: if the injected command never becomes a mux (no MUXUP), release
	// held input after a generous grace so input can't hang forever -- far longer
	// than any real mux_setup, so it never preempts a legitimately-slow startup.
	gate_deadline := monotonic_ms() + 20000
	for {
		mut to := -1
		if !muxready {
			rem := gate_deadline - monotonic_ms()
			if rem <= 0 {
				muxready = true // grace elapsed -> assume no mux; stop holding input
				if heldin.len > 0 {
					write_all(master, unsafe { &heldin[0] }, i64(heldin.len))
					heldin = []u8{}
				}
			} else {
				to = int(rem)
			}
		}
		if C.poll(voidptr(&fds[0]), 4, to) < 0 {
			break
		}
		// our stdin (user keystrokes) -> deeper pty (terminal down), but HELD until
		// the deeper mux is ready (MUXUP) so it can't interlace the setup exchange.
		if (fds[0].revents & readable) != 0 {
			n := C.read(0, voidptr(buf), bufsz)
			if n <= 0 {
				fds[0].fd = -1
			} else if muxready {
				write_all(master, buf, n)
			} else {
				for k in 0 .. int(n) {
					heldin << unsafe { buf[k] }
				}
			}
		}
		// deeper pty up: terminal -> our stdout; request APCs -> socket. EOF = end.
		// On MUXUP, release any held terminal input -- the deeper pump now demuxes it.
		if (fds[1].revents & readable) != 0 {
			n := C.read(master, voidptr(buf), bufsz)
			if n <= 0 {
				break
			}
			up.feed_raw(buf, int(n))
			if forward_up(mut up, sockfd) && !muxready {
				muxready = true
				if heldin.len > 0 {
					write_all(master, unsafe { &heldin[0] }, i64(heldin.len))
					heldin = []u8{}
				}
			}
		}
		// socket down: response bytes (raw APC re-frames) -> deeper pty verbatim.
		if (fds[2].revents & readable) != 0 {
			n := C.read(sockfd, voidptr(buf), bufsz)
			if n <= 0 {
				fds[2].fd = -1 // mux/socket gone: stop backhaul, keep terminal alive
			} else {
				write_all(master, buf, n)
			}
		}
		if (fds[3].revents & pollin) != 0 {
			mut si := [128]u8{}
			C.read(sfd, voidptr(&si[0]), 128)
			signo := unsafe { *(&u32(voidptr(&si[0]))) }
			if signo == u32(sigwinch) {
				if C.ioctl(0, tiocgwinsz, &ws) == 0 {
					C.ioctl(master, tiocswinsz, &ws)
				}
			}
		}
	}
	C.close(sockfd)
	relay_finish(pid, have_saved, mut saved)
}

// `sb inject <cmd> [args...]` (alias `sb i`): the injector. forkpty the given
// command -- the user's *usual* way to reach a shell (`ssh host`, `docker exec -it
// c bash`, ...). Inside a session (SB_TOKEN set + the host mux socket reachable) it
// fetches the bootstrap over the socket, feeds it into the injected shell, and
// BACKHAULS the new hop's protocol over that same socket (the conduit) -- so the
// host mux's child tty stays opaque and the deeper host joins the routing tree as a
// label-swap edge. With no session / no reachable mux it degrades to a faithful
// pass-through wrapper around the command.
@[noreturn]
fn run_inject(cmd []string) {
	if cmd.len == 0 {
		die('usage: sb inject <command> [args...]')
	}
	token := os.getenv('SB_TOKEN')
	if token == '' {
		plain_relay(cmd)
	}
	mut shell := os.getenv('SB_SHELL')
	if shell == '' {
		shell = 'bash'
	}
	// Connect + auth, DECLARE the conduit (so the host mux fans SURVEY to us and
	// routes pushes through us), then fetch the bootstrap to feed -- all on the one
	// socket we keep as the backhaul conduit.
	sockfd := mux_sock_connect(mux_sock_path(token))
	if sockfd < 0 {
		plain_relay(cmd)
	}
	write_str(sockfd, '${token_secret(token)}\n')
	ok_line, ok := read_line(sockfd)
	if !ok || ok_line != 'OK' {
		C.close(sockfd)
		plain_relay(cmd)
	}
	// CONDUIT carries the injected cmdline so `sb ctl -v` can show which sub-process
	// this relay is driving. `\n`/`:` would break line/field framing -> spaces.
	cmdline := cmd.join(' ').replace('\n', ' ').replace(':', ' ')
	write_str(sockfd, 'CONDUIT:${cmdline}\n')
	write_str(sockfd, 'BOOT:${shell}\n')
	status, b64 := read_resp_b64(sockfd)
	if status != fr_eof || b64.len == 0 {
		C.close(sockfd)
		plain_relay(cmd)
	}
	// `eval` the bootstrap from inline base64 -- one line, no heredoc/escaping; the
	// wrapper already base64-encoded it for delivery, so feed `b64` straight in.
	feed := 'eval "$(printf %s ${b64}|base64 -d)"\n'.bytes()
	conduit_relay(cmd, feed, sockfd, token)
}
