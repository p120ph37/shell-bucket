"""Cross-implementation wire-compat check (runs INSIDE a Linux container that has
both the native `sb` binary and Python+cryptography).

Drives the Python backhaul transport (backhaul.py) against the native `sb` over
REAL UDP loopback, proving the AES-GCM packet codec, the TCP-lite ARQ, and the
hole-punch handshake are byte-for-byte compatible between the two implementations
-- not merely compatible by construction. Invoked by test_cross_impl.py.
"""

import asyncio
import select
import socket
import subprocess
import sys
import time

sys.path.insert(0, "/work/src/shell_bucket")
from backhaul import Arq, UdpBackhaul, now_ms  # noqa: E402

SB = "/b/sb"


def key_from_seed(seed: int) -> bytes:
    # Must match the V side: key[i] = (i*7 + seed) & 0xff.
    return bytes((i * 7 + seed) & 0xFF for i in range(32))


def test_stream(n: int) -> bytes:
    # Must match the V side: byte[i] = (i*131 + 7) & 0xff.
    return bytes((i * 131 + 7) & 0xFF for i in range(n))


def cross_arq() -> None:
    """Python Arq sender <-> `sb __arqrecv` over a connected UDP pair."""
    seed, total, py_port, sb_port = 42, 256 * 1024, 41001, 41002
    proc = subprocess.Popen(
        [SB, "__arqrecv", str(sb_port), "127.0.0.1", str(py_port), str(total), str(seed)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.3)  # let sb bind before we send
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", py_port))
    sock.connect(("127.0.0.1", sb_port))
    sock.setblocking(False)
    a = Arq(key_from_seed(seed), tx_salt=1, rx_salt=2)  # sb recv uses tx=2/rx=1
    a.app_send(test_stream(total), now_ms())
    deadline = now_ms() + 30000
    while (a.pending or a.unacked) and now_ms() < deadline:
        for pkt in a.poll_out():
            sock.send(pkt)
        select.select([sock], [], [], max(0.001, a.next_timeout(now_ms()) / 1000))
        try:
            while True:
                a.on_packet(sock.recv(2048), now_ms())
        except BlockingIOError:
            pass
        a.tick(now_ms())
    for pkt in a.poll_out():
        sock.send(pkt)
    sock.close()
    out = proc.communicate(timeout=10)[0].decode()
    assert f"RECV:{total}:OK" in out, f"ARQ py->sb: {out!r}"
    print(f"ok: ARQ py->sb wire-compatible ({total} bytes)")


async def cross_punch() -> None:
    """Python UdpBackhaul <-> `sb __punchrecv`: hole punch, then transfer over the ARQ."""
    seed, total, py_port, sb_port = 43, 131072, 41003, 41004
    proc = subprocess.Popen(
        [SB, "__punchrecv", str(sb_port), "127.0.0.1", str(py_port), str(total), str(seed)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", py_port))
    bh = UdpBackhaul(key_from_seed(seed), 1, 2, [("127.0.0.1", sb_port)], lambda f: None)
    bh.start(sock)
    for _ in range(300):
        if bh.state == "up":
            break
        await asyncio.sleep(0.02)
    assert bh.state == "up", "punch did not establish"
    # sb __punchrecv inflates the backhaul stream, so send the deterministic run
    # through the compressor + ARQ directly (compress + queue, no frame wrapping
    # and no revert tracking -- this driver streams raw and never reverts).
    bh.arq.app_send(bh._compress(test_stream(total)), now_ms())
    bh._flush()
    for _ in range(2000):
        if not bh.arq.pending and not bh.arq.unacked:
            break
        await asyncio.sleep(0.02)
    bh.close()
    out = proc.communicate(timeout=10)[0].decode()
    assert f"RECV:{total}:OK" in out, f"punch py<->sb: {out!r}"
    print(f"ok: punch + ARQ py<->sb wire-compatible ({total} bytes)")


cross_arq()
asyncio.run(cross_punch())
print("CROSS-IMPL: all OK")
