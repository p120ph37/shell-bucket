"""E2E UDP-backhaul UPGRADE driver (runs INSIDE a Linux container with `sb` and
Python+cryptography).

Plays the wrapper side against a real `sb __upgradeserve`: mints a PSK, gathers a
candidate, sends the `UP:O:` offer over the in-band channel (the subprocess's
stdin), receives the mux's `UP:A:` answer (its stdout), establishes the UDP
backhaul via the real punch on loopback, and verifies a frame round-trips over
UDP (the mux echoes it). Exercises the full offer→answer→punch→frames-over-UDP
path with the real signaling codec, start_backhaul, Backhaul, and UdpBackhaul.
"""

import asyncio
import os
import socket
import sys

sys.path.insert(0, "/work/src/shell_bucket")
from apc_filter import APCFilter, apc_envelope  # noqa: E402
from backhaul import (  # noqa: E402
    SALT_MUX_TX,
    SALT_WRAPPER_TX,
    UdpBackhaul,
    decode_answer,
    encode_offer,
    local_ip,
)

SB = "/b/sb"


async def main() -> None:
    sb = await asyncio.create_subprocess_exec(
        SB, "__upgradeserve",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
    )
    try:
        # Wrapper side: mint PSK, gather our host candidate, send the offer in-band.
        psk, nonce = os.urandom(32), os.urandom(8)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", 0))
        my_cands = [(local_ip(), sock.getsockname()[1])]
        sb.stdin.write(apc_envelope(b"UP:O:" + encode_offer(psk, nonce, [], my_cands)))
        await sb.stdin.drain()

        # Receive the mux's UP:A answer (APC on its stdout) → establish the backhaul.
        got: list[bytes] = []
        bh = None
        apc = APCFilter()
        while bh is None:
            data = await asyncio.wait_for(sb.stdout.read(4096), timeout=10)
            if not data:
                break
            for ev in apc.feed(data)[1]:
                if ev.startswith(b"UP:A:"):
                    res = decode_answer(ev[5:])
                    assert res is not None, "undecodable UP:A"
                    _nonce, mux_cands = res
                    bh = UdpBackhaul(psk, SALT_WRAPPER_TX, SALT_MUX_TX, mux_cands, got.append)
                    bh.start(sock)
        assert bh is not None, "no UP:A answer from mux"

        for _ in range(300):  # wait for the punch to establish on loopback
            if bh.state == "up":
                break
            await asyncio.sleep(0.02)
        assert bh.state == "up", "backhaul did not establish"

        bh.send_frame(b"E2E-UPGRADE-PING")  # mux echoes it back over the backhaul
        for _ in range(200):
            if got:
                break
            await asyncio.sleep(0.02)
        bh.close()
        assert got == [b"E2E-UPGRADE-PING"], f"frame did not round-trip over UDP: {got}"
        print("UPGRADE-E2E: OK")
    finally:
        sb.terminate()


asyncio.run(main())
