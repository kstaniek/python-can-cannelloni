# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Klaudiusz Staniek

import socket
import struct
import threading
import time

import can

# If you're using the packaged plugin (entry point), you'll call can.Bus(interface="cannelloni", ...)

# --- Protocol helpers (must match cannelloni TCP server) ---------------------

HANDSHAKE = b"CANNELLONIv1"  # both peers send this, no NUL

CAN_EFF_FLAG = 0x80000000  # Extended frame
CAN_RTR_FLAG = 0x40000000  # Remote frame
CAN_ERR_FLAG = 0x20000000  # Error frame
CAN_SFF_MASK = 0x000007FF
CAN_EFF_MASK = 0x1FFFFFFF


def pack_frame(
    can_id: int, data: bytes, *, extended: bool, rtr: bool = False, err: bool = False
) -> bytes:
    """[BE u32 CANID(with flags)][u8 LEN][DATA...]"""
    cid = 0
    if extended:
        cid |= CAN_EFF_FLAG | (can_id & CAN_EFF_MASK)
    else:
        cid |= can_id & CAN_SFF_MASK
    if rtr:
        cid |= CAN_RTR_FLAG
    if err:
        cid |= CAN_ERR_FLAG
    return struct.pack("!IB", cid, len(data)) + data


# --- Test server fixtures ----------------------------------------------------


def make_echo_server(bind_host="127.0.0.1", ready_evt=None):
    """
    Accepts one client. Performs Cannelloni handshake.
    Then echoes back each frame it receives:
      read 5-byte header, then LEN bytes, then send the same bytes back.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_host, 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        if ready_evt is not None:
            ready_evt.set()
        try:
            conn, _ = srv.accept()
        except Exception:
            return
        with conn:
            # Handshake: read client's banner, send ours back
            try:
                hs = b""
                while len(hs) < len(HANDSHAKE):
                    chunk = conn.recv(len(HANDSHAKE) - len(hs))
                    if not chunk:
                        return
                    hs += chunk
                conn.sendall(HANDSHAKE)
            except Exception:
                return

            # Echo loop: [4B ID BE][1B LEN][LEN bytes]
            try:
                while True:
                    hdr = b""
                    while len(hdr) < 5:
                        chunk = conn.recv(5 - len(hdr))
                        if not chunk:
                            return
                        hdr += chunk
                    _cid_be, ln = struct.unpack("!IB", hdr)
                    payload = b""
                    while len(payload) < ln:
                        chunk = conn.recv(ln - len(payload))
                        if not chunk:
                            return
                        payload += chunk
                    conn.sendall(hdr + payload)
            except Exception:
                return

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return srv, port, t


def make_push_server(frames, bind_host="127.0.0.1"):
    """
    Accepts one client. Performs handshake. Immediately sends the provided
    bytes (concatenated frames) and then sleeps briefly.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_host, 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        conn, _ = srv.accept()
        with conn:
            # Read client's banner, respond with ours
            hs = b""
            while len(hs) < len(HANDSHAKE):
                chunk = conn.recv(len(HANDSHAKE) - len(hs))
                if not chunk:
                    return
                hs += chunk
            conn.sendall(HANDSHAKE)

            # Push frames (non-matching first to exercise filtering)
            try:
                conn.sendall(b"".join(frames))
                time.sleep(0.1)
            except Exception:
                return

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return srv, port, t


# --- Tests -------------------------------------------------------------------


def test_codec_roundtrip():
    """
    Sanity check the on-wire codec by building a frame blob and re-parsing it here.
    (This is a light-weight codec test; full protocol tests happen via the echo server.)
    """
    # Build two frames and parse them back locally
    f1 = pack_frame(0x6F4A, b"\xfe\x21\x78\x28", extended=True, rtr=False)
    f2 = pack_frame(0x0681, b"", extended=False, rtr=True)
    blob = f1 + f2

    # Local decode: walk the blob and verify fields
    pos = 0
    cid1, ln1 = struct.unpack("!IB", blob[pos : pos + 5])
    pos += 5
    data1 = blob[pos : pos + ln1]
    pos += ln1
    cid2, ln2 = struct.unpack("!IB", blob[pos : pos + 5])
    pos += 5
    pos += ln2

    assert ln1 == 4 and data1 == b"\xfe\x21\x78\x28"
    assert (cid1 & CAN_EFF_FLAG) and (cid1 & CAN_EFF_MASK) == 0x6F4A

    assert ln2 == 0 and (cid2 & CAN_RTR_FLAG) and not (cid2 & CAN_EFF_FLAG)
    assert (cid2 & CAN_SFF_MASK) == 0x681


def test_send_recv_loopback():
    ready = threading.Event()
    srv, port, _ = make_echo_server(ready_evt=ready)
    ready.wait(2.0)
    try:
        # If installed as a plugin:
        bus = can.Bus(
            interface="cannelloni",
            channel=f"127.0.0.1:{port}",
            receive_own_messages=True,
        )

        # If using the drop-in module instead, replace the line above with:
        # bus = CannelloniBus(channel=f"127.0.0.1:{port}")

        with bus:
            msg = can.Message(arbitration_id=0x123, data=b"ABC", is_extended_id=False)
            bus.send(msg)
            rx = bus.recv(timeout=1.0)
            assert rx is not None
            assert rx.arbitration_id == 0x123
            assert rx.data == b"ABC"
            assert not rx.is_extended_id
    finally:
        srv.close()


def test_filters_drop_nonmatching():
    # Server sends two frames back-to-back on connect: non-matching first, then matching.
    f_match = pack_frame(0x100, b"\x01", extended=False, rtr=False)
    f_other = pack_frame(0x555, b"\x02", extended=False, rtr=False)
    srv, port, _ = make_push_server([f_other, f_match])

    try:
        # Build bus and apply filters (client-side)
        bus = can.Bus(interface="cannelloni", channel=f"127.0.0.1:{port}")
        # If using drop-in module:
        # bus = CannelloniBus(channel=f"127.0.0.1:{port}")

        with bus:
            flt = [{"can_id": 0x100, "can_mask": 0x7FF, "extended": False}]
            bus.set_filters(flt)

            rx = bus.recv(timeout=1.0)
            assert rx is not None
            assert rx.arbitration_id == 0x100
            assert rx.data == b"\x01"
            assert not rx.is_extended_id
    finally:
        srv.close()
