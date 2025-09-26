# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Klaudiusz Staniek

import socket
import struct
import threading
import time

import can
from can_cannelloni.bus import CannelloniBus

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


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise OSError("eof")
        buf.extend(chunk)
    return bytes(buf)


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
                _ = _recv_exact(conn, len(HANDSHAKE))
                conn.sendall(HANDSHAKE)
            except Exception:
                return

            # Echo loop: [4B ID BE][1B LEN][LEN bytes]
            try:
                while True:
                    hdr = _recv_exact(conn, 5)
                    _cid_be, ln = struct.unpack("!IB", hdr)
                    payload = _recv_exact(conn, ln)
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
            # Read client's banner, respond with ours (in full)
            _ = _recv_exact(conn, len(HANDSHAKE))
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


def make_partial_handshake_server(bind_host="127.0.0.1", split_at=3, delay=0.05):
    """
    Accepts one client. Reads full client banner, then sends server banner
    in two parts with a small delay to exercise client-side partial recv handling.
    Then echoes frames.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_host, 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        conn, _ = srv.accept()
        with conn:
            try:
                _ = _recv_exact(conn, len(HANDSHAKE))
                conn.sendall(HANDSHAKE[:split_at])
                time.sleep(delay)
                conn.sendall(HANDSHAKE[split_at:])
            except Exception:
                return
            try:
                while True:
                    hdr = _recv_exact(conn, 5)
                    _cid_be, ln = struct.unpack("!IB", hdr)
                    payload = _recv_exact(conn, ln)
                    conn.sendall(hdr + payload)
            except Exception:
                return

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return srv, port, t


def make_flaky_server(frame1: bytes, frame2: bytes, bind_host="127.0.0.1"):
    """
    Accepts two consecutive clients on the same listening socket.
    First connection: handshake, send frame1, then close immediately.
    Second connection: handshake, send frame2, then sleep a bit.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_host, 0))
    srv.listen(2)
    port = srv.getsockname()[1]

    def handle_once(payload: bytes):
        try:
            conn, _ = srv.accept()
        except Exception:
            return
        with conn:
            try:
                _ = _recv_exact(conn, len(HANDSHAKE))
                conn.sendall(HANDSHAKE)
                if payload:
                    conn.sendall(payload)
            except Exception:
                return

    def run():
        # First client
        handle_once(frame1)
        # Close immediately after sending first frame by simply returning from context
        # Second client
        handle_once(frame2)
        time.sleep(0.05)

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
        bus = CannelloniBus(channel=f"127.0.0.1:{port}", receive_own_messages=True)
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
        bus = CannelloniBus(channel=f"127.0.0.1:{port}")
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


def test_handshake_partial_server_banner():
    srv, port, _ = make_partial_handshake_server(split_at=4, delay=0.02)
    try:
        bus = CannelloniBus(channel=f"127.0.0.1:{port}")
        with bus:
            # After handshake, echo should work
            msg = can.Message(arbitration_id=0x321, data=b"Z", is_extended_id=False)
            bus.send(msg)
            rx = bus.recv(timeout=1.0)
            assert rx is not None
            assert rx.arbitration_id == 0x321
            assert rx.data == b"Z"
    finally:
        srv.close()


ess_frames = [
    pack_frame(0x1ABCDEF, b"\x10", extended=True),
    pack_frame(0x7FF, b"\x20", extended=False),
]


def test_extended_vs_standard_filtering():
    # Push one extended and one standard frame
    srv, port, _ = make_push_server(ess_frames)
    try:
        bus = CannelloniBus(channel=f"127.0.0.1:{port}")
        with bus:
            # Only standard
            bus.set_filters([{"can_id": 0, "can_mask": 0, "extended": False}])
            rx = bus.recv(timeout=1.0)
            assert rx is not None
            assert not rx.is_extended_id
            assert rx.data == b"\x20"
    finally:
        srv.close()


def test_reconnect_receives_after_drop():
    # First frame on first connection, second on reconnection
    f1 = pack_frame(0x111, b"\x01", extended=False)
    f2 = pack_frame(0x222, b"\x02", extended=False)
    srv, port, _ = make_flaky_server(f1, f2)
    try:
        bus = CannelloniBus(
            channel=f"127.0.0.1:{port}", reconnect=True, reconnect_interval=0.05
        )
        with bus:
            rx1 = bus.recv(timeout=1.0)
            assert rx1 is not None and rx1.arbitration_id == 0x111
            # After server closes, client should reconnect and receive second frame
            rx2 = bus.recv(timeout=2.0)
            assert rx2 is not None and rx2.arbitration_id == 0x222
    finally:
        srv.close()


def make_slow_reader_server(pause_after_hdr=0.2, bind_host="127.0.0.1"):
    """
    Server that handshakes, then on first frame reads header, sleeps, and then
    slowly reads payload to trigger client-side send timeout.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_host, 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        conn, _ = srv.accept()
        with conn:
            _ = _recv_exact(conn, len(HANDSHAKE))
            conn.sendall(HANDSHAKE)
            try:
                hdr = _recv_exact(conn, 5)
                _cid_be, ln = struct.unpack("!IB", hdr)
                time.sleep(pause_after_hdr)
                _ = _recv_exact(conn, ln)
            except Exception:
                return

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return srv, port, t


def make_blackhole_server(bind_host="127.0.0.1"):
    """
    Server that performs handshake then never reads application data, keeping
    the connection open to fill the peer's send buffer.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_host, 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        conn, _ = srv.accept()
        with conn:
            try:
                _ = _recv_exact(conn, len(HANDSHAKE))
                conn.sendall(HANDSHAKE)
                # Do not read further; sleep to keep connection alive
                time.sleep(2.0)
            except Exception:
                return

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return srv, port, t


# --- New tests for IPv6 parsing and send timeout -----------------------------


def test_ipv6_channel_parsing_localhost():
    # Use IPv6 loopback literal form; server binds IPv6 if available
    try:
        srv6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        srv6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except OSError:
        # Platform may not support IPv6; skip
        return

    srv6.bind(("::1", 0))
    srv6.listen(1)
    port = srv6.getsockname()[1]

    def run():
        conn, _ = srv6.accept()
        with conn:
            _ = _recv_exact(conn, len(HANDSHAKE))
            conn.sendall(HANDSHAKE)
            # Close right after handshake

    t = threading.Thread(target=run, daemon=True)
    t.start()

    try:
        bus = CannelloniBus(channel=f"[::1]:{port}")
        with bus:
            # No data expected, just ensure connect/close works
            pass
    finally:
        srv6.close()


def test_send_timeout_total_window(monkeypatch):
    # Use echo server to complete handshake
    ready = threading.Event()
    srv, port, _ = make_echo_server(ready_evt=ready)
    ready.wait(2.0)
    try:
        bus = CannelloniBus(channel=f"127.0.0.1:{port}")
        with bus:
            # After handshake, patch socket send to always timeout
            def fake_send(self, _data):
                raise socket.timeout("simulated")

            monkeypatch.setattr(socket.socket, "send", fake_send, raising=True)

            msg = can.Message(
                arbitration_id=0x10, data=b"ABCDEFGH", is_extended_id=False
            )
            start = time.monotonic()
            try:
                bus.send(msg, timeout=0.05)
                assert False, "expected timeout"
            except can.CanError as e:
                assert "timed out" in str(e)
            elapsed = time.monotonic() - start
            assert elapsed >= 0.04 and elapsed < 0.5
    finally:
        srv.close()
