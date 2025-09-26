# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Klaudiusz Staniek

from __future__ import annotations
import selectors
import socket
import threading
import time
from typing import Optional, Tuple
from queue import Queue, Empty

import can

from .protocol import HANDSHAKE, encode_frames, decode_stream


def _parse_channel(channel: str) -> Tuple[str, int]:
    if ":" not in channel:
        raise ValueError("channel must be 'host:port'")
    host, ports = channel.rsplit(":", 1)
    return host, int(ports)


def _msg_matches_filters(msg: can.Message, filters) -> bool:
    """Local filter matcher compatible with python-can filter dicts.

    Each filter is a dict with keys like:
      - "can_id": int (base id to match against)
      - "can_mask": int (bitmask)
      - "extended": bool (whether to match only extended or only standard ids)
    A message matches if it matches **any** filter in the list.
    """
    if not filters:
        return True

    mid = int(msg.arbitration_id)
    is_ext = bool(getattr(msg, "is_extended_id", False))

    for f in filters:
        fid = int(f.get("can_id", 0))
        mask = f.get("can_mask", None)
        if mask is None:
            # Sensible default if not provided
            mask = 0x1FFFFFFF if is_ext else 0x7FF
        else:
            mask = int(mask)

        ext_required = f.get("extended", None)
        if ext_required is not None and bool(ext_required) != is_ext:
            continue

        if (mid & mask) == (fid & mask):
            return True

    return False


class CannelloniBus(can.BusABC):
    """
    TCP client for a cannelloni server, streaming back-to-back per-frame
    records (no outer packet header).
    """

    def __init__(
        self,
        channel: Optional[str] = None,
        *,
        host: Optional[str] = None,
        port: Optional[int] = None,
        nodelay: bool = True,
        keepalive: bool = True,
        handshake_timeout: float = 2.0,
        reconnect: bool = True,
        reconnect_interval: float = 1.0,
        **kwargs,
    ):
        super().__init__(channel=channel, **kwargs)
        if channel and (host or port):
            raise ValueError(
                "Provide either channel='host:port' or host+port, not both."
            )
        if channel:
            host, port = _parse_channel(channel)
        if not host or not port:
            raise ValueError("Missing host/port for cannelloni TCP client")

        self._host = host
        self._port = int(port)
        self._nodelay = bool(nodelay)
        self._keepalive = bool(keepalive)
        self._hs_timeout = float(handshake_timeout)
        self._reconnect = bool(reconnect)
        self._reconnect_interval = float(reconnect_interval)

        self._sock: Optional[socket.socket] = None
        self._rx_buf = bytearray()
        self._rx_queue: "Queue[can.Message]" = Queue(maxsize=10000)
        self._filters = None
        self._drops = 0  # count of RX frames dropped due to full queue

        self._alive = threading.Event()
        self._rx_thread = threading.Thread(
            target=self._rx_loop, name="cnl-rx", daemon=True
        )

        self._connect()
        self._alive.set()
        self._rx_thread.start()

    def shutdown(self) -> None:
        self._alive.clear()
        try:
            if self._sock:
                try:
                    self._sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        finally:
            if self._sock:
                try:
                    self._sock.close()
                except OSError:
                    pass
            self._sock = None
            # Ensure RX thread exits and is joined to avoid leaks
            try:
                if self._rx_thread.is_alive():
                    self._rx_thread.join(timeout=2.0)
            except Exception:
                pass

    def fileno(self) -> int:
        return self._sock.fileno() if self._sock is not None else -1

    def send(self, msg: can.Message, timeout: Optional[float] = None) -> None:
        if self._sock is None:
            raise can.CanError("Not connected")
        try:
            pkt = encode_frames([msg])  # ⬅️ direct per-frame encoding
            if not pkt:
                return
            self._sendall(pkt, timeout)
        except (OSError, Exception) as e:
            raise can.CanError(str(e)) from e

    def set_filters(self, filters=None):
        self._filters = filters

    def recv(self, timeout: Optional[float] = None) -> Optional[can.Message]:
        try:
            msg = self._rx_queue.get(timeout=timeout)
        except Empty:
            return None

        if self._filters and not _msg_matches_filters(msg, self._filters):
            # Drop filtered-out and see if there’s another queued message ready.
            while True:
                try:
                    msg = self._rx_queue.get_nowait()
                except Empty:
                    return None
                if not self._filters or _msg_matches_filters(msg, self._filters):
                    return msg
        return msg

    # --- internals ------------------------------------------------------------

    def _recv_exact(
        self, sock: socket.socket, n: int, timeout: Optional[float]
    ) -> bytes:
        """Read exactly n bytes or raise on timeout/EOF."""
        prev_to = sock.gettimeout()
        if timeout is not None:
            sock.settimeout(timeout)
        try:
            buf = bytearray()
            while len(buf) < n:
                chunk = sock.recv(n - len(buf))
                if not chunk:
                    raise can.CanError("connection closed during handshake")
                buf.extend(chunk)
            return bytes(buf)
        except socket.timeout as e:
            raise can.CanError("handshake timed out") from e
        finally:
            # Restore blocking mode
            sock.settimeout(prev_to)

    def _connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self._hs_timeout)
        if self._nodelay:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self._keepalive:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        s.connect((self._host, self._port))

        # Both peers send the banner (no NUL)
        s.sendall(HANDSHAKE)
        peer = self._recv_exact(s, len(HANDSHAKE), self._hs_timeout)
        if peer != HANDSHAKE:
            s.close()
            raise can.CanError(f"Unexpected handshake from server: {peer!r}")

        s.settimeout(None)
        self._sock = s

    def _reconnect_blocking(self):
        while self._alive.is_set():
            try:
                self._connect()
                return
            except Exception:
                time.sleep(self._reconnect_interval)

    def _sendall(self, data: bytes, timeout: Optional[float]):
        if self._sock is None:
            raise OSError("socket closed")
        if timeout is None:
            self._sock.sendall(data)
            return
        self._sock.settimeout(timeout)
        try:
            view = memoryview(data)
            sent = 0
            while sent < len(view):
                n = self._sock.send(view[sent:])
                if n == 0:
                    raise OSError("socket closed")
                sent += n
        finally:
            self._sock.settimeout(None)

    def _rx_loop(self):
        def make_selector():
            sel = selectors.DefaultSelector()
            if self._sock is not None:
                sel.register(self._sock, selectors.EVENT_READ)
            return sel

        sel = make_selector()

        try:
            while self._alive.is_set():
                # If socket is gone, try to reconnect (if allowed)
                if self._sock is None:
                    if not self._reconnect:
                        break
                    self._reconnect_blocking()
                    sel.close()
                    sel = make_selector()
                    continue

                events = sel.select(timeout=0.5)
                if not events:
                    continue

                for key, mask in events:
                    sock: socket.socket = key.fileobj  # SelectorKey.fileobj
                    try:
                        chunk = sock.recv(65536)
                    except OSError:
                        chunk = b""

                    if not chunk:
                        # peer closed or error
                        try:
                            sock.close()
                        except OSError:
                            pass
                        self._sock = None
                        if not self._reconnect:
                            return
                        # Rebuild selector after reconnect
                        self._reconnect_blocking()
                        sel.close()
                        sel = make_selector()
                        break

                    # Accumulate and decode as many frames as possible
                    self._rx_buf.extend(chunk)
                    while True:
                        consumed, msgs = decode_stream(self._rx_buf)
                        if consumed == 0:
                            break
                        del self._rx_buf[:consumed]
                        for m in msgs:
                            # Apply filters early to avoid queue pressure
                            if self._filters and not _msg_matches_filters(
                                m, self._filters
                            ):
                                continue
                            try:
                                self._rx_queue.put_nowait(m)
                            except Exception:
                                # Queue likely full → drop and count
                                self._drops += 1
        finally:
            try:
                sel.close()
            except Exception:
                pass
