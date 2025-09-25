from __future__ import annotations
import selectors
import socket
import threading
import time
from typing import Optional, Tuple
from queue import Queue, Empty

import can

# ⬇️ import updated helpers (note: no batch/seq anymore)
from .protocol import HANDSHAKE, encode_frames, decode_stream, DecodeError


def _parse_channel(channel: str) -> Tuple[str, int]:
    if ":" not in channel:
        raise ValueError("channel must be 'host:port'")
    host, ports = channel.rsplit(":", 1)
    return host, int(ports)


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
            raise ValueError("Provide either channel='host:port' or host+port, not both.")
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

        self._alive = threading.Event()
        self._rx_thread = threading.Thread(target=self._rx_loop, name="cnl-rx", daemon=True)

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

    def fileno(self) -> int:
        return self._sock.fileno() if self._sock is not None else -1

    def send(self, msg: can.Message, timeout: Optional[float] = None) -> None:
        if self._sock is None:
            raise can.CanError("Not connected")
        try:
            pkt = encode_frames([msg])   # ⬅️ direct per-frame encoding
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
            if self._filters and not can.util.match_filters([msg], self._filters):
                return None
            return msg
        except Empty:
            return None

    # --- internals ------------------------------------------------------------

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
        try:
            peer = s.recv(len(HANDSHAKE))
        except socket.timeout:
            peer = b""
        if peer and peer != HANDSHAKE:
            s.close()
            raise can.CanError(f"Unexpected handshake from server: {peer!r}")

        s.settimeout(None)
        self._sock = s

    def _reconnect_blocking(self):
        while self._alive.is_set():
            try:
                self._connect()
                return
            except OSError:
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
        sel = selectors.DefaultSelector()
        if self._sock is None:
            return
        sel.register(self._sock, selectors.EVENT_READ)

        while self._alive.is_set():
            try:
                events = sel.select(timeout=0.5)
                if not events:
                    continue
                sock: socket.socket = events[0].fileobj  # type: ignore
                chunk = sock.recv(65536)
                if not chunk:
                    raise OSError("peer closed")
                self._rx_buf.extend(chunk)

                # Pull as many complete frames as possible
                while True:
                    consumed, msgs = decode_stream(self._rx_buf)
                    if consumed == 0:
                        break
                    del self._rx_buf[:consumed]
                    for m in msgs:
                        try:
                            self._rx_queue.put_nowait(m)
                        except Exception:
                            pass
            except (OSError, DecodeError):
                # reconnect if allowed
                try:
                    if self._sock:
                        self._sock.close()
                except OSError:
                    pass
                self._sock = None
                if not self._reconnect:
                    break
                # block until back
                self._reconnect_blocking()
                sel.unregister(sock)
                sel.register(self._sock, selectors.EVENT_READ)
