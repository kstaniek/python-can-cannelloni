from __future__ import annotations
import struct
from typing import Iterable, List, Tuple
import can

# Cannelloni banner (no NUL)
HANDSHAKE = b"CANNELLONIv1"

# Per-frame record on the TCP stream:
#   can_id: u32 (big-endian, just the 29/11-bit ID; no kernel flag bits)
#   flags : u8  (bitfield defined below)
#   len   : u8  (0..8 classic, 0..64 FD)
#   data  : len bytes
_FR_HDR = struct.Struct("!IBB")

# Flag bits carried in the per-frame header
FLAG_EFF = 0x80   # extended frame format (29-bit)
FLAG_RTR = 0x40   # remote frame
FLAG_ERR = 0x20   # error frame
FLAG_FD  = 0x10   # CAN FD
FLAG_BRS = 0x08   # bitrate switch (FD)
FLAG_ESI = 0x04   # error state indicator (FD)


class EncodeError(Exception):
    pass


class DecodeError(Exception):
    pass


def _pack_flags(msg: can.Message) -> int:
    f = 0
    if msg.is_extended_id:        f |= FLAG_EFF
    if msg.is_remote_frame:       f |= FLAG_RTR
    if msg.is_error_frame:        f |= FLAG_ERR
    if getattr(msg, "is_fd", False):          f |= FLAG_FD
    if getattr(msg, "bitrate_switch", False): f |= FLAG_BRS
    if getattr(msg, "error_state_indicator", False): f |= FLAG_ESI
    return f


def encode_frames(msgs: Iterable[can.Message]) -> bytes:
    """
    Encode one or more CAN(/FD) messages as a TCP byte stream of
    back-to-back per-frame records: _FR_HDR + payload, with no outer header.
    """
    parts: List[bytes] = []
    for m in msgs:
        data = bytes(m.data or b"")
        if not getattr(m, "is_fd", False) and len(data) > 8:
            raise EncodeError("Classic CAN frame >8 bytes; set is_fd=True or trim data.")
        if len(data) > 64:
            raise EncodeError("CAN-FD payload must be <= 64 bytes.")
        flags = _pack_flags(m)
        parts.append(_FR_HDR.pack(m.arbitration_id & 0x1FFFFFFF, flags, len(data)))
        parts.append(data)
    return b"".join(parts)


def decode_stream(buf: bytearray) -> Tuple[int, list[can.Message]]:
    """
    Consume as many complete frames as available from the front of `buf`.
    Returns (consumed_bytes, [messages]). If no complete frame is present,
    returns (0, []).
    """
    pos = 0
    out: List[can.Message] = []

    # Need at least frame header
    while len(buf) - pos >= _FR_HDR.size:
        can_id, flags, length = _FR_HDR.unpack(buf[pos:pos + _FR_HDR.size])
        pos += _FR_HDR.size

        # Need the payload
        if len(buf) - pos < length:
            # Not enough payload yet: rewind to the start of this header
            pos -= _FR_HDR.size
            break

        payload = bytes(buf[pos:pos + length])
        pos += length

        msg = can.Message(
            arbitration_id=can_id & 0x1FFFFFFF,
            data=payload,
            is_extended_id=bool(flags & FLAG_EFF),
            is_remote_frame=bool(flags & FLAG_RTR),
            is_error_frame=bool(flags & FLAG_ERR),
            is_fd=bool(flags & FLAG_FD),
            bitrate_switch=bool(flags & FLAG_BRS),
            error_state_indicator=bool(flags & FLAG_ESI),
        )
        out.append(msg)

    if pos == 0:
        return 0, []
    return pos, out
