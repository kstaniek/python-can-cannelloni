# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Klaudiusz Staniek

from __future__ import annotations
import struct
from typing import Iterable, List, Tuple
import can

# Cannelloni banner (no NUL)
HANDSHAKE = b"CANNELLONIv1"

# Linux-style CANID flags in the upper bits (same as SocketCAN)
CAN_EFF_FLAG = 0x80000000  # Extended frame
CAN_RTR_FLAG = 0x40000000  # Remote frame
CAN_ERR_FLAG = 0x20000000  # Error frame

CAN_SFF_MASK = 0x000007FF
CAN_EFF_MASK = 0x1FFFFFFF

# On-wire per-frame header for your server:
#   u32 CANID (BIG-ENDIAN) | u8 LEN (0..8) | DATA[LEN]
_FR_HDR = struct.Struct("!IB")


class EncodeError(Exception):
    pass


class DecodeError(Exception):
    pass


def _to_canid(msg: can.Message) -> int:
    cid = 0
    if msg.is_extended_id:
        cid |= CAN_EFF_FLAG | (msg.arbitration_id & CAN_EFF_MASK)
    else:
        cid |= msg.arbitration_id & CAN_SFF_MASK
    if msg.is_remote_frame:
        cid |= CAN_RTR_FLAG
    if msg.is_error_frame:
        cid |= CAN_ERR_FLAG
    return cid


def _from_canid(cid: int) -> tuple[int, bool, bool, bool]:
    is_ext = bool(cid & CAN_EFF_FLAG)
    is_rtr = bool(cid & CAN_RTR_FLAG)
    is_err = bool(cid & CAN_ERR_FLAG)
    arb = cid & (CAN_EFF_MASK if is_ext else CAN_SFF_MASK)
    return arb, is_ext, is_rtr, is_err


def encode_frames(msgs: Iterable[can.Message]) -> bytes:
    """Encode frames as [BE u32 canid][u8 len][data...] with len<=8."""
    parts: List[bytes] = []
    for m in msgs:
        if getattr(m, "is_fd", False):
            raise EncodeError(
                "CAN-FD not supported on this TCP codec (len must be <= 8)."
            )
        data = bytes(m.data or b"")
        if m.is_remote_frame and data:
            raise EncodeError("RTR frame must not carry data.")
        if len(data) > 8:
            raise EncodeError("Classic CAN payload must be <= 8 bytes.")
        parts.append(_FR_HDR.pack(_to_canid(m), len(data)))
        parts.append(data)
    return b"".join(parts)


def decode_stream(buf: bytearray) -> Tuple[int, list[can.Message]]:
    """
    Consume as many complete frames as available from the front of `buf`.
    Format: [BE u32 canid][u8 len][data...].
    Returns (consumed_bytes, [messages]); if none ready, returns (0, []).
    Includes a 1-byte resync if header looks invalid.
    """
    pos = 0
    out: List[can.Message] = []
    n = len(buf)

    while True:
        if n - pos < _FR_HDR.size:
            break

        canid, ln_raw = _FR_HDR.unpack_from(buf, pos)
        ln = ln_raw & 0x7F  # server masks to 7 bits; top bit (if any) is ignored
        if ln > 8:
            # Not a sane header → shift one byte to resync
            pos += 1
            continue

        need = _FR_HDR.size + ln
        if n - pos < need:
            # wait for more bytes
            break

        payload = bytes(buf[pos + _FR_HDR.size : pos + need])
        pos += need

        arb, is_ext, is_rtr, is_err = _from_canid(canid)
        msg = can.Message(
            arbitration_id=arb,
            data=payload,
            is_extended_id=is_ext,
            is_remote_frame=is_rtr,
            is_error_frame=is_err,
            is_fd=False,
        )
        out.append(msg)

        if n - pos < _FR_HDR.size:
            break

    if not out and pos != 0:
        return pos, []
    if not out:
        return 0, []
    return pos, out
