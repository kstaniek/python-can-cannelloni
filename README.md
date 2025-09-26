# python-can-cannelloni

A `python-can` backend that connects to a **cannelloni** TCP server (client side).  
It speaks exactly the same minimal stream as the server codec:

```
[ CANID u32 (big-endian, with EFF/RTR/ERR bits) ][ LEN u8 (0..8) ][ DATA LEN bytes ]
```

- No outer packet header, no extra flag bytes  
- **Classic CAN only** (DLC ≤ 8; CAN‑FD is intentionally rejected on TX)  
- On connect **both peers send** the banner `CANNELLONIv1` (without `\0`)  
- TCP socket uses **TCP_NODELAY** and **keepalive** by default  
- Background RX loop with optional auto‑reconnect

---

## Repository layout

```
python-can-cannelloni/
├─ pyproject.toml
├─ README.md
└─ can_cannelloni/
   ├─ __init__.py          # exposes CannelloniBus
   ├─ bus.py               # python-can BusABC implementation + RX loop
   └─ protocol.py          # encode/decode for the wire format + handshake
```

(Optional tests:)
```
tests/
└─ test_bus.py
```

---

## Requirements

- Python **3.10+**
- `python-can >= 4.3`

Install in editable mode to register the plugin entry point:

```bash
pip install -e .
```

`pyproject.toml`:

```toml
[project.entry-points."can.interface"]
cannelloni = "can_cannelloni.bus:CannelloniBus"
```

---

## Quick start

```python
import can

# Option A: pass "host:port" in channel
bus = can.Bus(interface="cannelloni", channel="172.31.11.43:20000")

# Option B: use host/port kwargs
# bus = can.Bus(interface="cannelloni", host="172.31.11.43", port=20000)

# Send a classic CAN frame (extended-id example)
bus.send(
    can.Message(
        arbitration_id=0x6F4A,
        data=b"\xFE\x21\x78\x28",
        is_extended_id=True,
    )
)

# Receive (1.0 s timeout)
msg = bus.recv(1.0)
print(msg)

bus.shutdown()
```

You can use `python-can` utilities like `Notifier`, `Logger`, `BufferedReader`, etc.

---

## Constructor options

All options go to `can.Bus(interface="cannelloni", ...)`:

| Option | Type | Default | Description |
|---|---:|---:|---|
| `channel` | str | – | `"host:port"` (alt. to `host`/`port`) |
| `host` | str | – | Server IP/hostname |
| `port` | int | – | Server TCP port |
| `nodelay` | bool | `True` | Set `TCP_NODELAY` |
| `keepalive` | bool | `True` | Enable TCP keepalive |
| `handshake_timeout` | float | `2.0` | Timeout awaiting banner |
| `reconnect` | bool | `True` | Auto‑reconnect on drop |
| `reconnect_interval` | float | `1.0` | Seconds between attempts |
| `rx_queue_size` | int | `10000` | Bounded RX queue size |

### Filters (client‑side)

```python
# Only receive 0x100 (standard 11-bit)
bus.set_filters([{"can_id": 0x100, "can_mask": 0x7FF, "extended": False}])
```

> Filtering is applied locally in the client for maximum compatibility across `python-can` versions.

---

## Protocol details

- **Handshake:** both ends immediately send `CANNELLONIv1` (no terminator).
- **Frame on the TCP stream:**
  - `CANID` **u32 big‑endian** with SocketCAN‑style bits:
    - `0x80000000` → EFF (extended id)  
    - `0x40000000` → RTR (remote)  
    - `0x20000000` → ERR (error)
  - `LEN` **u8**; valid range `0..8` (top bit, if set on the wire, is ignored; parser masks with `& 0x7F`)
  - `DATA` **LEN** bytes
- **No CAN‑FD:** TX with `is_fd=True` is rejected; RX with `LEN>8` is considered invalid and the parser attempts a 1‑byte resync.

---

## Troubleshooting

- **Weird DLC (e.g., 254) or garbage IDs**  
  This indicates a header mismatch. Ensure the layout is exactly `!IB` (big‑endian `u32 CANID` + `u8 LEN`) and there are **no extra bytes** in the header.
- **Handshake errors**  
  The server must expect/emit `CANNELLONIv1` (no `\0`); transparent TCP path is required (no TLS/HTTP proxies).
- **No frames**  
  Verify reachability (`telnet host port`), server logs, and that frames are classic CAN (DLC ≤ 8).

---

## Testing

Minimal pytest to validate sending, receiving, and client‑side filtering.

Run:

```bash
pytest -q
```

---

## Contributing

PRs and issues welcome. Please include tests for protocol changes and keep the wire format exactly as documented (or make it configurable).

---

## License

MIT


```text
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Klaudiusz Staniek
```