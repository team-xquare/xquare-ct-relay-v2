"""Gateway <-> relay protocol. Must stay compatible with relay.app.protocol."""
from __future__ import annotations

import json
import struct
from typing import Any

PROTOCOL_VERSION = 2
MAX_FRAME_SIZE = 4 * 1024 * 1024

AUTH = 0x01
AUTH_OK = 0x02
AUTH_FAIL = 0x03
PING = 0x30
PONG = 0x31

OPEN = 0x10
OPENED = 0x11
DATA = 0x20
RESIZE = 0x21
CLOSE = 0x22

HEADER = struct.Struct(">BI")
RESIZE_STRUCT = struct.Struct(">HH")
HEADER_SIZE = HEADER.size


class ProtocolError(Exception):
    pass


def encode(msg_type: int, session_id: int = 0, payload: bytes | str | dict | None = None) -> bytes:
    if payload is None:
        body = b""
    elif isinstance(payload, dict):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    elif isinstance(payload, str):
        body = payload.encode("utf-8")
    else:
        body = bytes(payload)
    if len(body) > MAX_FRAME_SIZE:
        raise ProtocolError(f"frame too large: {len(body)}")
    return HEADER.pack(msg_type & 0xFF, session_id & 0xFFFFFFFF) + body


def decode(frame: bytes | bytearray | memoryview) -> tuple[int, int, bytes]:
    data = bytes(frame)
    if len(data) < HEADER_SIZE:
        raise ProtocolError("frame too short")
    msg_type, session_id = HEADER.unpack_from(data, 0)
    return msg_type, session_id, data[HEADER_SIZE:]


def decode_json(payload: bytes) -> Any:
    if not payload:
        return {}
    try:
        return json.loads(payload.decode("utf-8"))
    except Exception as exc:
        raise ProtocolError(f"invalid json payload: {exc}") from exc


def encode_resize(session_id: int, cols: int, rows: int) -> bytes:
    return encode(RESIZE, session_id, RESIZE_STRUCT.pack(max(1, cols) & 0xFFFF, max(1, rows) & 0xFFFF))


def decode_resize(payload: bytes) -> tuple[int, int]:
    if len(payload) < RESIZE_STRUCT.size:
        raise ProtocolError("resize payload too short")
    cols, rows = RESIZE_STRUCT.unpack_from(payload, 0)
    return max(1, cols), max(1, rows)
