from __future__ import annotations

import asyncio
import itertools
import logging
from dataclasses import dataclass, field
from typing import Any

from . import protocol

log = logging.getLogger("relay.registry")
_session_ids = itertools.count(1)


def next_session_id() -> int:
    return next(_session_ids)


@dataclass
class ClientSession:
    session_id: int
    gateway: "GatewayConn"
    vm_uid: str
    target_user: str
    writer: Any  # async write(bytes)
    opened: asyncio.Future = field(default_factory=lambda: asyncio.get_event_loop().create_future())
    closed: bool = False
    close_event: asyncio.Event = field(default_factory=asyncio.Event)

    async def send_to_client(self, data: bytes) -> None:
        if self.closed:
            return
        try:
            await self.writer.write(data)
        except Exception:
            await self.close(b"")

    async def close(self, reason: bytes = b"") -> None:
        if self.closed:
            return
        self.closed = True
        self.close_event.set()
        try:
            await self.gateway.send(protocol.CLOSE, self.session_id, reason)
        except Exception:
            pass
        self.gateway.sessions.pop(self.session_id, None)


class GatewayConn:
    def __init__(self, name: str, ws):
        self.name = name
        self.ws = ws
        self.sessions: dict[int, ClientSession] = {}
        self.send_lock = asyncio.Lock()
        self.closed = False

    async def send(self, msg_type: int, session_id: int = 0, payload: bytes | str | dict | None = None) -> None:
        if self.closed:
            raise ConnectionError("gateway closed")
        frame = protocol.encode(msg_type, session_id, payload)
        async with self.send_lock:
            await self.ws.send(frame)

    async def close(self, reason: str = "") -> None:
        if self.closed:
            return
        self.closed = True
        for s in list(self.sessions.values()):
            s.closed = True
            s.close_event.set()
        self.sessions.clear()
        try:
            await self.ws.close(code=1000, reason=reason)
        except Exception:
            pass


class GatewayRegistry:
    def __init__(self):
        self._gateways: dict[str, GatewayConn] = {}
        self._rr = itertools.cycle([])  # placeholder
        self._names: list[str] = []
        self._rr_index = 0
        self._lock = asyncio.Lock()

    async def add(self, conn: GatewayConn) -> GatewayConn | None:
        async with self._lock:
            old = self._gateways.get(conn.name)
            self._gateways[conn.name] = conn
            self._rebuild()
            return old

    async def remove(self, conn: GatewayConn) -> None:
        async with self._lock:
            cur = self._gateways.get(conn.name)
            if cur is conn:
                del self._gateways[conn.name]
                self._rebuild()

    def _rebuild(self) -> None:
        self._names = [n for n, g in self._gateways.items() if not g.closed]
        if self._rr_index >= len(self._names):
            self._rr_index = 0

    def get(self, name: str) -> GatewayConn | None:
        g = self._gateways.get(name)
        return None if g is None or g.closed else g

    def pick(self) -> GatewayConn | None:
        # round-robin among healthy gateways
        if not self._names:
            # rebuild opportunistically
            self._names = [n for n, g in self._gateways.items() if not g.closed]
            self._rr_index = 0
        for _ in range(len(self._names)):
            if not self._names:
                return None
            name = self._names[self._rr_index % len(self._names)]
            self._rr_index = (self._rr_index + 1) % max(1, len(self._names))
            gw = self._gateways.get(name)
            if gw and not gw.closed:
                return gw
            self._names = [n for n, g in self._gateways.items() if not g.closed]
            self._rr_index = 0
        return None

    def status(self) -> list[dict]:
        out = []
        for name, gw in self._gateways.items():
            out.append({
                "name": name,
                "online": not gw.closed,
                "sessions": len(gw.sessions),
            })
        out.sort(key=lambda x: x["name"])
        return out

    def find_session(self, session_id: int) -> ClientSession | None:
        for gw in self._gateways.values():
            s = gw.sessions.get(session_id)
            if s:
                return s
        return None

    async def shutdown(self) -> None:
        for gw in list(self._gateways.values()):
            await gw.close("relay shutdown")
        self._gateways.clear()
        self._names.clear()
