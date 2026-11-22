from __future__ import annotations

import asyncio
import logging

import websockets
from websockets.exceptions import ConnectionClosed

from . import protocol
from .config import Config
from .db import Database
from .registry import GatewayConn, GatewayRegistry

log = logging.getLogger("relay.gateway_ws")


async def _handle(ws, db: Database, registry: GatewayRegistry, config: Config) -> None:
    peer = getattr(ws, "remote_address", None)
    conn: GatewayConn | None = None
    try:
        raw = await asyncio.wait_for(ws.recv(), timeout=30)
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        mtype, _, payload = protocol.decode(raw)
        if mtype != protocol.AUTH:
            await ws.send(protocol.encode(protocol.AUTH_FAIL, 0, {"error": "expected AUTH"}))
            return
        auth = protocol.decode_json(payload)
        name = str(auth.get("name") or "")
        token = str(auth.get("token") or "")
        if not name or not token or not db.verify_gateway_token(name, token):
            log.warning("gateway auth failed name=%r peer=%s", name, peer)
            await ws.send(protocol.encode(protocol.AUTH_FAIL, 0, {"error": "auth failed"}))
            return

        conn = GatewayConn(name, ws)
        old = await registry.add(conn)
        if old is not None:
            await old.close("replaced")
        db.touch_gateway(name)
        await conn.send(protocol.AUTH_OK, 0, {"ok": True, "name": name})
        log.info("gateway connected name=%s peer=%s", name, peer)

        async for raw in ws:
            if isinstance(raw, str):
                raw = raw.encode("utf-8")
            try:
                mtype, sid, payload = protocol.decode(raw)
            except protocol.ProtocolError as exc:
                log.warning("bad frame from gateway %s: %s", name, exc)
                continue

            if mtype == protocol.OPENED:
                sess = conn.sessions.get(sid)
                if sess and not sess.opened.done():
                    sess.opened.set_result(protocol.decode_json(payload))
            elif mtype == protocol.DATA:
                sess = conn.sessions.get(sid)
                if sess:
                    await sess.send_to_client(payload)
            elif mtype == protocol.CLOSE:
                sess = conn.sessions.get(sid)
                if sess:
                    reason = payload
                    sess.closed = True
                    sess.close_event.set()
                    conn.sessions.pop(sid, None)
                    # forward final bytes if any
                    if reason:
                        try:
                            await sess.writer.write(reason)
                        except Exception:
                            pass
                    try:
                        await sess.writer.close()
                    except Exception:
                        pass
            elif mtype == protocol.PING:
                await conn.send(protocol.PONG, 0, b"")
            elif mtype == protocol.PONG:
                db.touch_gateway(name)
            # ignore unknown

    except asyncio.TimeoutError:
        log.warning("gateway auth timeout peer=%s", peer)
    except ConnectionClosed:
        pass
    except Exception:
        log.exception("gateway handler error peer=%s", peer)
    finally:
        if conn is not None:
            # fail active sessions attached to this gateway
            for sess in list(conn.sessions.values()):
                sess.closed = True
                sess.close_event.set()
                try:
                    await sess.writer.write(b"\r\nGateway disconnected.\r\n")
                except Exception:
                    pass
                try:
                    await sess.writer.close()
                except Exception:
                    pass
            conn.sessions.clear()
            await registry.remove(conn)
            await conn.close("disconnected")
            log.info("gateway disconnected name=%s", conn.name)


async def start_gateway_ws(db: Database, registry: GatewayRegistry, config: Config):
    async def handler(ws):
        # websockets v12 passes path in ws.path? in v13+ in request
        path = getattr(ws, "path", None)
        if path is None:
            req = getattr(ws, "request", None)
            path = getattr(req, "path", "") if req else ""
        path = (path or "/").split("?", 1)[0]
        if config.ws_path and path != config.ws_path:
            await ws.close(code=4404, reason="not found")
            return
        await _handle(ws, db, registry, config)

    return await websockets.serve(
        handler,
        config.ws_host,
        config.ws_port,
        max_size=protocol.MAX_FRAME_SIZE,
        ping_interval=config.ping_interval,
        ping_timeout=config.ping_timeout,
    )
