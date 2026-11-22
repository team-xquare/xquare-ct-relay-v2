from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal

import asyncssh
import websockets
from websockets.exceptions import ConnectionClosed

from . import protocol
from .config import Config

log = logging.getLogger("gateway")


class GatewaySession:
    def __init__(self, session_id: int, send_func):
        self.session_id = session_id
        self._send = send_func
        self._conn: asyncssh.SSHClientConnection | None = None
        self._proc: asyncssh.SSHClientProcess | None = None
        self._read_task: asyncio.Task | None = None
        self._stderr_task: asyncio.Task | None = None
        self.closed = False

    async def open(self, *, host: str, port: int, username: str, password: str, term: str, cols: int, rows: int, connect_timeout: float):
        self._conn = await asyncssh.connect(
            host,
            port=port,
            username=username,
            password=password,
            known_hosts=None,
            encoding=None,
            connect_timeout=connect_timeout,
            login_timeout=connect_timeout,
        )
        self._proc = await self._conn.create_process(
            term_type=term or "xterm-256color",
            term_size=(cols or 80, rows or 24),
            encoding=None,
        )
        self._read_task = asyncio.create_task(self._pump(self._proc.stdout, "stdout"))
        self._stderr_task = asyncio.create_task(self._pump(self._proc.stderr, "stderr"))
        # also watch exit
        asyncio.create_task(self._wait_exit())

    async def _pump(self, stream, label: str):
        try:
            while not self.closed:
                data = await stream.read(4096)
                if not data:
                    break
                if isinstance(data, str):
                    data = data.encode("utf-8", "replace")
                await self._send(protocol.DATA, self.session_id, data)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.debug("session %s %s pump ended: %s", self.session_id, label, exc)

    async def _wait_exit(self):
        try:
            if self._proc is not None:
                await self._proc.wait_closed()
        except Exception:
            pass
        await self.close(notify=True)

    async def write(self, data: bytes):
        if self.closed or self._proc is None:
            return
        try:
            self._proc.stdin.write(data)
        except Exception as exc:
            log.debug("session %s write failed: %s", self.session_id, exc)
            await self.close(notify=True)

    async def resize(self, cols: int, rows: int):
        if self.closed or self._proc is None:
            return
        try:
            self._proc.change_terminal_size(cols, rows)
        except Exception:
            pass

    async def close(self, notify: bool = False):
        if self.closed:
            return
        self.closed = True
        for t in (self._read_task, self._stderr_task):
            if t and not t.done():
                t.cancel()
        try:
            if self._proc is not None:
                self._proc.close()
        except Exception:
            pass
        try:
            if self._conn is not None:
                self._conn.close()
                await self._conn.wait_closed()
        except Exception:
            pass
        if notify:
            try:
                await self._send(protocol.CLOSE, self.session_id, b"")
            except Exception:
                pass


class GatewayClient:
    def __init__(self, config: Config):
        self.config = config
        self.ws = None
        self.send_lock = asyncio.Lock()
        self.sessions: dict[int, GatewaySession] = {}
        self.stop_event = asyncio.Event()

    async def send(self, msg_type: int, session_id: int = 0, payload=None):
        if self.ws is None:
            raise ConnectionError("not connected")
        frame = protocol.encode(msg_type, session_id, payload)
        async with self.send_lock:
            await self.ws.send(frame)

    async def run(self):
        backoff = self.config.reconnect_min
        while not self.stop_event.is_set():
            try:
                await self._connect_once()
                backoff = self.config.reconnect_min
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("gateway connection error: %s", exc)
            if self.stop_event.is_set():
                break
            log.info("reconnecting in %.1fs", backoff)
            try:
                await asyncio.wait_for(self.stop_event.wait(), timeout=backoff)
            except asyncio.TimeoutError:
                pass
            backoff = min(self.config.reconnect_max, backoff * 2)

    async def _connect_once(self):
        log.info("connecting to relay %s as %s", self.config.relay_ws_url, self.config.gateway_name)
        async with websockets.connect(
            self.config.relay_ws_url,
            max_size=protocol.MAX_FRAME_SIZE,
            ping_interval=self.config.ping_interval,
            ping_timeout=self.config.ping_timeout,
        ) as ws:
            self.ws = ws
            try:
                await self.send(protocol.AUTH, 0, {
                    "name": self.config.gateway_name,
                    "token": self.config.gateway_token,
                })
                raw = await asyncio.wait_for(ws.recv(), timeout=15)
                if isinstance(raw, str):
                    raw = raw.encode("utf-8")
                mtype, _, payload = protocol.decode(raw)
                if mtype != protocol.AUTH_OK:
                    err = protocol.decode_json(payload).get("error", "auth failed") if payload else "auth failed"
                    raise RuntimeError(f"relay auth failed: {err}")
                log.info("authenticated to relay")
                async for raw in ws:
                    if isinstance(raw, str):
                        raw = raw.encode("utf-8")
                    await self._handle_frame(raw)
            finally:
                self.ws = None
                await self._close_all_sessions()

    async def _handle_frame(self, raw: bytes):
        try:
            mtype, sid, payload = protocol.decode(raw)
        except protocol.ProtocolError as exc:
            log.warning("bad frame: %s", exc)
            return

        if mtype == protocol.OPEN:
            await self._handle_open(sid, payload)
        elif mtype == protocol.DATA:
            sess = self.sessions.get(sid)
            if sess:
                await sess.write(payload)
        elif mtype == protocol.RESIZE:
            sess = self.sessions.get(sid)
            if sess:
                try:
                    cols, rows = protocol.decode_resize(payload)
                    await sess.resize(cols, rows)
                except protocol.ProtocolError:
                    pass
        elif mtype == protocol.CLOSE:
            sess = self.sessions.pop(sid, None)
            if sess:
                await sess.close(notify=False)
        elif mtype == protocol.PING:
            await self.send(protocol.PONG, 0, b"")

    async def _handle_open(self, sid: int, payload: bytes):
        try:
            req = protocol.decode_json(payload)
        except Exception as exc:
            await self.send(protocol.OPENED, sid, {"ok": False, "error": f"bad request: {exc}"})
            return

        host = str(req.get("ip") or req.get("host") or "")
        port = int(req.get("ssh_port") or 22)
        username = str(req.get("target_user") or req.get("username") or "root")
        password = str(req.get("password") or "")
        term = str(req.get("term") or "xterm-256color")
        cols = int(req.get("cols") or 80)
        rows = int(req.get("rows") or 24)
        vm_uid = str(req.get("vm_uid") or "")

        if not host or not password:
            await self.send(protocol.OPENED, sid, {"ok": False, "error": "missing host or password"})
            return

        sess = GatewaySession(sid, self.send)
        self.sessions[sid] = sess
        try:
            await sess.open(
                host=host, port=port, username=username, password=password,
                term=term, cols=cols, rows=rows, connect_timeout=self.config.ssh_connect_timeout,
            )
        except Exception as exc:
            self.sessions.pop(sid, None)
            log.warning("ssh open failed vm=%s host=%s user=%s: %s", vm_uid, host, username, exc)
            await self.send(protocol.OPENED, sid, {"ok": False, "error": f"ssh connect failed: {exc}"})
            return

        await self.send(protocol.OPENED, sid, {"ok": True})
        log.info("session opened sid=%s vm=%s %s@%s:%s", sid, vm_uid, username, host, port)

    async def _close_all_sessions(self):
        for sid, sess in list(self.sessions.items()):
            try:
                await sess.close(notify=False)
            except Exception:
                pass
        self.sessions.clear()

    def stop(self):
        self.stop_event.set()


async def amain(config: Config):
    if not config.gateway_token:
        raise SystemExit("GATEWAY_TOKEN is required")
    if not config.gateway_name:
        raise SystemExit("GATEWAY_NAME is required")
    client = GatewayClient(config)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, client.stop)
        except NotImplementedError:
            pass
    await client.run()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="xquare ct gateway v2")
    parser.add_argument("-c", "--config")
    args = parser.parse_args(argv)
    config = Config.load(args.config)
    logging.basicConfig(
        level=getattr(logging, str(config.log_level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    try:
        asyncio.run(amain(config))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
