from __future__ import annotations

import asyncio
import logging
import os

import asyncssh

from . import protocol
from .config import Config
from .db import Database
from .registry import ClientSession, GatewayRegistry, next_session_id

log = logging.getLogger("relay.ssh")


def load_or_create_host_key(path: str) -> asyncssh.SSHKey:
    if os.path.exists(path):
        with open(path, "rb") as f:
            return asyncssh.import_private_key(f.read())
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    key = asyncssh.generate_private_key("ssh-ed25519")
    with open(path, "wb") as f:
        f.write(key.export_private_key())
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    log.info("generated host key: %s", path)
    return key


def parse_ssh_username(username: str) -> tuple[str, str] | None:
    # format: <target_user>-<vm_uid>
    if "-" not in username:
        return None
    target_user, vm_uid = username.rsplit("-", 1)
    if not target_user or not vm_uid:
        return None
    return target_user, vm_uid


class SSHSession(asyncssh.SSHServerSession):
    def __init__(self, vm_uid: str, target_user: str, db: Database, registry: GatewayRegistry, config: Config):
        self.vm_uid = vm_uid
        self.target_user = target_user
        self.db = db
        self.registry = registry
        self.config = config
        self._chan: asyncssh.SSHServerChannel | None = None
        self._session: ClientSession | None = None
        self._input = asyncio.Queue()
        self._term = ("xterm-256color", 80, 24, 0, 0, {})
        self._bridge_task: asyncio.Task | None = None

    def connection_made(self, chan):
        self._chan = chan

    def pty_requested(self, pty_type, pty_size, term_modes):
        self._term = (pty_type or "xterm-256color", pty_size[0], pty_size[1], pty_size[2], pty_size[3], term_modes or {})
        return True

    def shell_requested(self):
        self._bridge_task = asyncio.create_task(self._run())
        return True

    def exec_requested(self, command):
        # exec not supported in this minimal v2; treat as shell-less not supported
        return False

    def terminal_size_changed(self, width, height, pixwidth, pixheight):
        if self._session and not self._session.closed:
            asyncio.create_task(self._session.gateway.send(protocol.encode_resize(self._session.session_id, width, height)))

    def data_received(self, data, datatype):
        if isinstance(data, str):
            data = data.encode("utf-8", "replace")
        if self._session and not self._session.closed:
            asyncio.create_task(self._session.gateway.send(protocol.DATA, self._session.session_id, data))

    def eof_received(self):
        if self._session and not self._session.closed:
            asyncio.create_task(self._session.close(b""))
        return False

    def break_received(self, msec):
        return False

    def close_received(self):
        if self._session and not self._session.closed:
            asyncio.create_task(self._session.close(b""))

    async def _run(self):
        chan = self._chan
        assert chan is not None
        gw = self.registry.pick()
        if gw is None:
            chan.write(b"\r\nNo gateway available. Please try again later.\r\n")
            chan.exit(1)
            return

        writer = _ChanWriter(chan)
        session_id = next_session_id()
        sess = ClientSession(session_id=session_id, gateway=gw, vm_uid=self.vm_uid, target_user=self.target_user, writer=writer)
        self._session = sess
        gw.sessions[session_id] = sess

        term_type, cols, rows, _, _, _ = self._term
        vm = self.db.get_vm_by_uid(self.vm_uid)
        if vm is None or not vm.enabled:
            gw.sessions.pop(session_id, None)
            chan.write(b"\r\nVM not found or disabled.\r\n")
            chan.exit(1)
            return
        try:
            await gw.send(protocol.OPEN, session_id, {
                "vm_uid": self.vm_uid,
                "target_user": self.target_user,
                "ip": vm.ip,
                "ssh_port": vm.ssh_port,
                "password": vm.password,
                "term": term_type,
                "cols": cols,
                "rows": rows,
            })
            result = await asyncio.wait_for(sess.opened, timeout=self.config.open_timeout)
        except asyncio.TimeoutError:
            gw.sessions.pop(session_id, None)
            chan.write(b"\r\nGateway timeout while opening session.\r\n")
            chan.exit(1)
            return
        except Exception as exc:
            gw.sessions.pop(session_id, None)
            chan.write(f"\r\nFailed to open session: {exc}\r\n".encode())
            chan.exit(1)
            return

        if not result.get("ok"):
            gw.sessions.pop(session_id, None)
            err = result.get("error") or "failed to open session"
            chan.write(f"\r\n{err}\r\n".encode("utf-8", "replace"))
            chan.exit(1)
            return

        log.info("session opened sid=%s vm=%s user=%s gw=%s", session_id, self.vm_uid, self.target_user, gw.name)
        await sess.close_event.wait()
        if not sess.closed:
            try:
                await sess.close(b"")
            except Exception:
                pass
        try:
            chan.exit(0)
        except Exception:
            pass

    def connection_lost(self, exc):
        if self._session and not self._session.closed:
            asyncio.create_task(self._session.close(b""))


class _ChanWriter:
    def __init__(self, chan: asyncssh.SSHServerChannel):
        self.chan = chan

    async def write(self, data: bytes) -> None:
        try:
            self.chan.write(data)
        except Exception:
            pass

    async def close(self) -> None:
        try:
            self.chan.close()
        except Exception:
            pass


class RelaySSHServer(asyncssh.SSHServer):
    def __init__(self, db: Database, registry: GatewayRegistry, config: Config):
        self.db = db
        self.registry = registry
        self.config = config
        self._username = ""
        self._vm_uid = ""
        self._target_user = ""

    def connection_made(self, conn):
        self._conn = conn

    def begin_auth(self, username):
        self._username = username or ""
        parsed = parse_ssh_username(self._username)
        if not parsed:
            # force failure later with generic message
            self._target_user = ""
            self._vm_uid = ""
            return True
        self._target_user, self._vm_uid = parsed
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        parsed = parse_ssh_username(username or "")
        if not parsed:
            return False
        target_user, vm_uid = parsed
        vm = self.db.get_vm_by_uid(vm_uid)
        if not vm or not vm.enabled:
            return False
        # The SSH login password is the VM's stored password (for that target user access)
        # Spec: "유저 이름에 대한 비밀번호를 넣어야지 접속이 되게 해야 함."
        # We validate against stored VM password.
        if not vm.password:
            return False
        if password != vm.password:
            return False
        # Also ensure target user is allowed - v2 simple: allow requested target user,
        # but use it when connecting. We store default username in VM; accept any requested
        # target user as long as password matches? Better enforce target_user == vm.username
        # OR allow override. Spec shows (접속할 유저 이름)-... so target user is chosen by client.
        # We'll allow any target username; gateway will ssh as that user with VM's password.
        self._target_user = target_user
        self._vm_uid = vm_uid
        return True

    def session_requested(self):
        return SSHSession(self._vm_uid, self._target_user, self.db, self.registry, self.config)


async def start_ssh_server(db: Database, registry: GatewayRegistry, config: Config):
    host_key = load_or_create_host_key(config.host_key_path)
    return await asyncssh.create_server(
        lambda: RelaySSHServer(db, registry, config),
        config.ssh_host,
        config.ssh_port,
        server_host_keys=[host_key],
        encoding=None,
        login_timeout=60,
    )
