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


def parse_c2_username(username: str, config: Config) -> bool:
    return bool(username) and username == config.c2_admin_user


class SSHSession(asyncssh.SSHServerSession):
    def __init__(self, vm_uid: str, target_user: str, password: str, db: Database, registry: GatewayRegistry, config: Config):
        self.vm_uid = vm_uid
        self.target_user = target_user
        self.password = password
        self.db = db
        self.registry = registry
        self.config = config
        self._chan: asyncssh.SSHServerChannel | None = None
        self._session: ClientSession | None = None
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
                "password": self.password,
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


class C2Session(asyncssh.SSHServerSession):
    def __init__(self, db: Database, registry: GatewayRegistry, config: Config):
        self.db = db
        self.registry = registry
        self.config = config
        self._chan = None
        self._buf = b""
        self._task: asyncio.Task | None = None

    def connection_made(self, chan):
        self._chan = chan

    def shell_requested(self):
        self._task = asyncio.create_task(self._run())
        return True

    def pty_requested(self, pty_type, pty_size, term_modes):
        return True

    def data_received(self, data, datatype):
        if isinstance(data, str):
            data = data.encode("utf-8", "replace")
        self._buf += data

    def eof_received(self):
        if self._task:
            self._task.cancel()
        return False

    def connection_lost(self, exc):
        if self._task:
            self._task.cancel()

    def _w(self, s: str):
        if self._chan:
            try:
                self._chan.write(s.replace("\n", "\r\n").encode("utf-8", "replace"))
            except Exception:
                pass

    async def _prompt(self) -> str | None:
        self._w("c2> ")
        while True:
            if b"\n" in self._buf or b"\r" in self._buf:
                # consume one line
                line = self._buf
                # split on first \r or \n
                for i, c in enumerate(line):
                    if c in (10, 13):
                        out = line[:i].decode("utf-8", "replace")
                        rest = line[i+1:]
                        if c == 13 and rest.startswith(b"\n"):
                            rest = rest[1:]
                        self._buf = rest
                        return out
            await asyncio.sleep(0.05)

    async def _run(self):
        self._w("Xquare CT Relay v2 C2\r\nType 'help' for commands.\r\n")
        try:
            while True:
                line = await self._prompt()
                if line is None:
                    return
                await self._handle(line.strip())
        except asyncio.CancelledError:
            return
        except Exception as exc:
            log.exception("c2 error: %s", exc)
        finally:
            try:
                if self._chan:
                    self._chan.exit(0)
            except Exception:
                pass

    async def _handle(self, line: str):
        if not line:
            return
        parts = line.split()
        cmd = parts[0].lower()
        args = parts[1:]
        if cmd in ("help", "?"):
            self._w(
                "Commands:\n"
                "  status\n"
                "  vms\n"
                "  vm-add <name> <ip> [ssh_port] [username] [description...]\n"
                "  vm-rm <vm_uid>\n"
                "  vm-enable <vm_uid>\n"
                "  vm-disable <vm_uid>\n"
                "  gws\n"
                "  gw-add <name> [token]\n"
                "  gw-rm <name>\n"
                "  exit\n"
            )
        elif cmd == "status":
            gws = self.registry.status()
            vms = self.db.list_vms()
            online = sum(1 for g in gws if g["online"])
            sess = sum(g.get("sessions", 0) for g in gws)
            self._w(f"vms={len(vms)} gateways={len(gws)} online={online} sessions={sess}\n")
        elif cmd == "vms":
            vms = self.db.list_vms()
            if not vms:
                self._w("(no vms)\n")
            for v in vms:
                st = "on" if v.enabled else "off"
                self._w(f"{v.vm_uid}\t{st}\t{v.name}\t{v.ip}:{v.ssh_port}\tuser={v.username}\t{v.description}\n")
        elif cmd == "vm-add":
            if len(args) < 2:
                self._w("usage: vm-add <name> <ip> [ssh_port] [username] [description...]\n")
                return
            name, ip = args[0], args[1]
            ssh_port = int(args[2]) if len(args) > 2 else 22
            username = args[3] if len(args) > 3 else "root"
            desc = " ".join(args[4:]) if len(args) > 4 else ""
            try:
                vm = self.db.add_vm(name=name, ip=ip, ssh_port=ssh_port, username=username, description=desc)
                self._w(f"added {vm.name} uid={vm.vm_uid}\n")
            except Exception as exc:
                self._w(f"error: {exc}\n")
        elif cmd == "vm-rm":
            if not args:
                self._w("usage: vm-rm <vm_uid>\n")
                return
            ok = self.db.remove_vm(args[0])
            self._w("ok\n" if ok else "not found\n")
        elif cmd in ("vm-enable", "vm-disable"):
            if not args:
                self._w(f"usage: {cmd} <vm_uid>\n")
                return
            vm = self.db.update_vm(args[0], enabled=(cmd == "vm-enable"))
            self._w("ok\n" if vm else "not found\n")
        elif cmd == "gws":
            db_gws = {g.name: g for g in self.db.list_gateways()}
            status = {g["name"]: g for g in self.registry.status()}
            names = sorted(set(db_gws) | set(status))
            if not names:
                self._w("(no gateways)\n")
            for name in names:
                g = db_gws.get(name)
                st = status.get(name, {})
                online = "online" if st.get("online") else "offline"
                en = "on" if (g.enabled if g else True) else "off"
                sess = st.get("sessions", 0)
                token = g.token if g else ""
                self._w(f"{name}\t{en}\t{online}\tsessions={sess}\ttoken={token}\n")
        elif cmd == "gw-add":
            if not args:
                self._w("usage: gw-add <name> [token]\n")
                return
            name = args[0]
            token = args[1] if len(args) > 1 else None
            try:
                gw = self.db.add_gateway(name=name, token=token)
                self._w(f"added {gw.name} token={gw.token}\n")
            except Exception as exc:
                self._w(f"error: {exc}\n")
        elif cmd == "gw-rm":
            if not args:
                self._w("usage: gw-rm <name>\n")
                return
            ok = self.db.remove_gateway(args[0])
            self._w("ok\n" if ok else "not found\n")
        elif cmd in ("exit", "quit"):
            if self._chan:
                self._chan.exit(0)
        else:
            self._w("unknown command. type 'help'\n")


class RelaySSHServer(asyncssh.SSHServer):
    def __init__(self, db: Database, registry: GatewayRegistry, config: Config):
        self.db = db
        self.registry = registry
        self.config = config
        self._username = ""
        self._vm_uid = ""
        self._target_user = ""
        self._password = ""
        self._is_admin = False

    def connection_made(self, conn):
        self._conn = conn

    def begin_auth(self, username):
        self._username = username or ""
        self._is_admin = parse_c2_username(self._username, self.config)
        if self._is_admin:
            return True
        parsed = parse_ssh_username(self._username)
        if not parsed:
            self._target_user = ""
            self._vm_uid = ""
            return True
        self._target_user, self._vm_uid = parsed
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        username = username or ""
        if parse_c2_username(username, self.config):
            expected = self.config.c2_admin_password
            if not expected:
                return False
            ok = password == expected
            if ok:
                self._is_admin = True
                self._password = password
            return ok

        parsed = parse_ssh_username(username)
        if not parsed:
            return False
        target_user, vm_uid = parsed
        vm = self.db.get_vm_by_uid(vm_uid)
        if not vm or not vm.enabled:
            return False
        # Do not store/validate VM password in relay. Pass it through to gateway->VM SSH.
        self._target_user = target_user
        self._vm_uid = vm_uid
        self._password = password
        self._is_admin = False
        return True

    def session_requested(self):
        if self._is_admin:
            return C2Session(self.db, self.registry, self.config)
        return SSHSession(self._vm_uid, self._target_user, self._password, self.db, self.registry, self.config)


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
