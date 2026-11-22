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
    """Interactive SSH C2 admin shell."""

    PROMPT = "xq-c2> "

    def __init__(self, db: Database, registry: GatewayRegistry, config: Config):
        self.db = db
        self.registry = registry
        self.config = config
        self._chan: asyncssh.SSHServerChannel | None = None
        self._buf = bytearray()
        self._task: asyncio.Task | None = None
        self._eof = False

    def connection_made(self, chan):
        self._chan = chan
        log.info("c2 connected peer=%s", chan.get_extra_info("peername"))

    def pty_requested(self, pty_type, pty_size, term_modes):
        return True

    def shell_requested(self):
        self._task = asyncio.create_task(self._run())
        return True

    def exec_requested(self, command):
        return False

    def data_received(self, data, datatype):
        if isinstance(data, str):
            data = data.encode("utf-8", "replace")
        if not data:
            return
        # Echo and buffer input with simple line editing.
        for b in bytes(data):
            if b in (10, 13):  # LF/CR
                # Normalize enter: echo newline and commit line
                self._write("\r\n")
                self._buf.extend(b"\n")
            elif b in (127, 8):  # backspace / DEL
                if self._buf and self._buf[-1] != 10:
                    del self._buf[-1]
                    self._write("\b \b")
            elif b == 3:  # Ctrl+C
                self._buf.clear()
                self._write("^C\r\n" + self.PROMPT)
            elif b == 4:  # Ctrl+D
                if not self._buf:
                    self._eof = True
                    self._write("\r\n")
                # if buffer has chars, ignore
            elif b == 12:  # Ctrl+L
                self._write("\x1b[2J\x1b[H" + self.PROMPT)
                # re-echo current buffer
                try:
                    self._write(self._buf.decode("utf-8", "replace"))
                except Exception:
                    pass
            elif b == 21:  # Ctrl+U
                n = len(self._buf)
                if n:
                    self._buf.clear()
                    self._write("\b \b" * n)
            elif b == 27:  # ESC - start of escape seq; ignore common CSI/SS3
                # Best-effort: consume escape sequences from remaining data in this same callback
                # by marking; easier to handle by storing pending escape state.
                self._esc_pending = getattr(self, "_esc_pending", b"") + b"\x1b"
            elif b == 9:  # tab - ignore
                pass
            elif b < 32:
                pass
            else:
                # If we had pending ESC, try to swallow simple sequences
                esc = getattr(self, "_esc_pending", b"")
                if esc:
                    esc += bytes([b])
                    # complete CSI: ESC [ ... final 0x40-0x7E
                    if esc.startswith(b"\x1b["):
                        if 64 <= b <= 126:
                            self._esc_pending = b""
                        else:
                            self._esc_pending = esc
                        continue
                    if esc.startswith(b"\x1bO"):
                        if len(esc) >= 3:
                            self._esc_pending = b""
                        else:
                            self._esc_pending = esc
                        continue
                    # unknown/short escape, drop it
                    if len(esc) >= 3:
                        self._esc_pending = b""
                    else:
                        self._esc_pending = esc
                    continue
                self._buf.append(b)
                self._write(bytes([b]).decode("utf-8", "replace"))

    def eof_received(self):
        self._eof = True
        return False

    def break_received(self, msec):
        self._buf.clear()
        self._write("^C\r\n" + self.PROMPT)
        return True

    def connection_lost(self, exc):
        self._eof = True
        if self._task and not self._task.done():
            self._task.cancel()

    def _write(self, s: str) -> None:
        if not self._chan:
            return
        try:
            self._chan.write(s)
        except Exception:
            pass

    async def _readline(self) -> str | None:
        while True:
            if self._eof and b"\n" not in self._buf:
                return None
            if b"\n" in self._buf:
                idx = self._buf.index(b"\n")
                line = bytes(self._buf[:idx])
                del self._buf[: idx + 1]
                # strip optional CR
                line = line.replace(b"\r", b"")
                return line.decode("utf-8", "replace")
            await asyncio.sleep(0.03)

    async def _run(self) -> None:
        self._write("\r\nXquare CT Relay v2 - C2 Admin\r\n")
        self._write("Type 'help' for commands.\r\n\r\n")
        try:
            while True:
                self._write(self.PROMPT)
                line = await self._readline()
                if line is None:
                    return
                line = line.strip()
                if not line:
                    continue
                try:
                    should_exit = await self._handle(line)
                except Exception as exc:
                    log.exception("c2 command error")
                    self._write(f"error: {exc}\r\n")
                    should_exit = False
                if should_exit:
                    return
        except asyncio.CancelledError:
            return
        except Exception:
            log.exception("c2 session error")
        finally:
            try:
                if self._chan:
                    self._chan.exit(0)
            except Exception:
                pass

    async def _handle(self, line: str) -> bool:
        parts = line.split()
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ("help", "?", "h"):
            self._cmd_help()
        elif cmd in ("status", "info"):
            self._cmd_status()
        elif cmd in ("vms", "vm", "list-vm", "list-vms"):
            self._cmd_vms()
        elif cmd in ("gws", "gw", "gateways", "gateway", "list-gw", "list-gws"):
            self._cmd_gws()
        elif cmd in ("ls", "list"):
            self._cmd_ls(args)
        elif cmd in ("vm-add", "add-vm"):
            self._cmd_vm_add(args)
        elif cmd in ("vm-rm", "rm-vm", "vm-del", "del-vm"):
            self._cmd_vm_rm(args)
        elif cmd in ("vm-enable", "enable-vm"):
            self._cmd_vm_set_enabled(args, True)
        elif cmd in ("vm-disable", "disable-vm"):
            self._cmd_vm_set_enabled(args, False)
        elif cmd in ("gw-add", "add-gw"):
            self._cmd_gw_add(args)
        elif cmd in ("gw-rm", "rm-gw", "gw-del", "del-gw"):
            self._cmd_gw_rm(args)
        elif cmd in ("clear", "cls"):
            self._write("\x1b[2J\x1b[H")
        elif cmd in ("whoami",):
            self._write(f"{self.config.c2_admin_user}\r\n")
        elif cmd in ("exit", "quit", "q"):
            self._write("bye\r\n")
            return True
        else:
            self._write(f"unknown command: {cmd} (type 'help')\r\n")
        return False

    def _cmd_help(self) -> None:
        self._write(
            "\r\nCommands:\r\n"
            "  status                           relay/gateway/vm summary\r\n"
            "  vms                              list VMs\r\n"
            "  gws                              list gateways\r\n"
            "  ls [vms|gws]                     list alias\r\n"
            "  vm-add <name> <ip> [port] [user] [desc...]\r\n"
            "  vm-rm <vm_uid>\r\n"
            "  vm-enable <vm_uid>\r\n"
            "  vm-disable <vm_uid>\r\n"
            "  gw-add <name> [token]\r\n"
            "  gw-rm <name>\r\n"
            "  clear\r\n"
            "  exit\r\n\r\n"
        )

    def _cmd_status(self) -> None:
        gws = self.registry.status()
        vms = self.db.list_vms()
        online = sum(1 for g in gws if g.get("online"))
        sessions = sum(int(g.get("sessions", 0)) for g in gws)
        self._write(f"vms={len(vms)} gateways={len(gws)} online={online} sessions={sessions}\r\n")

    def _cmd_vms(self) -> None:
        vms = self.db.list_vms()
        if not vms:
            self._write("(no vms)\r\n")
            return
        self._write("UID          ST  NAME                 TARGET               USER       DESC\r\n")
        self._write("-" * 90 + "\r\n")
        for v in vms:
            st = "on " if v.enabled else "off"
            desc = (v.description or "")[:28]
            target = f"{v.ip}:{v.ssh_port}"
            self._write(f"{v.vm_uid:<12} {st:<3} {v.name:<20} {target:<20} {v.username:<10} {desc}\r\n")

    def _cmd_gws(self) -> None:
        db_gws = {g.name: g for g in self.db.list_gateways()}
        status = {g["name"]: g for g in self.registry.status()}
        names = sorted(set(db_gws) | set(status))
        if not names:
            self._write("(no gateways)\r\n")
            return
        self._write("NAME                 EN  STATE    SESS  TOKEN\r\n")
        self._write("-" * 88 + "\r\n")
        for name in names:
            g = db_gws.get(name)
            st = status.get(name, {})
            en = "on" if (g.enabled if g else True) else "off"
            online = "online" if st.get("online") else "offline"
            sess = int(st.get("sessions", 0))
            token = g.token if g else ""
            shown = (token[:10] + "...") if len(token) > 13 else token
            self._write(f"{name:<20} {en:<3} {online:<7} {sess:<5} {shown}\r\n")

    def _cmd_ls(self, args: list[str]) -> None:
        target = args[0].lower() if args else "all"
        if target in ("vms", "vm"):
            self._cmd_vms()
        elif target in ("gws", "gw", "gateways", "gateway"):
            self._cmd_gws()
        elif target == "all":
            self._cmd_vms()
            self._cmd_gws()
        else:
            self._write("usage: ls [vms|gws|all]\r\n")

    def _cmd_vm_add(self, args: list[str]) -> None:
        if len(args) < 2:
            self._write("usage: vm-add <name> <ip> [ssh_port] [username] [description...]\r\n")
            return
        name, ip = args[0], args[1]
        ssh_port = 22
        if len(args) > 2:
            try:
                ssh_port = int(args[2])
            except ValueError:
                self._write("invalid ssh_port\r\n")
                return
        username = args[3] if len(args) > 3 else "root"
        desc = " ".join(args[4:]) if len(args) > 4 else ""
        try:
            vm = self.db.add_vm(name=name, ip=ip, ssh_port=ssh_port, username=username, description=desc)
        except Exception as exc:
            self._write(f"error: {exc}\r\n")
            return
        self._write(f"added {vm.name} uid={vm.vm_uid}\r\n")
        self._write(f"connect: ssh <user>-{vm.vm_uid}@<relay-host> -p <ssh-port>\r\n")

    def _cmd_vm_rm(self, args: list[str]) -> None:
        if not args:
            self._write("usage: vm-rm <vm_uid>\r\n")
            return
        ok = self.db.remove_vm(args[0])
        self._write("ok\r\n" if ok else "not found\r\n")

    def _cmd_vm_set_enabled(self, args: list[str], enabled: bool) -> None:
        if not args:
            self._write(f"usage: vm-{'enable' if enabled else 'disable'} <vm_uid>\r\n")
            return
        vm = self.db.update_vm(args[0], enabled=enabled)
        self._write("ok\r\n" if vm else "not found\r\n")

    def _cmd_gw_add(self, args: list[str]) -> None:
        if not args:
            self._write("usage: gw-add <name> [token]\r\n")
            return
        name = args[0]
        token = args[1] if len(args) > 1 else None
        try:
            gw = self.db.add_gateway(name=name, token=token)
        except Exception as exc:
            self._write(f"error: {exc}\r\n")
            return
        self._write(f"added {gw.name} token={gw.token}\r\n")

    def _cmd_gw_rm(self, args: list[str]) -> None:
        if not args:
            self._write("usage: gw-rm <name>\r\n")
            return
        ok = self.db.remove_gateway(args[0])
        self._write("ok\r\n" if ok else "not found\r\n")


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
