from __future__ import annotations

import os
import secrets
import sqlite3
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class VM:
    id: int
    vm_uid: str
    name: str
    ip: str
    ssh_port: int
    username: str
    enabled: bool
    description: str


@dataclass(frozen=True)
class Gateway:
    id: int
    name: str
    token: str
    enabled: bool
    description: str


SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS vms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vm_uid TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL UNIQUE,
    ip TEXT NOT NULL,
    ssh_port INTEGER NOT NULL DEFAULT 22,
    username TEXT NOT NULL DEFAULT 'root',
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS gateways (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    token TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    last_seen_at TEXT
);
"""


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _new_vm_uid() -> str:
    # 10-char unguessable id, URL/SSH-safe
    return secrets.token_urlsafe(8).replace("-", "").replace("_", "")[:10]


class Database:
    def __init__(self, path: str):
        self.path = path

    def connect(self) -> sqlite3.Connection:
        directory = os.path.dirname(os.path.abspath(self.path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def init(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    # -- VMs ---------------------------------------------------------------
    def list_vms(self) -> list[VM]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM vms ORDER BY name").fetchall()
        return [self._vm(r) for r in rows]

    def get_vm_by_uid(self, vm_uid: str) -> VM | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM vms WHERE vm_uid = ?", (vm_uid,)).fetchone()
        return self._vm(row) if row else None

    def get_vm_by_name(self, name: str) -> VM | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM vms WHERE name = ?", (name,)).fetchone()
        return self._vm(row) if row else None

    def add_vm(
        self,
        *,
        name: str,
        ip: str,
        ssh_port: int = 22,
        username: str = "root",
        description: str = "",
        enabled: bool = True,
    ) -> VM:
        with self.connect() as conn:
            for _ in range(10):
                vm_uid = _new_vm_uid()
                try:
                    conn.execute(
                        """
                        INSERT INTO vms (vm_uid, name, ip, ssh_port, username, enabled, description, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (vm_uid, name, ip, ssh_port, username, 1 if enabled else 0, description, _now()),
                    )
                    row = conn.execute("SELECT * FROM vms WHERE vm_uid = ?", (vm_uid,)).fetchone()
                    return self._vm(row)
                except sqlite3.IntegrityError as exc:
                    if "vm_uid" in str(exc):
                        continue
                    raise
        raise RuntimeError("failed to generate unique vm uid")

    def update_vm(self, vm_uid: str, **fields) -> VM | None:
        allowed = {"name", "ip", "ssh_port", "username", "enabled", "description"}
        updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
        if not updates:
            return self.get_vm_by_uid(vm_uid)
        if "enabled" in updates:
            updates["enabled"] = 1 if updates["enabled"] else 0
        sets = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [vm_uid]
        with self.connect() as conn:
            cur = conn.execute(f"UPDATE vms SET {sets} WHERE vm_uid = ?", values)
            if cur.rowcount == 0:
                return None
        return self.get_vm_by_uid(vm_uid)

    def remove_vm(self, vm_uid: str) -> bool:
        with self.connect() as conn:
            cur = conn.execute("DELETE FROM vms WHERE vm_uid = ?", (vm_uid,))
        return cur.rowcount > 0

    # -- Gateways ----------------------------------------------------------
    def list_gateways(self) -> list[Gateway]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM gateways ORDER BY name").fetchall()
        return [self._gw(r) for r in rows]

    def get_gateway_by_name(self, name: str) -> Gateway | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM gateways WHERE name = ?", (name,)).fetchone()
        return self._gw(row) if row else None

    def add_gateway(self, *, name: str, token: str | None = None, description: str = "", enabled: bool = True) -> Gateway:
        token = token or secrets.token_urlsafe(32)
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO gateways (name, token, enabled, description, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (name, token, 1 if enabled else 0, description, _now()),
            )
            row = conn.execute("SELECT * FROM gateways WHERE name = ?", (name,)).fetchone()
        return self._gw(row)

    def update_gateway(self, name: str, **fields) -> Gateway | None:
        allowed = {"token", "enabled", "description"}
        updates = {k: v for k, v in fields.items() if k in allowed and v is not None}
        if not updates:
            return self.get_gateway_by_name(name)
        if "enabled" in updates:
            updates["enabled"] = 1 if updates["enabled"] else 0
        sets = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [name]
        with self.connect() as conn:
            cur = conn.execute(f"UPDATE gateways SET {sets} WHERE name = ?", values)
            if cur.rowcount == 0:
                return None
        return self.get_gateway_by_name(name)

    def remove_gateway(self, name: str) -> bool:
        with self.connect() as conn:
            cur = conn.execute("DELETE FROM gateways WHERE name = ?", (name,))
        return cur.rowcount > 0

    def touch_gateway(self, name: str) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE gateways SET last_seen_at = ? WHERE name = ?", (_now(), name))

    def verify_gateway_token(self, name: str, token: str) -> bool:
        gw = self.get_gateway_by_name(name)
        return bool(gw and gw.enabled and secrets.compare_digest(gw.token, token))

    @staticmethod
    def _vm(row: sqlite3.Row) -> VM:
        return VM(
            id=row["id"],
            vm_uid=row["vm_uid"],
            name=row["name"],
            ip=row["ip"],
            ssh_port=int(row["ssh_port"]),
            username=row["username"],
            enabled=bool(row["enabled"]),
            description=row["description"] or "",
        )

    @staticmethod
    def _gw(row: sqlite3.Row) -> Gateway:
        return Gateway(
            id=row["id"],
            name=row["name"],
            token=row["token"],
            enabled=bool(row["enabled"]),
            description=row["description"] or "",
        )
