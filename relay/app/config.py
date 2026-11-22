from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import yaml


def _env(key: str, default: Any) -> Any:
    val = os.environ.get(key)
    if val is None:
        return default
    if isinstance(default, bool):
        return val.strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(default, int):
        return int(val)
    return val


@dataclass
class Config:
    ssh_host: str = "0.0.0.0"
    ssh_port: int = 22022
    ws_host: str = "0.0.0.0"
    ws_port: int = 18765
    ws_path: str = "/gateway"
    http_host: str = "0.0.0.0"
    http_port: int = 18080
    db_path: str = "data/relay.db"
    host_key_path: str = "data/relay_host_key"
    admin_api_key: str = ""
    open_timeout: float = 15.0
    ping_interval: float = 20.0
    ping_timeout: float = 20.0
    log_level: str = "INFO"
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | None = None) -> "Config":
        data: dict[str, Any] = {}
        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        c = cls()
        for section in ("relay", "ssh", "ws", "http", "db", "auth"):
            if isinstance(data.get(section), dict):
                for k, v in data[section].items():
                    if hasattr(c, k):
                        setattr(c, k, v)
        # flat keys also allowed
        if isinstance(data, dict):
            for k, v in data.items():
                if hasattr(c, k) and not isinstance(v, dict):
                    setattr(c, k, v)

        c.ssh_host = _env("RELAY_SSH_HOST", c.ssh_host)
        c.ssh_port = _env("RELAY_SSH_PORT", c.ssh_port)
        c.ws_host = _env("RELAY_WS_HOST", c.ws_host)
        c.ws_port = _env("RELAY_WS_PORT", c.ws_port)
        c.ws_path = _env("RELAY_WS_PATH", c.ws_path)
        c.http_host = _env("RELAY_HTTP_HOST", c.http_host)
        c.http_port = _env("RELAY_HTTP_PORT", c.http_port)
        c.db_path = _env("RELAY_DB_PATH", c.db_path)
        c.host_key_path = _env("RELAY_HOST_KEY", c.host_key_path)
        c.admin_api_key = _env("RELAY_ADMIN_API_KEY", c.admin_api_key)
        c.log_level = _env("RELAY_LOG_LEVEL", c.log_level)
        return c
