from __future__ import annotations

import os
from dataclasses import dataclass

import yaml


def _env(key: str, default):
    val = os.environ.get(key)
    if val is None:
        return default
    if isinstance(default, bool):
        return val.strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(default, int):
        return int(val)
    if isinstance(default, float):
        return float(val)
    return val


@dataclass
class Config:
    relay_ws_url: str = "ws://relay:18765/gateway"
    gateway_name: str = "gateway-1"
    gateway_token: str = ""
    reconnect_min: float = 1.0
    reconnect_max: float = 30.0
    ping_interval: float = 20.0
    ping_timeout: float = 20.0
    ssh_connect_timeout: float = 15.0
    log_level: str = "INFO"

    @classmethod
    def load(cls, path: str | None = None) -> "Config":
        data = {}
        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        c = cls()
        if isinstance(data, dict):
            for k, v in data.items():
                if hasattr(c, k) and not isinstance(v, dict):
                    setattr(c, k, v)
            for section in ("gateway", "relay"):
                sec = data.get(section)
                if isinstance(sec, dict):
                    for k, v in sec.items():
                        if hasattr(c, k):
                            setattr(c, k, v)
        c.relay_ws_url = _env("GATEWAY_RELAY_WS_URL", c.relay_ws_url)
        c.gateway_name = _env("GATEWAY_NAME", c.gateway_name)
        c.gateway_token = _env("GATEWAY_TOKEN", c.gateway_token)
        c.reconnect_min = float(_env("GATEWAY_RECONNECT_MIN", c.reconnect_min))
        c.reconnect_max = float(_env("GATEWAY_RECONNECT_MAX", c.reconnect_max))
        c.ping_interval = float(_env("GATEWAY_PING_INTERVAL", c.ping_interval))
        c.ping_timeout = float(_env("GATEWAY_PING_TIMEOUT", c.ping_timeout))
        c.ssh_connect_timeout = float(_env("GATEWAY_SSH_CONNECT_TIMEOUT", c.ssh_connect_timeout))
        c.log_level = _env("GATEWAY_LOG_LEVEL", c.log_level)
        return c
