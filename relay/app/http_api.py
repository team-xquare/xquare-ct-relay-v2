from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from aiohttp import web

from .config import Config
from .db import Database
from .registry import GatewayRegistry

log = logging.getLogger("relay.http")

HERE = Path(__file__).resolve().parent
WEB_DIR = HERE / "web"


def _json(data, status=200):
    return web.json_response(data, status=status, dumps=lambda x: json.dumps(x, ensure_ascii=False))


def _require_api_key(request: web.Request, config: Config) -> None:
    key = config.admin_api_key
    if not key:
        raise web.HTTPServiceUnavailable(text="RELAY_ADMIN_API_KEY is not configured")
    got = request.headers.get("X-API-Key") or ""
    if not got:
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            got = auth[7:].strip()
    if got != key:
        raise web.HTTPUnauthorized(text="invalid api key")


def _vm_dict(vm):
    return {
        "vm_uid": vm.vm_uid,
        "name": vm.name,
        "ip": vm.ip,
        "ssh_port": vm.ssh_port,
        "username": vm.username,
        "has_password": bool(vm.password),
        "enabled": vm.enabled,
        "description": vm.description,
        "ssh_command_example": f"ssh <user>-{vm.vm_uid}@<relay-host> -p <relay-ssh-port>",
    }


def _vm_secret(vm):
    d = _vm_dict(vm)
    d["password"] = vm.password
    return d


def _gw_dict(gw, online=False, sessions=0):
    return {
        "name": gw.name,
        "enabled": gw.enabled,
        "description": gw.description,
        "online": online,
        "sessions": sessions,
    }


async def handle_index(request):
    index = WEB_DIR / "index.html"
    if index.exists():
        return web.FileResponse(index)
    return web.Response(text="xquare ct relay v2", content_type="text/plain")


async def handle_health(request):
    db: Database = request.app["db"]
    registry: GatewayRegistry = request.app["registry"]
    vms = db.list_vms()
    gws = registry.status()
    return _json({"ok": True, "vms": len(vms), "gateways": gws})


# --- API: VMs ---
async def api_list_vms(request):
    _require_api_key(request, request.app["config"])
    db: Database = request.app["db"]
    return _json({"items": [_vm_secret(v) for v in db.list_vms()]})


async def api_create_vm(request):
    config: Config = request.app["config"]
    _require_api_key(request, config)
    db: Database = request.app["db"]
    body = await request.json()
    name = str(body.get("name") or "").strip()
    ip = str(body.get("ip") or "").strip()
    if not name or not ip:
        raise web.HTTPBadRequest(text="name and ip are required")
    ssh_port = int(body.get("ssh_port") or 22)
    username = str(body.get("username") or "root").strip() or "root"
    password = str(body.get("password") or "")
    description = str(body.get("description") or "")
    enabled = bool(body.get("enabled", True))
    try:
        vm = db.add_vm(name=name, ip=ip, ssh_port=ssh_port, username=username, password=password, description=description, enabled=enabled)
    except Exception as exc:
        raise web.HTTPBadRequest(text=str(exc))
    return _json(_vm_secret(vm), status=201)


async def api_get_vm(request):
    _require_api_key(request, request.app["config"])
    db: Database = request.app["db"]
    vm = db.get_vm_by_uid(request.match_info["vm_uid"])
    if not vm:
        raise web.HTTPNotFound(text="vm not found")
    return _json(_vm_secret(vm))


async def api_update_vm(request):
    _require_api_key(request, request.app["config"])
    db: Database = request.app["db"]
    body = await request.json()
    fields = {}
    for k in ("name", "ip", "ssh_port", "username", "password", "description", "enabled"):
        if k in body:
            fields[k] = body[k]
    if "ssh_port" in fields and fields["ssh_port"] is not None:
        fields["ssh_port"] = int(fields["ssh_port"])
    vm = db.update_vm(request.match_info["vm_uid"], **fields)
    if not vm:
        raise web.HTTPNotFound(text="vm not found")
    return _json(_vm_secret(vm))


async def api_delete_vm(request):
    _require_api_key(request, request.app["config"])
    db: Database = request.app["db"]
    ok = db.remove_vm(request.match_info["vm_uid"])
    if not ok:
        raise web.HTTPNotFound(text="vm not found")
    return _json({"ok": True})


# --- API: Gateways ---
async def api_list_gateways(request):
    _require_api_key(request, request.app["config"])
    db: Database = request.app["db"]
    registry: GatewayRegistry = request.app["registry"]
    status = {s["name"]: s for s in registry.status()}
    items = []
    for gw in db.list_gateways():
        st = status.get(gw.name, {})
        items.append({
            "name": gw.name,
            "token": gw.token,
            "enabled": gw.enabled,
            "description": gw.description,
            "online": bool(st.get("online")),
            "sessions": int(st.get("sessions", 0)),
        })
    return _json({"items": items})


async def api_create_gateway(request):
    _require_api_key(request, request.app["config"])
    db: Database = request.app["db"]
    body = await request.json()
    name = str(body.get("name") or "").strip()
    if not name:
        raise web.HTTPBadRequest(text="name is required")
    token = str(body.get("token") or "").strip() or None
    description = str(body.get("description") or "")
    enabled = bool(body.get("enabled", True))
    try:
        gw = db.add_gateway(name=name, token=token, description=description, enabled=enabled)
    except Exception as exc:
        raise web.HTTPBadRequest(text=str(exc))
    return _json({"name": gw.name, "token": gw.token, "enabled": gw.enabled, "description": gw.description}, status=201)


async def api_update_gateway(request):
    _require_api_key(request, request.app["config"])
    db: Database = request.app["db"]
    body = await request.json()
    fields = {}
    for k in ("token", "enabled", "description"):
        if k in body:
            fields[k] = body[k]
    gw = db.update_gateway(request.match_info["name"], **fields)
    if not gw:
        raise web.HTTPNotFound(text="gateway not found")
    return _json({"name": gw.name, "token": gw.token, "enabled": gw.enabled, "description": gw.description})


async def api_delete_gateway(request):
    _require_api_key(request, request.app["config"])
    db: Database = request.app["db"]
    ok = db.remove_gateway(request.match_info["name"])
    if not ok:
        raise web.HTTPNotFound(text="gateway not found")
    return _json({"ok": True})


async def api_status(request):
    _require_api_key(request, request.app["config"])
    db: Database = request.app["db"]
    registry: GatewayRegistry = request.app["registry"]
    return _json({
        "ok": True,
        "vms": len(db.list_vms()),
        "gateways": registry.status(),
    })


def create_app(db: Database, registry: GatewayRegistry, config: Config) -> web.Application:
    app = web.Application()
    app["db"] = db
    app["registry"] = registry
    app["config"] = config

    app.router.add_get("/", handle_index)
    app.router.add_get("/health", handle_health)
    app.router.add_get("/api/status", api_status)
    app.router.add_get("/api/vms", api_list_vms)
    app.router.add_post("/api/vms", api_create_vm)
    app.router.add_get("/api/vms/{vm_uid}", api_get_vm)
    app.router.add_put("/api/vms/{vm_uid}", api_update_vm)
    app.router.add_delete("/api/vms/{vm_uid}", api_delete_vm)
    app.router.add_get("/api/gateways", api_list_gateways)
    app.router.add_post("/api/gateways", api_create_gateway)
    app.router.add_put("/api/gateways/{name}", api_update_gateway)
    app.router.add_delete("/api/gateways/{name}", api_delete_gateway)

    if WEB_DIR.exists():
        app.router.add_static("/static/", WEB_DIR, show_index=False)
    return app


async def start_http_server(db: Database, registry: GatewayRegistry, config: Config):
    app = create_app(db, registry, config)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, config.http_host, config.http_port)
    await site.start()
    log.info("http listening on %s:%s", config.http_host, config.http_port)
    return runner
