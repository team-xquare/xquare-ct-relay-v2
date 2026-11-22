from __future__ import annotations

import argparse
import asyncio
import logging
import signal

from .config import Config
from .db import Database
from .gateway_ws import start_gateway_ws
from .http_api import start_http_server
from .registry import GatewayRegistry
from .ssh_server import start_ssh_server

log = logging.getLogger("relay")


async def amain(config: Config) -> None:
    db = Database(config.db_path)
    db.init()
    registry = GatewayRegistry()

    ssh_server = await start_ssh_server(db, registry, config)
    ws_server = await start_gateway_ws(db, registry, config)
    http_runner = await start_http_server(db, registry, config)

    log.info("ssh listening on %s:%s", config.ssh_host, config.ssh_port)
    log.info("gateway ws listening on ws://%s:%s%s", config.ws_host, config.ws_port, config.ws_path)
    log.info("http listening on %s:%s", config.http_host, config.http_port)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    await stop.wait()

    log.info("shutting down")
    await registry.shutdown()
    ssh_server.close()
    await ssh_server.wait_closed()
    ws_server.close()
    await ws_server.wait_closed()
    await http_runner.cleanup()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="xquare ct relay v2")
    parser.add_argument("-c", "--config", help="config yaml path")
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
