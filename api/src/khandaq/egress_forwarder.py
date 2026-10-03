"""Per-run egress forwarder (spec 012, ADR-0009).

The adapter container sits on an ``--internal`` Docker network with no route out. This forwarder is
the only other member of that network: it answers to the target's hostname (a network alias) and
relays TCP to **one** address that the worker resolved and checked before launch. It never
resolves names and never chooses a destination, so the adapter can reach the in-scope target and
nothing else. TLS passes through untouched (SNI and certificate checks stay end to end).

Standard library only: the worker runs this file with ``python -c`` in any image that has Python 3,
so the forwarder needs nothing from the khandaq package at runtime.

Usage: ``python egress_forwarder.py --listen-port 443 --connect 203.0.113.7:443``
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import logging
import signal
import sys
from pathlib import Path

log = logging.getLogger("khandaq.egress_forwarder")

_CHUNK = 64 * 1024


def parse_address(value: str) -> tuple[str, int]:
    """Parse ``ip:port`` or ``[ipv6]:port``; refuses names — the forwarder never resolves DNS."""
    host, sep, port_text = value.rpartition(":")
    if not sep:
        raise ValueError(f"expected ip:port, got {value!r}")
    host = host.removeprefix("[").removesuffix("]")
    ipaddress.ip_address(host)  # raises ValueError for a hostname
    port = int(port_text)
    if not 0 < port < 65536:
        raise ValueError(f"port out of range in {value!r}")
    return host, port


async def _pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(_CHUNK):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        with contextlib.suppress(OSError):
            if writer.can_write_eof():
                writer.write_eof()


async def _relay(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream: tuple[str, int],
) -> None:
    try:
        up_reader, up_writer = await asyncio.open_connection(*upstream)
    except OSError as exc:
        log.warning("upstream %s:%d unreachable: %s", upstream[0], upstream[1], exc)
        client_writer.close()
        return
    try:
        await asyncio.gather(_pump(client_reader, up_writer), _pump(up_reader, client_writer))
    finally:
        for w in (up_writer, client_writer):
            with contextlib.suppress(OSError):
                w.close()


async def serve(listen_port: int, upstream: tuple[str, int], ready: asyncio.Event | None = None):
    """Relay every connection on ``listen_port`` (all interfaces) to ``upstream``, until
    cancelled."""
    server = await asyncio.start_server(
        lambda r, w: _relay(r, w, upstream), host=None, port=listen_port
    )
    log.info("forwarding :%d -> %s:%d", listen_port, upstream[0], upstream[1])
    if ready is not None:
        ready.set()
    async with server:
        await server.serve_forever()


def source() -> str:
    """This module's source, for ``python -c`` in an image without the khandaq package."""
    return Path(__file__).read_text()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--connect", required=True, help="ip:port (never a hostname)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    upstream = parse_address(args.connect)

    loop = asyncio.new_event_loop()
    task = loop.create_task(serve(args.listen_port, upstream))
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, task.cancel)
    with contextlib.suppress(asyncio.CancelledError):
        loop.run_until_complete(task)
    return 0


if __name__ == "__main__":
    sys.exit(main())
