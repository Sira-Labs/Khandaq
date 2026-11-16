"""Per-run egress forwarder (spec 012, ADR-0009).

The adapter container sits on an ``--internal`` Docker network with no route out. This forwarder is
the only other member of that network: it answers to the target's hostname (a network alias) and
relays TCP to **one** address that the worker resolved and checked before launch. It never
resolves names and never chooses a destination, so the adapter can reach the in-scope target and
nothing else. TLS passes through untouched (SNI and certificate checks stay end to end).

With ``--pace-per-minute`` it also holds a request rate for an adapter that has no limiter of its
own (spec 032). It cannot read TLS, so it counts *turns*: the first bytes a client sends on a
connection, and the first it sends after the target has answered. In HTTP/1.1 without pipelining
every request starts a turn, so letting one turn through per ``60 / rate`` seconds keeps the
request rate at or under ``rate``. Clients that could put several requests into one turn (HTTP/2)
are refused before a byte is relayed. Pacing adds a delay, never a destination.

Standard library only: the worker runs this file with ``python -c`` in any image that has Python 3,
so the forwarder needs nothing from the khandaq package at runtime.

Usage: ``python egress_forwarder.py --listen-port 443 --connect 203.0.113.7:443
[--pace-per-minute 60]``
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import logging
import math
import signal
import sys
from pathlib import Path

log = logging.getLogger("khandaq.egress_forwarder")

_CHUNK = 64 * 1024

_TLS_HANDSHAKE, _CLIENT_HELLO = 0x16, 0x01
_TLS_RECORD_HEADER, _TLS_MAX_RECORD = 5, 16384
_EXT_ALPN, _EXT_ECH = 16, 0xFE0D
_HTTP1 = b"http/1.1"
_H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


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


def parse_pace(value: str) -> float:
    """A requests-per-minute pace: a finite number above 0."""
    pace = float(value)
    if not math.isfinite(pace) or pace <= 0:
        raise ValueError(f"the pace must be a finite number above 0, got {value!r}")
    return pace


class Pacer:
    """Hands out slots ``60 / per_minute`` seconds apart, shared by every connection of the run.

    No burst: a slot is never earlier than one interval after the one before it, so at most
    ``per_minute`` turns (rounded up) fall into any 60 seconds that start at a slot.
    """

    def __init__(self, per_minute: float, clock=None, sleep=asyncio.sleep) -> None:
        self.interval = 60.0 / per_minute
        self._clock = clock
        self._sleep = sleep
        self._next = -math.inf

    async def wait_turn(self) -> None:
        now = self._clock() if self._clock else asyncio.get_running_loop().time()
        slot = max(now, self._next)
        # Reserved before the first await, so two waiting connections never share a slot.
        self._next = slot + self.interval
        if slot > now:
            await self._sleep(slot - now)


class RefusedProtocol(Exception):
    """The client could put several requests into one turn; pacing would not hold for it."""


def client_hello_alpn(record: bytes) -> list[bytes]:
    """The ALPN protocols a TLS ClientHello offers (empty when it offers none).

    ``record`` is one complete TLS record. Raises ``RefusedProtocol`` for anything that is not a
    plain, complete ClientHello: the caller cannot tell what such a client will speak.
    """
    try:
        body = record[_TLS_RECORD_HEADER:]
        if body[0] != _CLIENT_HELLO:
            raise RefusedProtocol("the first TLS message is not a ClientHello")
        length = int.from_bytes(body[1:4], "big")
        hello = body[4:]
        if length != len(hello):
            raise RefusedProtocol("the ClientHello spans more than one TLS record")
        at = 2 + 32  # legacy_version, random
        at += 1 + hello[at]  # session id
        at += 2 + int.from_bytes(hello[at : at + 2], "big")  # cipher suites
        at += 1 + hello[at]  # compression methods
        if at == len(hello):
            return []  # no extensions at all
        end = at + 2 + int.from_bytes(hello[at : at + 2], "big")
        at += 2
        if end != len(hello):
            raise RefusedProtocol("the ClientHello's extensions are malformed")
        offered: list[bytes] = []
        while at < end:
            kind = int.from_bytes(hello[at : at + 2], "big")
            size = int.from_bytes(hello[at + 2 : at + 4], "big")
            data = hello[at + 4 : at + 4 + size]
            if len(data) != size:
                raise RefusedProtocol("the ClientHello's extensions are malformed")
            at += 4 + size
            if kind == _EXT_ECH:
                raise RefusedProtocol("the ClientHello hides its real offer (ECH)")
            if kind == _EXT_ALPN:
                names, pos = data[2:], 0
                if int.from_bytes(data[:2], "big") != len(names):
                    raise RefusedProtocol("the ClientHello's ALPN list is malformed")
                while pos < len(names):
                    name = names[pos + 1 : pos + 1 + names[pos]]
                    if len(name) != names[pos] or not name:
                        raise RefusedProtocol("the ClientHello's ALPN list is malformed")
                    offered.append(name)
                    pos += 1 + names[pos]
        return offered
    except IndexError as exc:
        raise RefusedProtocol("the ClientHello is truncated") from exc


async def _first_bytes(reader: asyncio.StreamReader) -> bytes:
    """Read a paced connection's opening bytes and refuse a client that may speak HTTP/2.

    Returns what was read (to be relayed) once the opening is known to be HTTP/1.1-only TLS or
    plaintext that is not the HTTP/2 preface.
    """
    data = await reader.read(_CHUNK)
    if not data:
        return data
    if data[0] == _TLS_HANDSHAKE:
        while len(data) < _TLS_RECORD_HEADER:
            data += await reader.readexactly(_TLS_RECORD_HEADER - len(data))
        size = int.from_bytes(data[3:5], "big")
        if size > _TLS_MAX_RECORD:
            raise RefusedProtocol("the first TLS record is oversized")
        missing = _TLS_RECORD_HEADER + size - len(data)
        if missing > 0:
            data += await reader.readexactly(missing)
        offered = client_hello_alpn(data[: _TLS_RECORD_HEADER + size])
        extra = sorted({name.decode("ascii", "replace") for name in offered if name != _HTTP1})
        if extra:
            raise RefusedProtocol(f"the client offers {', '.join(extra)}; only http/1.1 is paced")
        return data
    while _H2_PREFACE.startswith(data[: len(_H2_PREFACE)]):
        if len(data) >= len(_H2_PREFACE):
            raise RefusedProtocol("the client opens with the HTTP/2 preface")
        more = await reader.read(_CHUNK)
        if not more:
            break
        data += more
    return data


class _Turns:
    """Whose turn it is on one connection: ``open`` while the client is mid-request."""

    def __init__(self) -> None:
        self.open = False


async def _pump(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    first: bytes = b"",
    before_write=None,
    on_data=None,
) -> None:
    try:
        data = first or await reader.read(_CHUNK)
        while data:
            if on_data is not None:
                on_data()
            if before_write is not None:
                await before_write()
            writer.write(data)
            await writer.drain()
            data = await reader.read(_CHUNK)
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
    pacer: Pacer | None = None,
) -> None:
    first = b""
    if pacer is not None:
        try:
            first = await _first_bytes(client_reader)
        except RefusedProtocol as exc:
            log.warning("connection refused, pacing would not hold: %s", exc)
            client_writer.close()
            return
        except (ConnectionError, asyncio.IncompleteReadError):
            client_writer.close()
            return
        if not first:
            client_writer.close()
            return
    try:
        up_reader, up_writer = await asyncio.open_connection(*upstream)
    except OSError as exc:
        log.warning("upstream %s:%d unreachable: %s", upstream[0], upstream[1], exc)
        client_writer.close()
        return
    turns = _Turns()

    async def take_turn() -> None:
        # The first client bytes since the target last spoke start a turn and wait for its slot.
        if pacer is not None and not turns.open:
            turns.open = True
            await pacer.wait_turn()

    def target_spoke() -> None:
        turns.open = False

    try:
        await asyncio.gather(
            _pump(client_reader, up_writer, first=first, before_write=take_turn),
            _pump(up_reader, client_writer, on_data=target_spoke),
        )
    finally:
        for w in (up_writer, client_writer):
            with contextlib.suppress(OSError):
                w.close()


async def serve(
    listen_port: int,
    upstream: tuple[str, int],
    ready: asyncio.Event | None = None,
    pace_per_minute: float | None = None,
):
    """Relay every connection on ``listen_port`` (all interfaces) to ``upstream``, until
    cancelled; with ``pace_per_minute``, one turn per ``60 / pace`` seconds (spec 032)."""
    pacer = Pacer(pace_per_minute) if pace_per_minute is not None else None
    server = await asyncio.start_server(
        lambda r, w: _relay(r, w, upstream, pacer), host=None, port=listen_port
    )
    log.info("forwarding :%d -> %s:%d", listen_port, upstream[0], upstream[1])
    if pacer is not None:
        log.info("pacing: one turn per %.3f s", pacer.interval)
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
    parser.add_argument(
        "--pace-per-minute", type=parse_pace, help="hold this request rate (spec 032)"
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    upstream = parse_address(args.connect)

    loop = asyncio.new_event_loop()
    task = loop.create_task(serve(args.listen_port, upstream, pace_per_minute=args.pace_per_minute))
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, task.cancel)
    with contextlib.suppress(asyncio.CancelledError):
        loop.run_until_complete(task)
    return 0


if __name__ == "__main__":
    sys.exit(main())
