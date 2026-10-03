"""The per-run egress forwarder (spec 012): relays to one fixed address and never resolves names."""

from __future__ import annotations

import asyncio
import socket
import sys

import pytest

from khandaq import egress_forwarder as fwd


@pytest.mark.parametrize("bad", ["target.test:443", "443", "10.0.0.1", "10.0.0.1:0", "[::1]:99999"])
def test_only_ip_and_port_are_accepted(bad):
    with pytest.raises(ValueError):
        fwd.parse_address(bad)


def test_ipv4_and_ipv6_addresses_parse():
    assert fwd.parse_address("203.0.113.7:443") == ("203.0.113.7", 443)
    assert fwd.parse_address("[2001:db8::1]:8443") == ("2001:db8::1", 8443)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def _pong_server() -> asyncio.Server:
    async def handle(reader, writer):
        data = await reader.read(100)
        writer.write(b"pong:" + data)
        await writer.drain()
        writer.close()

    return await asyncio.start_server(handle, "127.0.0.1", 0)


async def _ping(port: int) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"ping")
    await writer.drain()
    reply = await asyncio.wait_for(reader.read(100), 5)
    writer.close()
    return reply


def test_bytes_flow_both_ways_to_the_upstream():
    async def scenario() -> bytes:
        upstream = await _pong_server()
        listen = _free_port()
        ready = asyncio.Event()
        relay = asyncio.create_task(
            fwd.serve(listen, ("127.0.0.1", upstream.sockets[0].getsockname()[1]), ready)
        )
        await ready.wait()
        try:
            return await _ping(listen)
        finally:
            relay.cancel()
            upstream.close()

    assert asyncio.run(scenario()) == b"pong:ping"


def test_an_unreachable_upstream_closes_the_client_connection():
    async def scenario() -> bytes:
        listen = _free_port()
        ready = asyncio.Event()
        relay = asyncio.create_task(fwd.serve(listen, ("127.0.0.1", _free_port()), ready))
        await ready.wait()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", listen)
            data = await asyncio.wait_for(reader.read(100), 5)
            writer.close()
            return data
        finally:
            relay.cancel()

    assert asyncio.run(scenario()) == b""


def test_it_runs_from_its_source_alone_as_the_container_does():
    """The worker runs ``python3 -c <source>`` in an image without the khandaq package."""

    async def scenario(listen: int) -> bytes:
        upstream = await _pong_server()
        up_port = upstream.sockets[0].getsockname()[1]
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-I",  # isolated: no khandaq on the path, like a bare image
            "-c",
            fwd.source(),
            "--listen-port",
            str(listen),
            "--connect",
            f"127.0.0.1:{up_port}",
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            for _ in range(100):
                try:
                    return await _ping(listen)
                except OSError:
                    await asyncio.sleep(0.05)
            raise AssertionError("forwarder never listened")
        finally:
            proc.terminate()
            await proc.wait()
            upstream.close()

    assert asyncio.run(scenario(_free_port())) == b"pong:ping"
