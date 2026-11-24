"""The per-run egress forwarder (spec 012): relays to one fixed address and never resolves names."""

from __future__ import annotations

import asyncio
import contextlib
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


# --- pacing (spec 032) ----------------------------------------------------------------------------


class _FakeTime:
    """A clock the pacer's sleeps advance, so spacing is asserted without waiting."""

    def __init__(self) -> None:
        self.now = 100.0
        self.slept: list[float] = []

    def clock(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def test_pacer_spaces_turns():
    time = _FakeTime()
    pacer = fwd.Pacer(120, clock=time.clock, sleep=time.sleep)  # one turn per 0.5 s

    async def scenario() -> None:
        await pacer.wait_turn()  # the first turn is not delayed
        await pacer.wait_turn()
        time.now += 5  # an idle spell earns no burst
        await pacer.wait_turn()
        await pacer.wait_turn()

    asyncio.run(scenario())
    assert time.slept == [0.5, 0.5]


def _release_times(time: _FakeTime, pacer: fwd.Pacer, waiters: int) -> list[float]:
    released: list[float] = []

    async def turn() -> None:
        await pacer.wait_turn()
        released.append(time.now)

    async def scenario() -> None:
        await asyncio.gather(*(turn() for _ in range(waiters)))

    asyncio.run(scenario())
    return released


def test_pacer_shares_slots():
    """Connections waiting at the same moment are let through one interval apart."""
    time = _FakeTime()
    pacer = fwd.Pacer(60, clock=time.clock, sleep=time.sleep)
    assert _release_times(time, pacer, 4) == [100.0, 101.0, 102.0, 103.0]


def test_pacer_keeps_the_interval_after_a_stall():
    """A sleep that ends late (a stalled event loop) must not let the waiters through together:
    the next slot counts from when the last turn was really let through."""

    class Stalling(_FakeTime):
        async def sleep(self, seconds: float) -> None:
            await super().sleep(seconds + 5)  # every wakeup is five seconds late

    time = Stalling()
    pacer = fwd.Pacer(60, clock=time.clock, sleep=time.sleep)
    released = _release_times(time, pacer, 4)
    assert all(b - a >= 1.0 for a, b in zip(released, released[1:], strict=False)), released


def test_pacer_wakes_early_and_still_waits_out_the_slot():
    class Early(_FakeTime):
        async def sleep(self, seconds: float) -> None:
            await super().sleep(seconds / 2)  # a sleep may return before its time

    time = Early()
    pacer = fwd.Pacer(60, clock=time.clock, sleep=time.sleep)
    released = _release_times(time, pacer, 3)
    assert all(b - a >= 1.0 for a, b in zip(released, released[1:], strict=False)), released


def test_the_first_turn_waits_for_the_first_slot():
    """The forwarder sets the first slot one interval after its start, so a run's first request
    keeps its distance from the last request of the run before it."""
    time = _FakeTime()
    pacer = fwd.Pacer(60, clock=time.clock, sleep=time.sleep, first_slot=time.now + 1.0)
    assert _release_times(time, pacer, 2) == [101.0, 102.0]


@pytest.mark.parametrize("bad", ["0", "-1", "nan", "inf", "fast", "1e-308", "5e-324"])
def test_pace_argument_must_be_positive(bad):
    """Also a rate so small that its interval is infinite: no turn would ever be let through."""
    with pytest.raises(ValueError):
        fwd.parse_pace(bad)
    assert fwd.parse_pace("0.5") == 0.5
    assert fwd.Pacer(fwd.parse_pace("1e-300")).interval == 6e301  # tiny, but a real interval


def test_usable_pace_is_the_one_rule_for_admission_and_forwarder():
    assert fwd.usable_pace(0.5) and fwd.usable_pace(600) and fwd.usable_pace(1e-300)
    for bad in (0, -1, float("nan"), float("inf"), 1e-308, 10**400):
        assert not fwd.usable_pace(bad)


class _CountingPacer(fwd.Pacer):
    def __init__(self) -> None:
        super().__init__(60)
        self.turns = 0

    @contextlib.asynccontextmanager
    async def turn(self):
        self.turns += 1
        yield


async def _http_server() -> asyncio.Server:
    """Answers every request line with one response, keeping the connection open."""

    async def handle(reader, writer):
        while await reader.readline():
            while (await reader.readline()) not in (b"\r\n", b""):
                pass
            writer.write(b"HTTP/1.1 204 No Content\r\n\r\n")
            await writer.drain()
        writer.close()

    return await asyncio.start_server(handle, "127.0.0.1", 0)


async def _paced(upstream: asyncio.Server, pacer: fwd.Pacer | None, client) -> object:
    """Run ``client(port)`` against a relay to ``upstream`` that uses ``pacer``."""
    up = ("127.0.0.1", upstream.sockets[0].getsockname()[1])
    relay = await asyncio.start_server(lambda r, w: fwd._relay(r, w, up, pacer), "127.0.0.1", 0)
    try:
        return await client(relay.sockets[0].getsockname()[1])
    finally:
        relay.close()
        upstream.close()


async def _request(reader, writer, parts: list[bytes]) -> bytes:
    for part in parts:  # one request, possibly written in several pieces
        writer.write(part)
        await writer.drain()
    return await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)


def test_paced_relay_counts_one_turn_per_request():
    pacer = _CountingPacer()

    async def client(port: int) -> None:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await _request(reader, writer, [b"GET /a HTTP/1.1\r\n", b"Host: t\r\n", b"\r\n"])
        await _request(reader, writer, [b"GET /b HTTP/1.1\r\nHost: t\r\n\r\n"])
        other_reader, other_writer = await asyncio.open_connection("127.0.0.1", port)
        await _request(other_reader, other_writer, [b"GET /c HTTP/1.1\r\nHost: t\r\n\r\n"])
        writer.close()
        other_writer.close()

    async def scenario() -> None:
        await _paced(await _http_server(), pacer, client)

    asyncio.run(scenario())
    assert pacer.turns == 3  # three requests on two connections, whatever the write sizes


def test_unpaced_relay_is_unchanged():
    """Without a pace nothing is inspected: even an HTTP/2 preface is relayed as bytes."""

    async def client(port: int) -> bytes:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(fwd._H2_PREFACE)
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(100), 5)
        writer.close()
        return reply

    async def scenario() -> object:
        return await _paced(await _pong_server(), None, client)

    assert asyncio.run(scenario()) == b"pong:" + fwd._H2_PREFACE


def _client_hello(alpn: list[str] | None) -> bytes:
    """The ClientHello record Python's own TLS stack sends for this ALPN offer."""
    import ssl

    context = ssl.create_default_context()
    if alpn is not None:
        context.set_alpn_protocols(alpn)
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_hostname="target.test")
    with pytest.raises(ssl.SSLWantReadError):
        tls.do_handshake()
    return outgoing.read()


def test_client_hello_alpn():
    assert fwd.client_hello_alpn(_client_hello(["http/1.1"])) == [b"http/1.1"]
    assert fwd.client_hello_alpn(_client_hello(["h2", "http/1.1"])) == [b"h2", b"http/1.1"]
    assert fwd.client_hello_alpn(_client_hello(None)) == []


def _with_extension(record: bytes, kind: int, data: bytes = b"") -> bytes:
    """``record`` with one extension of ``kind`` appended, all lengths corrected."""
    hello = bytearray(record[9:])
    at = 34
    at += 1 + hello[at]
    at += 2 + int.from_bytes(hello[at : at + 2], "big")
    at += 1 + hello[at]
    size = int.from_bytes(hello[at : at + 2], "big") + 4 + len(data)
    hello[at : at + 2] = size.to_bytes(2, "big")
    hello += kind.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data
    body = b"\x01" + len(hello).to_bytes(3, "big") + bytes(hello)
    return record[:3] + len(body).to_bytes(2, "big") + body


def _with_trailing_bytes(record: bytes, tail: bytes) -> bytes:
    """``record`` with ``tail`` appended inside its extensions block, all lengths corrected: what
    is left after the last complete extension is not a whole extension header."""
    assert len(tail) < 4, "four bytes are a complete header: use _with_extension"
    hello = bytearray(record[9:])
    at = 34
    at += 1 + hello[at]
    at += 2 + int.from_bytes(hello[at : at + 2], "big")
    at += 1 + hello[at]
    size = int.from_bytes(hello[at : at + 2], "big") + len(tail)
    hello[at : at + 2] = size.to_bytes(2, "big")
    hello += tail
    body = b"\x01" + len(hello).to_bytes(3, "big") + bytes(hello)
    return record[:3] + len(body).to_bytes(2, "big") + body


def test_client_hello_that_cannot_be_judged_is_refused():
    record = _client_hello(["http/1.1"])
    for broken in (
        record[:40],  # cut off: the message claims more than the record holds
        record[:3] + (40).to_bytes(2, "big") + b"\x01" + (36).to_bytes(3, "big") + record[9:45],
        record[:5] + b"\x02" + record[6:],  # a ServerHello, not a ClientHello
        record[:8] + bytes([record[8] + 1]) + record[9:],  # claims to continue in another record
        _with_extension(record, 0xFE0D),  # Encrypted Client Hello
        # An ALPN extension that names no protocol (RFC 7301 forbids it) is not "no ALPN".
        _with_extension(_client_hello(None), 16, b"\x00\x00"),
        _with_extension(_client_hello(None), 16),  # not even the list's length
        # Bytes after the last extension that are not a whole type-and-length header. Read
        # leniently, the missing length is zero and the HTTP/1.1 offer before it would pass.
        _with_trailing_bytes(record, b"\x00"),
        _with_trailing_bytes(record, b"\xff\xaa"),
        _with_trailing_bytes(record, b"\xff\xaa\x00"),
    ):
        with pytest.raises(fwd.RefusedProtocol):
            fwd.client_hello_alpn(broken)
    assert fwd.client_hello_alpn(_with_extension(record, 0xFFAA)) == [b"http/1.1"]


def _refused(opening: bytes) -> tuple[bytes, int]:
    """What a client that opens with ``opening`` gets back, and how many connections the target
    saw."""
    seen = 0

    async def handle(reader, writer):
        nonlocal seen
        seen += 1
        writer.close()

    async def client(port: int) -> bytes:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(opening)
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(100), 5)
        writer.close()
        return reply

    async def scenario() -> object:
        upstream = await asyncio.start_server(handle, "127.0.0.1", 0)
        return await _paced(upstream, _CountingPacer(), client)

    return asyncio.run(scenario()), seen  # type: ignore[return-value]


def test_paced_relay_refuses_h2_client_hello():
    assert _refused(_client_hello(["h2", "http/1.1"])) == (b"", 0)


def test_paced_relay_refuses_h2_preface():
    assert _refused(fwd._H2_PREFACE) == (b"", 0)


def test_paced_relay_passes_an_http11_client_hello():
    hello = _client_hello(["http/1.1"])

    async def client(port: int) -> bytes:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(hello[:3])  # the record arrives in pieces
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.write(hello[3:])
        await writer.drain()
        reply = await asyncio.wait_for(reader.readexactly(5 + 100), 5)
        writer.close()
        return reply

    async def scenario() -> object:
        return await _paced(await _pong_server(), _CountingPacer(), client)

    assert asyncio.run(scenario()) == b"pong:" + hello[:100]


def test_paced_forwarder_holds_the_rate_end_to_end():
    """The real process, paced at 600/min: four requests take at least three 0.1 s intervals."""

    async def scenario(listen: int) -> float:
        upstream = await _http_server()
        up_port = upstream.sockets[0].getsockname()[1]
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-I",
            "-c",
            fwd.source(),
            "--listen-port",
            str(listen),
            "--connect",
            f"127.0.0.1:{up_port}",
            "--pace-per-minute",
            "600",
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            for _ in range(100):
                try:
                    reader, writer = await asyncio.open_connection("127.0.0.1", listen)
                    break
                except OSError:
                    await asyncio.sleep(0.05)
            else:
                raise AssertionError("forwarder never listened")
            loop = asyncio.get_running_loop()
            started = loop.time()
            for _ in range(4):
                await _request(reader, writer, [b"GET / HTTP/1.1\r\nHost: t\r\n\r\n"])
            writer.close()
            return loop.time() - started
        finally:
            proc.terminate()
            await proc.wait()
            upstream.close()

    # Three intervals between four requests, and one before the first (the run boundary).
    assert asyncio.run(scenario(_free_port())) >= 0.3


class _GatedPacer(fwd.Pacer):
    """Every turn waits until the test opens the gate."""

    def __init__(self) -> None:
        super().__init__(60)
        self.gate = asyncio.Event()
        self.entered = asyncio.Event()
        self.waiting = 0

    @contextlib.asynccontextmanager
    async def turn(self):
        self.waiting += 1
        self.entered.set()
        await self.gate.wait()
        yield

    async def until_waiting(self) -> None:
        """Until a turn has begun, or fail: a relay that skips the pacer must not hang the test."""
        await asyncio.wait_for(self.entered.wait(), 5)


def test_the_target_sees_nothing_of_a_connection_before_its_slot():
    """Not even a TCP connection: the forwarder connects to the target once the slot has come."""
    seen: list[bytes] = []

    async def handle(reader, writer):
        seen.append(b"connected")
        seen.append(await reader.read(100))
        writer.write(b"HTTP/1.1 204 No Content\r\n\r\n")
        await writer.drain()
        writer.close()

    pacer = _GatedPacer()

    async def client(port: int) -> tuple[list[bytes], bytes]:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n")
        await writer.drain()
        await pacer.until_waiting()
        await asyncio.sleep(0.05)
        before = list(seen)
        pacer.gate.set()
        reply = await asyncio.wait_for(reader.read(100), 5)
        writer.close()
        return before, reply

    async def scenario() -> object:
        return await _paced(await asyncio.start_server(handle, "127.0.0.1", 0), pacer, client)

    before, reply = asyncio.run(scenario())  # type: ignore[misc]
    assert before == [] and reply.startswith(b"HTTP/1.1 204")
    assert seen == [b"connected", b"GET / HTTP/1.1\r\nHost: t\r\n\r\n"]


def test_a_request_abandoned_while_waiting_is_not_delivered():
    """A client that timed out and went away must not have its request reach the target later."""
    seen: list[bytes] = []

    async def handle(reader, writer):
        seen.append(await reader.read(100))
        writer.close()

    pacer = _GatedPacer()

    async def client(port: int) -> None:
        _, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET /gone HTTP/1.1\r\nHost: t\r\n\r\n")
        await writer.drain()
        await pacer.until_waiting()
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.05)
        pacer.gate.set()
        await asyncio.sleep(0.1)

    async def scenario() -> None:
        await _paced(await asyncio.start_server(handle, "127.0.0.1", 0), pacer, client)

    asyncio.run(scenario())
    assert seen == [] and pacer.waiting == 1  # the slot was used up, the request was dropped


def test_a_request_abandoned_while_the_target_connects_is_not_delivered(monkeypatch):
    """The client was still there when its slot came, and went away while the connection to the
    target opened: the request is dropped and the unused connection closed."""
    seen: list[bytes] = []
    closed = asyncio.Event()

    async def handle(reader, writer):
        seen.append(await reader.read(100))  # b"" when the forwarder closes without writing
        closed.set()
        writer.close()

    real_open = asyncio.open_connection
    connecting, client_gone = asyncio.Event(), asyncio.Event()

    async def open_after_the_client_left(*args, **kwargs):
        connecting.set()
        await asyncio.wait_for(client_gone.wait(), 5)
        return await real_open(*args, **kwargs)

    pacer = _CountingPacer()

    async def client(port: int) -> None:
        _, writer = await real_open("127.0.0.1", port)
        writer.write(b"GET /gone HTTP/1.1\r\nHost: t\r\n\r\n")
        await writer.drain()
        await asyncio.wait_for(connecting.wait(), 5)
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.05)  # the forwarder has seen the client's EOF
        client_gone.set()
        await asyncio.wait_for(closed.wait(), 5)

    async def scenario() -> None:
        upstream = await asyncio.start_server(handle, "127.0.0.1", 0)
        monkeypatch.setattr(fwd.asyncio, "open_connection", open_after_the_client_left)
        await _paced(upstream, pacer, client)

    asyncio.run(scenario())
    assert seen == [b""] and pacer.turns == 1  # connected, nothing written; the slot was used


def test_a_paced_connection_that_never_shows_its_opening_is_dropped(monkeypatch):
    monkeypatch.setattr(fwd, "_OPENING_SECONDS", 0.1)
    assert _refused(b"\x16") == (b"", 0)  # one byte of a TLS record, then silence


def test_a_slow_connect_does_not_bring_two_first_requests_closer(monkeypatch):
    """The interval counts from when a turn's bytes were written, not from when its slot came:
    a first connection that takes long to open must not let the next connection's request follow
    it by less than the interval."""
    writes: list[float] = []

    class Stamped:
        """The forwarder's connection to the target, noting when its first bytes are written:
        that is where the pace is held. When the target reads them is the network's business."""

        def __init__(self, writer):
            self._writer, self._written = writer, False

        def write(self, data):
            if not self._written:
                self._written = True
                writes.append(asyncio.get_running_loop().time())
            self._writer.write(data)

        def __getattr__(self, name):
            return getattr(self._writer, name)

    async def handle(reader, writer):
        await reader.read(100)
        writer.write(b"HTTP/1.1 204 No Content\r\n\r\n")
        await writer.drain()
        writer.close()

    real_open = asyncio.open_connection
    opened = 0

    async def slow_first_open(*args, **kwargs):
        nonlocal opened
        opened += 1
        if opened == 1:
            await asyncio.sleep(0.15)  # the first connection to the target is slow to open
        reader, writer = await real_open(*args, **kwargs)
        return reader, Stamped(writer)

    interval = 0.1
    pacer = fwd.Pacer(60 / interval)

    async def one_request(port: int) -> None:
        reader, writer = await real_open("127.0.0.1", port)
        writer.write(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(100), 5)
        writer.close()

    async def client(port: int) -> None:
        first = asyncio.create_task(one_request(port))
        await asyncio.sleep(0.02)  # the second arrives while the first is still connecting
        await asyncio.gather(first, one_request(port))

    async def scenario() -> None:
        upstream = await asyncio.start_server(handle, "127.0.0.1", 0)
        monkeypatch.setattr(fwd.asyncio, "open_connection", slow_first_open)
        await _paced(upstream, pacer, client)

    asyncio.run(scenario())
    assert len(writes) == 2
    # Measured at the forwarder's own writes, so the interval holds in full (less the clock's
    # rounding); if the interval counted from when the slot came, the gap would be close to zero.
    assert writes[1] - writes[0] >= interval - 0.002, writes


def test_a_target_that_does_not_accept_in_time_costs_only_its_turn(monkeypatch):
    """The first connection's target never accepts: it is dropped at the connect limit, and the
    shared pacer is free for the next connection, which gets its answer."""
    monkeypatch.setattr(fwd, "_CONNECT_SECONDS", 0.05)
    real_open = asyncio.open_connection
    opened = 0

    async def first_never_opens(*args, **kwargs):
        nonlocal opened
        opened += 1
        if opened == 1:
            await asyncio.sleep(3600)
        return await real_open(*args, **kwargs)

    async def client(port: int) -> tuple[bytes, bytes]:
        answers = []
        for _ in range(2):
            reader, writer = await real_open("127.0.0.1", port)
            writer.write(b"ping")
            await writer.drain()
            try:
                answers.append(await asyncio.wait_for(reader.read(100), 5))
            finally:
                writer.close()
        return answers[0], answers[1]

    async def scenario() -> object:
        upstream = await _pong_server()
        monkeypatch.setattr(fwd.asyncio, "open_connection", first_never_opens)
        return await _paced(upstream, fwd.Pacer(6000), client)

    # The first is closed, not hung; the second passes the same pacer and is answered.
    assert asyncio.run(scenario()) == (b"", b"pong:ping")
