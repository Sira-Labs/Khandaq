"""Worker: executes queued container runs (spec 012, ADR-0015).

The API commits container runs as ``queued`` and sends ``NOTIFY khandaq_runs``. The worker:

1. at start, fails runs left ``running`` past the adapter timeout (a previous worker was lost);
1a. on every iteration, queues runs for due campaigns (spec 016, ADR-0017) and delivers due
    alerts on worsened campaign diffs (spec 017);
2. claims the oldest queued run (``FOR UPDATE SKIP LOCKED``), re-checks its scope, marks it
   ``running`` and commits — or records it ``rejected``;
3. executes it in a sandboxed container (``DockerRunner``) and records the outcome;
4. when the queue is empty, waits for a notification or the poll interval, whichever comes first,
   so a lost notification only delays a run.

One run at a time per worker process; scale by running more workers.
"""

from __future__ import annotations

import datetime as dt
import logging
import signal
import threading
import time
from collections.abc import Callable

from sqlalchemy import Engine, create_engine
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from . import deployment
from .alerts import deliver_due
from .campaigns import schedule_due
from .runs import NOTIFY_CHANNEL, claim_next_run, execute_run, recover_stale_runs
from .settings import Settings, get_settings

log = logging.getLogger("khandaq.worker")

# Past the adapter timeout, a run can only still be "running" if its worker died: the runner
# kills the container at the timeout and recording results takes seconds.
STALE_MARGIN = dt.timedelta(minutes=10)
HEARTBEAT_SECONDS = 30.0


class Notifications:
    """A dedicated autocommit connection LISTENing on the run channel."""

    def __init__(self, engine: Engine) -> None:
        raw = engine.raw_connection()
        conn = raw.driver_connection
        if conn is None:  # pragma: no cover - a pooled connection always has its driver connection
            raise RuntimeError("no driver connection to LISTEN on")
        self._raw = raw
        self._conn = conn
        self._conn.autocommit = True
        self._conn.execute(f"LISTEN {NOTIFY_CHANNEL}")

    def wait(self, timeout: float) -> None:
        for _ in self._conn.notifies(timeout=timeout, stop_after=1):
            pass

    def close(self) -> None:
        self._raw.close()


def work_once(engine: Engine, runner=None) -> bool:
    """Claim and execute one run; ``True`` if there was a queued run to look at."""
    with Session(engine) as session:
        run_id = claim_next_run(session)
        if run_id is None:
            return False
        log.info("executing run %s", run_id)
        run = execute_run(session, run_id, runner=runner)
        log.info("run %s %s", run_id, run.state)
        return True


def schedule_campaigns(engine: Engine) -> int:
    """Queue runs for due campaigns (spec 016, ADR-0017); returns how many were due."""
    with Session(engine) as session:
        return schedule_due(session)


def deliver_alerts(engine: Engine) -> int:
    """Send due alerts on worsened campaign diffs (spec 017); returns how many were attempted."""
    with Session(engine) as session:
        return deliver_due(session)


def drain(engine: Engine, runner=None) -> int:
    """Execute queued runs until none is left; returns how many were looked at."""
    count = 0
    while work_once(engine, runner):
        count += 1
    return count


def _recover_lost_runs(engine: Engine, settings: Settings) -> None:
    with Session(engine) as session:
        older = dt.timedelta(seconds=settings.adapter_timeout_seconds) + STALE_MARGIN
        if lost := recover_stale_runs(session, older_than=older):
            log.warning("failed %d run(s) a previous worker lost", lost)


class Heartbeat:
    """Writes this worker's heartbeat at start and then at most every ``every`` seconds (spec
    023), and prunes week-old rows once."""

    def __init__(self, settings: Settings, every: float = HEARTBEAT_SECONDS) -> None:
        self.settings = settings
        self.every = every
        self.wid = deployment.worker_id()
        self.started_at = dt.datetime.now(dt.UTC)
        self._last: float | None = None
        self._pruned = False

    def maybe_beat(self, engine: Engine) -> bool:
        now = time.monotonic()
        if self._last is not None and now - self._last < self.every:
            return False
        self._last = now  # a failed beat is retried after the interval, not on every iteration
        try:
            with Session(engine) as session:
                if not self._pruned:
                    deployment.prune(session)
                    self._pruned = True
                deployment.beat(session, self.settings, wid=self.wid, started_at=self.started_at)
        except SQLAlchemyError as exc:  # telemetry must never stop the worker from running work
            log.warning("worker heartbeat not recorded: %s", type(exc).__name__)
            return False
        return True


def run_forever(
    settings: Settings,
    stop: threading.Event,
    engine_factory: Callable[[str], Engine] | None = None,
) -> None:
    make_engine = engine_factory or (lambda url: create_engine(url, pool_pre_ping=True))
    engine = make_engine(settings.database_url)
    listen_engine = create_engine(settings.database_url, poolclass=NullPool)
    notifications: Notifications | None = None
    recovered = False
    heartbeat = Heartbeat(settings)
    try:
        while not stop.is_set():
            try:
                # Inside the retry loop: a database still starting when the worker starts is
                # retried like any later outage instead of killing the process (PR #31 review).
                if not recovered:
                    _recover_lost_runs(engine, settings)
                    recovered = True
                if notifications is None:
                    notifications = Notifications(listen_engine)
                heartbeat.maybe_beat(engine)
                schedule_campaigns(engine)
                deliver_alerts(engine)
                if work_once(engine):
                    continue
                notifications.wait(settings.worker_poll_seconds)
            except OperationalError as exc:  # database restarting: back off, reconnect
                log.error("database unavailable: %s", exc)
                if notifications is not None:
                    notifications.close()
                    notifications = None
                stop.wait(settings.worker_poll_seconds)
    finally:
        if notifications is not None:
            notifications.close()
        engine.dispose()
        listen_engine.dispose()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    settings = get_settings()
    settings.validate_runtime()
    log.info("khandaq-worker up (env=%s)", settings.env)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    if not settings.database_url:
        log.error("KHANDAQ_DATABASE_URL is not set; the worker has nothing to do")
        stop.wait()
        return
    run_forever(settings, stop)
    log.info("khandaq-worker shutting down")


if __name__ == "__main__":
    main()
