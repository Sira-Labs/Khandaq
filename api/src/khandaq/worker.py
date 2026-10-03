"""Worker: executes queued container runs (spec 012, ADR-0015).

The API commits container runs as ``queued`` and sends ``NOTIFY khandaq_runs``. The worker:

1. at start, fails runs left ``running`` past the adapter timeout (a previous worker was lost);
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
from collections.abc import Callable

from sqlalchemy import Engine, create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from .runs import NOTIFY_CHANNEL, claim_next_run, execute_run, recover_stale_runs
from .settings import Settings, get_settings

log = logging.getLogger("khandaq.worker")

# Past the adapter timeout, a run can only still be "running" if its worker died: the runner
# kills the container at the timeout and recording results takes seconds.
STALE_MARGIN = dt.timedelta(minutes=10)


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
