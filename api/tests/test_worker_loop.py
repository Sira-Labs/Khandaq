"""The worker loop survives a database that is down when it starts (PR #31 review). No database:
the loop's collaborators are replaced, so this only checks the retry and cleanup control flow."""

from __future__ import annotations

import threading

from sqlalchemy.exc import OperationalError

from khandaq import worker
from khandaq.settings import Settings


class _Quiet:
    def __init__(self, engine) -> None:
        pass

    def wait(self, timeout: float) -> None:
        pass

    def close(self) -> None:
        pass


def test_recovery_is_retried_when_the_database_is_down_at_start(monkeypatch):
    stop = threading.Event()
    attempts: list[int] = []
    disposed: list[str] = []

    def recover(session, older_than):
        attempts.append(1)
        if len(attempts) == 1:
            raise OperationalError("SELECT 1", {}, ConnectionRefusedError("db starting"))
        stop.set()  # second attempt succeeds; end the loop
        return 0

    monkeypatch.setattr(worker, "recover_stale_runs", recover)
    monkeypatch.setattr(worker, "Notifications", _Quiet)
    monkeypatch.setattr(worker, "work_once", lambda engine, runner=None: False)
    monkeypatch.setattr(worker, "schedule_campaigns", lambda engine: 0)
    monkeypatch.setattr(worker, "deliver_alerts", lambda engine: 0)

    from sqlalchemy import create_engine

    def factory(url):
        engine = create_engine(url)
        real = engine.dispose
        monkeypatch.setattr(engine, "dispose", lambda: (disposed.append("engine"), real())[1])
        return engine

    settings = Settings(database_url="sqlite://", worker_poll_seconds=0.01)
    worker.run_forever(settings, stop, engine_factory=factory)

    assert len(attempts) == 2  # retried, not raised
    assert disposed == ["engine"]


def test_recovery_runs_once(monkeypatch):
    stop = threading.Event()
    attempts: list[int] = []
    loops: list[int] = []

    monkeypatch.setattr(worker, "recover_stale_runs", lambda s, older_than: attempts.append(1) or 0)
    monkeypatch.setattr(worker, "Notifications", _Quiet)
    scheduled: list[int] = []
    monkeypatch.setattr(worker, "schedule_campaigns", lambda engine: scheduled.append(1) or 0)
    monkeypatch.setattr(worker, "deliver_alerts", lambda engine: 0)

    def work_once(engine, runner=None):
        loops.append(1)
        if len(loops) == 3:
            stop.set()
        return False

    monkeypatch.setattr(worker, "work_once", work_once)
    worker.run_forever(Settings(database_url="sqlite://", worker_poll_seconds=0.01), stop)
    assert attempts == [1] and len(loops) == 3
    assert len(scheduled) == 3  # campaigns are scheduled on every iteration


def test_a_failing_heartbeat_never_stops_the_work(monkeypatch):
    # sqlite:// has no worker_heartbeats table, so every beat fails (spec 023): runs still happen.
    stop = threading.Event()
    loops: list[int] = []
    monkeypatch.setattr(worker, "recover_stale_runs", lambda s, older_than: 0)
    monkeypatch.setattr(worker, "Notifications", _Quiet)
    monkeypatch.setattr(worker, "schedule_campaigns", lambda engine: 0)
    monkeypatch.setattr(worker, "deliver_alerts", lambda engine: 0)

    def work_once(engine, runner=None):
        loops.append(1)
        if len(loops) == 2:
            stop.set()
        return False

    monkeypatch.setattr(worker, "work_once", work_once)
    worker.run_forever(Settings(database_url="sqlite://", worker_poll_seconds=0.01), stop)
    assert len(loops) == 2


def test_a_worker_started_before_the_migrations_waits_for_them(monkeypatch):
    # A fresh install can start the worker before the API has created the tables.
    from psycopg.errors import UndefinedTable
    from sqlalchemy.exc import ProgrammingError

    stop = threading.Event()
    attempts: list[int] = []

    def recover(session, older_than):
        attempts.append(1)
        if len(attempts) == 1:
            raise ProgrammingError("SELECT", {}, UndefinedTable('relation "runs" does not exist'))
        stop.set()
        return 0

    monkeypatch.setattr(worker, "recover_stale_runs", recover)
    monkeypatch.setattr(worker, "Notifications", _Quiet)
    monkeypatch.setattr(worker, "work_once", lambda engine, runner=None: False)
    monkeypatch.setattr(worker, "schedule_campaigns", lambda engine: 0)
    monkeypatch.setattr(worker, "deliver_alerts", lambda engine: 0)
    worker.run_forever(Settings(database_url="sqlite://", worker_poll_seconds=0.01), stop)
    assert len(attempts) == 2  # waited and retried, not crashed


def test_any_other_programming_error_still_ends_the_loop(monkeypatch):
    import pytest
    from sqlalchemy.exc import ProgrammingError

    def recover(session, older_than):
        raise ProgrammingError("SELECT", {}, ValueError("a real bug"))

    monkeypatch.setattr(worker, "recover_stale_runs", recover)
    monkeypatch.setattr(worker, "Notifications", _Quiet)
    with pytest.raises(ProgrammingError):
        worker.run_forever(
            Settings(database_url="sqlite://", worker_poll_seconds=0.01), threading.Event()
        )
