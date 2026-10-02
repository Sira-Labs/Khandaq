"""Worker entrypoint (skeleton).

The real worker runs the job queue and the adapter host (specs 005+, ADR-0008/0009). For now it
boots, validates configuration the same way the API does, logs that it is up, and stays alive so the
deployment's worker app is healthy. No jobs are processed yet.
"""

from __future__ import annotations

import logging
import signal
import threading

from .settings import get_settings

log = logging.getLogger("khandaq.worker")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    settings = get_settings()
    settings.validate_runtime()
    log.info(
        "khandaq-worker up (env=%s); no job queue yet — adapter host lands in spec 005",
        settings.env,
    )
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    stop.wait()
    log.info("khandaq-worker shutting down")


if __name__ == "__main__":
    main()
