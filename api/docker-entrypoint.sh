#!/bin/sh
# Start the API or the worker depending on KHANDAQ_ROLE (ADR-0008). Default: api.
set -e
if [ "$KHANDAQ_ROLE" = "worker" ]; then
  exec khandaq-worker
else
  exec uvicorn khandaq.main:app --host 0.0.0.0 --port "${PORT:-8000}"
fi
