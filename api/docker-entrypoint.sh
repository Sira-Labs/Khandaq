#!/bin/sh
# Start the API or the worker depending on KHANDAQ_ROLE (ADR-0008). Default: api.
# The API runs database migrations on boot (retrying while the database comes up), then serves.
set -e

if [ "$KHANDAQ_ROLE" = "worker" ]; then
  # The worker never migrates: it must not carry the owner login.
  unset KHANDAQ_MIGRATION_DATABASE_URL
  exec khandaq-worker
fi

if [ -n "$KHANDAQ_MIGRATION_DATABASE_URL" ] || [ -n "$KHANDAQ_DATABASE_URL" ]; then
  n=0
  until khandaq-db upgrade head; do
    n=$((n + 1))
    if [ "$n" -ge 10 ]; then
      echo "migrations failed after $n attempts" >&2
      exit 1
    fi
    echo "migrations: database not ready, retry $n/10 in 3s" >&2
    sleep 3
  done
fi

# Migrations are done: drop the owner login so the long-lived server process (which replaces this
# shell via exec) never holds credentials that could disable the append-only triggers.
unset KHANDAQ_MIGRATION_DATABASE_URL
exec uvicorn khandaq.main:app --host 0.0.0.0 --port "${PORT:-8000}"
