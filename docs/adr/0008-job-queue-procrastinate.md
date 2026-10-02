# ADR-0008: Runs and campaigns execute on a Postgres-backed job queue (Procrastinate)

- **Status:** Accepted
- **Date:** 2026-10-02
- **Deciders:** owner

## Context

Adapter runs are long, resource-heavy and launched asynchronously; campaigns are scheduled. We need a
job queue with retries, scheduling and visibility, without adding another datastore. Tabayyun already
uses Procrastinate (Postgres-backed) successfully.

## Decision

Use **Procrastinate** (Postgres `LISTEN/NOTIFY`) for the worker: run execution (launch adapter
container, collect output, hand to the core) and campaign scheduling (periodic suite runs + diff). No
Redis/RabbitMQ; the queue lives in the same Postgres as the data, so one backup covers everything and
self-hosting stays a single datastore.

## Alternatives considered

| Option | Pros | Cons | Why not |
|---|---|---|---|
| Celery + Redis | Popular | Second datastore; more ops for self-host | Avoid extra infra |
| Arq / Dramatiq + Redis | Lightweight | Still needs Redis | Same |
| Temporal | Powerful workflows | Heavy; another service | Over-engineered now |
| **Procrastinate (chosen)** | No extra datastore; family-proven; scheduling built in | Postgres-coupled | Accepted |

## Consequences

- One datastore to back up and operate; matches the deployment story.
- Multi-node adapter runners (R3) layer on top by running more workers; the adapter host launches
  containers, so scaling is adding worker capacity.
- Job state and history are queryable from the same DB for run/campaign visibility.
