# ADR-0009: Each adapter runs in its own container with egress constrained to the in-scope target

- **Status:** Accepted
- **Date:** 2026-10-02
- **Deciders:** owner

## Context

Adapters wrap third-party tools with large, conflicting dependency trees (different Python versions,
CUDA, Node). They execute offensive logic and must reach a target — but only the **authorised** one.
Two problems to solve at once: dependency isolation, and making the scope lock physically true rather
than advisory.

## Decision

- **One container image per adapter**, pinned to an exact upstream tool version. This ends dependency
  conflicts between tools and makes each adapter independently buildable and replaceable.
- **Network egress is constrained to the single in-scope target of the run.** The control plane does
  the scope check (`04-engagement-scope-and-authz.md`) and then launches the adapter with host-level
  egress restricted to that one target (default-deny egress; allow only the resolved host/port for the
  run). A compromised or buggy adapter therefore **cannot** reach anything outside the authorised
  scope, because the restriction is enforced below the adapter.
- **Least privilege inside the container:** no host mounts except the per-run evidence volume and the
  run request; read-only rootfs where the tool allows; dropped capabilities; per-run resource limits;
  no access to other engagements' data.
- Adapters receive the target and (ephemeral) credentials from the control plane; they never read the
  engagement scope or pick their own target.

## Alternatives considered

| Option | Pros | Cons | Why not |
|---|---|---|---|
| Run tools in-process in the API | Simple | Dependency hell; a tool bug compromises the control plane; no egress control | Unacceptable isolation |
| One big "all tools" image (à la BlackIce) | One image | Dependency conflicts; no per-tool pinning; coarse isolation | Loses pinning and isolation |
| VM per run | Strong isolation | Heavy; slow; harder to self-host | Container + egress policy is enough; VMs an option later |
| **Container per adapter, egress-locked (chosen)** | Isolation + real scope enforcement + pinning | Host must support egress policy; more images | Accepted |

## Consequences

- The deployment must support per-container egress restriction; `deploy/` documents the compose and
  CapRover setups (and the fallback on hosts that cannot do fine-grained egress: a per-run network
  namespace/proxy that only forwards to the resolved target).
- Adapter images are published to GHCR and pinned; air-gapped installs mirror them.
- The "egress is constrained to the resolved target" property is tested with a negative test (an
  adapter attempting an out-of-scope host fails to connect).
