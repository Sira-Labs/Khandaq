# Khandaq control-plane image (serves the API, or the worker when KHANDAQ_ROLE=worker).
# Build context is the repository root: `docker build -f api/Dockerfile .`
FROM python:3.12-slim AS build
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# build-essential + a Rust toolchain are needed to compile the khandaq-core PyO3 wheel (maturin);
# only the resulting venv is copied into the runtime stage, so these never ship in the final image.
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential curl pkg-config && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"
RUN pip install --no-cache-dir uv
WORKDIR /app
# The api package sources khandaq-core from ../core/khandaq-py (api/pyproject.toml [tool.uv.sources]),
# so the Rust workspace must sit beside it in the build context (resolves to /core/khandaq-py).
COPY core /core
COPY api/pyproject.toml ./
COPY api/src ./src
# Install the package and its dependencies (building the khandaq-core wheel) into a self-contained venv.
RUN uv venv /opt/venv && VIRTUAL_ENV=/opt/venv uv pip install --no-cache .

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PATH="/opt/venv/bin:$PATH" DOCKER_CONFIG=/tmp/docker-config
WORKDIR /app
RUN useradd --system --uid 10001 khandaq \
 && mkdir -p /var/lib/khandaq/evidence && chown khandaq /var/lib/khandaq/evidence
# The worker launches adapter containers through the Docker socket with the Docker CLI (spec 012).
# The static client binary only, pinned by digest; the API role never uses it.
COPY --from=docker:28.5.2-cli@sha256:625d9431a9f54c5a2bc90f24f0e1c3d55b1349fd857dd85035f98c2c9acbdd4d \
     /usr/local/bin/docker /usr/local/bin/docker
COPY --from=build /opt/venv /opt/venv
COPY api/docker-entrypoint.sh /usr/local/bin/khandaq-entrypoint
RUN chmod +x /usr/local/bin/khandaq-entrypoint
USER khandaq
EXPOSE 8000
# The same image runs the worker (KHANDAQ_ROLE=worker), which serves no HTTP: probing :8000 there
# would mark it unhealthy and Swarm/CapRover would keep replacing it. The worker is the container's
# main process, so the container already exits if it dies.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD if [ "$KHANDAQ_ROLE" = "worker" ]; then exit 0; fi; \
      python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health').status==200 else 1)" || exit 1
ENTRYPOINT ["khandaq-entrypoint"]
