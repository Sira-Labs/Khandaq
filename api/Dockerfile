# Khandaq control-plane image (serves the API, or the worker when KHANDAQ_ROLE=worker).
# Build context is the repository root: `docker build -f api/Dockerfile .`
FROM python:3.12-slim AS build
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN pip install --no-cache-dir uv
COPY api/pyproject.toml ./
COPY api/src ./src
# Install the package and its dependencies into a self-contained venv.
RUN uv venv /opt/venv && VIRTUAL_ENV=/opt/venv uv pip install --no-cache .

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PATH="/opt/venv/bin:$PATH"
WORKDIR /app
RUN useradd --system --uid 10001 khandaq
COPY --from=build /opt/venv /opt/venv
COPY api/docker-entrypoint.sh /usr/local/bin/khandaq-entrypoint
RUN chmod +x /usr/local/bin/khandaq-entrypoint
USER khandaq
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health').status==200 else 1)" || exit 1
ENTRYPOINT ["khandaq-entrypoint"]
