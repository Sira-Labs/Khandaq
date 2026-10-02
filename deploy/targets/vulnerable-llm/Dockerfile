# Intentionally-vulnerable demo target (never expose; authorised self-testing only).
FROM python:3.12-slim
# Pinned to the versions the control plane is tested with (api/uv.lock).
RUN pip install --no-cache-dir "fastapi==0.142.2" "uvicorn[standard]==0.54.0"
COPY app.py /app/app.py
WORKDIR /app
RUN useradd --system --uid 10002 target
USER target
EXPOSE 8900
# 0.0.0.0 inside the container so the compose network can reach it; publish it only on loopback.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8900"]
