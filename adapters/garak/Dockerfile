# garak adapter image (spec 006). Pins garak to an EXACT version (ADR-0001).
# Built by the release workflow; executed by the worker/adapter-runner at engagement time.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
# Pin the exact upstream garak version; bump deliberately with the contract test.
RUN pip install "garak==0.17.0"
COPY wrap.py /usr/local/bin/wrap.py
RUN chmod +x /usr/local/bin/wrap.py
# The adapter reads /run-request.json and writes to /evidence (mounted by the host).
ENTRYPOINT ["python", "/usr/local/bin/wrap.py"]
