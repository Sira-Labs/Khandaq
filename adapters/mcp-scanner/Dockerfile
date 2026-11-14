# Cisco mcp-scanner adapter image (specs 025, 031). Pins mcp-scanner to an EXACT version (ADR-0001).
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN pip install "cisco-ai-mcp-scanner==4.8.5"
COPY wrap.py /usr/local/bin/wrap.py
RUN chmod +x /usr/local/bin/wrap.py
# The wrapper reads the run request from KHANDAQ_RUN_REQUEST and writes a tar of /evidence to
# stdout (spec 012 contract v2).
ENTRYPOINT ["python", "/usr/local/bin/wrap.py"]
