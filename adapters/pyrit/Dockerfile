# PyRIT adapter image (spec 009). Pins PyRIT to an EXACT version (ADR-0001).
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN pip install "pyrit==1.1.0"
COPY wrap.py /usr/local/bin/wrap.py
RUN chmod +x /usr/local/bin/wrap.py
ENTRYPOINT ["python", "/usr/local/bin/wrap.py"]
