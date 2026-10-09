# garak adapter image (specs 006, 027). Pins garak to an EXACT version (ADR-0001).
# Built by the release workflow; executed by the worker/adapter-runner at engagement time.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
# garak needs torch, but in Khandaq it only sends prompts to the target over HTTP: no model runs in
# this container. PyPI's default Linux torch is the CUDA build (about 5 GB of GPU libraries), so the
# CPU build of an exact version is installed first; garak's `torch>=2.13.0` is then already met.
RUN pip install "torch==2.14.0" --index-url https://download.pytorch.org/whl/cpu
# Pin the exact upstream garak version; bump deliberately with the contract test.
RUN pip install "garak==0.17.0"
COPY wrap.py /usr/local/bin/wrap.py
RUN chmod +x /usr/local/bin/wrap.py
# The wrapper reads the run request from KHANDAQ_RUN_REQUEST and writes a tar of /evidence to
# stdout (spec 012 contract v2).
ENTRYPOINT ["python", "/usr/local/bin/wrap.py"]
