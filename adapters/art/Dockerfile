# ART adapter image (specs 033 and 035). Pins the Adversarial Robustness Toolbox and what it loads
# models and data with to EXACT versions (ADR-0001), from requirements.txt.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt && rm /tmp/requirements.txt
COPY wrap.py /usr/local/bin/wrap.py
RUN chmod +x /usr/local/bin/wrap.py
ENTRYPOINT ["python", "/usr/local/bin/wrap.py"]
