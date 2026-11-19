# ART adapter image (spec 033). Pins the Adversarial Robustness Toolbox to an EXACT version
# (ADR-0001). `packaging` is installed by name because ART 1.20.1 imports it without declaring it.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN pip install "adversarial-robustness-toolbox==1.20.1" packaging
COPY wrap.py /usr/local/bin/wrap.py
RUN chmod +x /usr/local/bin/wrap.py
ENTRYPOINT ["python", "/usr/local/bin/wrap.py"]
