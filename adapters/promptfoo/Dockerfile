# promptfoo adapter image (spec 010). Pins promptfoo to an EXACT version (ADR-0001).
FROM node:22-slim
RUN npm install -g promptfoo@0.118.0
COPY wrap.py /usr/local/bin/wrap.py
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/* \
    && chmod +x /usr/local/bin/wrap.py
ENTRYPOINT ["python3", "/usr/local/bin/wrap.py"]
