# Intentionally-vulnerable demo target (never expose; authorised self-testing only).
FROM python:3.12-slim
RUN pip install --no-cache-dir fastapi "uvicorn[standard]"
COPY app.py /app/app.py
WORKDIR /app
EXPOSE 8900
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8900"]
