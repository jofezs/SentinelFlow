# syntax=docker/dockerfile:1
# Demo/e2e webhook receiver. Build context: repository root.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app
WORKDIR /app
COPY tools/webhook-receiver/receiver.py ./
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"]
CMD ["python", "/app/receiver.py"]
