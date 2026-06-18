FROM debian:12-slim

# Version: 1.0.0
# Date:    2026-06-17
# Notes:   ARCIS-SWARM container — Python 3.12 FastAPI + audit engine

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    openssh-client bash curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt /app/requirements.txt
RUN python3 -m venv /app/venv \
    && /app/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

COPY backend/  /app/backend/
COPY frontend/ /app/frontend/
COPY scripts/  /app/scripts/

RUN chmod +x /app/scripts/audit.sh

EXPOSE 8000

ENV PYTHONPATH=/app/backend

CMD ["/app/venv/bin/uvicorn", "main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--app-dir", "/app/backend"]
