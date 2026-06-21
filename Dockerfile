# Version: 2.0.0
# Date:    2026-06-21
# Notes:   Clone from public GitHub repo instead of COPY — enables self-update via /api/system/update

FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    openssh-client bash curl git \
    && rm -rf /var/lib/apt/lists/*

ARG REPO_URL=https://github.com/gaetanmarais/SWARM-AUDIT.git
ARG GIT_BRANCH=main

# Shallow clone — depth=50 gives enough history for git pull to work cleanly
RUN git clone --depth=50 --branch=${GIT_BRANCH} ${REPO_URL} /app/repo

WORKDIR /app

RUN python3 -m venv /app/venv \
    && /app/venv/bin/pip install --no-cache-dir -r /app/repo/backend/requirements.txt \
    && chmod +x /app/repo/scripts/audit.sh \
    && mkdir -p /app/data/dumps

EXPOSE 8000

ENV PYTHONPATH=/app/repo/backend
ENV SWARM_DATA_DIR=/app/data
ENV SWARM_REPO_DIR=/app/repo
ENV SWARM_REPO_REMOTE=https://github.com/gaetanmarais/SWARM-AUDIT.git

CMD ["/app/venv/bin/uvicorn", "main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--app-dir", "/app/repo/backend"]
