# =====================================================================
# Shogun Command Centre — Production Docker Image
# Multi-stage build: builder → slim runtime
# =====================================================================
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies for cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="Shogun Command Centre" \
      org.opencontainers.image.description="Enterprise security orchestration & intelligence platform" \
      org.opencontainers.image.vendor="KirkForge" \
      org.opencontainers.image.source="https://github.com/KirkForge/Shogun" \
      org.opencontainers.image.licenses="MIT"

# Security: non-root user
RUN groupadd -r shogun && useradd -r -g shogun -d /app -s /sbin/nologin shogun

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY . .

# Create necessary directories with proper ownership
RUN mkdir -p /app/logs /app/backups && \
    chown -R shogun:shogun /app

USER shogun

ENV SHOGUN_ENV=production \
    SHOGUN_SECRET_KEY=change-me-in-production \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8765/health')" || exit 1

CMD ["python", "-m", "uvicorn", "api.server:app", "--host", "0.0.0.0", "--port", "8765", "--workers", "4", "--no-access-log"]
