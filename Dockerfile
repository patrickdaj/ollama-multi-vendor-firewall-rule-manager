# ── Stage 1: Build frontend ────────────────────────────────────────────────────
FROM node:22-slim AS frontend-builder
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./frontend/
RUN cd frontend && npm ci
COPY frontend/ ./frontend/
# outDir is '../src/api/static' relative to frontend/ → /app/src/api/static
RUN cd frontend && npm run build

# ── Stage 2: Python application ────────────────────────────────────────────────
FROM python:3.12-slim

# System deps needed by netmiko / paramiko / cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install uv for fast dependency resolution
RUN pip install --no-cache-dir uv

COPY pyproject.toml .
COPY alembic.ini .
COPY alembic/ ./alembic/
COPY src/ ./src/
COPY scripts/ ./scripts/

# Copy built frontend assets
COPY --from=frontend-builder /app/src/api/static ./src/api/static

# Install project and all dependencies
RUN uv pip install --system --no-cache -e .

# Non-root user
RUN useradd -m appuser && chown -R appuser /app
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command overridden by docker-compose
CMD ["fw-api"]
