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
COPY src/ ./src/
COPY scripts/ ./scripts/

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
