# ── NIGHTWATCH WAF — Dockerfile ──────────────────────────────────
# Multi-stage build keeps the final image small.
# Stage 1: install dependencies
# Stage 2: copy app + run with Gunicorn

FROM python:3.12-slim AS builder

WORKDIR /app

# Install build deps (needed for LightGBM, XGBoost)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ── Final stage ───────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# Runtime deps only (LightGBM needs libgomp at runtime)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY . .

# Create directory for SQLite database volume
RUN mkdir -p /app/data

# Non-root user for security
RUN useradd -m -u 1000 nightwatch && chown -R nightwatch:nightwatch /app
USER nightwatch

EXPOSE 8000

# Gunicorn: 4 workers, bind to 0.0.0.0:8000
CMD ["gunicorn", \
     "--workers", "4", \
     "--worker-class", "sync", \
     "--bind", "0.0.0.0:8000", \
     "--timeout", "60", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "info", \
     "app:create_app()"]
