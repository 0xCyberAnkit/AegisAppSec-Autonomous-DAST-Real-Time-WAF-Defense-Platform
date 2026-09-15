# ==============================================================================
# AegisAppSec Enterprise Multi-Stage Dockerfile
# Supports FastAPI Web Server, ASGI WAF, and Celery Distributed Workers
# ==============================================================================
FROM python:3.11-slim as base

# Prevent Python from writing .pyc files & enable unbuffered standard I/O
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/backend

WORKDIR /app

# Install system utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    libmariadb-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy application files
COPY backend /app/backend
COPY frontend /app/frontend

EXPOSE 8000

# Default command: Launch FastAPI ASGI Server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
