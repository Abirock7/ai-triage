# Use a small, stable Python image
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install nmap (for /scan/run) and curl (optional for health tests)
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap curl \
    && rm -rf /var/lib/apt/lists/*

# Workdir
WORKDIR /app

# Copy deps first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY . .

# Default env for demo (override in docker run / compose)
ENV API_KEYS="demo-key-1" \
    DB_PATH="/app/triage.db" \
    TRIAGE_PROVIDER="mock"

EXPOSE 8000

# Start API
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
