# Cloudie Flask malware-analysis API — Cloud Run image
FROM python:3.12-slim

# System deps occasionally needed by scientific wheels; keep minimal.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install Python dependencies first (better build caching)
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt && \
    pip install gunicorn

# Copy the application code + model artifacts
COPY . .

# Cloud Run provides $PORT (defaults to 8080). gunicorn binds to it.
# Long timeout because a VirusTotal upload+poll can take ~60s.
ENV PORT=8080
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 120 app:app
