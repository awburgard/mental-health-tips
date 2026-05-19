FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DB_PATH=/data/tips.db

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8080

# --access-logfile=/dev/null is intentional: we do not want HTTP access logs.
# Only gunicorn error logs (no request bodies, no client IPs) go to stderr.
CMD ["gunicorn", "-b", "0.0.0.0:8080", "--workers", "2", \
     "--access-logfile", "/dev/null", \
     "--error-logfile", "-", \
     "app:app"]
