# Production container for System Health Reporter
FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/memarzade-dev/system-health-reporter" \
      org.opencontainers.image.title="System Health Reporter" \
      org.opencontainers.image.description="Cross-platform system monitoring and reporting tool" \
      org.opencontainers.image.version="1.0.2"

WORKDIR /app

# Install runtime dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application sources
COPY sys_health_reporter.py /app/sys_health_reporter.py
COPY README.md /app/README.md

# Create non-root user
RUN useradd -m appuser && mkdir -p /data && chown -R appuser:appuser /data /app
USER appuser

# Reports will be written under /data (mounted volume recommended)
ENV OUTPUT_DIR=/data

ENTRYPOINT ["python", "/app/sys_health_reporter.py"]
CMD ["/data"]