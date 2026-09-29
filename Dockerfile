# Cloud Honeypot & Attack Surface Monitor
# ------------------------------------------
# Multi-purpose image: run the SSH honeypot server, the log parser, or the
# report generator, selected via the CMD/entrypoint argument at runtime.

FROM python:3.11-slim

LABEL maintainer="Security Operations"
LABEL description="Cloud Honeypot & Attack Surface Monitor - decoy SSH/Telnet honeypot, log parser, GeoIP enrichment, and reporting"

WORKDIR /app

# Install OS-level build deps needed for cryptography/paramiko wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data /app/reports /app/config \
    && useradd --create-home --shell /bin/bash honeypot \
    && chown -R honeypot:honeypot /app

USER honeypot

# Default: expose the decoy SSH port (mapped to real port 22 externally via
# docker-compose port mapping, e.g. "22:2222")
EXPOSE 2222

# Default command runs the honeypot server. Override at `docker run` time,
# e.g.:
#   docker run <image> python -m src.log_parser
#   docker run <image> python -m src.report_generator
ENTRYPOINT ["python", "-m"]
CMD ["src.honeypot_server", "--config", "config/settings.json"]
