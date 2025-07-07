# Multi-stage Dockerfile for Fedora Security Hardening Toolkit
# Optimized for security, size, and performance

# Build stage
FROM python:3.11-slim-bullseye AS builder

# Set build arguments
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=1.0.0

# Add metadata
LABEL org.opencontainers.image.title="Fedora Security Hardening Toolkit"
LABEL org.opencontainers.image.description="Comprehensive security hardening toolkit for Fedora Linux systems"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${VCS_REF}"
LABEL org.opencontainers.image.vendor="Security Hardening Toolkit Team"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/swipswaps/fedora-security-hardening-toolkit"

# Install system dependencies for building
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt requirements-dev.txt ./

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip and install dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim-bullseye AS production

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    curl \
    iptables \
    systemctl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r security && useradd -r -g security -d /app -s /bin/bash security

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=security:security . .

# Install the package
RUN pip install --no-cache-dir -e .

# Create necessary directories
RUN mkdir -p /app/logs /app/reports && \
    chown -R security:security /app

# Switch to non-root user
USER security

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python security_audit.py --help || exit 1

# Default command
CMD ["python", "security_audit.py", "--help"]

# Development stage
FROM production AS development

# Switch back to root for development tools installation
USER root

# Install development dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    shellcheck \
    git \
    vim \
    less \
    && rm -rf /var/lib/apt/lists/*

# Install development Python packages
COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt

# Install pre-commit
RUN pip install --no-cache-dir pre-commit

# Switch back to security user
USER security

# Set development environment variables
ENV DEVELOPMENT=1
ENV PYTHONPATH=/app

# Default command for development
CMD ["bash"]

# Testing stage
FROM development AS testing

# Copy test files
COPY tests/ tests/
COPY pytest.ini tox.ini noxfile.py ./

# Run tests
RUN python -m pytest tests/ -v

# Security scanning stage
FROM development AS security-scan

# Run security scans
RUN bandit -r . -f json -o bandit-report.json || true
RUN safety check || true

# Final production image
FROM production AS final

# Add final metadata
LABEL stage="production"

# Expose any necessary ports (none needed for CLI tool)
# EXPOSE 8080

# Final health check
HEALTHCHECK --interval=60s --timeout=30s --start-period=10s --retries=3 \
    CMD python security_audit.py --version || exit 1

# Entry point script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["python", "security_audit.py"]
