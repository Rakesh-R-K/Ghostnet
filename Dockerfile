# Stage 1: Build
FROM python:3.11-slim as builder

WORKDIR /app
RUN pip install --no-cache-dir pip-tools

# Copy only requirements-related files first
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Stage 2: Runtime
FROM python:3.11-slim

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy source code
COPY common/ common/
COPY client/ client/
COPY server/ server/
COPY README.md .
COPY config.json .

# Default environment variables
ENV GHOSTNET_SERVER_IP=0.0.0.0
ENV GHOSTNET_SERVER_PORT=53

# Expose DNS port
EXPOSE 53/udp

# Run server by default
CMD ["python", "-m", "server.ghostnet_server"]
