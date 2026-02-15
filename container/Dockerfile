FROM python:3.12-slim

WORKDIR /app

# Install dependencies first (cache layer)
COPY pyproject.toml .
RUN pip install --no-cache-dir -e . 2>/dev/null || pip install --no-cache-dir .

# Copy source code
COPY src/ src/

# Expose HTTP port
EXPOSE 8002

# Default: run HTTP transport on port 8002
CMD ["python", "-m", "src.server", "--transport", "sse", "--host", "0.0.0.0", "--port", "8002"]
