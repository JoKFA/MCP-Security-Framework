# mcp-runner-python - Pre-built Python runtime for MCP servers
# This is a "fat image" containing common dependencies pre-installed
# MCPs are volume-mounted at runtime (no rebuild needed!)

FROM python:3.11-slim-bookworm

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install uv (fast Python package manager)
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.cargo/bin:$PATH"

# Pre-install common Python packages used by MCP servers
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    httpx \
    aiohttp \
    requests \
    psycopg2-binary \
    pymongo \
    sqlalchemy \
    pydantic \
    stripe \
    openai \
    anthropic \
    mcp

# Set working directory
WORKDIR /app

# Default command (will be overridden by volume mount or command)
CMD ["python", "--version"]
