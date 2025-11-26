# mcp-runner-node - Pre-built Node.js runtime for MCP servers
# This is a "fat image" containing common dependencies pre-installed
# MCPs are volume-mounted at runtime (no rebuild needed!)

FROM node:20-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Pre-install common npm packages globally
# Note: @modelcontextprotocol/sdk is installed globally for all MCPs
RUN npm install -g \
    typescript \
    ts-node \
    @modelcontextprotocol/sdk \
    fastify \
    express \
    axios \
    dotenv

# Set working directory
WORKDIR /app

# Default command (will be overridden by volume mount or command)
CMD ["node", "--version"]
