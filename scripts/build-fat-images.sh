#!/bin/bash
# Build script for AMSAW v2 fat images
# These images are built once and reused for all MCP assessments

set -e

echo "========================================="
echo "  Building AMSAW v2 Fat Images"
echo "========================================="
echo ""

echo "[*] Building mcp-runner-python..."
docker build \
    -t mcp-runner-python:latest \
    -f docker/mcp-runner-python.Dockerfile \
    .

echo ""
echo "[*] Building mcp-runner-node..."
docker build \
    -t mcp-runner-node:latest \
    -f docker/mcp-runner-node.Dockerfile \
    .

echo ""
echo "========================================="
echo "  ✅ Fat images built successfully!"
echo "========================================="
echo ""
docker images | grep mcp-runner
echo ""
echo "Test with:"
echo "  docker run --rm mcp-runner-python python --version"
echo "  docker run --rm mcp-runner-node node --version"
