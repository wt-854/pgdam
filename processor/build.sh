#!/bin/bash
set -e

echo "Building pgdam-processor..."

# 1. Build binary using the shared builder container
podman run --rm -v "$(pwd)/..:/workspace" -w /workspace/processor pgdam-builder \
    cargo build --release

# 2. Build processor docker image
podman build -t pgdam-processor:latest -f Dockerfile.processor .

echo "Successfully built pgdam-processor:latest"
