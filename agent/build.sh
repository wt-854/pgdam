#!/bin/bash
set -e

# This script should be run from the agent directory
# but it builds the entire monorepo stack.

# Configuration
IMAGE_NAME="pgdam-builder"
AGENT_IMAGE="pgdam-agent:latest"
PROCESSOR_IMAGE="pgdam-processor:latest"
CLUSTER_NAME="pgdam-dev"

# Calculate ROOT_DIR (one level up from this script's location)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CARGO_CACHE_DIR="$ROOT_DIR/.cargo-cache"

echo "Using Root Directory: $ROOT_DIR"
mkdir -p "$CARGO_CACHE_DIR"

# Build the builder image if it doesn't exist
if [[ "$(docker images -q $IMAGE_NAME 2> /dev/null)" == "" ]]; then
  echo "Building $IMAGE_NAME..."
  docker build -t $IMAGE_NAME -f "$SCRIPT_DIR/Dockerfile.builder" "$SCRIPT_DIR"
fi

# Build eBPF program
echo "Compiling eBPF program..."
docker run --rm \
  -v "$ROOT_DIR:/src" \
  -v "$CARGO_CACHE_DIR:/usr/local/cargo/registry" \
  -e RUSTFLAGS="-C llvm-args=-bpf-stack-size=2048" \
  $IMAGE_NAME \
  bash -c "cargo +nightly build -Z build-std=core --manifest-path agent/pgdam-ebpf/Cargo.toml --release --target bpfel-unknown-none"

# Build User-space Agent
echo "Compiling user-space agent..."
docker run --rm \
  -v "$ROOT_DIR:/src" \
  -v "$CARGO_CACHE_DIR:/usr/local/cargo/registry" \
  $IMAGE_NAME \
  cargo build --manifest-path agent/pgdam-agent/Cargo.toml --release

# Build Processor
echo "Compiling processor..."
docker run --rm \
  -v "$ROOT_DIR:/src" \
  -v "$CARGO_CACHE_DIR:/usr/local/cargo/registry" \
  $IMAGE_NAME \
  cargo build --manifest-path processor/Cargo.toml --release

# Build Agent Image
echo "Building agent image $AGENT_IMAGE..."
docker build -t $AGENT_IMAGE -f "$SCRIPT_DIR/Dockerfile.agent" "$SCRIPT_DIR"

# Build Processor Image
echo "Building processor image $PROCESSOR_IMAGE..."
docker build -t $PROCESSOR_IMAGE -f "$ROOT_DIR/processor/Dockerfile.processor" "$ROOT_DIR/processor"

# Load into Kind
echo "Loading images into Kind cluster $CLUSTER_NAME..."
export KIND_EXPERIMENTAL_PROVIDER=podman
kind load docker-image $AGENT_IMAGE --name $CLUSTER_NAME
kind load docker-image $PROCESSOR_IMAGE --name $CLUSTER_NAME
