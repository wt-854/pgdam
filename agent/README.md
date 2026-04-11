# pgDAM Agent

The eBPF-based agent responsible for capturing PostgreSQL traffic.

## Components
- **pgdam-ebpf**: The eBPF program that hooks into PostgreSQL's `pg_parse_query` function.
- **pgdam-agent**: The user-space daemon that loads the eBPF program, collects events via a RingBuffer, and streams them to the processor.

## Building Separately

Assuming you are in the root directory:

```bash
# Build binary
docker run --rm -v "$(pwd):/src" pgdam-builder bash -c " \
  cargo +nightly build -Z build-std=core --manifest-path agent/pgdam-ebpf/Cargo.toml --release --target bpfel-unknown-none && \
  cargo build --manifest-path agent/pgdam-agent/Cargo.toml --release"

# Build Image
docker build -t pgdam-agent:latest -f agent/Dockerfile.agent agent/
```
