# PostgreSQL Database Activity Monitoring (pgDAM)

A high-performance PostgreSQL Database Activity Monitoring (DAM) system using eBPF for zero-overhead SQL capture and Open Policy Agent (OPA) for dynamic PII masking.

## Architecture

The system is deployed as a Kubernetes DaemonSet with three containers per pod:
1. **Agent (Rust/eBPF)**: Captures PostgreSQL network traffic using eBPF uprobes/kprobes and streams events to the Processor.
2. **Processor (Rust)**: Normalizes raw SQL, extracts potential PII, and queries OPA for masking decisions.
3. **OPA (Open Policy Agent)**: Evaluates Rego policies to determine which data points should be redacted.

## Prerequisites

- **Kubernetes Cluster**: local development using [Kind](https://kind.sigs.k8s.io/) is recommended.
- **Container Runtime**: Podman or Docker.
- **Tools**: `kubectl`, `rustc`, `cargo`, `clang`, `llvm`.

## Deployment

### 1. Build Entire Stack (Recommended)
The project includes a unified build script:
```bash
cd agent
./build.sh
```

### 2. Build Components Separately
If you prefer to build individual components, follow these steps:

#### Setup Builder Image
Ensure the shared builder image is available:
```bash
docker build -t pgdam-builder -f agent/Dockerfile.builder agent/
```

#### Build Agent
```bash
# Compile eBPF and Userspace binaries
docker run --rm -v "$(pwd):/src" pgdam-builder bash -c " \
  cargo +nightly build -Z build-std=core --manifest-path agent/pgdam-ebpf/Cargo.toml --release --target bpfel-unknown-none && \
  cargo build --manifest-path agent/pgdam-agent/Cargo.toml --release"

# Build Docker image
docker build -t pgdam-agent:latest -f agent/Dockerfile.agent agent/
```

#### Build Processor
```bash
# Compile Processor binary
docker run --rm -v "$(pwd):/src" pgdam-builder \
  cargo build --manifest-path processor/Cargo.toml --release

# Build Docker image
docker build -t pgdam-processor:latest -f processor/Dockerfile.processor processor/
```

## Testing the Solution
Apply the OPA Rego policies via a ConfigMap.

```bash
kubectl apply -f deploy/configs.yaml
```

### 3. Deploy the DAM Stack
Deploy the DaemonSet which orchestrates the monitoring sidecars.

```bash
kubectl apply -f deploy/daemonset.yaml
```

## Testing the Solution

Once the `pgdam-agent` pods are running in the `pgdam` namespace, you can verify the end-to-end flow.

### 1. Execute a Query with PII
Connect to your PostgreSQL instance and run a query containing sensitive data (e.g., a credit card number).

```bash
kubectl exec -it <postgres-pod-name> -- psql -U postgres -c "SELECT '4111222233334444' as card_number;"
```

### 2. Verify Masking in Logs
Check the logs of the `processor` container within the `pgdam-agent` DaemonSet.

```bash
kubectl logs daemonset/pgdam-agent -n pgdam -c processor --tail=10
```

You should see an entry similar to:
```json
{
  "pid": 1234,
  "raw_sql": "SELECT '4111222233334444' as card_number;",
  "normalized_sql": "SELECT $1 as card_number;",
  "masked_sql": "SELECT <REDACTED> as card_number;"
}
```

## Repository Structure

/
├── .github/workflows      # CI/CD pipelines
├── /agent                 # [Rust Agent] eBPF logic & Uprobes
├── /processor             # [Processing Engine] AST Parsing & Normalization
├── /deploy                # [Deployment Agent Workspace]
│   ├── /configs.yaml      # OPA Policies
│   └── /daemonset.yaml    # K8s Deployment manifests
├── /contracts             # Protobuf/JSON schemas
└── AGENTS.md              # Global "Rules of Engagement"
