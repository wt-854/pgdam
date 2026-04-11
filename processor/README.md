# pgDAM Processor

The processing engine responsible for SQL normalization and PII masking.

## Features
- **SQL Normalization**: Uses `pg_query` to parameterize SQL queries.
- **PII Masking**: Integrates with Open Policy Agent (OPA) to redact sensitive data based on configurable Rego policies.
- **Concurrent Processing**: Built on Tokio for high-throughput event handling.

## Building Separately

Assuming you are in the root directory:

```bash
# Build binary
docker run --rm -v "$(pwd):/src" pgdam-builder \
  cargo build --manifest-path processor/Cargo.toml --release

# Build Image
docker build -t pgdam-processor:latest -f processor/Dockerfile.processor processor/
```
