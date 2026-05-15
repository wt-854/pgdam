# FROM rust:1.85-slim-bookworm
FROM rust:latest

RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    libssl-dev \
    pkg-config \
    clang \
    libclang-dev \
    libsasl2-dev \
    librdkafka-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly && \
    rustup component add rust-src --toolchain nightly && \
    rustup component add llvm-tools-preview --toolchain nightly

# RUN cargo +nightly install bpf-linker
RUN cargo install bpf-linker

WORKDIR /src