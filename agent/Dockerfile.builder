FROM rust:latest

RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    libssl-dev \
    pkg-config \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly && \
    rustup component add rust-src --toolchain nightly && \
    rustup component add llvm-tools-preview --toolchain nightly

RUN cargo install bpf-linker

WORKDIR /src
