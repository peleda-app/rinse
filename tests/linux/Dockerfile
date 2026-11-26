FROM rust:1.99.1-trixie
RUN apt-get update && apt-get install -y --no-install-recommends build-essential clang \
    && rm -rf /var/lib/apt/lists/*
RUN rustup component add rustfmt clippy && rustup target add wasm32-wasip2
WORKDIR /work/rinse
