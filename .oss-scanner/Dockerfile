FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive
# capnproto: sq's keystore compiles a Cap'n Proto schema. libclang-dev: the ossl test dependency runs bindgen.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git build-essential clang libclang-dev pkg-config perl \
      gnupg capnproto libssl-dev libsqlite3-dev libbz2-dev \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable --no-modify-path \
    && rustc --version && cargo --version

# Debian's sq 1.3.1 cannot read the engine's RFC 9980 artifacts; the post-quantum interop tests would skip.
RUN cargo install --locked sequoia-sq --version 1.5.0 --no-default-features --features crypto-openssl

COPY . /src
WORKDIR /src/pgp-mobile
RUN bash /src/scripts/assert_min_gpg_version.sh 2.4.0 && bash /src/scripts/assert_min_sq_version.sh 1.3.0

ENV RUSTFLAGS="-Cforce-frame-pointers=yes" \
    CFLAGS="-g -fno-omit-frame-pointer"
RUN cargo fetch --locked
RUN cargo test --locked --no-run

ENV CARGO_NET_OFFLINE=true
WORKDIR /src
