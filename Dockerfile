# mcp-server-rs image.
#
# Base image: public debian:12-slim. There is no glibc Rust image on Docker Hub's official
# set (rust is 1-alpine only), so the builder is debian with a pinned toolchain installed by
# rustup; builder and runtime share one glibc.
# RUST_TOOLCHAIN must equal rust-toolchain.toml and the toolchain in .github/workflows/ci-public.yml.
ARG RUST_TOOLCHAIN=1.99.0

FROM debian:12-slim AS build
ARG RUST_TOOLCHAIN
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
# cmake/perl: aws-lc-sys (rustls' default crypto provider, via sqlx tls-rustls).
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential ca-certificates cmake curl perl pkg-config \
    && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path --profile minimal --default-toolchain "${RUST_TOOLCHAIN}" \
    && rustc --version

WORKDIR /src
COPY . .
# sqlx::migrate! embeds migrations/ into the binary, so the runtime image needs no SQL files.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
    && install -D -m 0755 target/release/mcp-server-rs /out/service \
    && install -D -m 0755 target/release/mcp-worker /out/worker

FROM debian:12-slim AS runtime
# ca-certificates: outbound https (rustls-native-certs). curl: the HEALTHCHECK.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 65532 app \
    && useradd --system --uid 65532 --gid 65532 --home-dir /var/lib/app --create-home app
COPY --from=build /out/service /usr/local/bin/mcp-server-rs
# The executor binary. The deployment selects it by overriding the entrypoint; the service
# binary remains the image's default command.
COPY --from=build /out/worker /usr/local/bin/mcp-worker
# No port is baked in: BIND_ADDR (host:port) and DATABASE_URL are required at runtime and are
# supplied by the deployment (which also maps the Service port).
ENV RUST_LOG=info
WORKDIR /var/lib/app
USER 65532:65532
# Liveness of the HTTP server on whatever port BIND_ADDR names.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["sh", "-c", "curl -fsS -o /dev/null \"http://127.0.0.1:${BIND_ADDR##*:}/health\""]
ENTRYPOINT ["/usr/local/bin/mcp-server-rs"]
