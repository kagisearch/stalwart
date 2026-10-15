# FORK CHANGES (this is the image Cloud Build deploys to dev and prod):
# - The cargo-chef base is pinned to Rust 1.96.0 instead of upstream's floating
#   `latest-rust-slim-trixie`. The sqlite feature pulls libsqlite3-sys 0.38.1,
#   whose build script uses the cfg_select! macro (stable as of Rust 1.95).
# - The amd64 RUSTFLAGS add `-C target-cpu=x86-64-v2`. Upstream sets this in
#   .cargo/config.toml, but the explicit RUSTFLAGS below replace config-file
#   rustflags entirely, so it has to be repeated here to match upstream's
#   release builds.
# - The feature set is trimmed from upstream's full CI set to the backends our
#   deployments use. Nothing we run needs sqlite, mysql, rocks, azure or
#   enterprise; the enterprise feature only compiles in license-gated code
#   plus the SCIM endpoint, which nothing provisions through.

# Stalwart Dockerfile
# Credits: https://github.com/33KK

FROM --platform=$BUILDPLATFORM docker.io/lukemathwalker/cargo-chef:latest-rust-1.96.0-slim-trixie AS chef
WORKDIR /build

FROM --platform=$BUILDPLATFORM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path /recipe.json

FROM --platform=$BUILDPLATFORM chef AS builder
ARG TARGETPLATFORM
RUN case "${TARGETPLATFORM}" in \
    "linux/arm64") echo "aarch64-unknown-linux-gnu" > /target.txt && echo "-C linker=aarch64-linux-gnu-gcc" > /flags.txt ;; \
    "linux/amd64") echo "x86_64-unknown-linux-gnu" > /target.txt && echo "-C linker=x86_64-linux-gnu-gcc -C target-cpu=x86-64-v2" > /flags.txt ;; \
    *) exit 1 ;; \
    esac
RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -yq --no-install-recommends build-essential libclang-19-dev \
    g++-aarch64-linux-gnu binutils-aarch64-linux-gnu \
    g++-x86-64-linux-gnu binutils-x86-64-linux-gnu
RUN rustup target add "$(cat /target.txt)"
COPY --from=planner /recipe.json /recipe.json
RUN RUSTFLAGS="$(cat /flags.txt)" cargo chef cook --target "$(cat /target.txt)" --release --no-default-features --features "postgres s3 redis nats" --recipe-path /recipe.json
COPY . .
RUN RUSTFLAGS="$(cat /flags.txt)" cargo build --target "$(cat /target.txt)" --release -p stalwart --no-default-features --features "postgres s3 redis nats"
RUN mv "/build/target/$(cat /target.txt)/release" "/output"

FROM docker.io/debian:trixie-slim
RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -yq --no-install-recommends ca-certificates curl libcap2-bin && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r -g 2000 stalwart && \
    useradd -r -u 2000 -g 2000 -s /usr/sbin/nologin -M stalwart && \
    mkdir -p /etc/stalwart /var/lib/stalwart && \
    chown stalwart:stalwart /etc/stalwart /var/lib/stalwart
COPY --from=builder --chmod=0755 /output/stalwart /usr/local/bin/stalwart
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/stalwart
USER stalwart
WORKDIR /var/lib/stalwart
VOLUME ["/etc/stalwart", "/var/lib/stalwart"]
EXPOSE	443 25 110 587 465 143 993 995 4190 8080
ENV STALWART_HEALTHCHECK_URL=https://127.0.0.1:443/healthz/live
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsSk -H "X-Forwarded-For: 127.0.0.1" "$STALWART_HEALTHCHECK_URL" || curl -fsS -H "X-Forwarded-For: 127.0.0.1" http://127.0.0.1:8080/healthz/live || exit 1
ENTRYPOINT ["/usr/local/bin/stalwart"]
CMD ["--config", "/etc/stalwart/config.json"]
