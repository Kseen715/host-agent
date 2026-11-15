# host-agent alone, for a host whose agent runs in Docker. Built in the
# first stage, on the builder's own platform for any target's: Rust's
# linker links a static musl binary for either architecture, so the
# image holds nothing else and needs no emulation. Its configuration
# comes in HOST_AGENT_CONFIG; see README.md for the mounts it needs.
FROM --platform=$BUILDPLATFORM rust:1.100.0-alpine3.22 AS build
ARG TARGETARCH
# Cargo features, comma-separated: the parts this host needs.
ARG FEATURES=default
ENV RUSTFLAGS="-C linker=rust-lld"
WORKDIR /src
RUN case "$TARGETARCH" in \
      amd64) echo x86_64-unknown-linux-musl ;; \
      arm64) echo aarch64-unknown-linux-musl ;; \
      *) echo "unsupported: $TARGETARCH" >&2; exit 1 ;; \
    esac > /target && rustup target add "$(cat /target)"
# The crates first, in a layer of their own: a change to the sources
# does not fetch and build them again.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked --target "$(cat /target)" \
       --no-default-features --features "$FEATURES" && rm -r src
COPY src src
# Newer than the stub's build, whatever times the copy kept.
RUN touch src/main.rs \
    && cargo build --release --locked --target "$(cat /target)" \
       --no-default-features --features "$FEATURES" \
    && cp "target/$(cat /target)/release/host-agent" /host-agent

FROM scratch
COPY --from=build /host-agent /host-agent
ENTRYPOINT ["/host-agent"]
