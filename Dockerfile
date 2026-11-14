# host-agent alone, for a host whose agent runs in Docker. Built in the
# first stage: Alpine's Rust targets musl, so the binary is static and
# the image holds nothing else. Its configuration comes in
# HOST_AGENT_CONFIG; see README.md for the mounts it needs.
FROM rust:1.100.0-alpine3.22 AS build
WORKDIR /src
# The crates first, in a layer of their own: a change to the sources
# does not fetch and build them again.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked && rm -r src
COPY src src
# Newer than the stub's build, whatever times the copy kept.
RUN touch src/main.rs && cargo build --release --locked

FROM scratch
COPY --from=build /src/target/release/host-agent /host-agent
ENTRYPOINT ["/host-agent"]
