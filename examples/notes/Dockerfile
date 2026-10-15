# syntax=docker/dockerfile:1
# tangra-notes (example go-tangra v4 module in Rust) - standalone image, in
# the shape of go-tangra-deployer's Dockerfile.
# Build context: the go-tangra-sdk-rust repository root (the example builds
# against the SDK in the same workspace). A module in its own repository uses
# its own root and drops the examples/notes/ prefixes.
#
#   docker buildx build -f examples/notes/Dockerfile --secret id=npm_token,env=NODE_AUTH_TOKEN \
#     --build-arg APP_VERSION=1.0.0 --build-arg VCS_REF=$(git rev-parse HEAD) -t tangra-notes:dev .
#
# npm_token is a GitHub token with read:packages for @go-tangra/ui on npm.pkg.github.com.
# It is mounted only for the npm ci step and written to a tmpfs, so it never lands in a layer.

FROM node:22-alpine AS ui
WORKDIR /src/ui
COPY examples/notes/ui/package.json examples/notes/ui/package-lock.json ./
RUN --mount=type=secret,id=npm_token,required=true \
    --mount=type=tmpfs,target=/run/npmrc \
    --mount=type=cache,target=/root/.npm \
    set -eu; \
    printf '@go-tangra:registry=https://npm.pkg.github.com\n//npm.pkg.github.com/:_authToken=%s\nignore-scripts=true\nfund=false\naudit=false\n' \
      "$(cat /run/secrets/npm_token)" > /run/npmrc/.npmrc; \
    NPM_CONFIG_USERCONFIG=/run/npmrc/.npmrc npm ci --no-audit --no-fund
COPY examples/notes/ui/ ./
RUN npm run build

# glibc build on Debian 12, run on Debian 12 slim (same glibc). protoc is
# vendored by the build (protoc-bin-vendored); ring needs only the C compiler
# the image has. rust-toolchain.toml selects the stable toolchain.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
COPY --from=ui /src/ui/dist ./examples/notes/ui/dist
ARG APP_VERSION=dev
# Stamped into the binary and reported to the gateway (Go: -ldflags -X main.version).
ENV NOTES_VERSION=${APP_VERSION}
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release -p tangra-notes --features ui --bin tangra-notes \
 && install -D -m 0755 target/release/tangra-notes /out/tangra-notes

FROM debian:bookworm-slim
ARG APP_VERSION=dev
ARG VCS_REF=unknown
LABEL org.opencontainers.image.source="https://github.com/go-tangra/go-tangra-sdk-rust" \
      org.opencontainers.image.title="tangra-notes" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"
# ca-certificates: public-roots TLS (first enrolment through the gateway edge,
# Valkey without ca_file). /state is owned by app so a named volume mounted
# there (join bundle) is writable. No wget/curl: the compose healthcheck runs
# `tangra-notes --healthcheck`.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin app \
 && install -d -o app -g app -m 0700 /state
COPY --from=build /out/tangra-notes /usr/local/bin/
WORKDIR /app
USER 10001:10001
ENTRYPOINT ["tangra-notes"]
CMD ["-config","/app/config.yaml"]
