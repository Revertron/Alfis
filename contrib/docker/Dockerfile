# syntax=docker/dockerfile:1

# Multi-arch, build-from-source image for Alfis (server / no-GUI, DoH enabled).
#
# linux/amd64 and linux/arm64 are cross-compiled with cargo-zigbuild, so both
# are built natively on the (amd64) runner with no QEMU emulation. The runtime
# is Google's distroless "cc" image (glibc, no shell or package manager).

########################################################################
# 1. Cross-compile stage
########################################################################
# Pinned to the build platform so the compiler always runs natively; only the
# *target* triple changes per requested platform.
FROM --platform=$BUILDPLATFORM rust:1-trixie AS builder

# Zig is the cross C toolchain that cargo-zigbuild drives. It is needed because
# the `sqlite` crate compiles a bundled SQLite C amalgamation for the target.
ARG ZIG_VERSION=0.13.0
RUN curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz" \
      | tar -xJ -C /opt \
 && ln -s "/opt/zig-linux-x86_64-${ZIG_VERSION}/zig" /usr/local/bin/zig

RUN cargo install cargo-zigbuild --locked \
 && rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu

# Cargo features to build with. Default: DoH on, GUI off (a server image).
# Set FEATURES="" for a plain-DNS build with no bundled TLS stack.
ARG FEATURES=doh

# Target glibc, pinned at/below the distroless runtime's glibc (2.36) so the
# binary stays forward-compatible.
ARG GLIBC=2.31

WORKDIR /src
COPY . .

# Docker sets TARGETARCH (amd64 / arm64) for the platform being built.
ARG TARGETARCH
RUN --mount=type=cache,target=/root/.cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    set -eux; \
    case "$TARGETARCH" in \
      amd64) RUST_TARGET=x86_64-unknown-linux-gnu ;; \
      arm64) RUST_TARGET=aarch64-unknown-linux-gnu ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    cargo zigbuild --release --locked \
      --no-default-features --features "${FEATURES}" \
      --target "${RUST_TARGET}.${GLIBC}"; \
    # cargo-zigbuild writes artifacts under the plain triple dir; copy the
    # binary out of the cache-mounted target dir so it survives the layer.
    cp "target/${RUST_TARGET}/release/alfis" /alfis

########################################################################
# 2. Runtime stage
########################################################################
# distroless "cc" (glibc + libgcc), runs as root so binding DNS port 53 works.
FROM gcr.io/distroless/cc-debian13 AS runtime

LABEL org.opencontainers.image.title="Alfis"
LABEL org.opencontainers.image.description="Alfis - peer-to-peer blockchain DNS (server, no-GUI)"
LABEL org.opencontainers.image.source="https://github.com/Revertron/Alfis"
LABEL org.opencontainers.image.url="https://alfis.name"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"

COPY --from=builder /alfis /usr/bin/alfis
# Container defaults (resolver node, DNS on 0.0.0.0:53). Override by mounting
# your own config over /etc/alfis.conf.
COPY contrib/docker/alfis.toml /etc/alfis.conf

# P2P (4244) and DNS (53 tcp + udp).
EXPOSE 4244
EXPOSE 53/tcp
EXPOSE 53/udp

# Blockchain DB and any key files live here; mount a volume to persist them.
VOLUME /var/lib/alfis
WORKDIR /var/lib/alfis

ENTRYPOINT ["/usr/bin/alfis"]
CMD ["-n", "-c", "/etc/alfis.conf"]
