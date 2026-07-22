# 仅固定 Docker Official Image 的多架构 index digest；更新流程见 docs/OPERATIONS.md。
FROM rust:1.88.0-bookworm@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 AS builder

WORKDIR /workspace
COPY . .
ARG CARGO_BUILD_JOBS=1
RUN CARGO_INCREMENTAL=0 cargo build --locked --release \
        -p mindone-coordinator -j "$CARGO_BUILD_JOBS" \
    && install -D -m 0755 /workspace/target/release/mindone-coordinator /out/mindone-coordinator \
    && rm -rf /workspace/target

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 mindone \
    && useradd --system --uid 10001 --gid mindone --home-dir /nonexistent --shell /usr/sbin/nologin mindone

COPY --from=builder /out/mindone-coordinator /usr/local/bin/mindone-coordinator

USER 10001:10001
EXPOSE 8787
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
    CMD curl --fail --silent --show-error http://127.0.0.1:8787/ready >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/mindone-coordinator"]
