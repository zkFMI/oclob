# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.97.1
ARG NODE_VERSION=20.19.2
ARG MP_SPDZ_COMMIT=9d809599ea6ce627216a389ca7d984fbb75d0cb9
ARG QOMM_COMMIT=27299a1b49818d8c33ecfe9f4eeafab664f6ca64
ARG BUILD_JOBS=16

FROM debian:bookworm-slim AS mp-spdz-builder
ARG MP_SPDZ_COMMIT
ARG QOMM_COMMIT
ARG BUILD_JOBS
RUN apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=5 update \
    && apt-get install -y --no-install-recommends \
       ca-certificates git build-essential clang cmake yasm python3 \
       libssl-dev libgmp-dev libsodium-dev libboost-dev libboost-thread-dev \
       libboost-filesystem-dev libboost-iostreams-dev libntl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/shukob/qomm.git /tmp/qomm \
    && git -C /tmp/qomm checkout --detach "${QOMM_COMMIT}" \
    && test "$(git -C /tmp/qomm rev-parse HEAD)" = "${QOMM_COMMIT}" \
    && git clone https://github.com/data61/MP-SPDZ.git /opt/MP-SPDZ \
    && git -C /opt/MP-SPDZ checkout --detach "${MP_SPDZ_COMMIT}" \
    && test "$(git -C /opt/MP-SPDZ rev-parse HEAD)" = "${MP_SPDZ_COMMIT}" \
    && git -C /opt/MP-SPDZ apply --check /tmp/qomm/rust/qomm-mpc/patches/expose-machine-to-embedder.patch \
    && git -C /opt/MP-SPDZ apply /tmp/qomm/rust/qomm-mpc/patches/expose-machine-to-embedder.patch \
    && make -C /opt/MP-SPDZ -j"${BUILD_JOBS}" libSPDZ.so malicious-shamir-party.x \
    && cd /opt/MP-SPDZ \
    && Scripts/setup-ssl.sh 7

FROM node:${NODE_VERSION}-bookworm-slim AS node-runtime

FROM rust:${RUST_VERSION}-bookworm AS oclob-test
RUN apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=5 update \
    && apt-get install -y --no-install-recommends \
       ca-certificates git build-essential clang cmake pkg-config yasm python3 \
       libssl-dev libgmp-dev libsodium-dev libboost-dev libboost-thread-dev \
       libboost-filesystem-dev libboost-iostreams-dev libntl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && rustup component add rustfmt clippy
COPY --from=mp-spdz-builder /opt/MP-SPDZ /opt/MP-SPDZ
COPY --from=node-runtime /usr/local/ /usr/local/
ENV MP_SPDZ_ROOT=/opt/MP-SPDZ
ENV LD_LIBRARY_PATH=/opt/MP-SPDZ
ENV CARGO_TARGET_DIR=/var/cache/oclob/target
ENV NPM_CONFIG_UPDATE_NOTIFIER=false
WORKDIR /workspace
CMD ["cargo", "test", "--workspace", "--release"]

FROM oclob-test AS oclob-builder
COPY . /workspace
RUN cd /workspace/oclob_demo/react-flow \
    && npm ci --no-audit --no-fund \
    && npm run build \
    && cd /workspace \
    && cargo build --release -p oclob-demo --bin oclob-server

FROM debian:bookworm-slim AS oclob-server
RUN apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=5 update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl python3 libssl3 libgmp10 libgmpxx4ldbl libsodium23 libboost-thread1.74.0 \
       libboost-filesystem1.74.0 libboost-iostreams1.74.0 libntl44 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system oclob \
    && useradd --system --gid oclob --home-dir /var/lib/oclob --create-home oclob
COPY --from=mp-spdz-builder --chown=oclob:oclob /opt/MP-SPDZ /opt/MP-SPDZ
COPY --from=oclob-builder --chown=oclob:oclob /var/cache/oclob/target/release/oclob-server /usr/local/bin/oclob-server
RUN ! ldd /opt/MP-SPDZ/malicious-shamir-party.x | grep -F 'not found' \
    && ! ldd /opt/MP-SPDZ/libSPDZ.so | grep -F 'not found'
ENV MP_SPDZ_ROOT=/opt/MP-SPDZ
ENV LD_LIBRARY_PATH=/opt/MP-SPDZ
ENV PYTHONDONTWRITEBYTECODE=1
EXPOSE 18800
VOLUME ["/var/lib/oclob"]
USER oclob
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=6 \
    CMD curl --fail --silent http://127.0.0.1:18800/health >/dev/null || exit 1
ENTRYPOINT ["oclob-server", "--host", "0.0.0.0", "--port", "18800", "--state-dir", "/var/lib/oclob"]
