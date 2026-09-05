# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.97.1
ARG NODE_VERSION=20.19.2
ARG MP_SPDZ_COMMIT=9d809599ea6ce627216a389ca7d984fbb75d0cb9
ARG QOMM_COMMIT=27299a1b49818d8c33ecfe9f4eeafab664f6ca64
ARG DEFMI_COMMIT=4b07c2b7ec218b5b09ab20b6c4342710dfc23a83
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
RUN --mount=type=cache,id=oclob-npm,target=/root/.npm \
    --mount=type=cache,id=oclob-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=oclob-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=oclob-cargo-target,target=/var/cache/oclob/target \
    cd /workspace/oclob_demo/react-flow \
    && npm ci --no-audit --no-fund \
    && npm run build \
    && cd /workspace \
    && cargo build --release --workspace --bins \
    && /var/cache/oclob/target/release/oclob-compile-program \
       --root /opt/MP-SPDZ --program oclob_match_v1 \
    && install -d -m 0755 /opt/oclob-bin \
    && install -m 0755 \
       /var/cache/oclob/target/release/oclob-server \
       /var/cache/oclob/target/release/oclob-avalanche-acceptance \
       /var/cache/oclob/target/release/oclob-node \
       /var/cache/oclob/target/release/oclob-lab-provision \
       /var/cache/oclob/target/release/oclob-edge-submit \
       /var/cache/oclob/target/release/oclob-cluster-e2e \
       /var/cache/oclob/target/release/oclob-native-bootstrap \
       /var/cache/oclob/target/release/oclob-native-e2e \
       /opt/oclob-bin/

FROM rust:${RUST_VERSION}-bookworm AS defmi-vm-builder
ARG DEFMI_COMMIT
RUN apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=5 update \
    && apt-get install -y --no-install-recommends \
       ca-certificates git build-essential clang cmake pkg-config protobuf-compiler libssl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/shukob/defmi.git /source/defmi \
    && git -C /source/defmi checkout --detach "${DEFMI_COMMIT}" \
    && test "$(git -C /source/defmi rev-parse HEAD)" = "${DEFMI_COMMIT}"
WORKDIR /source/defmi/rust
RUN --mount=type=cache,id=defmi-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=defmi-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=defmi-vm-target,target=/source/defmi/rust/target \
    env -u MP_SPDZ_ROOT cargo build --locked --release \
      -p qomm-avalanche-vm --bin qomm-avalanche-vm \
    && install -d /out \
    && install -m 0755 target/release/qomm-avalanche-vm /out/qomm-avalanche-vm

FROM debian:bookworm-slim AS avalanche-download
ARG TARGETARCH
ARG AVALANCHEGO_VERSION=1.14.2
ARG ANR_VERSION=1.8.3
RUN apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=5 update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) \
        avalanche_sha=daf7f2739f0790c033ad728af6ee29bcd2660baf5265844079eb60f22d101e46; \
        anr_sha=0944cc0d8dd9b893d0f150cbca41a270563ba2ac137403d4cd1658c4e6a00368 ;; \
      arm64) \
        avalanche_sha=0c4563c55659fd9923bd1ea9d3dbcd0a85668325091ffc4a259d0a137033ad0b; \
        anr_sha=60a6306a246c7a89092788fd254c9b574287bb0a83de7b01e196ea5883a4dcfb ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 2 ;; \
    esac; \
    mkdir -p /download/avalanchego /download/anr; \
    curl --location --fail --silent --show-error \
      "https://github.com/ava-labs/avalanchego/releases/download/v${AVALANCHEGO_VERSION}/avalanchego-linux-${TARGETARCH}-v${AVALANCHEGO_VERSION}.tar.gz" \
      -o /tmp/avalanchego.tar.gz; \
    echo "${avalanche_sha}  /tmp/avalanchego.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/avalanchego.tar.gz -C /download/avalanchego --strip-components=1; \
    curl --location --fail --silent --show-error \
      "https://github.com/ava-labs/avalanche-network-runner/releases/download/v${ANR_VERSION}/avalanche-network-runner_${ANR_VERSION}_linux_${TARGETARCH}.tar.gz" \
      -o /tmp/anr.tar.gz; \
    echo "${anr_sha}  /tmp/anr.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/anr.tar.gz -C /download/anr; \
    test -x /download/avalanchego/avalanchego; \
    test -x /download/anr/avalanche-network-runner

# The distributed acceptance image does not need the browser bundle or the
# monolithic demo server. Keeping this builder separate avoids relinking those
# binaries whenever only MPC-node code or deployment policy changes.
FROM oclob-test AS oclob-cluster-builder
COPY . /workspace
RUN --mount=type=cache,id=oclob-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=oclob-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=oclob-cargo-target,target=/var/cache/oclob/target \
    cargo build --release -p oclob-node -p oclob-mpc --bins \
    && /var/cache/oclob/target/release/oclob-compile-program \
       --root /opt/MP-SPDZ --program oclob_match_v1 \
    && install -d -m 0755 /opt/oclob-bin \
    && install -m 0755 \
       /var/cache/oclob/target/release/oclob-node \
       /var/cache/oclob/target/release/oclob-lab-provision \
       /var/cache/oclob/target/release/oclob-edge-submit \
       /var/cache/oclob/target/release/oclob-cluster-e2e \
       /var/cache/oclob/target/release/oclob-native-bootstrap \
       /var/cache/oclob/target/release/oclob-native-e2e \
       /opt/oclob-bin/

FROM debian:bookworm-slim AS oclob-server
RUN apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=5 update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl python3 libssl3 libgmp10 libgmpxx4ldbl libsodium23 libboost-thread1.74.0 \
       libboost-filesystem1.74.0 libboost-iostreams1.74.0 libntl44 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system oclob \
    && useradd --system --gid oclob --home-dir /var/lib/oclob --create-home oclob
COPY --from=oclob-builder --chown=oclob:oclob /opt/MP-SPDZ /opt/MP-SPDZ
COPY --from=oclob-builder --chown=oclob:oclob /opt/oclob-bin/oclob-server /usr/local/bin/oclob-server
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

FROM debian:bookworm-slim AS oclob-cluster
RUN apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=5 update \
    && apt-get install -y --no-install-recommends \
       ca-certificates libssl3 libgmp10 libgmpxx4ldbl libsodium23 libboost-thread1.74.0 \
       libboost-filesystem1.74.0 libboost-iostreams1.74.0 libntl44 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 oclob \
    && useradd --system --uid 10001 --gid 10001 --home-dir /var/lib/oclob --create-home oclob
COPY --from=oclob-cluster-builder --chown=oclob:oclob /opt/MP-SPDZ /opt/MP-SPDZ
COPY --from=oclob-cluster-builder /opt/oclob-bin/oclob-node /usr/local/bin/oclob-node
COPY --from=oclob-cluster-builder /opt/oclob-bin/oclob-lab-provision /usr/local/bin/oclob-lab-provision
COPY --from=oclob-cluster-builder /opt/oclob-bin/oclob-edge-submit /usr/local/bin/oclob-edge-submit
COPY --from=oclob-cluster-builder /opt/oclob-bin/oclob-cluster-e2e /usr/local/bin/oclob-cluster-e2e
COPY --from=oclob-cluster-builder /opt/oclob-bin/oclob-native-bootstrap /usr/local/bin/oclob-native-bootstrap
COPY --from=oclob-cluster-builder /opt/oclob-bin/oclob-native-e2e /usr/local/bin/oclob-native-e2e
RUN ! ldd /opt/MP-SPDZ/malicious-shamir-party.x | grep -F 'not found' \
    && ! ldd /opt/MP-SPDZ/libSPDZ.so | grep -F 'not found' \
    && ! ldd /usr/local/bin/oclob-node | grep -F 'not found'
ENV LD_LIBRARY_PATH=/opt/MP-SPDZ
USER oclob
WORKDIR /var/lib/oclob
CMD ["oclob-node", "--config", "/node/config.json"]

FROM debian:bookworm-slim AS oclob-avalanche-acceptance
RUN apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=5 update \
    && apt-get install -y --no-install-recommends \
       bash ca-certificates coreutils curl python3 sed \
       libssl3 libsqlite3-0 libgmp10 libgmpxx4ldbl libsodium23 libboost-thread1.74.0 \
       libboost-filesystem1.74.0 libboost-iostreams1.74.0 libntl44 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 oclob \
    && useradd --system --uid 10001 --gid 10001 --home-dir /var/lib/oclob --create-home oclob \
    && install -d -o oclob -g oclob -m 0700 /var/lib/oclob \
    && install -d -o oclob -g oclob -m 0700 /out
COPY --from=oclob-builder --chown=oclob:oclob /opt/MP-SPDZ /opt/MP-SPDZ
COPY --from=oclob-builder /opt/oclob-bin/oclob-avalanche-acceptance /usr/local/bin/oclob-avalanche-acceptance
COPY --from=defmi-vm-builder /out/qomm-avalanche-vm /usr/local/bin/qomm-avalanche-vm
COPY --from=defmi-vm-builder /source/defmi/avalanche/defmivm /opt/defmi/avalanche/defmivm
COPY --from=avalanche-download /download/avalanchego/avalanchego /usr/local/bin/avalanchego
COPY --from=avalanche-download /download/anr/avalanche-network-runner /usr/local/bin/avalanche-network-runner
RUN ! ldd /opt/MP-SPDZ/malicious-shamir-party.x | grep -F 'not found' \
    && ! ldd /opt/MP-SPDZ/libSPDZ.so | grep -F 'not found' \
    && ! ldd /usr/local/bin/oclob-avalanche-acceptance | grep -F 'not found' \
    && ! ldd /usr/local/bin/qomm-avalanche-vm | grep -F 'not found'
ENV AVALANCHEGO_PATH=/usr/local/bin/avalanchego
ENV AVALANCHE_NETWORK_RUNNER=/usr/local/bin/avalanche-network-runner
ENV QOMM_AVALANCHE_ACCEPTANCE_BIN=/usr/local/bin/oclob-avalanche-acceptance
ENV QOMM_AVALANCHE_VM_BIN=/usr/local/bin/qomm-avalanche-vm
ENV QOMM_AVALANCHE_ARTIFACT=/out/oclob_avalanche_acceptance.json
ENV MP_SPDZ_ROOT=/opt/MP-SPDZ
ENV LD_LIBRARY_PATH=/opt/MP-SPDZ
ENV PYTHONDONTWRITEBYTECODE=1
USER oclob
WORKDIR /var/lib/oclob
ENTRYPOINT ["/opt/defmi/avalanche/defmivm/scripts/run-local-l1.sh"]
