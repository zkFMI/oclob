# Third-party components and provenance

OCLOB source is MIT-licensed. It also builds on independently versioned components whose licenses and notices remain authoritative in their own distributions.

## Pinned protocol dependencies

| Component | Source | Pin | Purpose |
|---|---|---|---|
| DeKYX | `https://github.com/shukob/dekyx.git` | workspace `Cargo.toml` | Anonymous organizational eligibility |
| QOMM / zkPI / DeFMI SDK | `https://github.com/shukob/qomm.git` | workspace `Cargo.toml` | MPC compiler adapter, proofs, settlement instruction, canonical ledger |
| MP-SPDZ | `https://github.com/data61/MP-SPDZ.git` | `docker/Dockerfile` | Official MPC compiler and malicious-Shamir runtime |

The exact commit strings are kept in source-controlled manifests rather than duplicated here. Review `Cargo.toml`, `Cargo.lock`, and `docker/Dockerfile` together.

MP-SPDZ includes its official `compile.py`. OCLOB does not copy or modify that compiler as project-owned Python. Rust calls the pinned upstream compiler through `qomm_mpc::compiler::OfficialCompiler`; the Docker build applies the pinned QOMM embedding patch after `git apply --check` succeeds.

## Rust and frontend packages

The complete resolved Rust dependency graph is recorded in `Cargo.lock`. The complete React demo graph is recorded in `oclob_demo/react-flow/package-lock.json`. Preserve both lockfiles in releases and use the license texts supplied by each package.

Do not replace pinned cryptographic components, update a Git revision, or regenerate either lockfile as a cosmetic maintenance change. Dependency updates require protocol compatibility tests, a fresh rough end-to-end receipt, and review of upstream security and license changes.
