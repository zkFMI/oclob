# Third-party components and provenance

OCLOB source is MIT-licensed. It also builds on independently versioned components whose licenses and notices remain authoritative in their own distributions.

## Pinned protocol dependencies

| Component | Source | Pin | Purpose |
|---|---|---|---|
| DeKYX | `https://github.com/shukob/dekyx.git` | workspace `Cargo.toml` | Anonymous organizational eligibility |
| QOMM | `https://github.com/shukob/qomm.git` | workspace `Cargo.toml` | Official MPC compiler adapter |
| zkPI / DeFMI SDK | `https://github.com/shukob/defmi.git` | workspace `Cargo.toml` | Proofs, settlement instruction, canonical ledger |
| Tari Triptych | `https://github.com/tari-project/triptych.git` | transitive DeFMI dependency in `Cargo.lock` | Parallel ownership/value membership for native notes |
| MP-SPDZ | `https://github.com/data61/MP-SPDZ.git` | `docker/Dockerfile` | Official MPC compiler and malicious-Shamir runtime |

The exact commit strings are kept in source-controlled manifests rather than duplicated here. Review `Cargo.toml`, `Cargo.lock`, and `docker/Dockerfile` together.

MP-SPDZ includes its official `compile.py`. OCLOB does not copy or modify that compiler as project-owned Python. Rust calls the pinned upstream compiler through `qomm_mpc::compiler::OfficialCompiler`; the Docker build applies the pinned QOMM embedding patch after `git apply --check` succeeds.

## Rust and frontend packages

The complete resolved Rust dependency graph is recorded in `Cargo.lock`. The complete React demo graph is recorded in `oclob_demo/react-flow/package-lock.json`. Preserve both lockfiles in releases and use the license texts supplied by each package.

Do not replace pinned cryptographic components, update a Git revision, or regenerate either lockfile as a cosmetic maintenance change. Dependency updates require protocol compatibility tests, a fresh rough end-to-end receipt, and review of upstream security and license changes.

## Tari Triptych notice

DeFMI's native-note adapter uses the unchanged upstream parallel RingCT API at
commit `bf0cb42fff55636a8bb037020411fb3a050af23f`. The algorithm is a pinned
dependency, not copied or modified in OCLOB. The upstream implementation is
experimental and explicitly not suitable for production. No upstream audit,
endorsement or production suitability is implied. Include this full notice
when distributing standalone binaries or images that contain the dependency.

BSD 3-Clause License

Copyright (c) 2024, The Tari Project
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
