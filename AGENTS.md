# OCLOB repository instructions

- OCLOB-owned backend, protocol, experiment, and harness code is Rust. Do not add Python or Go. The official upstream MP-SPDZ `compile.py`, called through `qomm_mpc::compiler::OfficialCompiler`, is the only Python exception.
- DeKYX and zkPI/DeFMI are independent dependencies. Keep their Git revisions pinned in the workspace manifest and test protocol compatibility before updating either revision.
- Do not describe the single-host seven-process runner as a seven-operator deployment, and do not describe the in-process DeFMI state machine as a live Avalanche validator network.
- Never log or expose a private order's side, limit, quantity, participant handle, DeKYX nullifier, reservation opening, nonce, or salt before the allowed post-match disclosure.
- Run all builds, tests, benchmarks, Docker builds, and acceptance runs on `omenx_ubuntu_zerotier` or `softbank-l40s` through `make remote-test`. Do not compile or test on the developer laptop.
- UI completion requires remote typecheck/build/tests and real-browser inspection at desktop and narrow viewport sizes.
- Keep durable project facts and decisions in `.codex/project-memory/` using the schema established there.
