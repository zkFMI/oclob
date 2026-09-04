# Security policy

OCLOB is research software. Do not use it with production funds, securities, credentials, signing keys, or personally identifiable information.

## Reporting a vulnerability

Do not open a public issue when a report could reveal:

- a way to recover a pending order's side, limit, quantity, participant, nonce, or salt;
- an ordering-equivocation, replay, reservation-bypass, or double-settlement path;
- a flaw in DeKYX credential verification, zkPI verification, or DeFMI atomicity;
- a secret key, credential opening, queue key, account opening, or private test fixture.

Use GitHub's private security-advisory flow for the repository. Include the affected commit, the smallest reproducible input, the violated invariant, and whether the problem is observable before or after settlement. Remove real credentials and secrets from every attachment.

## Supported state

Only the current `main` branch is maintained. A commit is a research candidate only after its pinned dependency revisions, remote release gate, and rough end-to-end receipt are published together. That still does not make it production-ready.

## Security boundary of the current MVP

The current implementation verifies the protocol path on one Linux host. Seven MP-SPDZ processes do not constitute seven independent operators. The demo coordinator receives a `SecretOrder` before producing Shamir shares with operating-system randomness; because that coordinator still sees both the clear order and every outgoing share, this is not client-edge distributed input sharing. The DeFMI state machine is canonical within the process, but is not a live Avalanche validator network. These are known P0 boundaries, not undisclosed vulnerabilities.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [docs/STATUS.md](docs/STATUS.md) before evaluating a report.
