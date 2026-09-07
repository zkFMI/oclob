# OCLOB hybrid application authentication

All newly accepted OCLOB application authorizations require both Ed25519 and
ML-DSA-65 through `zkfmi-crypto`'s RustCrypto-backed `HybridSigner` and
`HybridVerifier`. This includes order authority, edge manifests and shares,
threshold capability shares, cancellation, market ingress, public depth,
node admission/release/private-state/execution receipts, ordering votes and
transition committee attestations. Unsigned expiry remains an explicit rule
checked against the admitted order deadline; it does not become a signature.

A 32-byte OCLOB verification identity is now SHA-256 of
`OCLOB:APPLICATION-KEY-FINGERPRINT:v2`, the common suite encoding, the
Attestation purpose code and the complete 1,984-byte hybrid public key. It is
never interpreted as an Ed25519 public key. The closed 5,371-byte signature
contains `OCLSIG02`, the four-byte Ed25519MlDsa65 suite/version, the two-byte
Attestation purpose, the complete public key and the 3,373-byte hybrid
signature. Verification checks every length, the fixed suite/version/purpose,
the enrolled fingerprint and both signatures. Per-operation versioned message
domains separate workflows using the same node key. Legacy raw Ed25519 keys,
unknown envelope versions and either missing component fail closed.

Application private custody consists of exactly 64 bytes: separately generated
32-byte Ed25519 and ML-DSA seeds. Provisioning draws both from the CSPRNG.
Startup restores owner-only, single-link regular files of exactly that size;
it never generates a replacement after a failed load. The corporate encrypted
outbox stores the same complete two-seed record and rejects the previous
32-byte record. The native reservation issuer additionally stores a separate
independently random 32-byte private admission-tag key, preserving the private
hold tag across restarts and reissuance.

DeFMI mandates and admission permits use the foundation's complete hybrid key
and raw signature with SettlementInstruction purpose. Facility receipts use
AuditCheckpoint. They do not use OCLOB fingerprint envelopes. These explicit
adapters keep foundation crates independent from OCLOB and prevent a signature
from one protocol being accepted by the other.

The node store is version 11. Earlier stores require explicit authenticated
migration; startup leaves their bytes intact and rejects them. New completed
execution receipts are cryptographically checked on persistence and restore;
RPC startup also binds them to the configured node signing identity. Client
configuration is version 2, cluster configuration version 5, node configuration
version 4, edge records version 7 and the node transport record version 4.
Fixed-size padded transport buffers were enlarged for full hybrid envelopes
and allocated on the heap. Existing TLS and hybrid KEM paths remain required.

This change does not claim that curve-based financial proofs or anonymous
credentials become post-quantum. Their proof systems are separate boundaries.

The node configuration keeps native permit/admission trust as the complete 1,984-byte hybrid public key. The separate optional `qomm_pretrade_ack_fingerprint` pins a QOMM application identity only when that typed ACK integration is enrolled. OCLOB native provisioning leaves it null because native settlement uses its own SDK permits and admission attestations; the unused QOMM ACK authorization remains disabled. A native receipt key is never truncated or silently reinterpreted as this fingerprint.

Node admission responses are persisted verbatim with their admitted record before returning them. Retries restore and verify this exact receipt against the configured signing identity, including after later store generations or restart. Receipt caches are excluded from the semantic state digest they attest to avoid self-reference; their complete signature and enrolled identity are checked before serving. Market intake uses a padded 1 MiB record for the fixed 64 KiB encrypted authority, seven hybrid node receipts, and signed manifest.
