# Security Readiness Report

## Scope

This repository-local review covers the current Swift package state for proof transcripts, recursive folding, seal/envelope verification, attestation binding, sync and cluster transport, vault persistence, typed prover persistence, and the cSHAKE/XOF boundary.

This is not an external cryptanalysis report. The profile certificate remains explicit that the in-repo security estimator is informational and that production parameter claims require independent review.

## Current Readiness State

The default SwiftPM test target now includes the security and crypto-hardening suites that previously lived outside the normal `swift test` lane:

- envelope signature, namespace, attestation, and proof-format rejection tests
- transcript vector and challenge-domain tests
- PiCCS, PiRLC, PiDEC, and sum-check negative tests
- cSHAKE/XOF and binary codec tests
- sync encryption, strict attestation binding, and replay-defense tests
- cluster packet validation, delegation attestation, and replay-defense tests
- typed prover vault persistence, tamper, wrong-key, and forged-header tests

Metal-dependent tests skip on hosts without a supported Metal device. Apple post-quantum integration tests compile only when `NUMETALQ_ENABLE_APPLE_PQ=1` is set.

## Resolved Historical Findings

### PiRLC Scalar Challenge Entropy

`PiRLC` no longer folds field-valued claims with a 2-bit coefficient projection from the weak ring challenge set. The prover and verifier derive full-field Fiat-Shamir scalar challenges via `PiRLC.scalar_fold` for public inputs, CCS evaluations, and relaxation factors, while ring-valued witness, commitment, and error folding continue to use typed ring challenges from `C = {-1, 0, 1, 2}`.

Coverage: `CryptoHardeningTests` exercises direct and negative PiRLC verification, statement binding, and inherited error-term binding.

### Attestation Purpose And Device Binding

Sync attestation now uses stable author and target device identifiers on both send and receive paths. Cluster attestation validation likewise uses stable principal and co-prover identities for delegation validation. Envelope verification validates attestation under the public verification purpose.

Coverage: `SyncProtocolTests`, `EnvelopeSecurityTests`, and `ClusterWorkPacketTests` include strict attestation context tests and mismatch rejection.

### Public Seal Statement Semantics

`PublicSealStatement` no longer exposes accumulator metadata that standalone public verification cannot prove. Public verification binds the backend, transcript ID, shape digest, decider layout digest, seal parameter digest, public header, and public inputs.

Coverage: envelope/security tests reject invalid proof formats, namespace mismatches, public-header mismatches, and malformed seal proof encodings.

### Typed Prover Persistence Policy

`MetalFoldProver` now computes `maxWitnessClass` from policy-classified typed traces and rejects non-persistable lanes before vault storage rather than hardcoding `.public`.

Coverage: typed prover tests verify vault round trips, wrong-key rejection, tamper rejection, missing step registration rejection, forged header rejection, and forged child rejection.

### cSHAKE/XOF Failure Boundary

The C cSHAKE wrapper returns an explicit success code, and Swift callers fail closed if the XOF operation fails.

Coverage: support codec tests assert deterministic and domain-separated cSHAKE output.

## Additional Hardening Completed

Signed sync and cluster payload encoders now use the shared canonical binary writer for length-prefixed fields. This removes silent `UInt32(clamping:)` saturation from cryptographic signing and attestation-binding payloads; oversized values now fail closed instead of being encoded with saturated length metadata.

## Verification

The following checks pass in the current workspace:

```bash
Scripts/check_repo_metadata.sh
swift build
swift test
swift run NuMetalQAcceptanceDemo --help
swift run NuMetalQBenchmarks --help
swift run NuMetalQBenchmarks --list-workloads
NUMETALQ_ENABLE_APPLE_PQ=1 swift test --filter ApplePQIntegrationTests
```

The expanded `swift test` run executed 80 tests with 0 failures.
The optional Apple PQ integration run executed 12 tests with 0 failures on this host.

## Remaining Non-Goals

- Independent cryptanalysis of the AG64/SuperNeo/Hachi profile is still required before making production security claims.
- Full Apple PQ API tests require `NUMETALQ_ENABLE_APPLE_PQ=1` and a platform/SDK that exposes the relevant CryptoKit ML-KEM, X-Wing HPKE, and ML-DSA types.
- Benchmark-scale Metal parity and performance validation remains in the manual Apple-silicon validation lane.
