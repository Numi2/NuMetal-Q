# NuVault

Encrypted persistence, envelope construction, attestation boundaries, and sync transport.

## Responsibilities

- at-rest encryption for fold states
- proof-envelope serialization and signing payloads
- attestation context modeling
- device-to-device sync transport

## Main Types

- `FoldVault`
- `ProofEnvelope`
- `ResumeArtifact`
- `SyncChannel`
- `NuPolicy`

## Test Coverage

- vault behavior in `ApplePQIntegrationTests`
- envelope boundary checks in `EnvelopeSecurityTests`
- sync transport and replay checks in `SyncProtocolTests`

## Current Gaps

- strict attestation semantics remain easiest to validate in focused tests, not yet in full end-to-end flows
