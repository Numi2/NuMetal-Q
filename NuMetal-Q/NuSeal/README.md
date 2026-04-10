# NuSeal

Terminal decider, Hachi opening backend, proof artifacts, and proof-codec logic.

## Responsibilities

- build and verify the Hachi terminal proof
- manage the direct-packed relation-opening path and the general authenticated repetition-oracle path
- encode and decode public seal proofs and resume payloads
- expose public seal artifacts to the SDK layer

## Main Types

- `HachiSealEngine`
- `HachiPCSBackend`
- `SealProofCodec`
- `PublicSealProof`
- `SealProof`

## Test Coverage

- codec guardrails in `EnvelopeSecurityTests`
- parity and tamper checks in `CryptoHardeningTests`
- cluster seal packet checks in `ClusterWorkPacketTests`

## Current Gaps

- this folder still carries the densest concentration of large files
- API documentation is thinner here than in the rest of the package
