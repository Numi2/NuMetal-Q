# NuSDK

Public API surface for creating, combining, sealing, resuming, and verifying proofs.

## Responsibilities

- construct `NuMeQ` engine instances
- manage per-shape `ProofContext` lifecycles
- bind public verification to compiled shapes and namespace checks
- bridge cluster and vault flows into the main API

## Main Types

- `NuMeQ`
- `ProofContext`
- `ProofHandle`
- `MetalFoldProver`

## Test Coverage

- envelope validation in `EnvelopeSecurityTests`
- typed prover persistence in `MetalFoldProverTests`
- proof-context edge cases in `ProofContextValidationTests`

## Current Gaps

- `ProofContext.swift` is the main control-plane hotspot and still needs a structural split
