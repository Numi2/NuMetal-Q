# NuFold

Recursive SuperNeo folding over the canonical AG64 profile.

## Responsibilities

- seed-state creation and recursive accumulation
- PiCCS, PiRLC, and PiDEC orchestration
- norm-budget tracking and decomposition scheduling
- accumulator serialization for resume/seal handoff

## Main Types

- `FoldEngine`
- `FoldConfig`
- `PiCCS`
- `PiRLC`
- `PiDEC`
- `NormBudget`

## Test Coverage

- direct protocol tests in `CryptoHardeningTests`
- witness packing validation in `WitnessPackingTests`
- proof-context edge cases in `ProofContextValidationTests`

## Current Gaps

- `FoldEngine.swift` remains the main orchestration hotspot and should be split further
