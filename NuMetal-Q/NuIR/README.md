# NuIR

Constraint-system and compiled-shape metadata used by both proving and sealing.

## Responsibilities

- CCS relation and sparse-matrix representation
- witness lane descriptors and packing metadata
- shape digests, signed packs, and kernel configuration metadata
- DAG/header abstractions for typed proof flows

## Main Types

- `CCSRelation`
- `Shape`
- `ShapePack`
- `CompiledShape`
- `WitnessLane`
- `Witness`

## Test Coverage

- shape/ABI assertions in `CryptoHardeningTests`
- compiled-shape helpers in `AcceptanceSupport`

## Current Gaps

- `Shape.swift` still carries a large amount of signing and serialization logic
