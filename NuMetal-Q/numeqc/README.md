# numeqc

Build-time shape compiler for signed `ShapePack` artifacts.

## Responsibilities

- freeze CCS relations into signed shape assets
- emit lifted matrices, transcript constants, Ajtai parameters, and kernel configs
- bind the signed pack to the current Metal artifact digest and profile certificate

## Main Types

- `ShapeCompiler`
- `ShapeCompiler.Config`

## Test Coverage

- compiled-shape assertions in `CryptoHardeningTests`
- broad helper coverage in `AcceptanceSupport`

## Current Gaps

- kernel-config policy remains heuristic and lives in a single file
