# Getting Started

## Package-First Workflow

NuMetal-Q is authored and validated as a Swift package.

```bash
swift build
swift test --filter TranscriptVectorTests
swift run NuMetalQAcceptanceDemo --help
swift run NuMetalQBenchmarks --list-workloads
```

## Environment Expectations

- Apple-silicon hardware is required for full proving and Metal-assisted validation.
- CPU-safe checks are documented in `docs/testing.md`.
- `Scripts/check_repo_metadata.sh` verifies status-note drift before changes land.

## Where To Go Next

- Use ``NuMeQ`` for the top-level engine.
- Use ``ProofContext`` for shape-scoped proof lifecycles.
- Use ``CompiledShape`` and `numeqc` for signed shape-pack generation.
