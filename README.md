# NuMeQ

Post-quantum proof-carrying data engine for Apple platforms.

## Active Layout

This repository is a Swift package with one primary library target, two example executables, and a test suite:

- `NuMetal-Q/`: library sources grouped by subsystem (`NuField`, `NuFold`, `NuMetal`, `NuSDK`, `NuSeal`, `NuVault`, `NuCluster`)
- `Examples/`: acceptance demo and benchmark runners
- `docs/`: benchmark review references and lightweight package notes
- `Tests/`: package tests
- `Scripts/build_metal_artifacts.sh`: offline Metal artifact builder
- `Scripts/check_repo_metadata.sh`: docs/version drift checker used locally and in CI

Bundled Metal artifacts in `NuMetal-Q/NuMetal/Compiled/` are part of the package. They are source-controlled input to the runtime load path, unlike local build output under `.build/` or generated benchmark reports under `artifacts/benchmarks/`.

## Public Flow

The public API follows the current proving lifecycle:

1. `seed`: create a base proof from witness data and public inputs
2. `fuse`: combine proofs into a larger accumulator
3. `seal`: compile the terminal decider and export a signed `ProofEnvelope`
4. `resume`: verify an envelope and rebind it into a fresh recursive state
5. `verify`: validate a sealed envelope without prover state

## Build

```bash
Scripts/check_repo_metadata.sh
swift test
swift run NuMetalQAcceptanceDemo
swift run NuMetalQAcceptanceDemo --format json --output /tmp/numeq-acceptance.json
swift run NuMetalQBenchmarks
swift run NuMetalQBenchmarks --list-workloads
swift run NuMetalQBenchmarks --seal-workload auth-policy-sparse
```

## Subsystem Docs

- `NuMetal-Q/NuField/README.md`
- `NuMetal-Q/NuIR/README.md`
- `NuMetal-Q/NuFold/README.md`
- `NuMetal-Q/NuSeal/README.md`
- `NuMetal-Q/NuMetal/README.md`
- `NuMetal-Q/NuVault/README.md`
- `NuMetal-Q/NuCluster/README.md`
- `NuMetal-Q/NuSDK/README.md`
- `NuMetal-Q/numeqc/README.md`

## Notes

- The canonical proving stack stays on the AG64 profile described in the package sources.
- Math reference: see `MATH.md` for the consolidated algebra and protocol notes.
- Local development and CI conventions: see `docs/development.md` and `docs/testing.md`.
- Benchmark runs write incremental artifacts under `artifacts/benchmarks/` by default.
- The Xcode project is optional convenience metadata; the Swift package is the authoritative build entry point.
