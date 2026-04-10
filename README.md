# NuMeQ

Post-quantum proof-carrying data engine for Apple platforms.

## Active Layout

This repository is a Swift package with one primary library target, two example executables, and a test suite:

- `NuMetal-Q/`: library sources grouped by subsystem (`NuField`, `NuFold`, `NuMetal`, `NuSDK`, `NuSeal`, `NuVault`, `NuCluster`)
- `Examples/`: acceptance demo and benchmark runners
- `Tests/`: package tests
- `Scripts/build_metal_artifacts.sh`: offline Metal artifact builder

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
swift test
swift run NuMetalQAcceptanceDemo
swift run NuMetalQBenchmarks
```

## Notes

- The canonical proving stack stays on the AG64 profile described in the package sources.
- Math reference: see `MATH.md` for the consolidated algebra and protocol notes.
- The Xcode project is optional convenience metadata; the Swift package is the authoritative build entry point.
