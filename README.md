# NuMeQ

Post-quantum proof-carrying data engine for Apple platforms.

## Current Status

NuMeQ is maintained as a Swift package first. The package exposes the `NuMetal_Q` library, the `NuMetalQAcceptanceDemo` executable, the `NuMetalQBenchmarks` executable, and the `NuMetalQSealXOF` C helper target.

The active proving stack is the AG64 profile with the Hachi terminal decider. Public API usage follows the `seed`, `fuse`, `seal`, `resume`, and standalone `verify` lifecycle exposed through `NuMeQ` and `ProofContext`.

Recent implementation work is focused on the Metal-first seal path:

- Direct-packed final-opening execution now uses staged Metal kernels for Gaussian mask decode, image-vector preparation, evaluation reduction/finalize, response formation, and rejection-metric reduction/finalize.
- The direct-packed Metal fast path is enabled only on Apple GPU family 9 or newer. Older supported Apple GPU families fall back to the CPU final-opening oracle while preserving the same proof semantics.
- Seal workload benchmarks preflight packed witnesses for PiDEC representability before proving work starts.
- Benchmark reports now include norm ceiling, generator headroom, preflight maximum centered magnitude, representability status, CPU/Metal verification parity, GPU timing, and dispatch trace state.

`SealProof.currentVersion` is `9`; `PublicSealProof.currentVersion` is `5`.

## Repository Layout

- `NuMetal-Q/`: library sources grouped by subsystem.
- `SealXOF/`: C Keccak/XOF helper target used by seal proof code.
- `Examples/`: acceptance demo and benchmark runners.
- `Tests/`: CPU-safe package tests and Apple-silicon parity coverage.
- `docs/`: development, testing, benchmarking, protocol, and state-of-the-art notes.
- `Scripts/build_metal_artifacts.sh`: rebuilds the offline Metal artifact bundle.
- `Scripts/run_apple_silicon_validation.sh`: deterministic Apple-silicon validation lane for Metal proving and CPU/Metal parity.
- `Scripts/check_repo_metadata.sh`: docs/version drift checker used locally and in CI.

Bundled Metal artifacts in `NuMetal-Q/NuMetal/Compiled/` are source-controlled runtime inputs. Local build output under `.build/` and generated benchmark reports under `artifacts/benchmarks/` are not.

## Commands

CPU-safe local loop:

```bash
Scripts/check_repo_metadata.sh
swift build
swift test
```

Acceptance and benchmark entry points:

```bash
swift run NuMetalQAcceptanceDemo
swift run NuMetalQAcceptanceDemo --format json --output /tmp/numeq-acceptance.json
swift run NuMetalQBenchmarks --list-workloads
swift run NuMetalQBenchmarks --seal-workload auth-policy-sparse
```

Apple-silicon validation:

```bash
Scripts/run_apple_silicon_validation.sh [OUTPUT_DIR]
```

Metal shader changes require rebuilding the bundled artifacts:

```bash
Scripts/build_metal_artifacts.sh
```

## Public Flow

1. `seed`: create a base proof from witness data and public inputs.
2. `fuse`: combine proofs into a larger accumulator.
3. `seal`: compile the terminal decider and export a signed `ProofEnvelope` plus encrypted resume artifact.
4. `resume`: verify an envelope and rebind it into fresh recursive state.
5. `verify`: validate a sealed envelope without prover state.

## Subsystem Docs

- `NuMetal-Q/NuField/README.md`
- `NuMetal-Q/NuIR/README.md`
- `NuMetal-Q/NuFold/README.md`
- `NuMetal-Q/NuSeal/README.md`
- `NuMetal-Q/NuMetal/README.md`
- `NuMetal-Q/NuVault/README.md`
- `NuMetal-Q/NuCluster/README.md`
- `NuMetal-Q/NuSDK/README.md`
- `NuMetal-Q/NuSupport/README.md`
- `NuMetal-Q/numeqc/README.md`

## References

- `MATH.md`: consolidated algebra and protocol notes.
- `METAL_FIRST_VNEXT.md`: implementation status for the Metal-first proving path.
- `docs/development.md`: local workflow and docs-drift rules.
- `docs/testing.md`: CPU-safe and Apple-silicon validation lanes.
- `docs/benchmarking.md`: benchmark runner, report fields, and trace artifacts.
- `docs/protocol-note.md`: protocol orientation.
- `docs/state-of-the-art.md`: related-work notes.

The Xcode project is optional convenience metadata. The Swift package is the authoritative build entry point.
