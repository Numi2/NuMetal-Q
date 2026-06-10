# Testing Guide

NuMetal-Q has one default validation lane and one manual hardware lane:

## 1. CPU-safe CI lane

These checks are intended to run on generic macOS CI without assuming Apple silicon or a working Metal device. The default SwiftPM test target is pruned to this lane.

```bash
Scripts/check_repo_metadata.sh
swift build
swift test
swift run NuMetalQAcceptanceDemo --help
swift run NuMetalQBenchmarks --help
swift run NuMetalQBenchmarks --list-workloads
```

## 2. Apple-silicon validation lane

This lane is for proving and Metal-assisted verification on a supported Apple-silicon host.
Use the scripted entrypoint so the output locations stay deterministic:

```bash
Scripts/run_apple_silicon_validation.sh [OUTPUT_DIR]
```

The script now prints stage names before each command so failures are classified by validation stage rather than surfacing as an unlabeled shell exit.

## Current Test Coverage Emphasis

- transcript vectors and deterministic challenge derivation
- witness packing and canonical ring embedding
- binary codec and cSHAKE/XOF helpers
- sync envelope encryption, attestation, and replay defense
- vault serialization and attestation/security boundaries

The CI lane is the correctness floor. GPU-assisted proving, packed-witness representability preflight, direct-packed Metal final-opening work, and end-to-end CPU/Metal parity remain manual hardware checks.
