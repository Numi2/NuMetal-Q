# Testing Guide

NuMetal-Q has two practical validation lanes:

## 1. CPU-safe CI lane

These checks are intended to run on generic macOS CI without assuming Apple silicon or a working Metal device:

```bash
Scripts/check_repo_metadata.sh
swift build
swift test --filter TranscriptVectorTests
swift test --filter WitnessPackingTests
swift test --filter SupportCodecTests
swift test --filter SyncProtocolTests
swift run NuMetalQAcceptanceDemo --help
swift run NuMetalQBenchmarks --help
swift run NuMetalQBenchmarks --list-workloads
```

## 2. Apple-silicon validation lane

This is the release-readiness gate for proving and Metal-assisted verification on a supported Apple-silicon host.
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

The CI lane is the correctness floor. GPU-assisted proving, packed-witness representability preflight, direct-packed Metal final-opening work, and end-to-end CPU/Metal parity remain validated in the Apple-silicon lane.
