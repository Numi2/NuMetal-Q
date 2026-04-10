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

Run the broader suite on a supported Apple-silicon host:

```bash
swift test
Scripts/build_metal_artifacts.sh
swift run NuMetalQAcceptanceDemo
swift run NuMetalQBenchmarks --iterations 1 --warmups 0
```

## Current Test Coverage Emphasis

- transcript vectors and deterministic challenge derivation
- witness packing and canonical ring embedding
- binary codec and cSHAKE/XOF helpers
- sync envelope encryption, attestation, and replay defense
- vault serialization and attestation/security boundaries

GPU-assisted proving and full end-to-end flows remain best validated on local Apple-silicon hardware.
