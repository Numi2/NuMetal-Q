# Testing Guide

NuMetal-Q has one default validation lane and one manual hardware lane:

## 1. CPU-safe CI lane

These checks are intended to run on generic macOS CI without assuming Apple silicon or a working Metal device. The default SwiftPM test target includes the security and crypto-hardening suites; Metal-dependent tests skip when a supported device is unavailable, and Apple PQ integration tests are enabled only with `NUMETALQ_ENABLE_APPLE_PQ=1`.

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
- envelope signature, namespace, attestation, and proof-format rejection paths
- sync envelope encryption, strict attestation binding, and replay defense
- vault serialization, typed prover persistence, tamper rejection, and policy boundaries
- cluster work packet validation, delegation attestation, and replay defense

The CI lane is the correctness floor. Long-running benchmark/report validation, packed-witness representability preflight at benchmark scale, direct-packed Metal final-opening performance work, and end-to-end CPU/Metal parity remain manual hardware checks.
