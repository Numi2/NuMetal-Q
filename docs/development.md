# Development Guide

NuMetal-Q is maintained as a Swift package first. The Xcode project is convenience metadata only.

## Local Workflow

Use these commands for the shortest useful loop:

```bash
Scripts/check_repo_metadata.sh
swift build
swift test --filter TranscriptVectorTests
swift test --filter WitnessPackingTests
swift test --filter SupportCodecTests
swift test --filter SyncProtocolTests
swift run NuMetalQAcceptanceDemo --help
swift run NuMetalQBenchmarks --list-workloads
```

## Environment Notes

- GPU-backed tests and end-to-end proving flows require Apple silicon plus a supported Apple GPU family.
- CPU-safe tests are the default CI lane.
- `Scripts/run_apple_silicon_validation.sh [OUTPUT_DIR]` is the deterministic local validation gate for Metal proving and CPU/Metal verification parity.
- `Scripts/build_metal_artifacts.sh` requires Xcode command-line tools with `xcrun metal` and `xcrun metallib`.

## Docs Drift

`Scripts/check_repo_metadata.sh` verifies the implementation-status note against source constants and documented test filters. Run it before changing:

- proof format versions
- Metal ABI/storage-layout versions
- validation commands in `METAL_FIRST_VNEXT.md`
