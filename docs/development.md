# Development Guide

NuMetal-Q is maintained as a Swift package first. The Xcode project is convenience metadata only.

## Local Workflow

Use these commands for the shortest useful loop:

```bash
Scripts/check_repo_metadata.sh
swift build
swift test
swift run NuMetalQAcceptanceDemo --help
swift run NuMetalQBenchmarks --list-workloads
```

## Environment Notes

- GPU-backed tests and end-to-end proving flows require Apple silicon plus a supported Apple GPU family.
- CPU-safe tests are the default SwiftPM and CI lane.
- `Scripts/run_apple_silicon_validation.sh [OUTPUT_DIR]` is the manual local validation lane for Metal proving and CPU/Metal verification parity.
- `Scripts/build_metal_artifacts.sh` requires Xcode command-line tools with `xcrun metal` and `xcrun metallib`.
- Heavy integration, Metal parity, and Apple PQ test sources are excluded from the default SwiftPM test target until they are explicitly revived.

## Docs Drift

`Scripts/check_repo_metadata.sh` verifies the implementation-status note against source constants. Run it before changing:

- proof format versions
- Metal ABI/storage-layout versions
