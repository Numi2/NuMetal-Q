# Developer Workflow

## Fast Validation Loop

1. Run `Scripts/check_repo_metadata.sh`.
2. Run `swift build`.
3. Run the CPU-safe tests from `docs/testing.md`.
4. Run Apple-silicon proving and benchmark checks on local hardware when touching `NuMetal`, `NuFold`, or `NuSeal`.

## Artifact Discipline

- `NuMetal-Q/NuMetal/Compiled/` stores the bundled Metal artifact set.
- `Scripts/build_metal_artifacts.sh` regenerates the offline artifact bundle.
- `METAL_FIRST_VNEXT.md` should stay in sync with source constants and current validation commands.
