# NuMeQ Metal-First vNext

## Scope
- Metal is now the required canonical proving path on supported Apple silicon.
- `Shape.digest` stays stable.
- The GPU artifact ABI is versioned independently.
- The seal proof format is bumped for GPU PCS openings.

## Implemented Changes
- `ShapePack` now carries `version`, `gpuLiftedMatrices`, and a signed `gpuArtifactDigest`.
- `MetalStorageLayout.currentVersion` is now `3`.
- `ShapePack.currentVersion` is now `3`.
- `KernelConfig` now includes:
  - `threadgroupSize`
  - `threadExecutionWidthMultiple`
  - `laneTile`
  - `matrixRowTile`
  - `storageLayoutVersion`
  - `queueDepth`
  - `gpuFamilyTag`
  - `sealChunkSize`
  - `merkleChunkSize`
- Canonical Metal ABI added for:
  - `Fq` as two `UInt32` limbs
  - `Fq2` as two packed base-field pairs
  - `Rq` in SoA 64-lane tiles
- Production field, matrix, sum-check, PiDEC, seal encode/query, and ring-operation kernels now use the same SoA ABI.
- All AG64 Metal kernels now share one `NuAG64Common.metal` module instead of carrying duplicated arithmetic helpers.
- Binary archive cache keys now include:
  - GPU family
  - canonical Metal artifact digest
  - storage layout version
- `MetalContext` now prefers bundled offline `NuMetal.metallib`, then the default library, and only falls back to source compilation in debug or test.
- Offline Metal artifacts can be generated with `Scripts/build_metal_artifacts.sh`, which emits:
  - `NuMetal-Q/NuMetal/Compiled/NuMetal.metallib`
  - `NuMetal-Q/NuMetal/Compiled/NuMetalManifest.json`
- Ajtai commitment now uses the Metal sparse rotation-add kernel instead of CPU fallback.
- Batched sparse rotation-add commitment dispatch is now available for verifier and commitment recomputation paths.
- `AG64RingMetal.multiply` now runs through the canonical SoA GPU ABI.
- Batched ring bind/fold dispatch is now available for PiRLC and PiDEC verifier recomputation.
- PiCCS now uses GPU matrix lift and a full GPU sum-check reduction tree.
- PiDEC now keeps decomposition on GPU and uses Metal commitment for limb vectors.
- PiRLC and PiDEC now expose Metal verifier paths directly, and `FoldEngine` delegates recursive verification through them.
- Recursive accumulator verification now uses GPU assistance for:
  - seed commitment recomputation
  - PiCCS verifier recomputation
  - PiRLC cross-term and fold recomputation
  - PiDEC decomposition and reconstructed-commitment checks
- Hachi PCS now commits to:
  - `tableCommitment`
  - `tableDigest`
  - `merkleRoot`
  - `codewordLength`
- Hachi PCS openings now carry:
  - `codewordIndex`
  - `codewordValue`
  - `merkleAuthenticationPath`
- `SealProof.currentVersion` is now `6`.
- Hachi PCS now stages codeword extension and leaf hashing in one command buffer before waiting.
- PCS benchmarking now reports live CPU/Metal timings plus:
  - threadgroup widths
  - counter-sampling availability
  - counter-capture status
- Verifier-stage benchmarking now reports CPU vs Metal-assisted timings for:
  - PiCCS verify
  - PiRLC verify
  - PiDEC verify

## Correctness Fixes Applied During Implementation
- Fixed the negacyclic rotation-matrix convention so `RotationMatrix.apply(to:)` matches ring multiplication exactly.
- Removed repeated heap exhaustion in long proof paths by:
  - moving transient commitment and matrix work onto the arena allocator
  - allowing buffer allocation fallback outside heaps when heap allocation fails
  - short-circuiting empty sparse matrices in the Metal matrix path

## Validation
- `swift build`
- `swift test --filter CryptoHardeningTests`
- `swift test --filter ApplePQIntegrationTests/testSealProofCodecRejectsVersionMismatch`
- `Scripts/build_metal_artifacts.sh`
- `swift run NuMetalQBenchmarks --iterations 1 --warmups 0 --output /tmp/numeq-bench-smoke`

## New or Expanded Coverage
- SoA ABI round-trip tests for `Fq`, `Fq2`, and `Rq`
- ShapePack version/storage-layout validation
- ShapePack GPU artifact digest validation
- Metal Ajtai commitment equivalence
- Metal batched Ajtai commitment equivalence
- Metal ring bind/fold equivalence
- Metal PiCCS equivalence
- Metal PiDEC equivalence
- Metal PiRLC verifier equivalence and tamper rejection
- Metal PiDEC verifier equivalence and tamper rejection
- Recursive verifier CPU vs Metal parity for seed and decomposed folded accumulators
- Recursive verifier tamper rejection for:
  - PiCCS matrix evaluations
  - PiRLC cross-term commitments
  - PiDEC reconstructed commitments
- Seal tamper rejection for:
  - `codewordIndex`
  - `merkleAuthenticationPath`
- Seal proof codec rejection on version mismatch
- Rotation-matrix equivalence to negacyclic multiplication

## Remaining Gaps
- Timed PCS kernels and verifier-stage benchmarks now emit per-dispatch GPU trace artifacts and rolled-up dispatch summaries, but dispatch-boundary counter capture remains unavailable on this host and currently falls back to GPU timeline reporting.
- End-to-end seal verification now uses a semantic Hachi verifier in both CPU-only and Metal-assisted modes, and benchmark reports surface explicit CPU/Metal verification parity. Metal-assisted verification remains the canonical default path on supported Apple silicon; CPU-only is the validated fallback and reference oracle.
