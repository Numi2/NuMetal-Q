# NuMeQ Metal-First vNext

## Scope
- Metal is now the required canonical proving path on supported Apple silicon.
- `Shape.digest` stays stable.
- The GPU artifact ABI is versioned independently.
- The seal proof format is bumped for the direct-packed PCS cutover.
- This note tracks the current implementation surface and recommended validation commands.
  It is not a certification artifact.

## Implemented Changes
- `ShapePack` now carries `version`, `gpuLiftedMatrices`, and a signed `gpuArtifactDigest`.
- `MetalStorageLayout.currentVersion` is now `1`.
- `ShapePack.currentVersion` is now `4`.
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
- Production field, matrix, sum-check, PiDEC, and ring-operation kernels now use the same SoA ABI.
- All AG64 Metal kernels now share one `NuAG64Common.metal` module instead of carrying duplicated arithmetic helpers.
- Binary archive cache keys now include:
  - GPU family
  - canonical Metal artifact digest
  - storage layout version
- `MetalContext` now loads the measured bundled `NuMetal.metallib` when present and only falls back to source compilation in debug or test.
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
- Direct-packed Hachi PCS is now the only supported opening mode.
- Direct-packed commitments now carry:
  - aggregate `tableCommitment`
  - per-chunk `directPackedOuterCommitments`
  - `packedChunkCount`
  - `statementDigest`
- Direct-packed openings no longer carry verifier-visible reduction artifacts.
- `ShortLinearWitnessProof` now carries:
  - `initialBindingCommitment`
  - `accumulatorRounds`
  - `finalOpening`
  - `restartNonce`
  - `transcriptBinding`
- Each accumulator round now publishes hiding Ajtai commitments only:
  - binding image commitments
  - relation image commitments
  - evaluation image commitments
  - outer image commitments
- The direct-packed final opening now carries masked residual responses over chunk-local `s_j` and `t̂_j`, not witness-length sigma responses.
- Direct-packed parameter derivation now includes:
  - image-commitment seeds
  - binary fold arity
  - challenge distribution ID
  - round and final Gaussian mask scales
  - rejection slack
  - residual block count per chunk
  - accumulator and rejection transcript domains
  - security profile digest
- `SealProof.currentVersion` is now `9`.
- `PublicSealProof.currentVersion` is now `5`.
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

## Validation Commands
- `Scripts/check_repo_metadata.sh`
- `swift build`
- `swift test --filter TranscriptVectorTests`
- `swift test --filter WitnessPackingTests`
- `swift test --filter SupportCodecTests`
- `swift test --filter SyncProtocolTests`
- `swift test --filter CryptoHardeningTests`
- `swift test --filter ClusterWorkPacketTests`
- `Scripts/build_metal_artifacts.sh`
- `swift run NuMetalQAcceptanceDemo --help`
- `swift run NuMetalQBenchmarks --help`
- `swift run NuMetalQBenchmarks --list-workloads`
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
- Direct-packed PCS tamper rejection for:
  - final residual short responses
  - initial binding commitment
  - query point derived schedules
- Seal proof codec rejection on version mismatch
- Rotation-matrix equivalence to negacyclic multiplication

## Remaining Gaps
- Verifier-stage benchmarks now emit per-dispatch GPU trace artifacts and rolled-up dispatch summaries, but dispatch-boundary counter capture remains unavailable on this host and currently falls back to GPU timeline reporting.
- The direct-packed prover/verifier now uses the hiding accumulator carrier and transcript-bound rejection acceptance, but Gaussian sampling and rejection still run through host orchestration over existing AG64/Ajtai Metal primitives rather than dedicated protocol-specific kernels.
- End-to-end seal verification uses a semantic Hachi verifier in both CPU-only and Metal-assisted modes, and benchmark reports surface explicit CPU/Metal verification parity. Metal-assisted verification remains the canonical default path on supported Apple silicon; CPU-only remains the reference oracle for parity and tests.
- CI currently exercises a CPU-safe lane plus CLI smoke checks; the full proving/Metal path still depends on local Apple-silicon validation.
