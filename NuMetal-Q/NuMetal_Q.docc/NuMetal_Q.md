# ``NuMetal_Q``

Post-quantum zero-knowledge proof-carrying data for Apple platforms.

## Overview

NuMeQ is an Apple-only PCD engine built on SuperNeo CCS folding with the
Almost Goldilocks field profile (q = 2^64 − 2^32 − 31, d = 64, ~129-bit Module-SIS security).
The frozen production line is `HACHI-AG64-K4-DNU`: SuperNeo over `Fq/Fq2`
for recursive accumulation, Hachi as the compiled terminal decider `D_Nu`
over an `Fq4` decider field, and application-layer signing plus
transport around the exported envelope.

The quartic decider field is mathematically natural here because `X^64 + 1`
splits over `Fq` into irreducible quartics, so `Fq4` is the smallest extension
where the negacyclic ring polynomial splits completely.

The terminal opening backend is direct-packed only. In code this backend is
named `HachiPCSBackend`:

- every packed multilinear oracle uses the same direct-packed relation-opening path,
- the direct-packed path proves the chunk-local short linear witness relation
  with hiding accumulator commitments and a residual masked opening,
- legacy codeword/Merkle openings are not part of the vNext verifier surface.

The public API model:

1. **Seed**: Create a base-case proof from a witness and public inputs.
2. **Fuse**: Combine two proofs into one (binary fuse).
3. **Seal**: Compile the Hachi decider for the final accumulator and export it in a signed envelope.
4. **Resume**: Verify an exported envelope and rebind a fresh recursive state.
5. **Verify**: Check an envelope's cryptographic bindings and signature.

Cluster-assisted seed and seal operations are policy-bound. Delegated fragments
are session-bound on the co-prover, and resumed handles preserve provenance so
cluster eligibility stays fail-closed across verify-then-rebind resume.

## Topics

### Getting Started

- <doc:GettingStarted>
- <doc:DeveloperWorkflow>
- ``NuMeQ``
- ``ProofContext``
- ``ProofHandle``
- ``ClusterSeedReceipt``
- ``ClusterExecutionEligibility``

### Field Arithmetic

- ``Fq``
- ``Fq2``
- ``RingElement``
- ``RotationMatrix``

### Transcripts and Challenges

- ``NuTranscriptField``
- ``NuTranscriptSeal``
- ``NuDigest``
- ``NuSampler``

### Profile and Parameters

- ``NuProfile``
- ``NuParams``
- ``ProfileCertificate``

### Folding Protocol

- ``PiRLC``
- ``PiCCS``
- ``PiDEC``
- ``FoldEngine``
- ``FoldConfig``
- ``NormBudget``
- ``AjtaiCommitment``
- ``AjtaiKey``

### Terminal Decider

- ``NuSealBackend``
- ``SealEngine``
- ``SealProof``
- ``HachiSealProof``

### Security Envelope

- ``ProofEnvelope``
- ``EnvelopeBuilder``
- ``NuPolicy``
- ``WitnessClass``

### Device and Cluster

- ``MetalContext``
- ``ProverScheduler``
- ``ClusterSession``
- ``ClusterWorkExecutor``
- ``ClusterWorkContext``
- ``ClusterFoldWorkPacket``
- ``ClusterFoldWorkResult``
- ``ClusterDecomposeWorkPacket``
- ``ClusterDecomposeWorkResult``
- ``HachiClusterSealWorkPacket``
- ``HachiClusterSealWorkResult``
- ``SyncChannel``

### IR and Shapes

- ``CCSRelation``
- ``Shape``
- ``CompiledShape``
- ``WitnessLane``
- ``Witness``
