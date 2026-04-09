// NuMeQ — Post-Quantum Zero-Knowledge Proof-Carrying Data
//
// Apple-only. Almost Goldilocks64 SuperNeo folding.
// Frozen one-stack line: SuperNeo over Fq/Fq2, Hachi as the terminal D_Nu decider
// over the certified quartic tower Fq4, and application-layer envelope export.
// Zero-knowledge by default. Apple's post-quantum security stack.
//
// Modules:
//   NuField   — Almost Goldilocks64 field arithmetic (Fq, Fq², Rq, rotation matrices,
//               NuDigest, NuTranscriptField/Poseidon2, NuSampler, NuProfile, NuParams)
//   NuIR      — CCS intermediate representation, witness lanes, shapes, Header/Step
//   NuFold    — SuperNeo folding engine (PiCCS, PiRLC, PiDEC, FoldState)
//   NuSeal    — Terminal decider compilation and export verification
//   NuMetal   — Metal GPU compute (kernel families, scheduler, autotuner)
//   NuVault   — Encrypted FoldState storage, ProofEnvelope signing, NuPolicy
//   NuCluster — Distributed iPhone/MacBook proving with witness-class enforcement
//   NuSDK     — Public API surface (NuMeQ, ProofContext, seed/fuse/seal/verify/resume)
//   numeqc    — Build-time shape compiler (ShapePack emitter)
//
// Protocol stage order (SuperNeo paper):
//   1. PiCCS  — strong interactive reduction: sum-check CCS → CE
//   2. PiRLC  — weak interactive reduction: random linear combination from C
//   3. PiDEC  — norm reduction: decompose B = b^k → b
//
// Transcript split:
//   NuTranscriptField — Poseidon2 algebraic sponge for proof semantics only
//   NuTranscriptSeal  — cSHAKE256 byte transcript for seal proofs only
//   NuDigest          — CryptoKit SHA-256 for envelopes, shape packs, and metadata
//
// Field extension:
//   Fq2 = Fq[u]/(u² − 3), β = 3 verified nonsquare via Euler's criterion
//   Fq4 = Fq2[v]/(v² − η), η compiler-chosen and certified irreducible

import Foundation
