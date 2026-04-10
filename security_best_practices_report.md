# Security Audit Report

## Executive Summary

This review focused on the recursive proof system, transcript/XOF implementation, envelope and resume bindings, the encrypted vault, the cluster delegation channel, and the signed GPU artifact path. I did not run the test suite.

The most serious issue is in `PiRLC`: the recursive folding stage does not carry forward the existing relaxed-claim `errorTerms`, and its cross-term construction is anchored only to `inputs[0]`. Because both prover and verifier share that logic, the recursive verifier can accept folded claims that are no longer equivalent to their children after the first non-trivial fold.

I also found integrity gaps in the GPU artifact validation path, a legacy-style vault decryption fallback that weakens ciphertext binding, replay/freshness gaps in cluster work handling, and a fail-open behavior in the cSHAKE C shim under allocation failure.

## Critical Findings

### 1. `PiRLC` does not preserve the relaxed CCS error state across recursive folds

Impact: recursive proofs can be accepted even though the folded claim no longer represents the semantics of its child accumulators.

Evidence:

- [`/Users/home/NuMetal-Q/NuMetal-Q/NuFold/FoldEngine.swift:913`](./NuMetal-Q/NuFold/FoldEngine.swift) passes `summary.currentClaim.errorTerms` into `PiRLC.Input`.
- [`/Users/home/NuMetal-Q/NuMetal-Q/NuFold/PiRLC.swift:101`](./NuMetal-Q/NuFold/PiRLC.swift) computes new cross-terms only from `inputs[0].witness` against later witnesses.
- [`/Users/home/NuMetal-Q/NuMetal-Q/NuFold/PiRLC.swift:154`](./NuMetal-Q/NuFold/PiRLC.swift) builds `foldedError` from those new cross-terms only.
- [`/Users/home/NuMetal-Q/NuMetal-Q/NuFold/PiRLC.swift:573`](./NuMetal-Q/NuFold/PiRLC.swift) repeats the same logic in the verifier helper.

Why this is a bug:

- `PiRLC.Input` explicitly carries prior `errorTerms`, which means the recursive state expects them to participate in the next fold.
- The implementation never reads `input.errorTerms` in either the prover or verifier.
- The cross-term computation is also asymmetric: it only multiplies `inputs[0]` by each later witness instead of accounting for the already-relaxed child claims in general.
- As a result, once an accumulator already contains non-empty `errorTerms`, the next fold silently drops part of the recursive claim while still producing a verifier-accepted transcript.

## High Findings

### 2. Shape-pack GPU artifact validation can fail open and does not guarantee the runtime executes the measured artifact

Impact: a signed `ShapePack` can validate without proving that the GPU library actually loaded at runtime matches the artifact that was hashed and signed.

Evidence:

- [`/Users/home/NuMetal-Q/NuMetal-Q/NuIR/Shape.swift:353`](./NuMetal-Q/NuIR/Shape.swift) accepts `shapePack.gpuArtifactDigest == ShapeArtifact.gpuArtifactDigest()`.
- [`/Users/home/NuMetal-Q/NuMetal-Q/NuIR/Shape.swift:515`](./NuMetal-Q/NuIR/Shape.swift) maps any `MetalArtifactBundle.artifactDigest()` failure to 32 zero bytes instead of failing closed.
- [`/Users/home/NuMetal-Q/NuMetal-Q/numeqc/ShapeCompiler.swift:105`](./NuMetal-Q/numeqc/ShapeCompiler.swift) uses the same helper during signing, so a build-time failure can also freeze an all-zero digest into a signed pack.
- [`/Users/home/NuMetal-Q/NuMetal-Q/NuMetal/MetalArtifactBundle.swift:34`](./NuMetal-Q/NuMetal/MetalArtifactBundle.swift) hashes either the bundled `metallib` or the source files.
- [`/Users/home/NuMetal-Q/NuMetal-Q/NuMetal/MetalArtifactBundle.swift:50`](./NuMetal-Q/NuMetal/MetalArtifactBundle.swift) may execute `device.makeDefaultLibrary()` instead of either measured input when no bundled `metallib` is found.

Why this matters:

- The zero-digest fallback is fail-open: digest computation errors degrade into a concrete value that can be signed and later accepted.
- Even when digest computation succeeds, the runtime can execute `makeDefaultLibrary()` while validation compared the shape pack against the bundled `metallib` or source tree instead.
- That breaks the claimed binding between the signed shape pack and the GPU kernels that actually prove or verify statements.

## Medium Findings

### 3. Vault decryption still accepts non-AAD AES-GCM records after the chain-bound open fails

Impact: legacy or maliciously reintroduced vault records can bypass the `chainID` binding that current writes rely on.

Evidence:

- [`/Users/home/NuMetal-Q/NuMetal-Q/NuVault/FoldVault.swift:98`](./NuMetal-Q/NuVault/FoldVault.swift) stores entries using AES-GCM with `vaultAssociatedData(for: state.chainID)`.
- [`/Users/home/NuMetal-Q/NuMetal-Q/NuVault/FoldVault.swift:177`](./NuMetal-Q/NuVault/FoldVault.swift) first tries to open with that AAD.
- [`/Users/home/NuMetal-Q/NuMetal-Q/NuVault/FoldVault.swift:185`](./NuMetal-Q/NuVault/FoldVault.swift) then falls back to `AES.GCM.open(box, using: key)` with no AAD.

Why this matters:

- The file format and comments claim entries are chain-bound.
- The fallback means the reader still accepts a weaker, unbound ciphertext class.
- If older records exist, or if an attacker can inject a no-AAD ciphertext under a recovered key, the vault stops enforcing the `chainID` binding the rest of the code assumes.

### 4. Cluster work packets have timestamps and in-memory replay tracking, but no freshness check or durable replay cache

Impact: signed fragments can be replayed after long delays or across process restarts, causing stale delegated work to be re-executed.

Evidence:

- [`/Users/home/NuMetal-Q/NuMetal-Q/NuCluster/ClusterSession.swift:134`](./NuMetal-Q/NuCluster/ClusterSession.swift), [`/Users/home/NuMetal-Q/NuMetal-Q/NuCluster/ClusterSession.swift:166`](./NuMetal-Q/NuCluster/ClusterSession.swift), and [`/Users/home/NuMetal-Q/NuMetal-Q/NuCluster/ClusterSession.swift:195`](./NuMetal-Q/NuCluster/ClusterSession.swift) stamp outgoing fragments with `Date()`.
- [`/Users/home/NuMetal-Q/NuMetal-Q/NuCluster/ClusterSession.swift:229`](./NuMetal-Q/NuCluster/ClusterSession.swift) tracks replays only in actor memory keyed by `fragmentID`.
- [`/Users/home/NuMetal-Q/NuMetal-Q/NuCluster/ClusterSession.swift:396`](./NuMetal-Q/NuCluster/ClusterSession.swift) passes the timestamp into attestation context, but the session itself never checks an age window.
- By contrast, [`/Users/home/NuMetal-Q/NuMetal-Q/NuVault/SyncProtocol.swift:369`](./NuMetal-Q/NuVault/SyncProtocol.swift) explicitly validates timestamp freshness and [`/Users/home/NuMetal-Q/NuMetal-Q/NuVault/SyncProtocol.swift:382`](./NuMetal-Q/NuVault/SyncProtocol.swift) uses a replay cache.

Why this matters:

- `ClusterSession` relies on ephemeral in-memory maps only.
- A restarted co-prover can accept an old signed fragment as the first fragment of a new session binding, because there is no timestamp window and no persisted replay state.
- Since attestation validation is delegated to an external verifier, the transport layer itself does not enforce freshness.

## Low Findings

### 5. The cSHAKE wrapper returns silently on allocation failure, leaving the caller with an all-zero digest buffer

Impact: under memory pressure, transcript and digest derivation can fail open instead of surfacing an error.

Evidence:

- [`/Users/home/NuMetal-Q/SealXOF/keccak_xof.c:242`](./SealXOF/keccak_xof.c) returns early if `combined`, `encoded_name`, or `encoded_custom` allocation fails.
- [`/Users/home/NuMetal-Q/SealXOF/keccak_xof.c:252`](./SealXOF/keccak_xof.c) returns early if `bytepad` allocation fails.
- [`/Users/home/NuMetal-Q/SealXOF/keccak_xof.c:262`](./SealXOF/keccak_xof.c) returns early if `message` allocation fails.

Why this matters:

- The Swift wrapper preallocates an output array with zeros and does not receive an error signal from the C API.
- Any early return therefore produces a deterministic zero digest instead of failing the cryptographic operation.

## Testing Gaps

- The existing tests cover tampering and some envelope/vault invariants, but I did not find coverage for recursive folds where child accumulators already carry non-empty `errorTerms`.
- I did not find coverage for the zero-digest GPU artifact path, default-library divergence, or cluster replay across process restarts.

