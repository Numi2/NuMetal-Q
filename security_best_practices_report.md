# Security Audit Report

## Executive Summary

This review focused on the proof transcript, recursive folding, sealing and verification flow, attestation handling, vault persistence, sync and cluster transport, and the custom cSHAKE implementation. I did not run the test suite.

The most serious cryptographic weakness I found is in `PiRLC`: field-valued claim components are folded with `rho.coeffs[0]`, so each scalar challenge lives in `{ -1, 0, 1, 2 }` instead of a full-field domain. That collapses the randomness protecting folded public inputs, matrix evaluations, and relaxation factors from field-sized entropy to 2 bits per child.

I also found a systemic attestation design bug: the same serialized attestation blob is reused across phases while being validated under different `AttestationPurpose` values, and in sync flows under different local/remote device bindings. With a strict verifier, those flows are not satisfiable; with a permissive verifier, the purpose and device fields stop carrying security meaning.

Separately, public seal verification does not semantically enforce several fields exposed in `PublicSealStatement`, the public typed prover bypasses the witness-class policy model and persists full typed traces as `.public`, and the cSHAKE C shim still fails open on allocation failure.

## Critical Findings

### 1. `PiRLC` folds field-valued claim components with only a 2-bit scalar projection of each ring challenge

Impact: folded public inputs, matrix evaluations, and relaxation factors are protected by only four possible coefficients per child, materially weakening recursive soundness and making collision-style targeting of folded claims much easier than the protocol comments imply.

Evidence:

- `NuMetal-Q/NuFold/PiRLC.swift:113-119` samples `ringChallenges` from `NuSampler.challengeRingFromC(...)` and then derives `scalarChallenges` as `ringChallenges.map { $0.coeffs[0] }`.
- `NuMetal-Q/NuFold/PiRLC.swift:129-143` uses those 4-value `rhoScalar` values to fold `publicInputs`, `ccsEvaluations`, and `relaxationFactor`.
- `NuMetal-Q/NuFold/PiRLC.swift:345-387` repeats the same projection in the Metal verifier path.
- `NuMetal-Q/NuField/Transcript.swift:472-492` shows each coefficient of `challengeRingFromC` is sampled from `C = { -1, 0, 1, 2 }`, so `coeffs[0]` carries only 2 bits of entropy.

Why this is a bug:

- The comments for `PiRLC` describe a random linear combination over transcript challenges, but the field-valued components are not folded with a field challenge or a high-entropy projection of the ring challenge.
- Using the constant coefficient gives only four scalar possibilities per folded child.
- Because the prover and verifier share the same reduction, malformed folded claims can target this tiny challenge space and still verify.

## High Findings

### 2. The same attestation blob is validated under mutually incompatible purposes and device contexts

Impact: if the attestation verifier actually enforces `purpose`, `localDeviceID`, or `remoteDeviceID`, export/sync/cluster flows become unsatisfiable; if deployments relax those checks to interoperate, the attestation context stops carrying the security meaning the API suggests.

Evidence:

- Proof export validates the envelope attestation under `.envelopeExport` in `NuMetal-Q/NuSDK/ProofContext.swift:223-227`, while later proof verification validates the same `envelope.attestation` under `.envelopeVerification` in `NuMetal-Q/NuSDK/ProofContext.swift:557-569` and `NuMetal-Q/NuSDK/NuMeQ.swift:158-180`.
- Sync send-side validation uses `.syncEnvelope` with `localDeviceID = sender` and `remoteDeviceID = recipient` in `NuMetal-Q/NuVault/SyncProtocol.swift:109-113` and `NuMetal-Q/NuVault/SyncProtocol.swift:424-435`, while receive-side validation reuses the same blob with `localDeviceID = recipient` and `remoteDeviceID = sender` in `NuMetal-Q/NuVault/SyncProtocol.swift:293-297` and `NuMetal-Q/NuVault/SyncProtocol.swift:319-323`.
- Cluster delegation validates the fragment attestation under `.clusterDelegation` in `NuMetal-Q/NuCluster/ClusterSession.swift:159`, `NuMetal-Q/NuCluster/ClusterSession.swift:191`, and `NuMetal-Q/NuCluster/ClusterSession.swift:220`, then the co-prover revalidates that same `fragment.attestation` under `.clusterExecution` in `NuMetal-Q/NuCluster/ClusterSession.swift:244` using the context builder in `NuMetal-Q/NuCluster/ClusterSession.swift:425-435`.

Why this matters:

- There is only one serialized `attestation` field on `ProofEnvelope` and one on `JobFragment`.
- The code treats those single blobs as if they can simultaneously satisfy different `AttestationPurpose` values and, in sync, opposite local/remote device bindings.
- The current tests avoid this by using permissive verifiers (`nonEmptyAttestationVerifier`) or by testing only the verification-purpose envelope path, so the stricter intended semantics are not exercised.

### 3. Standalone seal verification does not semantically enforce `finalAccumulatorCommitment`, `relaxationFactor`, or `errorTerms`

Impact: a sealed proof can verify publicly even if these exposed statement fields are inaccurate. Consumers calling `verify(...)` do not actually get assurance about the recursive accumulator metadata the API surfaces and the resume path later trusts.

Evidence:

- `NuMetal-Q/NuSeal/PublicSealArtifacts.swift:17-21` exposes `finalAccumulatorCommitment`, `publicInputs`, `relaxationFactor`, and `errorTerms` as part of `PublicSealStatement`.
- `NuMetal-Q/NuSeal/HachiSealEngine.swift:655-676` absorbs those fields into the Fiat-Shamir transcript.
- `NuMetal-Q/NuSeal/HachiSealEngine.swift:223-255` and `NuMetal-Q/NuSeal/HachiSealEngine.swift:935-973` only enforce equations over `publicInputs`, row evaluations, matrix values, and witness evaluations; there is no semantic check tying the proof to `finalAccumulatorCommitment`, `relaxationFactor`, or `errorTerms`.
- `NuMetal-Q/NuSDK/NuMeQ.swift:189-204` and `NuMetal-Q/NuSDK/ProofContext.swift:578-590` accept the proof once header binding and seal verification succeed.
- `NuMetal-Q/NuFold/FoldEngine.swift:300-305` later treats those same statement fields as authoritative when restoring a sealed recursive state.

Why this matters:

- These fields are not just inert metadata: the resume path depends on them to match the encrypted accumulator artifact.
- Public verification, however, only proves the seal decider over the witness/public-input path and transcript commitments, not the truthfulness of these accumulator fields.
- A malicious prover with signing authority can therefore publish a publicly “valid” envelope whose accumulator metadata is misleading or unusable for resume.

## Medium Findings

### 4. `MetalFoldProver` bypasses the witness-class policy model and persists typed traces as `.public`

Impact: callers can persist device-confined or ephemeral witness material through the public typed prover path, contrary to the trust model documented for `NuPolicy`.

Evidence:

- `NuMetal-Q/NuVault/NuPolicy.swift:39-40` says policy is enforced at every boundary, including vault persistence.
- `NuMetal-Q/NuSDK/MetalFoldProver.swift:75-77` and `NuMetal-Q/NuSDK/MetalFoldProver.swift:129-131` immediately store typed states in `FoldVault`.
- `NuMetal-Q/NuSDK/MetalFoldProver.swift:229-245` hardcodes `maxWitnessClass: .public` when materializing those states.
- `NuMetal-Q/NuFold/FoldState.swift:27-28` and `NuMetal-Q/NuFold/FoldState.swift:244-249` show `typedTrace` binds the full lowered witness for every DAG node.
- `NuMetal-Q/NuVault/FoldVault.swift:283-287` persists that optional `typedTrace` payload inside the vault record.

Why this matters:

- `ProofContext` rejects persistence of `.ephemeralDerived` material before sealing, but the separate public `MetalFoldProver` path has no equivalent policy gate.
- Hardcoding `.public` also destroys provenance once the state is serialized, so later consumers cannot recover how sensitive the original witness material was.

## Low Findings

### 5. The cSHAKE wrapper still fails open on allocation failure and returns an all-zero digest buffer

Impact: under memory pressure, transcript and digest derivation can silently degrade to zero bytes instead of surfacing an error.

Evidence:

- `SealXOF/keccak_xof.c:242-268` returns early if any intermediate allocation fails.
- `NuMetal-Q/NuField/Transcript.swift:275-286` preinitializes the output buffer with zeros before calling the C shim and receives no error signal.

Why this matters:

- The Swift caller cannot distinguish “valid digest of zero bytes” from “digest computation aborted”.
- This is low-probability, but cryptographic failure should be fail-closed.

## Residual Risks And Gaps

- `NuMetal-Q/NuField/NuProfile.swift:465-472` explicitly sets both minimum security-bit gates to `0`, so the profile certificate does not enforce any quantitative release threshold. That is a governance risk rather than a code bug, but it means security claims remain informational unless backed by external review.
- The seal transcript’s `challengeScalar` path in `NuMetal-Q/NuField/Transcript.swift:48-50` reduces a single 64-bit word modulo `Fq`, unlike the 128-bit reduction used by `NuTranscriptField`. I did not elevate this to a formal finding because the larger structural issues above dominate, but it is still weaker challenge derivation than the rest of the codebase uses.
- I did not find tests covering any strict attestation verifier across both sides of sync or cluster flows, nor tests asserting that public seal verification rejects tampering of `finalAccumulatorCommitment`, `relaxationFactor`, or `errorTerms`.
