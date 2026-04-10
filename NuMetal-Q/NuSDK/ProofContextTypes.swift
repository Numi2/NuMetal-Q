import Foundation

enum EnvelopeAttestationValidation {
    case valid
    case required
    case verifierMissing
    case invalid
}

/// Opaque handle to an in-progress proof.
///
/// ProofHandle is a lightweight reference to a FoldState managed by a ProofContext.
/// The underlying state is never exposed through this handle.
public struct ProofHandle: Sendable, Hashable {
    public let chainID: UUID
    public let shapeDigest: ShapeDigest
}

/// Receipt for a cluster-assisted seed operation.
public struct ClusterSeedReceipt: Sendable {
    public let handle: ProofHandle
    public let delegatedCommitment: AjtaiCommitment
    public let finalCommitment: AjtaiCommitment
    public let confinedIndices: [Int]
    public let laneCommitments: [ClusterLaneCommitment]
}

public enum ClusterExecutionEligibility: Sendable, Equatable {
    case allowed
    case blocked(maxWitnessClass: WitnessClass)
}

/// Result of envelope verification.
public struct VerificationResult: Sendable {
    public let isValid: Bool
    public let reason: VerificationFailure?
}

public enum VerificationFailure: Sendable, Equatable {
    case signatureInvalid
    case signerIdentityMissing
    case unsupportedEnvelopeVersion
    case invalidTimestamp
    case appIDMismatch
    case teamIDMismatch
    case shapeMismatch
    case profileMismatch
    case backendMismatch
    case attestationRequired
    case attestationVerifierMissing
    case attestationInvalid
    case proofInvalid
}

func verificationFailure(for error: ProofEnvelopeValidationError) -> VerificationFailure {
    switch error {
    case .unsupportedVersion:
        return .unsupportedEnvelopeVersion
    case .missingSignerKeyID:
        return .signerIdentityMissing
    case .missingAppID:
        return .proofInvalid
    case .invalidTimestamp:
        return .invalidTimestamp
    case .unsupportedPrivacyMode,
            .invalidSealBackend,
            .invalidSealParamDigest,
            .missingTeamID,
            .invalidPublicHeaderDigest,
            .missingProofBytes:
        return .proofInvalid
    }
}

public enum ProofContextError: Error, Sendable {
    case handleNotFound
    case insufficientInputs
    case shapeMismatch
    case witnessShapeMismatch
    case invalidWitnessElementCount(expected: Int, actual: Int)
    case invalidPublicInputCount(expected: Int, actual: Int)
    case sealFailed
    case recursiveFoldingUnavailable
    case unsupportedStoredState
    case accumulatorTooLarge
    case witnessExceedsPiDECRepresentability(maxMagnitude: UInt64, base: UInt8, limbs: UInt8)
    case policyViolation(PolicyViolation)
    case attestationValidation(AttestationValidationError)
    case clusterResultInvalid
    case clusterDelegationProhibited(WitnessClass)
    case proofVerificationFailed
}
