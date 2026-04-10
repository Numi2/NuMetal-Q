import Foundation

extension ProofContext {
    // MARK: - Verify

    /// Verify a ProofEnvelope's signature and public terminal proof against the compiled shape.
    ///
    /// This is a static verification: it checks the envelope's cryptographic
    /// bindings without requiring any prover state.
    public func verify(
        envelope: ProofEnvelope,
        verifySignature: PQKeyedVerifyClosure,
        requireAttestation: Bool = false
    ) async throws -> VerificationResult {
        do {
            try envelope.validateCryptographicFormat()
        } catch let error as ProofEnvelopeValidationError {
            return VerificationResult(
                isValid: false,
                reason: verificationFailure(for: error)
            )
        }

        guard try envelope.isSignatureValid(verify: verifySignature) else {
            return VerificationResult(isValid: false, reason: .signatureInvalid)
        }
        guard envelope.shapeDigest == compiledShape.shape.digest else {
            return VerificationResult(isValid: false, reason: .shapeMismatch)
        }
        guard envelope.profileID == profile.profileID else {
            return VerificationResult(isValid: false, reason: .profileMismatch)
        }
        guard envelope.sealBackendID == sealBackend.backendID else {
            return VerificationResult(isValid: false, reason: .backendMismatch)
        }
        guard envelope.sealParamDigest == Data(NuParams.derive(from: profile).seal.parameterDigest) else {
            return VerificationResult(isValid: false, reason: .proofInvalid)
        }
        if let namespaceFailure = envelopeMatchesNamespace(
            envelope: envelope,
            expectedAppID: appID,
            expectedTeamID: teamID
        ) {
            return VerificationResult(isValid: false, reason: namespaceFailure)
        }

        switch validateEnvelopeAttestation(
            envelope,
            requireAttestation: requireAttestation,
            purpose: .envelopeVerification
        ) {
        case .valid:
            break
        case .required:
            return VerificationResult(isValid: false, reason: .attestationRequired)
        case .verifierMissing:
            return VerificationResult(isValid: false, reason: .attestationVerifierMissing)
        case .invalid:
            return VerificationResult(isValid: false, reason: .attestationInvalid)
        }

        let proof: PublicSealProof
        do {
            proof = try envelope.proof()
        } catch {
            return VerificationResult(isValid: false, reason: .proofInvalid)
        }
        guard publicHeaderMatchesShape(envelope.publicHeaderBytes, shape: compiledShape.shape) else {
            return VerificationResult(isValid: false, reason: .proofInvalid)
        }
        guard await sealBackend.verify(
            proof: proof,
            shape: compiledShape.shape,
            publicHeader: envelope.publicHeaderBytes
        ) else {
            return VerificationResult(isValid: false, reason: .proofInvalid)
        }

        return VerificationResult(isValid: true, reason: nil)
    }

    public func verify(
        envelope: ProofEnvelope,
        verifySignature: @escaping PQVerifyClosure,
        expectedSignerKeyID: Data,
        requireAttestation: Bool = false
    ) async throws -> VerificationResult {
        try await verify(
            envelope: envelope,
            verifySignature: keyedEnvelopeVerifier(
                expectedSignerKeyID: expectedSignerKeyID,
                verifySignature: verifySignature
            ),
            requireAttestation: requireAttestation
        )
    }

    func verifyEnvelopeAttestation(
        _ envelope: ProofEnvelope,
        requireAttestation: Bool,
        purpose: AttestationPurpose
    ) throws {
        switch validateEnvelopeAttestation(
            envelope,
            requireAttestation: requireAttestation,
            purpose: purpose
        ) {
        case .valid:
            return
        case .required:
            throw ProofContextError.attestationValidation(.invalidAttestation)
        case .verifierMissing:
            throw ProofContextError.attestationValidation(.missingVerifier)
        case .invalid:
            throw ProofContextError.attestationValidation(.invalidAttestation)
        }
    }

    func validateEnvelopeAttestation(
        _ envelope: ProofEnvelope,
        requireAttestation: Bool,
        purpose: AttestationPurpose
    ) -> EnvelopeAttestationValidation {
        guard let attestation = envelope.attestation, attestation.isEmpty == false else {
            return requireAttestation ? .required : .valid
        }
        guard let attestationVerifier else {
            return .verifierMissing
        }
        let context = AttestationContext(
            purpose: purpose,
            appID: envelope.appID,
            teamID: envelope.teamID,
            shapeDigest: envelope.shapeDigest,
            signerKeyID: envelope.signerKeyID,
            timestamp: envelope.timestamp,
            payloadDigest: NuSecurityDigest.sha256(envelope.attestationBindingPayload())
        )
        do {
            return try attestationVerifier(attestation, context) ? .valid : .invalid
        } catch {
            return .invalid
        }
    }
}
