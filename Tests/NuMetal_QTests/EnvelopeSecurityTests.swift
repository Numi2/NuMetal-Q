import XCTest
@testable import NuMetal_Q

final class EnvelopeSecurityTests: XCTestCase {
    func testSealRejectsEphemeralDerivedWitnessPersistence() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "EphemeralSealPersistence")
        let policy = NuPolicy(
            laneClasses: ["amounts": .ephemeralDerived],
            defaultClass: .syncableEncrypted,
            clusterDelegationAllowed: true,
            maxDelegatableClass: .syncableEncrypted
        )
        let context = await engine.createContext(
            compiledShape: compiledShape,
            policy: policy,
            appID: "NuMetalQ.Tests.EphemeralSeal"
        )
        let handle = try await context.seed(
            witness: AcceptanceSupport.makeWitness(seed: 13),
            publicInputs: [Fq(5), Fq(9)]
        )

        do {
            _ = try await context.seal(
                handle,
                sessionKey: AcceptanceSupport.makeSessionKey(),
                signerKeyID: Data("test-signer".utf8),
                signEnvelope: AcceptanceSupport.signer
            )
            XCTFail("Expected ephemeral witness state to be rejected for persistence")
        } catch let error as ProofContextError {
            guard case let .policyViolation(violation) = error else {
                return XCTFail("Unexpected proof context error: \(error)")
            }
            XCTAssertEqual(violation.kind, .ephemeralCannotPersist)
        }
    }

    func testSealProofCodecRejectsZeroInstanceStatement() throws {
        let serialized = try SealProofCodec.serialize(makeMinimalPublicSealProof(instanceCount: 0))

        XCTAssertThrowsError(try SealProofCodec.deserialize(serialized)) { error in
            guard let codecError = error as? BinaryReader.Error,
                  case .invalidData = codecError else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
    }

    func testSealProofCodecRejectsOversizedPublicInputVectorCount() throws {
        XCTAssertThrowsError(try SealProofCodec.deserialize(makeOversizedPublicInputsSealProof())) { error in
            guard let codecError = error as? BinaryReader.Error,
                  case .invalidData = codecError else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
    }

    func testPublicStatementBindingRejectsMismatchedHeaderEncoding() throws {
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "HeaderBindingMismatch")
        let mismatchedHeader = Data([1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0])

        XCTAssertFalse(
            publicStatementMatchesHeader(
                publicHeader: mismatchedHeader,
                publicInputs: [Fq(1), Fq(3)],
                shape: compiledShape.shape
            )
        )
    }

    func testVerificationRequiresAttestationWhenRequested() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "AttestationRequired")
        let envelope = try AcceptanceSupport.makeSyntheticEnvelope(compiledShape: compiledShape)

        let verification = try await engine.verify(
            envelope: envelope,
            compiledShape: compiledShape,
            verifySignature: AcceptanceSupport.verifier,
            expectedSignerKeyID: envelope.signerKeyID,
            expectedAppID: envelope.appID,
            expectedTeamID: envelope.teamID,
            attestationVerifier: AcceptanceSupport.attestationVerifier,
            requireAttestation: true
        )

        XCTAssertFalse(verification.isValid)
        XCTAssertEqual(verification.reason, .attestationRequired)
    }

    func testVerificationRejectsAttestationBoundToDifferentContext() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "AttestationContextMismatch")
        let unsigned = try AcceptanceSupport.makeSyntheticEnvelope(compiledShape: compiledShape)
        let attestation = try AcceptanceSupport.makeVerificationAttestation(for: unsigned)
        let attested = try AcceptanceSupport.resignEnvelope(unsigned, attestation: attestation)
        let tampered = try AcceptanceSupport.resignEnvelope(
            attested,
            appID: "NuMetalQ.Tests.Tampered"
        )

        let verification = try await engine.verify(
            envelope: tampered,
            compiledShape: compiledShape,
            verifySignature: AcceptanceSupport.verifier,
            expectedSignerKeyID: tampered.signerKeyID,
            expectedAppID: tampered.appID,
            expectedTeamID: tampered.teamID,
            attestationVerifier: AcceptanceSupport.attestationVerifier,
            requireAttestation: true
        )

        XCTAssertFalse(verification.isValid)
        XCTAssertEqual(verification.reason, .attestationInvalid)
    }

    func testVerificationFallsThroughToProofValidationWhenAttestationMatches() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "AttestationThenProof")
        let unsigned = try AcceptanceSupport.makeSyntheticEnvelope(compiledShape: compiledShape)
        let attested = try AcceptanceSupport.resignEnvelope(
            unsigned,
            attestation: try AcceptanceSupport.makeVerificationAttestation(for: unsigned)
        )

        let verification = try await engine.verify(
            envelope: attested,
            compiledShape: compiledShape,
            verifySignature: AcceptanceSupport.verifier,
            expectedSignerKeyID: attested.signerKeyID,
            expectedAppID: attested.appID,
            expectedTeamID: attested.teamID,
            attestationVerifier: AcceptanceSupport.attestationVerifier,
            requireAttestation: true
        )

        XCTAssertFalse(verification.isValid)
        XCTAssertEqual(verification.reason, .proofInvalid)
    }

    func testVerificationMapsInvalidTimestampSeparately() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "InvalidTimestamp")
        let envelope = try AcceptanceSupport.makeSyntheticEnvelope(
            compiledShape: compiledShape,
            timestamp: Date(timeIntervalSince1970: .infinity)
        )

        let verification = try await engine.verify(
            envelope: envelope,
            compiledShape: compiledShape,
            verifySignature: AcceptanceSupport.verifier,
            expectedSignerKeyID: envelope.signerKeyID,
            expectedAppID: envelope.appID,
            expectedTeamID: envelope.teamID
        )

        XCTAssertFalse(verification.isValid)
        XCTAssertEqual(verification.reason, .invalidTimestamp)
    }

    func testVerificationRejectsAppNamespaceMismatch() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "AppNamespaceMismatch")
        let envelope = try AcceptanceSupport.makeSyntheticEnvelope(compiledShape: compiledShape)

        let verification = try await engine.verify(
            envelope: envelope,
            compiledShape: compiledShape,
            verifySignature: AcceptanceSupport.verifier,
            expectedSignerKeyID: envelope.signerKeyID,
            expectedAppID: "NuMetalQ.Tests.Other",
            expectedTeamID: envelope.teamID
        )

        XCTAssertFalse(verification.isValid)
        XCTAssertEqual(verification.reason, .appIDMismatch)
    }

    func testVerificationRejectsTeamNamespaceMismatch() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "TeamNamespaceMismatch")
        let envelope = try AcceptanceSupport.makeSyntheticEnvelope(compiledShape: compiledShape)

        let verification = try await engine.verify(
            envelope: envelope,
            compiledShape: compiledShape,
            verifySignature: AcceptanceSupport.verifier,
            expectedSignerKeyID: envelope.signerKeyID,
            expectedAppID: envelope.appID,
            expectedTeamID: "NuMetalQ.OtherTeam"
        )

        XCTAssertFalse(verification.isValid)
        XCTAssertEqual(verification.reason, .teamIDMismatch)
    }

    func testVerificationRejectsUnexpectedSignerKeyIDInPlainVerifierOverload() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "SignerKeyIDMismatch")
        let envelope = try AcceptanceSupport.makeSyntheticEnvelope(compiledShape: compiledShape)

        let verification = try await engine.verify(
            envelope: envelope,
            compiledShape: compiledShape,
            verifySignature: AcceptanceSupport.verifier,
            expectedSignerKeyID: Data("wrong-signer".utf8),
            expectedAppID: envelope.appID,
            expectedTeamID: envelope.teamID
        )

        XCTAssertFalse(verification.isValid)
        XCTAssertEqual(verification.reason, .signatureInvalid)
    }

    func testSealRequiresAttestationForStandardPolicyExport() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "SealAttestationRequired")
        let context = await engine.createContext(
            compiledShape: compiledShape,
            policy: .standard,
            appID: "NuMetalQ.Tests.AttestationRequired"
        )
        let handle = try await context.seed(
            witness: AcceptanceSupport.makeWitness(seed: 17),
            publicInputs: [Fq(8), Fq(13)]
        )

        do {
            _ = try await context.seal(
                handle,
                sessionKey: AcceptanceSupport.makeSessionKey(),
                signerKeyID: Data("test-signer".utf8),
                signEnvelope: AcceptanceSupport.signer
            )
            XCTFail("Expected export attestation policy to be enforced")
        } catch let error as ProofContextError {
            guard case let .policyViolation(violation) = error else {
                return XCTFail("Unexpected proof context error: \(error)")
            }
            XCTAssertEqual(violation.kind, .attestationRequired)
        }
    }

    func testEnvelopeBuilderCanonicalizesEmptyAttestationForSignatureRoundTrip() throws {
        let builder = EnvelopeBuilder(
            profileID: NuProfile.canonical.profileID,
            appID: "NuMetalQ.Tests",
            teamID: "NuMetalQ",
            privacyMode: .fullZK,
            signerKeyID: Data("test-signer".utf8),
            sealParamDigest: Data(NuParams.derive(from: .canonical).seal.parameterDigest)
        )
        let envelope = try builder.build(
            proof: makeMinimalPublicSealProof(instanceCount: 1),
            sign: AcceptanceSupport.signer,
            attestation: Data()
        )
        let decoded = try ProofEnvelope.deserialize(envelope.serialize())

        XCTAssertNil(envelope.attestation)
        XCTAssertNil(decoded.attestation)
        XCTAssertTrue(try decoded.isSignatureValid { message, signature, _ in
            try AcceptanceSupport.verifier(message, signature)
        })
    }

    func testProofEnvelopeDeserializeRejectsOversizedProofBlobLengthPrefix() throws {
        var writer = BinaryWriter()
        writer.append(ProofEnvelope.currentVersion)
        writer.append(Data(NuProfile.canonical.profileID.bytes))
        writer.appendLengthPrefixed(Data("NuMetalQ.Tests".utf8))
        writer.appendLengthPrefixed(Data("NuMetalQ".utf8))
        writer.append(Data(ShapeDigest(bytes: [UInt8](repeating: 0x11, count: 32)).bytes))
        writer.appendLengthPrefixed(Data(repeating: 0x22, count: 32))
        writer.appendLengthPrefixed(Data())
        writer.appendLengthPrefixed(Data(NuSealConstants.productionBackendID.utf8))
        writer.appendLengthPrefixed(Data(repeating: 0x33, count: 32))
        writer.append(PrivacyMode.fullZK.rawValue)
        writer.append(UInt32(16 * 1024 * 1024 + 1))

        XCTAssertThrowsError(try ProofEnvelope.deserialize(writer.data)) { error in
            guard let readerError = error as? BinaryReader.Error,
                  case .invalidData = readerError else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
    }

    func testConstrainedRelationRejectsInvalidWitnessBinding() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeConstrainedCompiledShape(name: "SeedConstraint")
        let context = await engine.createContext(
            compiledShape: compiledShape,
            policy: .standard,
            appID: "NuMetalQ.Tests.Constraint"
        )

        let witness = AcceptanceSupport.makeWitness(seed: 11)
        let flattened = witness.flatten()
        XCTAssertTrue(compiledShape.shape.relation.isSatisfied(by: [Fq(11), Fq(5)] + flattened))
        XCTAssertFalse(compiledShape.shape.relation.isSatisfied(by: [Fq(12), Fq(5)] + flattened))

        do {
            _ = try await context.seed(
                witness: witness,
                publicInputs: [Fq(12), Fq(5)]
            )
            XCTFail("Expected constrained relation to reject mismatched public input")
        } catch let error as FoldEngineError {
            if case .recursiveStageVerificationFailed(stage: .piCCS) = error {
                return
            }
            XCTFail("Unexpected fold engine error: \(error)")
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
}

private func makeMinimalPublicSealProof(instanceCount: UInt32) -> PublicSealProof {
    let commitment = HachiPCSCommitment(
        oracle: .witness(),
        tableCommitment: AjtaiCommitment(value: .zero),
        tableDigest: [],
        merkleRoot: [],
        parameterDigest: [],
        valueCount: 0,
        codewordLength: 0
    )
    let openingProof = HachiPCSBatchOpeningProof(batchSeedDigest: [], classes: [])
    let terminalProof = HachiTerminalProof(
        witnessCommitment: commitment,
        matrixEvaluationCommitments: [],
        blindingCommitments: SpartanBlindingCommitments(
            witness: commitment,
            matrixRows: []
        ),
        outerSumcheck: SpartanSumcheckProof(roundEvaluations: []),
        innerSumcheck: SpartanSumcheckProof(roundEvaluations: []),
        claimedEvaluations: SpartanClaimedEvaluations(
            rowPoint: [],
            columnPoint: [],
            matrixRowEvaluations: [],
            witnessEvaluation: .zero
        ),
        blindingEvaluations: SpartanBlindingEvaluations(
            matrixRows: [],
            witness: .zero
        ),
        pcsOpeningProof: openingProof,
        blindingOpeningProof: openingProof
    )
    let statement = PublicSealStatement(
        backendID: NuSealConstants.productionBackendID,
        sealTranscriptID: NuSealConstants.sealTranscriptID,
        shapeDigest: ShapeDigest(bytes: [UInt8](repeating: 0x11, count: 32)),
        deciderLayoutDigest: [],
        sealParamDigest: [],
        publicHeader: Data(),
        publicInputs: Array(repeating: .zero, count: Int(instanceCount))
    )
    return PublicSealProof(statement: statement, terminalProof: terminalProof)
}

private func makeOversizedPublicInputsSealProof() throws -> Data {
    var serialized = try SealProofCodec.serialize(makeMinimalPublicSealProof(instanceCount: 1))
    let backendIDBytes = NuSealConstants.productionBackendID.utf8.count
    let transcriptIDBytes = NuSealConstants.sealTranscriptID.utf8.count
    let offset =
        8
        + 2
        + 4 + backendIDBytes
        + 4 + transcriptIDBytes
        + 32
        + 4
        + 4
        + 4
    let oversizedCount = UInt32(65_537).littleEndian
    withUnsafeBytes(of: oversizedCount) { bytes in
        serialized.replaceSubrange(offset..<offset + MemoryLayout<UInt32>.size, with: bytes)
    }
    return serialized
}
