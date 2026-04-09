import XCTest
@testable import NuMetal_Q

final class EnvelopeSecurityTests: XCTestCase {
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
            verifySignature: AcceptanceSupport.verifier
        )

        XCTAssertFalse(verification.isValid)
        XCTAssertEqual(verification.reason, .invalidTimestamp)
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
