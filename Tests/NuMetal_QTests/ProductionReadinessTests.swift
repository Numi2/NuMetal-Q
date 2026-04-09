import Foundation
import XCTest
@testable import NuMetal_Q

final class ProductionReadinessTests: XCTestCase {
    func testEnvelopeVerificationRejectsUnsupportedVersionEvenWithValidSignature() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "UnsupportedVersion")
        let context = await engine.createContext(
            compiledShape: compiledShape,
            policy: .standard,
            appID: "NuMetalQ.ProductionTests",
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )

        let publicInputs = [Fq(2), Fq(8)]
        let handle = try await context.seed(
            witness: AcceptanceSupport.makeWitness(seed: 7),
            publicInputs: publicInputs
        )
        let sessionKey = AcceptanceSupport.makeSessionKey()
        let sealedExport = try await context.seal(
            handle,
            sessionKey: sessionKey,
            signerKeyID: Data("wallet-signer".utf8),
            attestation: Data("wallet-attestation".utf8),
            signEnvelope: AcceptanceSupport.signer
        )

        let tampered = try AcceptanceSupport.resignEnvelope(
            sealedExport.proofEnvelope,
            version: sealedExport.proofEnvelope.version &+ 1
        )

        let verification = try await engine.verify(
            envelope: tampered,
            compiledShape: compiledShape,
            verifySignature: AcceptanceSupport.verifier,
            sessionKey: sessionKey
        )

        XCTAssertFalse(verification.isValid)
        XCTAssertEqual(verification.reason, VerificationFailure.unsupportedEnvelopeVersion)
    }

    func testEnvelopeVerificationFailsClosedForInvalidTimestampEvenWithValidSignature() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "MalformedNonce")
        let context = await engine.createContext(
            compiledShape: compiledShape,
            policy: .standard,
            appID: "NuMetalQ.ProductionTests",
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )

        let publicInputs = [Fq(13), Fq(21)]
        let handle = try await context.seed(
            witness: AcceptanceSupport.makeWitness(seed: 37),
            publicInputs: publicInputs
        )
        let sessionKey = AcceptanceSupport.makeSessionKey()
        let sealedExport = try await context.seal(
            handle,
            sessionKey: sessionKey,
            signerKeyID: Data("wallet-signer".utf8),
            attestation: Data("wallet-attestation".utf8),
            signEnvelope: AcceptanceSupport.signer
        )

        let tampered = try AcceptanceSupport.resignEnvelope(
            sealedExport.proofEnvelope,
            timestamp: Date(timeIntervalSince1970: .infinity)
        )

        let verification = try await engine.verify(
            envelope: tampered,
            compiledShape: compiledShape,
            verifySignature: AcceptanceSupport.verifier,
            sessionKey: sessionKey
        )

        XCTAssertFalse(verification.isValid)
        XCTAssertEqual(verification.reason, VerificationFailure.decryptionFailed)
    }

    func testEnvelopeVerificationRejectsBackendMismatchEvenWithValidSignature() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "BackendMismatch")
        let context = await engine.createContext(
            compiledShape: compiledShape,
            policy: .standard,
            appID: "NuMetalQ.ProductionTests",
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )

        let publicInputs = [Fq(3), Fq(5)]
        let handle = try await context.seed(
            witness: AcceptanceSupport.makeWitness(seed: 11),
            publicInputs: publicInputs
        )
        let sessionKey = AcceptanceSupport.makeSessionKey()
        let sealedExport = try await context.seal(
            handle,
            sessionKey: sessionKey,
            signerKeyID: Data("wallet-signer".utf8),
            attestation: Data("wallet-attestation".utf8),
            signEnvelope: AcceptanceSupport.signer
        )

        let tampered = try AcceptanceSupport.resignEnvelope(
            sealedExport.proofEnvelope,
            sealBackendID: "bogus-backend"
        )

        let verification = try await engine.verify(
            envelope: tampered,
            compiledShape: compiledShape,
            verifySignature: AcceptanceSupport.verifier,
            sessionKey: sessionKey
        )

        XCTAssertFalse(verification.isValid)
        XCTAssertEqual(verification.reason, VerificationFailure.proofInvalid)
    }

    func testEnvelopeVerificationRejectsPublicHeaderTamperingEvenWithValidSignature() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "HeaderMismatch")
        let context = await engine.createContext(
            compiledShape: compiledShape,
            policy: .standard,
            appID: "NuMetalQ.ProductionTests",
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )

        let publicInputs = [Fq(3), Fq(5)]
        let handle = try await context.seed(
            witness: AcceptanceSupport.makeWitness(seed: 41),
            publicInputs: publicInputs
        )
        let sessionKey = AcceptanceSupport.makeSessionKey()
        let sealedExport = try await context.seal(
            handle,
            sessionKey: sessionKey,
            signerKeyID: Data("wallet-signer".utf8),
            attestation: Data("wallet-attestation".utf8),
            signEnvelope: AcceptanceSupport.signer
        )

        var tamperedHeader = sealedExport.proofEnvelope.publicHeaderBytes
        tamperedHeader[0] ^= 0x01

        let tampered = try AcceptanceSupport.resignEnvelope(
            sealedExport.proofEnvelope,
            publicHeaderBytes: tamperedHeader
        )

        let verification = try await engine.verify(
            envelope: tampered,
            compiledShape: compiledShape,
            verifySignature: AcceptanceSupport.verifier,
            sessionKey: sessionKey
        )

        XCTAssertFalse(verification.isValid)
        XCTAssertEqual(verification.reason, VerificationFailure.proofInvalid)
    }

    func testEnvelopeVerificationRejectsProofByteTamperingEvenWithValidSignature() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "ProvenanceMismatch")
        let context = await engine.createContext(
            compiledShape: compiledShape,
            policy: .standard,
            appID: "NuMetalQ.ProductionTests",
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )

        let handle = try await context.seed(
            witness: AcceptanceSupport.makeWitness(seed: 53),
            publicInputs: [Fq(8), Fq(13)]
        )
        let sessionKey = AcceptanceSupport.makeSessionKey()
        let sealedExport = try await context.seal(
            handle,
            sessionKey: sessionKey,
            signerKeyID: Data("wallet-signer".utf8),
            attestation: Data("wallet-attestation".utf8),
            signEnvelope: AcceptanceSupport.signer
        )

        var tamperedProofBytes = sealedExport.proofEnvelope.proofBytes
        tamperedProofBytes[tamperedProofBytes.startIndex] ^= 0x01
        let tampered = try AcceptanceSupport.resignEnvelope(
            sealedExport.proofEnvelope,
            proofBytes: tamperedProofBytes
        )

        let verification = try await engine.verify(
            envelope: tampered,
            compiledShape: compiledShape,
            verifySignature: AcceptanceSupport.verifier,
            sessionKey: sessionKey
        )

        XCTAssertFalse(verification.isValid)
        XCTAssertEqual(verification.reason, VerificationFailure.proofInvalid)
    }

    func testResumeResealPreservesCanonicalAccumulatorArtifact() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "ResumeCanonicalAccumulator")
        let context = await engine.createContext(
            compiledShape: compiledShape,
            policy: .standard,
            appID: "NuMetalQ.ProductionTests",
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )

        let handle = try await context.seed(
            witness: AcceptanceSupport.makeWitness(seed: 73),
            publicInputs: [Fq(3), Fq(9)]
        )
        let sessionKey = AcceptanceSupport.makeSessionKey()
        let sealedExport = try await context.seal(
            handle,
            sessionKey: sessionKey,
            signerKeyID: Data("wallet-signer".utf8),
            attestation: Data("wallet-attestation".utf8),
            signEnvelope: AcceptanceSupport.signer
        )

        let originalProof = try sealedExport.proofEnvelope.proof()
        let originalPayload = try sealedExport.resumeArtifact.decryptPayload(
            using: sessionKey,
            proof: originalProof
        )
        let resumed = try await context.resume(
            envelope: sealedExport.proofEnvelope,
            resumeArtifact: sealedExport.resumeArtifact,
            verifySignature: AcceptanceSupport.verifier,
            sessionKey: sessionKey
        )
        let resealed = try await context.seal(
            resumed,
            sessionKey: sessionKey,
            signerKeyID: Data("wallet-signer".utf8),
            attestation: Data("wallet-attestation".utf8),
            signEnvelope: AcceptanceSupport.signer
        )
        let resealedProof = try resealed.proofEnvelope.proof()
        let resealedPayload = try resealed.resumeArtifact.decryptPayload(
            using: sessionKey,
            proof: resealedProof
        )

        XCTAssertEqual(resealedPayload.accumulatorArtifact, originalPayload.accumulatorArtifact)
        XCTAssertEqual(
            resealedProof.statement.finalAccumulatorCommitment,
            originalProof.statement.finalAccumulatorCommitment
        )
    }

    func testFinalAccumulatorArtifactRejectsLegacyVersion() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "LegacyAccumulatorArtifact")
        let context = await engine.createContext(
            compiledShape: compiledShape,
            policy: .standard,
            appID: "NuMetalQ.ProductionTests",
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )

        let handle = try await context.seed(
            witness: AcceptanceSupport.makeWitness(seed: 97),
            publicInputs: [Fq(5), Fq(8)]
        )
        let sessionKey = AcceptanceSupport.makeSessionKey()
        let sealedExport = try await context.seal(
            handle,
            sessionKey: sessionKey,
            signerKeyID: Data("wallet-signer".utf8),
            attestation: Data("wallet-attestation".utf8),
            signEnvelope: AcceptanceSupport.signer
        )
        let proof = try sealedExport.proofEnvelope.proof()
        let payload = try sealedExport.resumeArtifact.decryptPayload(
            using: sessionKey,
            proof: proof
        )
        var json = try XCTUnwrap(
            JSONSerialization.jsonObject(with: payload.accumulatorArtifact) as? [String: Any]
        )
        json["version"] = 3
        let legacyArtifact = try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys])

        XCTAssertThrowsError(try FoldAccumulator.deserialize(legacyArtifact))
    }
}
