import XCTest
@testable import NuMetal_Q

final class EndToEndDemoTests: XCTestCase {
    func testSeedSealVerifyResumeFlow() async throws {
        let engine = try await AcceptanceSupport.makeEngine()
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "EndToEnd")
        let context = await engine.createContext(
            compiledShape: compiledShape,
            policy: .standard,
            appID: "NuMetalQ.EndToEndTests",
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

        let verification = try await engine.verify(
            envelope: sealedExport.proofEnvelope,
            compiledShape: compiledShape,
            verifySignature: AcceptanceSupport.verifier,
            sessionKey: sessionKey
        )

        XCTAssertTrue(verification.isValid)
        XCTAssertNil(verification.reason)

        let restored = try await context.resume(
            envelope: sealedExport.proofEnvelope,
            resumeArtifact: sealedExport.resumeArtifact,
            verifySignature: AcceptanceSupport.verifier,
            sessionKey: sessionKey
        )
        XCTAssertNotEqual(restored.chainID, handle.chainID)
        XCTAssertEqual(restored.shapeDigest, handle.shapeDigest)
    }
}
