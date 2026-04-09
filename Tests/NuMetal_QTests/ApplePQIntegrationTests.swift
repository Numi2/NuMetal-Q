import Foundation
import CryptoKit
import XCTest
@testable import NuMetal_Q

final class ApplePQIntegrationTests: XCTestCase {
    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    func testMLDSA87IdentitySignsAndVerifies() throws {
        let identity = try ApplePostQuantum.makeMLDSA87Identity()
        let message = Data("NuMeQ.ApplePQ.Signature".utf8)
        let signature = try identity.sign(message)

        XCTAssertTrue(try identity.verify(message, signature))
        XCTAssertFalse(try identity.verify(Data("tampered".utf8), signature))
        XCTAssertEqual(
            identity.signerKeyID,
            ApplePostQuantum.keyIdentifier(
                publicKeyRepresentation: identity.publicKeyRepresentation,
                algorithm: identity.algorithm
            )
        )
    }

    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    func testEnvelopeBuilderWrapsArtifactKeyWithMLKEM1024() throws {
        let signer = try ApplePostQuantum.makeMLDSA87Identity()
        let recipientPrivateKey = try MLKEM1024.PrivateKey()
        let proof = makeDummySealProof()
        let payload = makeDummyResumePayload()

        let envelope = try EnvelopeBuilder(
            profileID: NuProfile.canonical.profileID,
            appID: "NuMetalQ.ApplePQTests",
            teamID: "NuMetalQ.Tests",
            privacyMode: .fullZK,
            signerKeyID: signer.signerKeyID,
            sealParamDigest: Data(proof.statement.sealParamDigest)
        ).build(
            proof: proof,
            sign: signer.sign,
            attestation: Data("apple-pq-attestation".utf8)
        )
        let resumeArtifact = try ResumeArtifactBuilder.build(
            payload: payload,
            proof: proof,
            recipientPublicKey: recipientPrivateKey.publicKey
        )

        XCTAssertFalse(resumeArtifact.wrappedArtifactKeys.isEmpty)
        XCTAssertTrue(try signer.verify(envelope.signingPayload(), envelope.signature))

        let sessionKey = try resumeArtifact.unwrapArtifactKey(using: recipientPrivateKey)
        let decrypted = try resumeArtifact.decryptPayload(using: sessionKey, proof: proof)
        let decryptedViaPrivateKey = try resumeArtifact.decryptPayload(
            using: resumeArtifact.unwrapArtifactKey(using: recipientPrivateKey),
            proof: proof
        )
        let expectedProofData = try SealProofCodec.serialize(proof)

        XCTAssertEqual(ApplePostQuantum.symmetricKeyData(sessionKey).count, 32)
        XCTAssertEqual(envelope.proofBytes, expectedProofData)
        XCTAssertEqual(decrypted.accumulatorArtifact, payload.accumulatorArtifact)
        XCTAssertEqual(decryptedViaPrivateKey.accumulatorArtifact, payload.accumulatorArtifact)
    }

    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    func testFoldVaultUnlocksFromWrappedMLKEM1024MasterKey() async throws {
        let recipientPrivateKey = try MLKEM1024.PrivateKey()
        let wrapped = try ApplePostQuantum.wrapSessionKey(for: recipientPrivateKey.publicKey)
        let storageDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vault = FoldVault(storageDirectory: storageDirectory)

        try await vault.unlock(
            wrappedMasterKey: try wrapped.wrappedKey.serialize(),
            using: recipientPrivateKey
        )
        let isUnlocked = await vault.isUnlocked
        XCTAssertTrue(isUnlocked)

        let state = FoldState(
            shapeDigest: ShapeDigest(bytes: [UInt8](repeating: 0x31, count: 32)),
            commitment: AjtaiCommitment(value: .zero),
            witness: [.zero],
            publicInputs: [Fq(7), Fq(9)],
            normBudget: NormBudget(bound: 8, decompBase: 2, decompLimbs: 3),
            maxWitnessClass: .public
        )

        try await vault.store(state)
        let restored = try await vault.retrieve(chainID: state.chainID)
        XCTAssertEqual(restored.chainID, state.chainID)
        XCTAssertEqual(restored.shapeDigest, state.shapeDigest)
        XCTAssertEqual(restored.publicInputs, state.publicInputs)
    }

    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    func testXWingHPKESyncRoundTripsEnvelope() async throws {
        let signer = try ApplePostQuantum.makeMLDSA87Identity()
        let xwingRecipient = try XWingMLKEM768X25519.PrivateKey()
        let proof = makeDummySealProof()

        let envelope = try EnvelopeBuilder(
            profileID: NuProfile.canonical.profileID,
            appID: "NuMetalQ.ApplePQSync",
            teamID: "NuMetalQ.Tests",
            privacyMode: .fullZK,
            signerKeyID: signer.signerKeyID,
            sealParamDigest: Data(proof.statement.sealParamDigest)
        ).build(
            proof: proof,
            sign: signer.sign,
            attestation: Data("sync-attestation".utf8)
        )

        let senderID = UUID()
        let recipientID = UUID()
        let sender = try SyncChannel(
            localDeviceID: senderID,
            hpkeSharedSecret: AcceptanceSupport.sharedSecret,
            salt: AcceptanceSupport.syncSalt,
            info: AcceptanceSupport.syncInfo,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )
        let recipient = try SyncChannel(
            localDeviceID: recipientID,
            hpkeSharedSecret: AcceptanceSupport.sharedSecret,
            salt: AcceptanceSupport.syncSalt,
            info: AcceptanceSupport.syncInfo,
            attestationVerifier: AcceptanceSupport.attestationVerifier
        )

        let message = try await sender.sealUsingXWingHPKE(
            envelope: envelope,
            recipientID: recipientID,
            recipientPublicKey: xwingRecipient.publicKey,
            sign: signer.sign
        )
        let opened = try await recipient.openEnvelopeUsingXWingHPKE(
            message: message,
            recipientPrivateKey: xwingRecipient,
            verifySignature: signer.verify
        )

        XCTAssertEqual(opened.serialize(), envelope.serialize())
        XCTAssertEqual(opened.proofBytes, try SealProofCodec.serialize(proof))
    }

    func testSealProofCodecRoundTripsCanonicalWireFormat() throws {
        let proof = makeDummySealProof()
        let encoded = try SealProofCodec.serialize(proof)
        let decoded = try SealProofCodec.deserialize(encoded)
        XCTAssertEqual(try SealProofCodec.serialize(decoded), encoded)
    }

    func testSealProofCodecRejectsLegacyWireHeader() throws {
        let proof = makeDummySealProof()
        let encoded = try SealProofCodec.serialize(proof)
        let legacyEncoded = Data("NuSealP2".utf8) + encoded.dropFirst(Data("NuSealZK".utf8).count)
        XCTAssertThrowsError(try SealProofCodec.deserialize(legacyEncoded))
    }

    func testSealProofCodecRejectsTrailingBytes() throws {
        let proof = makeDummySealProof()
        var encoded = try SealProofCodec.serialize(proof)
        encoded.append(0xFF)
        XCTAssertThrowsError(try SealProofCodec.deserialize(encoded))
    }

    func testSealProofCodecRejectsVersionMismatch() throws {
        let proof = makeDummySealProof()
        var encoded = try SealProofCodec.serialize(proof)
        let magicCount = Data("NuSealZK".utf8).count
        encoded[magicCount] = 0xFF
        encoded[magicCount + 1] = 0x7F

        XCTAssertThrowsError(try SealProofCodec.deserialize(encoded))
    }

    func testFoldVaultRejectsCiphertextTransplantAcrossChainIDs() async throws {
        let storageDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vault = FoldVault(storageDirectory: storageDirectory)
        try await vault.unlock(with: Data("NuMetalQ.Vault.Transplant".utf8))

        let first = FoldState(
            shapeDigest: ShapeDigest(bytes: [UInt8](repeating: 0x11, count: 32)),
            commitment: AjtaiCommitment(value: .zero),
            witness: [.zero],
            publicInputs: [Fq(3)],
            normBudget: NormBudget(bound: 8, decompBase: 2, decompLimbs: 3),
            maxWitnessClass: .public
        )
        let second = FoldState(
            shapeDigest: ShapeDigest(bytes: [UInt8](repeating: 0x22, count: 32)),
            commitment: AjtaiCommitment(value: RingElement(coeffs: (0..<RingElement.degree).map { Fq(UInt64($0 + 1)) })),
            witness: [RingElement(coeffs: (0..<RingElement.degree).map { Fq(UInt64(($0 + 5) % 17)) })],
            publicInputs: [Fq(5)],
            normBudget: NormBudget(bound: 8, decompBase: 2, decompLimbs: 3),
            maxWitnessClass: .public
        )

        try await vault.store(first)
        try await vault.store(second)
        await vault.lock()
        try await vault.unlock(with: Data("NuMetalQ.Vault.Transplant".utf8))

        let firstURL = storageDirectory.appendingPathComponent("\(first.chainID.uuidString).vault")
        let secondURL = storageDirectory.appendingPathComponent("\(second.chainID.uuidString).vault")
        try FileManager.default.removeItem(at: firstURL)
        try FileManager.default.copyItem(at: secondURL, to: firstURL)

        do {
            _ = try await vault.retrieve(chainID: first.chainID)
            XCTFail("Expected transplanted ciphertext to be rejected")
        } catch let error as VaultError {
            XCTAssertEqual(error, .corruptedData)
        }
    }

    func testFoldVaultRejectsEmptyUnlockMaterial() async throws {
        let storageDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vault = FoldVault(storageDirectory: storageDirectory)

        do {
            try await vault.unlock(with: Data())
            XCTFail("Expected empty vault key material to be rejected")
        } catch let error as VaultError {
            XCTAssertEqual(error, .invalidKeyMaterial)
        }
    }

    private func makeDummySealProof() -> PublicSealProof {
        AcceptanceSupport.makeDummySealProof()
    }

    private func makeDummyResumePayload() -> ResumePayload {
        ResumePayload(
            accumulatorArtifact: Data("{\"version\":4}".utf8),
            normBudgetSnapshot: NormBudgetSnapshot(
                normBudget: NormBudget(bound: 32, decompBase: 2, decompLimbs: 4)
            ),
            provenanceClass: .public,
            stageAudit: []
        )
    }
}
