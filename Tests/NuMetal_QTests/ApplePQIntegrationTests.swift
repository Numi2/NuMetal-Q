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
    func testMLDSA87IdentityVerifyEnvelopeBindsSignerKeyID() throws {
        let identity = try ApplePostQuantum.makeMLDSA87Identity()
        let message = Data("NuMeQ.ApplePQ.Envelope".utf8)
        let signature = try identity.sign(message)

        XCTAssertTrue(try identity.verifyEnvelope(message, signature, identity.signerKeyID))
        XCTAssertFalse(
            try identity.verifyEnvelope(
                message,
                signature,
                Data(repeating: 0xA5, count: identity.signerKeyID.count)
            )
        )
    }

    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    func testMLKEM1024WrapUnwrapRoundTripsAndWrongKeyDoesNotRecoverSessionKey() throws {
        let recipientPrivateKey = try MLKEM1024.PrivateKey()
        let wrongPrivateKey = try MLKEM1024.PrivateKey()
        let wrapped = try ApplePostQuantum.wrapSessionKey(for: recipientPrivateKey.publicKey)

        let unwrapped = try ApplePostQuantum.unwrapSessionKey(
            wrapped.wrappedKey,
            using: recipientPrivateKey
        )
        let wrongUnwrapped = try ApplePostQuantum.unwrapSessionKey(
            wrapped.wrappedKey,
            using: wrongPrivateKey
        )

        XCTAssertEqual(
            ApplePostQuantum.symmetricKeyData(unwrapped),
            ApplePostQuantum.symmetricKeyData(wrapped.sessionKey)
        )
        XCTAssertNotEqual(
            ApplePostQuantum.symmetricKeyData(wrongUnwrapped),
            ApplePostQuantum.symmetricKeyData(wrapped.sessionKey)
        )
    }

    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    func testMLKEM1024UnwrapRejectsWrongWrappedKeyAlgorithm() throws {
        let privateKey = try MLKEM1024.PrivateKey()
        let wrappedKey = WrappedArtifactKey(
            algorithm: .mldsa87,
            encapsulatedKey: Data("not-a-kem-ciphertext".utf8)
        )

        XCTAssertThrowsError(
            try ApplePostQuantum.unwrapSessionKey(
                wrappedKey,
                using: privateKey
            )
        ) { error in
            guard case .unsupportedWrappedKeyAlgorithm(ApplePostQuantumAlgorithm.mldsa87.rawValue)
                = error as? ApplePostQuantumError else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
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
        XCTAssertEqual(restored.accumulatedWitness, state.accumulatedWitness)
        XCTAssertEqual(restored.commitment, state.commitment)
    }

    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    func testFoldVaultWrappedMasterKeyDoesNotReopenWithWrongRecipientKey() async throws {
        let recipientPrivateKey = try MLKEM1024.PrivateKey()
        let wrongPrivateKey = try MLKEM1024.PrivateKey()
        let wrapped = try ApplePostQuantum.wrapSessionKey(for: recipientPrivateKey.publicKey)
        let storageDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vault = FoldVault(storageDirectory: storageDirectory)

        let state = FoldState(
            shapeDigest: ShapeDigest(bytes: [UInt8](repeating: 0x41, count: 32)),
            commitment: AjtaiCommitment(value: RingElement(constant: Fq(9))),
            witness: [RingElement(constant: Fq(7))],
            publicInputs: [Fq(2), Fq(3)],
            normBudget: NormBudget(bound: 8, decompBase: 2, decompLimbs: 3),
            maxWitnessClass: .public
        )

        try await vault.unlock(
            wrappedMasterKey: try wrapped.wrappedKey.serialize(),
            using: recipientPrivateKey
        )
        try await vault.store(state)
        await vault.lock()

        try await vault.unlock(
            wrappedMasterKey: try wrapped.wrappedKey.serialize(),
            using: wrongPrivateKey
        )

        do {
            _ = try await vault.retrieve(chainID: state.chainID)
            XCTFail("Expected wrong ML-KEM recipient key to fail vault reopen")
        } catch let error as VaultError {
            XCTAssertEqual(error, .corruptedData)
        }
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

}
