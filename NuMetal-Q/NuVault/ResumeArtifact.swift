import Foundation
import CryptoKit

public struct ResumeArtifact: Sendable, Equatable {
    public static let currentVersion: UInt16 = 1

    public let version: UInt16
    public let proofDigest: Data
    public let ciphertext: Data
    public let nonce: Data
    public let tag: Data
    public let wrappedArtifactKeys: Data

    public init(
        version: UInt16 = ResumeArtifact.currentVersion,
        proofDigest: Data,
        ciphertext: Data,
        nonce: Data,
        tag: Data,
        wrappedArtifactKeys: Data = Data()
    ) {
        self.version = version
        self.proofDigest = proofDigest
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.tag = tag
        self.wrappedArtifactKeys = wrappedArtifactKeys
    }

    public func serialize() -> Data {
        var writer = BinaryWriter()
        writer.append(version)
        writer.appendLengthPrefixed(proofDigest)
        writer.appendLengthPrefixed(ciphertext)
        writer.append(nonce)
        writer.append(tag)
        writer.appendLengthPrefixed(wrappedArtifactKeys)
        return writer.data
    }

    public static func deserialize(_ data: Data) throws -> ResumeArtifact {
        var reader = BinaryReader(data)
        let version = try reader.readUInt16()
        let proofDigest = try reader.readLengthPrefixedData()
        let ciphertext = try reader.readLengthPrefixedData()
        let nonce = try reader.readData(count: 12)
        let tag = try reader.readData(count: 16)
        let wrappedArtifactKeys = try reader.readLengthPrefixedData()
        guard reader.isAtEnd else {
            throw BinaryReader.Error.invalidData
        }
        let artifact = ResumeArtifact(
            version: version,
            proofDigest: proofDigest,
            ciphertext: ciphertext,
            nonce: nonce,
            tag: tag,
            wrappedArtifactKeys: wrappedArtifactKeys
        )
        try artifact.validateCryptographicFormat()
        return artifact
    }

    func validateCryptographicFormat() throws {
        guard version == Self.currentVersion else {
            throw ResumeArtifactValidationError.unsupportedVersion(version)
        }
        guard nonce.count == 12 else {
            throw ResumeArtifactValidationError.invalidNonceLength(actual: nonce.count)
        }
        guard tag.count == 16 else {
            throw ResumeArtifactValidationError.invalidTagLength(actual: tag.count)
        }
        guard proofDigest.count == 32 else {
            throw ResumeArtifactValidationError.invalidProofDigest
        }
    }

    func decryptPayload(
        using sessionKey: SymmetricKey,
        proof: PublicSealProof
    ) throws -> ResumePayload {
        try validateCryptographicFormat()
        let serializedProof = try SealProofCodec.serialize(proof)
        let expectedProofDigest = Data(SealProofCodec.proofDigest(for: serializedProof))
        guard proofDigest == expectedProofDigest else {
            throw ResumeArtifactValidationError.invalidProofDigest
        }
        let aad = ResumeArtifactBuilder.aad(
            proof: proof,
            proofDigest: proofDigest
        )
        let sealedBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: nonce),
            ciphertext: ciphertext,
            tag: tag
        )
        let payload = try AES.GCM.open(sealedBox, using: sessionKey, authenticating: aad)
        return try ResumePayloadCodec.deserialize(payload)
    }

    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    public func unwrapArtifactKey(
        using privateKey: MLKEM1024.PrivateKey
    ) throws -> SymmetricKey {
        guard wrappedArtifactKeys.isEmpty == false else {
            throw ApplePostQuantumError.wrappedKeyMissing
        }
        let wrapped = try WrappedArtifactKey.deserialize(wrappedArtifactKeys)
        return try ApplePostQuantum.unwrapSessionKey(wrapped, using: privateKey)
    }

    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    public func unwrapArtifactKey(
        using privateKey: SecureEnclave.MLKEM1024.PrivateKey
    ) throws -> SymmetricKey {
        guard wrappedArtifactKeys.isEmpty == false else {
            throw ApplePostQuantumError.wrappedKeyMissing
        }
        let wrapped = try WrappedArtifactKey.deserialize(wrappedArtifactKeys)
        return try ApplePostQuantum.unwrapSessionKey(wrapped, using: privateKey)
    }
}

enum ResumeArtifactValidationError: Error, Sendable, Equatable {
    case unsupportedVersion(UInt16)
    case invalidNonceLength(actual: Int)
    case invalidTagLength(actual: Int)
    case invalidProofDigest
}

enum ResumeArtifactBuilder {
    static func build(
        payload: ResumePayload,
        proof: PublicSealProof,
        sessionKey: SymmetricKey,
        wrappedArtifactKeys: Data = Data()
    ) throws -> ResumeArtifact {
        let proofBytes = try SealProofCodec.serialize(proof)
        let proofDigest = Data(SealProofCodec.proofDigest(for: proofBytes))
        let aad = aad(proof: proof, proofDigest: proofDigest)
        let payloadBytes = try ResumePayloadCodec.serialize(payload)
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(
            payloadBytes,
            using: sessionKey,
            nonce: nonce,
            authenticating: aad
        )
        return ResumeArtifact(
            proofDigest: proofDigest,
            ciphertext: sealed.ciphertext,
            nonce: Data(nonce),
            tag: sealed.tag,
            wrappedArtifactKeys: wrappedArtifactKeys
        )
    }

    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    static func build(
        payload: ResumePayload,
        proof: PublicSealProof,
        recipientPublicKey: MLKEM1024.PublicKey
    ) throws -> ResumeArtifact {
        let wrapped = try ApplePostQuantum.wrapSessionKey(for: recipientPublicKey)
        return try build(
            payload: payload,
            proof: proof,
            sessionKey: wrapped.sessionKey,
            wrappedArtifactKeys: try wrapped.wrappedKey.serialize()
        )
    }

    static func aad(
        proof: PublicSealProof,
        proofDigest: Data
    ) -> Data {
        var writer = BinaryWriter()
        writer.appendLengthPrefixed(proofDigest)
        writer.append(Data(proof.statement.shapeDigest.bytes))
        writer.appendLengthPrefixed(Data(proof.statement.backendID.utf8))
        ResumePayloadCodec.encode(proof.statement.finalAccumulatorCommitment, into: &writer)
        writer.appendLengthPrefixed(Data(SealProofCodec.statementDigest(for: proof.statement)))
        return writer.data
    }
}
