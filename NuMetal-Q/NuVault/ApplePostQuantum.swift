import Foundation
import CryptoKit

// MARK: - Apple Post-Quantum Integration
// Concrete CryptoKit-backed helpers for ML-DSA signatures, ML-KEM key
// encapsulation, and key identifiers. These helpers keep the public SDK's
// closure-based boundary while giving applications a real Apple-native
// implementation on platforms that ship the post-quantum APIs.

public enum ApplePostQuantumError: Error, Sendable {
    case wrappedKeyMissing
    case unsupportedWrappedKeyAlgorithm(String)
    case secureEnclaveUnavailable
}

public enum ApplePostQuantumAlgorithm: String, Sendable, Codable {
    case mldsa87 = "mldsa87"
    case secureEnclaveMLDSA87 = "secure-enclave-mldsa87"
    case mlkem1024 = "mlkem1024"
}

/// Signing identity backed by a concrete Apple post-quantum keypair.
public struct PQSigningIdentity: Sendable {
    public let algorithm: ApplePostQuantumAlgorithm
    public let publicKeyRepresentation: Data
    public let signerKeyID: Data
    public let sign: PQSignClosure
    public let verify: PQVerifyClosure
    public let verifyEnvelope: PQKeyedVerifyClosure

    public init(
        algorithm: ApplePostQuantumAlgorithm,
        publicKeyRepresentation: Data,
        signerKeyID: Data? = nil,
        sign: @escaping PQSignClosure,
        verify: @escaping PQVerifyClosure,
        verifyEnvelope: PQKeyedVerifyClosure? = nil
    ) {
        self.algorithm = algorithm
        self.publicKeyRepresentation = publicKeyRepresentation
        self.signerKeyID = signerKeyID ?? ApplePostQuantum.keyIdentifier(
            publicKeyRepresentation: publicKeyRepresentation,
            algorithm: algorithm
        )
        self.sign = sign
        self.verify = verify
        let resolvedSignerKeyID = self.signerKeyID
        self.verifyEnvelope = verifyEnvelope ?? { message, signature, signerKeyID in
            guard signerKeyID == resolvedSignerKeyID else {
                return false
            }
            return try verify(message, signature)
        }
    }
}

/// Serialized wrapped symmetric key produced by Apple ML-KEM.
///
/// `wrappedArtifactKeys` on `ResumeArtifact` carry `serialize()` output from
/// this type so the private resume payload can be opened with an ML-KEM
/// private key.
public struct WrappedArtifactKey: Sendable, Codable, Equatable {
    private enum Limits {
        static let algorithmBytes = 64
        static let encapsulatedKeyBytes = 16 * 1024
    }

    public let algorithm: ApplePostQuantumAlgorithm
    public let encapsulatedKey: Data

    public init(algorithm: ApplePostQuantumAlgorithm, encapsulatedKey: Data) {
        self.algorithm = algorithm
        self.encapsulatedKey = encapsulatedKey
    }

    public func serialize() throws -> Data {
        var writer = BinaryWriter()
        writer.appendLengthPrefixed(Data(algorithm.rawValue.utf8))
        writer.appendLengthPrefixed(encapsulatedKey)
        return writer.data
    }

    public static func deserialize(_ data: Data) throws -> WrappedArtifactKey {
        var reader = BinaryReader(data)
        let algorithmData = try reader.readLengthPrefixedData(maxCount: Limits.algorithmBytes)
        let encapsulatedKey = try reader.readLengthPrefixedData(maxCount: Limits.encapsulatedKeyBytes)
        guard reader.isAtEnd,
              let rawAlgorithm = String(data: algorithmData, encoding: .utf8),
              let algorithm = ApplePostQuantumAlgorithm(rawValue: rawAlgorithm) else {
            throw BinaryReader.Error.invalidData
        }
        return WrappedArtifactKey(algorithm: algorithm, encapsulatedKey: encapsulatedKey)
    }
}

public enum ApplePostQuantum {
    public static let syncHPKEInfo = Data("NuMeQ.Sync.HPKE.XWing.v1".utf8)

    /// Stable key identifier derived from the public key bytes plus algorithm label.
    public static func keyIdentifier(
        publicKeyRepresentation: Data,
        algorithm: ApplePostQuantumAlgorithm
    ) -> Data {
        var hasher = SHA256()
        hasher.update(data: Data("NuMeQ.PQ.KeyID.v1".utf8))
        hasher.update(data: Data(algorithm.rawValue.utf8))
        hasher.update(data: publicKeyRepresentation)
        return Data(hasher.finalize())
    }

    public static func symmetricKeyData(_ key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }
}

#if NUMETALQ_APPLE_PQ
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
public extension ApplePostQuantum {
    static func makeMLDSA87Identity() throws -> PQSigningIdentity {
        let privateKey = try MLDSA87.PrivateKey()
        let publicKey = privateKey.publicKey
        let publicKeyBytes = publicKey.rawRepresentation

        return PQSigningIdentity(
            algorithm: .mldsa87,
            publicKeyRepresentation: publicKeyBytes,
            sign: { message in
                try privateKey.signature(for: message)
            },
            verify: { message, signature in
                publicKey.isValidSignature(signature, for: message)
            }
        )
    }

    static func makeMLDSA87Identity(
        seedRepresentation: Data,
        publicKey: MLDSA87.PublicKey? = nil
    ) throws -> PQSigningIdentity {
        let privateKey = try MLDSA87.PrivateKey(
            seedRepresentation: seedRepresentation,
            publicKey: publicKey
        )
        let resolvedPublicKey = privateKey.publicKey
        let publicKeyBytes = resolvedPublicKey.rawRepresentation

        return PQSigningIdentity(
            algorithm: .mldsa87,
            publicKeyRepresentation: publicKeyBytes,
            sign: { message in
                try privateKey.signature(for: message)
            },
            verify: { message, signature in
                resolvedPublicKey.isValidSignature(signature, for: message)
            }
        )
    }

    static func makeSecureEnclaveMLDSA87Identity() throws -> PQSigningIdentity {
        guard SecureEnclave.isAvailable else {
            throw ApplePostQuantumError.secureEnclaveUnavailable
        }

        let privateKey = try SecureEnclave.MLDSA87.PrivateKey()
        let publicKey = privateKey.publicKey
        let publicKeyBytes = publicKey.rawRepresentation

        return PQSigningIdentity(
            algorithm: .secureEnclaveMLDSA87,
            publicKeyRepresentation: publicKeyBytes,
            sign: { message in
                try privateKey.signature(for: message)
            },
            verify: { message, signature in
                publicKey.isValidSignature(signature, for: message)
            }
        )
    }

    static func wrapSessionKey(
        for recipientPublicKey: MLKEM1024.PublicKey
    ) throws -> (sessionKey: SymmetricKey, wrappedKey: WrappedArtifactKey) {
        let result = try recipientPublicKey.encapsulate()
        return (
            sessionKey: result.sharedSecret,
            wrappedKey: WrappedArtifactKey(
                algorithm: .mlkem1024,
                encapsulatedKey: result.encapsulated
            )
        )
    }

    static func unwrapSessionKey(
        _ wrappedKey: WrappedArtifactKey,
        using privateKey: MLKEM1024.PrivateKey
    ) throws -> SymmetricKey {
        guard wrappedKey.algorithm == .mlkem1024 else {
            throw ApplePostQuantumError.unsupportedWrappedKeyAlgorithm(
                wrappedKey.algorithm.rawValue
            )
        }
        return try privateKey.decapsulate(wrappedKey.encapsulatedKey)
    }

    static func unwrapSessionKey(
        _ wrappedKey: WrappedArtifactKey,
        using privateKey: SecureEnclave.MLKEM1024.PrivateKey
    ) throws -> SymmetricKey {
        guard wrappedKey.algorithm == .mlkem1024 else {
            throw ApplePostQuantumError.unsupportedWrappedKeyAlgorithm(
                wrappedKey.algorithm.rawValue
            )
        }
        return try privateKey.decapsulate(wrappedKey.encapsulatedKey)
    }
}
#endif
