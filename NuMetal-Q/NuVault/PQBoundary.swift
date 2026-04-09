import Foundation
import CryptoKit

// MARK: - Post-quantum boundary (CryptoKit envelope)
// Proof bytes never cross a device boundary without HPKE-derived AEAD keys
// and ML-DSA signatures (Secure Enclave–backed in production).

/// KEM ciphertext + info label for HPKE-style derivation of an AEAD key.
///
/// `sharedSecret` must be the raw output of an X-Wing / ML-KEM agreement
/// established out of band; it is not derived from classical ECDH.
public struct HPKEDerivedSenderSecret: Sendable {
    public let sharedSecret: Data
    public let kemCiphertext: Data
    public let info: Data

    public init(sharedSecret: Data, kemCiphertext: Data, info: Data = Data("NuMeQ.HPKE.Sync.v1".utf8)) {
        self.sharedSecret = sharedSecret
        self.kemCiphertext = kemCiphertext
        self.info = info
    }
}

public enum NuPQKDF: Sendable {
    /// Derives a 256-bit AES-GCM key from an HPKE shared secret (RFC 9180–style info/salt tagging).
    public static func deriveAEADKey(sharedSecret: Data, salt: Data, info: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecret),
            salt: salt,
            info: info,
            outputByteCount: 32
        )
    }
}

public enum AttestationPurpose: String, Sendable, Codable {
    case envelopeExport
    case envelopeVerification
    case syncEnvelope
    case clusterDelegation
    case clusterExecution
}

public struct AttestationContext: Sendable {
    public let purpose: AttestationPurpose
    public let appID: String?
    public let localDeviceID: UUID?
    public let remoteDeviceID: UUID?
    public let sessionID: UUID?
    public let messageID: UUID?
    public let shapeDigest: ShapeDigest?
    public let signerKeyID: Data?
    public let timestamp: Date
    public let payloadDigest: Data

    public init(
        purpose: AttestationPurpose,
        appID: String? = nil,
        localDeviceID: UUID? = nil,
        remoteDeviceID: UUID? = nil,
        sessionID: UUID? = nil,
        messageID: UUID? = nil,
        shapeDigest: ShapeDigest? = nil,
        signerKeyID: Data? = nil,
        timestamp: Date,
        payloadDigest: Data
    ) {
        self.purpose = purpose
        self.appID = appID
        self.localDeviceID = localDeviceID
        self.remoteDeviceID = remoteDeviceID
        self.sessionID = sessionID
        self.messageID = messageID
        self.shapeDigest = shapeDigest
        self.signerKeyID = signerKeyID
        self.timestamp = timestamp
        self.payloadDigest = payloadDigest
    }
}

public enum AttestationValidationError: Error, Sendable, Equatable {
    case missingVerifier
    case invalidAttestation
}

public typealias AttestationVerifier = @Sendable (Data, AttestationContext) throws -> Bool

/// ML-DSA (FIPS 204) signatures over arbitrary message bytes.
///
/// The concrete CryptoKit `MLDSA` types ship on supported Apple platforms;
/// call sites pass the signing closure from a Secure Enclave MLDSA87 private key.
public typealias PQMessageSignatureBytes = Data
public typealias PQSignClosure = @Sendable (Data) throws -> PQMessageSignatureBytes
public typealias PQVerifyClosure = @Sendable (Data, Data) throws -> Bool
public typealias PQKeyedVerifyClosure = @Sendable (Data, Data, Data) throws -> Bool

enum NuSecurityDigest {
    static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }
}
