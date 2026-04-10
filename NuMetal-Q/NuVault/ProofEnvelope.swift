import Foundation

public enum PrivacyMode: UInt8, Sendable, Codable {
    case fullZK = 0
    case selectiveDisclosure = 1
    case transparent = 2
}

public struct ProofEnvelope: Sendable {
    public static let currentVersion: UInt16 = 4

    private static let digestByteCount = 32
    private static let maxAppIDBytes = 512
    private static let maxTeamIDBytes = 512
    private static let maxSealBackendIDBytes = 128
    private static let maxPublicHeaderBytes = 64 * 1024
    private static let maxProofBytes = 16 * 1024 * 1024
    private static let maxSignerKeyIDBytes = 4 * 1024
    private static let maxSignatureBytes = 64 * 1024
    private static let maxAttestationBytes = 1 * 1024 * 1024

    public let version: UInt16
    public let profileID: ProfileID
    public let appID: String
    public let teamID: String
    public let shapeDigest: ShapeDigest
    public let publicHeaderDigest: Data
    public let publicHeaderBytes: Data
    public let sealBackendID: String
    public let sealParamDigest: Data
    public let privacyMode: PrivacyMode
    public let proofBytes: Data
    public let signerKeyID: Data
    public let signature: Data
    public let attestation: Data?
    public let timestamp: Date

    public func signingPayload() -> Data {
        unsignedPayload(includeAttestation: true)
    }

    public func attestationBindingPayload() -> Data {
        unsignedPayload(includeAttestation: false)
    }

    public func isSignatureValid(verify: PQKeyedVerifyClosure) throws -> Bool {
        try verify(signingPayload(), signature, signerKeyID)
    }

    public func proof() throws -> PublicSealProof {
        try SealProofCodec.deserialize(proofBytes)
    }

    func validateCryptographicFormat() throws {
        guard version == Self.currentVersion else {
            throw ProofEnvelopeValidationError.unsupportedVersion(version)
        }
        guard privacyMode == .fullZK else {
            throw ProofEnvelopeValidationError.unsupportedPrivacyMode(privacyMode)
        }
        guard appID.isEmpty == false else {
            throw ProofEnvelopeValidationError.missingAppID
        }
        guard sealBackendID == NuSealConstants.productionBackendID else {
            throw ProofEnvelopeValidationError.invalidSealBackend
        }
        guard signerKeyID.isEmpty == false else {
            throw ProofEnvelopeValidationError.missingSignerKeyID
        }
        guard teamID.isEmpty == false else {
            throw ProofEnvelopeValidationError.missingTeamID
        }
        guard proofBytes.isEmpty == false else {
            throw ProofEnvelopeValidationError.missingProofBytes
        }
        guard publicHeaderDigest.count == Self.digestByteCount else {
            throw ProofEnvelopeValidationError.invalidPublicHeaderDigest
        }
        guard sealParamDigest.count == Self.digestByteCount else {
            throw ProofEnvelopeValidationError.invalidSealParamDigest
        }
        guard publicHeaderDigest == NuSecurityDigest.sha256(publicHeaderBytes) else {
            throw ProofEnvelopeValidationError.invalidPublicHeaderDigest
        }
        guard timestamp.timeIntervalSince1970.isFinite else {
            throw ProofEnvelopeValidationError.invalidTimestamp
        }
    }

    public func serialize() -> Data {
        var writer = BinaryWriter()
        writer.append(version)
        writer.append(Data(profileID.bytes))
        writer.appendLengthPrefixed(Data(appID.utf8))
        writer.appendLengthPrefixed(Data(teamID.utf8))
        writer.append(Data(shapeDigest.bytes))
        writer.appendLengthPrefixed(publicHeaderDigest)
        writer.appendLengthPrefixed(publicHeaderBytes)
        writer.appendLengthPrefixed(Data(sealBackendID.utf8))
        writer.appendLengthPrefixed(sealParamDigest)
        writer.append(privacyMode.rawValue)
        writer.appendLengthPrefixed(proofBytes)
        writer.appendLengthPrefixed(signerKeyID)
        writer.appendLengthPrefixed(signature)
        writer.appendLengthPrefixed(canonicalAttestation ?? Data())
        writer.append(timestamp.timeIntervalSince1970)
        return writer.data
    }

    public static func deserialize(_ data: Data) throws -> ProofEnvelope {
        var reader = BinaryReader(data)
        let version = try reader.readUInt16()
        let profileID = ProfileID(bytes: Array(try reader.readData(count: 32)))
        let appID = try decodeString(from: &reader, maxBytes: Self.maxAppIDBytes)
        let teamID = try decodeString(from: &reader, maxBytes: Self.maxTeamIDBytes)
        let shapeDigest = ShapeDigest(bytes: Array(try reader.readData(count: 32)))
        let publicHeaderDigest = try reader.readLengthPrefixedData(maxCount: Self.digestByteCount)
        let publicHeaderBytes = try reader.readLengthPrefixedData(maxCount: Self.maxPublicHeaderBytes)
        let sealBackendID = try decodeString(from: &reader, maxBytes: Self.maxSealBackendIDBytes)
        let sealParamDigest = try reader.readLengthPrefixedData(maxCount: Self.digestByteCount)
        guard let privacyMode = PrivacyMode(rawValue: try reader.readUInt8()) else {
            throw BinaryReader.Error.invalidData
        }
        let proofBytes = try reader.readLengthPrefixedData(maxCount: Self.maxProofBytes)
        let signerKeyID = try reader.readLengthPrefixedData(maxCount: Self.maxSignerKeyIDBytes)
        let signature = try reader.readLengthPrefixedData(maxCount: Self.maxSignatureBytes)
        let attestationData = try reader.readLengthPrefixedData(maxCount: Self.maxAttestationBytes)
        let timestamp = Date(timeIntervalSince1970: try reader.readDouble())

        guard reader.isAtEnd else {
            throw BinaryReader.Error.invalidData
        }

        return ProofEnvelope(
            version: version,
            profileID: profileID,
            appID: appID,
            teamID: teamID,
            shapeDigest: shapeDigest,
            publicHeaderDigest: publicHeaderDigest,
            publicHeaderBytes: publicHeaderBytes,
            sealBackendID: sealBackendID,
            sealParamDigest: sealParamDigest,
            privacyMode: privacyMode,
            proofBytes: proofBytes,
            signerKeyID: signerKeyID,
            signature: signature,
            attestation: attestationData.isEmpty ? nil : attestationData,
            timestamp: timestamp
        )
    }

    private func unsignedPayload(includeAttestation: Bool) -> Data {
        var writer = BinaryWriter()
        writer.append(version)
        writer.append(Data(profileID.bytes))
        writer.appendLengthPrefixed(Data(appID.utf8))
        writer.appendLengthPrefixed(Data(teamID.utf8))
        writer.append(Data(shapeDigest.bytes))
        writer.appendLengthPrefixed(publicHeaderDigest)
        writer.appendLengthPrefixed(publicHeaderBytes)
        writer.appendLengthPrefixed(Data(sealBackendID.utf8))
        writer.appendLengthPrefixed(sealParamDigest)
        writer.append(privacyMode.rawValue)
        writer.appendLengthPrefixed(proofBytes)
        writer.appendLengthPrefixed(signerKeyID)

        if includeAttestation {
            writer.appendLengthPrefixed(canonicalAttestation ?? Data())
        }

        writer.append(timestamp.timeIntervalSince1970)
        return writer.data
    }

    private var canonicalAttestation: Data? {
        guard let attestation, attestation.isEmpty == false else {
            return nil
        }
        return attestation
    }

    private static func decodeString(
        from reader: inout BinaryReader,
        maxBytes: Int
    ) throws -> String {
        let data = try reader.readLengthPrefixedData(maxCount: maxBytes)
        guard let string = String(data: data, encoding: .utf8) else {
            throw BinaryReader.Error.invalidData
        }
        return string
    }
}

enum ProofEnvelopeValidationError: Error, Sendable {
    case unsupportedVersion(UInt16)
    case unsupportedPrivacyMode(PrivacyMode)
    case missingAppID
    case invalidSealBackend
    case missingSignerKeyID
    case missingTeamID
    case missingProofBytes
    case invalidPublicHeaderDigest
    case invalidSealParamDigest
    case invalidTimestamp
}

public struct EnvelopeBuilder: Sendable {
    public let profileID: ProfileID
    public let appID: String
    public let teamID: String
    public let privacyMode: PrivacyMode
    public let signerKeyID: Data
    public let sealParamDigest: Data

    public init(
        profileID: ProfileID,
        appID: String,
        teamID: String,
        privacyMode: PrivacyMode = .fullZK,
        signerKeyID: Data = Data(),
        sealParamDigest: Data
    ) {
        self.profileID = profileID
        self.appID = appID
        self.teamID = teamID
        self.privacyMode = privacyMode
        self.signerKeyID = signerKeyID
        self.sealParamDigest = sealParamDigest
    }

    public func build(
        proof: PublicSealProof,
        sign: PQSignClosure,
        attestation: Data? = nil
    ) throws -> ProofEnvelope {
        guard signerKeyID.isEmpty == false else {
            throw ProofEnvelopeValidationError.missingSignerKeyID
        }
        let proofBytes = try SealProofCodec.serialize(proof)
        let headerDigest = NuSecurityDigest.sha256(proof.statement.publicHeader)

        let canonicalAttestation = attestation?.isEmpty == false ? attestation : nil
        let unsigned = ProofEnvelope(
            version: ProofEnvelope.currentVersion,
            profileID: profileID,
            appID: appID,
            teamID: teamID,
            shapeDigest: proof.statement.shapeDigest,
            publicHeaderDigest: headerDigest,
            publicHeaderBytes: proof.statement.publicHeader,
            sealBackendID: NuSealConstants.productionBackendID,
            sealParamDigest: sealParamDigest,
            privacyMode: privacyMode,
            proofBytes: proofBytes,
            signerKeyID: signerKeyID,
            signature: Data(),
            attestation: canonicalAttestation,
            timestamp: Date()
        )

        return ProofEnvelope(
            version: unsigned.version,
            profileID: profileID,
            appID: appID,
            teamID: teamID,
            shapeDigest: proof.statement.shapeDigest,
            publicHeaderDigest: headerDigest,
            publicHeaderBytes: proof.statement.publicHeader,
            sealBackendID: NuSealConstants.productionBackendID,
            sealParamDigest: sealParamDigest,
            privacyMode: privacyMode,
            proofBytes: proofBytes,
            signerKeyID: signerKeyID,
            signature: try sign(unsigned.signingPayload()),
            attestation: canonicalAttestation,
            timestamp: unsigned.timestamp
        )
    }
}
