import Foundation

public enum PrivacyMode: UInt8, Sendable, Codable {
    case fullZK = 0
    case selectiveDisclosure = 1
    case transparent = 2
}

public struct ProofEnvelope: Sendable {
    public static let currentVersion: UInt16 = 4

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
        writer.appendLengthPrefixed(attestation ?? Data())
        writer.append(timestamp.timeIntervalSince1970)
        return writer.data
    }

    public static func deserialize(_ data: Data) throws -> ProofEnvelope {
        var reader = BinaryReader(data)
        let version = try reader.readUInt16()
        let profileID = ProfileID(bytes: Array(try reader.readData(count: 32)))
        let appID = try decodeString(from: &reader)
        let teamID = try decodeString(from: &reader)
        let shapeDigest = ShapeDigest(bytes: Array(try reader.readData(count: 32)))
        let publicHeaderDigest = try reader.readLengthPrefixedData()
        let publicHeaderBytes = try reader.readLengthPrefixedData()
        let sealBackendID = try decodeString(from: &reader)
        let sealParamDigest = try reader.readLengthPrefixedData()
        guard let privacyMode = PrivacyMode(rawValue: try reader.readUInt8()) else {
            throw BinaryReader.Error.invalidData
        }
        let proofBytes = try reader.readLengthPrefixedData()
        let signerKeyID = try reader.readLengthPrefixedData()
        let signature = try reader.readLengthPrefixedData()
        let attestationData = try reader.readLengthPrefixedData()
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
            writer.append(UInt8(attestation == nil ? 0 : 1))
            writer.appendLengthPrefixed(attestation ?? Data())
        }

        writer.append(timestamp.timeIntervalSince1970)
        return writer.data
    }

    private static func decodeString(from reader: inout BinaryReader) throws -> String {
        let data = try reader.readLengthPrefixedData()
        guard let string = String(data: data, encoding: .utf8) else {
            throw BinaryReader.Error.invalidData
        }
        return string
    }
}

enum ProofEnvelopeValidationError: Error, Sendable {
    case unsupportedVersion(UInt16)
    case invalidSealBackend
    case missingSignerKeyID
    case missingTeamID
    case missingProofBytes
    case invalidPublicHeaderDigest
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
            attestation: attestation,
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
            attestation: attestation,
            timestamp: unsigned.timestamp
        )
    }
}
