import Foundation
import CryptoKit
import XCTest
@testable import NuMetal_Q

enum AcceptanceSupport {
    static let sharedSecret = Data(repeating: 0x33, count: 32)
    static let syncSalt = Data("NuMetalQ.Sync.Salt".utf8)
    static let syncInfo = Data("NuMetalQ.Sync.Info".utf8)
    static let signerKey = SymmetricKey(data: Data(repeating: 0x5A, count: 32))

    static let signer: PQSignClosure = { message in
        Data(HMAC<SHA256>.authenticationCode(for: message, using: signerKey))
    }

    static let verifier: PQVerifyClosure = { message, signature in
        let expected = Data(HMAC<SHA256>.authenticationCode(for: message, using: signerKey))
        return expected == signature
    }

    static let attestationVerifier: AttestationVerifier = { attestation, context in
        let decoded = try JSONDecoder().decode(TestAttestation.self, from: attestation)
        return decoded == TestAttestation(context: context)
    }

    static func makeCompiledShape(name: String = "AcceptanceShape") throws -> CompiledShape {
        let lane = LaneDescriptor(index: 0, name: "amounts", width: .u16, length: 64)
        let relation = CCSRelation(
            m: 1,
            n: 66,
            nPublic: 2,
            matrices: [
                SparseMatrix(rows: 1, cols: 66, rowPtr: [0, 0], colIdx: [], values: []),
            ],
            gates: [
                CCSGate(coefficient: .zero, matrixIndices: [0]),
            ]
        )

        return try makeCompiledShape(
            name: name,
            relation: relation,
            lanes: [lane],
            publicHeaderSize: 16
        )
    }

    static func makeConstrainedCompiledShape(name: String = "ConstrainedAcceptanceShape") throws -> CompiledShape {
        let lane = LaneDescriptor(index: 0, name: "amounts", width: .u16, length: 64)
        let relation = CCSRelation(
            m: 1,
            n: 66,
            nPublic: 2,
            matrices: [
                SparseMatrix(
                    rows: 1,
                    cols: 66,
                    rowPtr: [0, 2],
                    colIdx: [0, 2],
                    values: [.one, Fq(raw: Fq.modulus &- 1)]
                )
            ],
            gates: [
                CCSGate(coefficient: .one, matrixIndices: [0]),
            ]
        )

        return try makeCompiledShape(
            name: name,
            relation: relation,
            lanes: [lane],
            publicHeaderSize: 16
        )
    }

    static func makeCompiledShape(
        name: String,
        relation: CCSRelation,
        lanes: [LaneDescriptor],
        publicHeaderSize: Int,
        defaultArity: UInt8 = 2,
        targetGPUFamilies: [String] = ["acceptance"]
    ) throws -> CompiledShape {
        let compiler = ShapeCompiler(
            config: .init(
                signShapePack: signer,
                targetGPUFamilies: targetGPUFamilies,
                defaultArity: defaultArity
            )
        )
        let pack = try compiler.compile(
            name: name,
            relation: relation,
            lanes: lanes,
            publicHeaderByteCount: UInt32(clamping: publicHeaderSize)
        )
        let shape = Shape(
            digest: pack.shapeDigest,
            name: name,
            relation: relation,
            lanes: lanes,
            publicHeaderSize: publicHeaderSize,
            defaultArity: defaultArity
        )
        return try CompiledShape(shape: shape, shapePack: pack, verifySignature: verifier)
    }

    static func makeWitness(seed: UInt64, laneName: String = "amounts") -> Witness {
        let lane = LaneDescriptor(index: 0, name: laneName, width: .u16, length: 64)
        let values = (0..<64).map { offset in
            Fq((seed + UInt64(offset * 7)) & 0xFFFF)
        }
        return Witness(lanes: [WitnessLane(descriptor: lane, values: values)])
    }

    static func makeBoundedWitness(
        seed: UInt64,
        laneName: String = "amounts",
        maxElement: UInt64
    ) -> Witness {
        precondition(maxElement > 0)
        let lane = LaneDescriptor(index: 0, name: laneName, width: .u16, length: 64)
        let values = (0..<64).map { offset in
            Fq((seed + UInt64(offset * 7)) % maxElement)
        }
        return Witness(lanes: [WitnessLane(descriptor: lane, values: values)])
    }

    static func makeSessionKey() -> SymmetricKey {
        SymmetricKey(data: Data(repeating: 0xA5, count: 32))
    }

    static func makeEngine(file: StaticString = #filePath, line: UInt = #line) async throws -> NuMeQ {
        do {
            return try await NuMeQ()
        } catch let error as NuMetalError {
            switch error {
            case .noGPU, .unsupportedCPUArchitecture, .unsupportedGPUFamily:
                throw XCTSkip("NuMeQ engine unavailable on this host: \(error)", file: file, line: line)
            default:
                throw error
            }
        }
    }

    static func makeContext(engine: NuMeQ, name: String = "AcceptanceShape") async throws -> ProofContext {
        await engine.createContext(
            compiledShape: try makeCompiledShape(name: name),
            policy: .standard,
            appID: "NuMetalQ.Tests",
            teamID: "NuMetalQ",
            attestationVerifier: attestationVerifier
        )
    }

    static func metalContextOrSkip(file: StaticString = #filePath, line: UInt = #line) throws -> MetalContext {
        do {
            return try MetalContext()
        } catch {
            throw XCTSkip("Metal unavailable: \(error)", file: file, line: line)
        }
    }

    static func randomRing(seed: UInt64, index: UInt64) -> RingElement {
        RingElement(coeffs: (0..<RingElement.degree).map { coeff in
            Fq((seed &+ UInt64(coeff) &* 17 &+ index &* 31) % Fq.modulus)
        })
    }

    static func randomBoundedRing(seed: UInt64, index: UInt64, maxCoefficient: UInt64) -> RingElement {
        precondition(maxCoefficient > 0)
        return RingElement(coeffs: (0..<RingElement.degree).map { coeff in
            Fq((seed &+ UInt64(coeff) &* 17 &+ index &* 31) % maxCoefficient)
        })
    }

    static func samplePiRLCInputs(key: AjtaiKey, seed: UInt64 = 100) -> [PiRLC.Input] {
        (0..<3).map { inputIndex in
            let witness = (0..<4).map { ringIndex in
                randomRing(
                    seed: seed &+ UInt64(inputIndex) &* 17,
                    index: UInt64(ringIndex)
                )
            }
            return PiRLC.Input(
                commitment: AjtaiCommitter.commit(key: key, witness: witness),
                witness: witness,
                publicInputs: [
                    Fq(seed &+ UInt64(inputIndex + 1)),
                    Fq(seed &+ UInt64(inputIndex + 9))
                ],
                ccsEvaluations: [
                    Fq(seed &+ UInt64(inputIndex + 11)),
                    Fq(seed &+ UInt64(inputIndex + 21))
                ],
                relaxationFactor: Fq(seed &+ UInt64(inputIndex + 2)),
                errorTerms: [randomRing(seed: seed &+ 100 &+ UInt64(inputIndex), index: 0)]
            )
        }
    }

    static func samplePiCCSInput(seed: UInt64 = 0) -> PiCCS.Input {
        let matrix = SparseMatrix(
            rows: 4,
            cols: 4,
            rowPtr: [0, 1, 2, 3, 4],
            colIdx: [0, 1, 2, 3],
            values: (0..<4).map { offset in
                Fq((seed &+ UInt64(offset * 11) &+ 3) % 257)
            }
        )
        let relation = CCSRelation(
            m: 4,
            n: 4,
            nPublic: 0,
            matrices: [matrix],
            gates: [CCSGate(coefficient: Fq((seed % 17) &+ 1), matrixIndices: [0])]
        )
        return PiCCS.Input(
            relation: relation,
            publicInputs: [],
            witness: (0..<4).map { offset in
                Fq((seed &+ UInt64(offset * 7) &+ 5) % 257)
            },
            relaxationFactor: .one
        )
    }

    static func samplePiDECInput(key: AjtaiKey, seed: UInt64 = 500) -> PiDEC.Input {
        let witness = (0..<3).map { ringIndex in
            randomBoundedRing(
                seed: seed,
                index: UInt64(ringIndex),
                maxCoefficient: 1 << 13
            )
        }
        return PiDEC.Input(
            witness: witness,
            commitment: AjtaiCommitter.commit(key: key, witness: witness),
            key: key,
            decompBase: 2,
            decompLimbs: 13
        )
    }

    static func samplePolynomial(seed: UInt64 = 0, numVars: Int = 3) -> MultilinearPoly {
        let evalCount = 1 << numVars
        return MultilinearPoly(
            numVars: numVars,
            evals: (0..<evalCount).map { index in
                Fq((seed &+ UInt64(index * 5) &+ 1) % 4096)
            }
        )
    }

    static func samplePoint(seed: UInt64, numVars: Int) -> [Fq] {
        (0..<numVars).map { index in
            Fq((seed &+ UInt64(index * 13) &+ 7) % 97)
        }
    }

    static func serializeLanes(_ lanes: [WitnessLane]) -> Data {
        var writer = BinaryWriter()
        writer.append(UInt32(lanes.count))
        for lane in lanes {
            let nameData = Data(lane.descriptor.name.utf8)
            writer.appendLengthPrefixed(nameData)
            writer.append(UInt32(lane.values.count))
            for value in lane.values {
                writer.append(value.v)
            }
        }
        return writer.data
    }

    static func deserializeLaneValues(_ data: Data) throws -> [[UInt64]] {
        var reader = BinaryReader(data)
        let laneCount = try Int(reader.readUInt32())
        var lanes = [[UInt64]]()
        for _ in 0..<laneCount {
            _ = try reader.readLengthPrefixedData()
            let valueCount = try Int(reader.readUInt32())
            lanes.append(try (0..<valueCount).map { _ in try reader.readUInt64() })
        }
        return lanes
    }

    static func makeVerificationAttestation(for envelope: ProofEnvelope) throws -> Data {
        try makeAttestation(
            context: AttestationContext(
                purpose: .envelopeVerification,
                appID: envelope.appID,
                teamID: envelope.teamID,
                shapeDigest: envelope.shapeDigest,
                signerKeyID: envelope.signerKeyID,
                timestamp: envelope.timestamp,
                payloadDigest: NuSecurityDigest.sha256(envelope.attestationBindingPayload())
            )
        )
    }

    static func makeAttestation(context: AttestationContext) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(TestAttestation(context: context))
    }

    static func makeSyntheticEnvelope(
        compiledShape: CompiledShape,
        appID: String = "NuMetalQ.Tests",
        teamID: String = "NuMetalQ",
        signerKeyID: Data = Data("test-signer".utf8),
        proofBytes: Data = Data([0x01]),
        attestation: Data? = nil,
        timestamp: Date = Date(timeIntervalSince1970: 1_720_000_000)
    ) throws -> ProofEnvelope {
        let publicHeaderBytes = Data(repeating: 0, count: compiledShape.shape.publicHeaderSize)
        let unsigned = ProofEnvelope(
            version: ProofEnvelope.currentVersion,
            profileID: NuProfile.canonical.profileID,
            appID: appID,
            teamID: teamID,
            shapeDigest: compiledShape.shape.digest,
            publicHeaderDigest: NuSecurityDigest.sha256(publicHeaderBytes),
            publicHeaderBytes: publicHeaderBytes,
            sealBackendID: NuSealConstants.productionBackendID,
            sealParamDigest: Data(NuParams.derive(from: .canonical).seal.parameterDigest),
            privacyMode: .fullZK,
            proofBytes: proofBytes,
            signerKeyID: signerKeyID,
            signature: Data(),
            attestation: attestation,
            timestamp: timestamp
        )

        return ProofEnvelope(
            version: unsigned.version,
            profileID: unsigned.profileID,
            appID: unsigned.appID,
            teamID: unsigned.teamID,
            shapeDigest: unsigned.shapeDigest,
            publicHeaderDigest: unsigned.publicHeaderDigest,
            publicHeaderBytes: unsigned.publicHeaderBytes,
            sealBackendID: unsigned.sealBackendID,
            sealParamDigest: unsigned.sealParamDigest,
            privacyMode: unsigned.privacyMode,
            proofBytes: unsigned.proofBytes,
            signerKeyID: unsigned.signerKeyID,
            signature: try signer(unsigned.signingPayload()),
            attestation: unsigned.attestation,
            timestamp: unsigned.timestamp
        )
    }

    static func resignEnvelope(
        _ envelope: ProofEnvelope,
        version: UInt16? = nil,
        appID: String? = nil,
        teamID: String? = nil,
        shapeDigest: ShapeDigest? = nil,
        publicHeaderDigest: Data? = nil,
        publicHeaderBytes: Data? = nil,
        sealBackendID: String? = nil,
        sealParamDigest: Data? = nil,
        privacyMode: PrivacyMode? = nil,
        proofBytes: Data? = nil,
        signerKeyID: Data? = nil,
        attestation: Data?? = nil,
        timestamp: Date? = nil
    ) throws -> ProofEnvelope {
        let unsigned = ProofEnvelope(
            version: version ?? envelope.version,
            profileID: envelope.profileID,
            appID: appID ?? envelope.appID,
            teamID: teamID ?? envelope.teamID,
            shapeDigest: shapeDigest ?? envelope.shapeDigest,
            publicHeaderDigest: publicHeaderDigest ?? envelope.publicHeaderDigest,
            publicHeaderBytes: publicHeaderBytes ?? envelope.publicHeaderBytes,
            sealBackendID: sealBackendID ?? envelope.sealBackendID,
            sealParamDigest: sealParamDigest ?? envelope.sealParamDigest,
            privacyMode: privacyMode ?? envelope.privacyMode,
            proofBytes: proofBytes ?? envelope.proofBytes,
            signerKeyID: signerKeyID ?? envelope.signerKeyID,
            signature: Data(),
            attestation: attestation ?? envelope.attestation,
            timestamp: timestamp ?? envelope.timestamp
        )

        return ProofEnvelope(
            version: unsigned.version,
            profileID: unsigned.profileID,
            appID: unsigned.appID,
            teamID: unsigned.teamID,
            shapeDigest: shapeDigest ?? envelope.shapeDigest,
            publicHeaderDigest: publicHeaderDigest ?? envelope.publicHeaderDigest,
            publicHeaderBytes: publicHeaderBytes ?? envelope.publicHeaderBytes,
            sealBackendID: sealBackendID ?? envelope.sealBackendID,
            sealParamDigest: sealParamDigest ?? envelope.sealParamDigest,
            privacyMode: privacyMode ?? envelope.privacyMode,
            proofBytes: proofBytes ?? envelope.proofBytes,
            signerKeyID: signerKeyID ?? envelope.signerKeyID,
            signature: try signer(unsigned.signingPayload()),
            attestation: unsigned.attestation,
            timestamp: unsigned.timestamp
        )
    }
}

private struct TestAttestation: Codable, Equatable {
    let purpose: String
    let appID: String?
    let teamID: String?
    let localDeviceID: UUID?
    let remoteDeviceID: UUID?
    let sessionID: UUID?
    let messageID: UUID?
    let shapeDigest: [UInt8]?
    let signerKeyID: Data?
    let timestampBits: UInt64
    let payloadDigest: Data

    init(context: AttestationContext) {
        self.purpose = context.purpose.rawValue
        self.appID = context.appID
        self.teamID = context.teamID
        self.localDeviceID = context.localDeviceID
        self.remoteDeviceID = context.remoteDeviceID
        self.sessionID = context.sessionID
        self.messageID = context.messageID
        self.shapeDigest = context.shapeDigest?.bytes
        self.signerKeyID = context.signerKeyID
        self.timestampBits = context.timestamp.timeIntervalSince1970.bitPattern
        self.payloadDigest = context.payloadDigest
    }
}
