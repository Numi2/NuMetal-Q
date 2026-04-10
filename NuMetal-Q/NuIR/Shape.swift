import Foundation
import CryptoKit

// MARK: - Shape and ShapePack
// A Shape is a compiled CCS circuit with its lane map, transcript constants,
// and kernel configuration. ShapePack is the signed, build-time-compiled asset
// that ships to device. One canonical CCS IR emits both the fold artifacts and
// the Hachi D_Nu decider layout.
//
// No on-device CCS matrix lifting. Compile signed ShapePack assets on Mac at build time.

/// Unique identifier for a compiled circuit shape.
public struct ShapeDigest: Sendable, Hashable, Codable {
    public let bytes: [UInt8]  // 32-byte SHA-256 digest

    public init(bytes: [UInt8]) {
        precondition(bytes.count == 32)
        self.bytes = bytes
    }
}

/// A compiled circuit shape containing the CCS relation and its metadata.
public struct Shape: Sendable {
    /// Unique content-addressed digest of this shape.
    public let digest: ShapeDigest

    /// Human-readable name for debugging.
    public let name: String

    /// The CCS relation (constraint matrices, gates).
    public let relation: CCSRelation

    /// Lane descriptors describing the witness structure.
    public let lanes: [LaneDescriptor]

    /// Number of public header bytes exposed in the proof envelope.
    public let publicHeaderSize: Int

    /// Suggested fold arity for this shape (may be overridden by scheduler).
    public let defaultArity: UInt8

    public init(
        digest: ShapeDigest,
        name: String,
        relation: CCSRelation,
        lanes: [LaneDescriptor],
        publicHeaderSize: Int,
        defaultArity: UInt8
    ) {
        let canonicalDigest = Self.canonicalDigest(
            name: name,
            relation: relation,
            lanes: lanes,
            publicHeaderSize: publicHeaderSize,
            defaultArity: defaultArity
        )
        self.digest = canonicalDigest
        self.name = name
        self.relation = relation
        self.lanes = lanes
        self.publicHeaderSize = publicHeaderSize
        self.defaultArity = defaultArity
    }

    /// Total commitment bit cost across all lanes.
    public var totalCommitmentBits: Int {
        lanes.reduce(0) { $0 + $1.commitmentBitCost * Int($1.length) }
    }

    public static func canonicalDigest(
        name: String,
        relation: CCSRelation,
        lanes: [LaneDescriptor],
        publicHeaderSize: Int,
        defaultArity: UInt8
    ) -> ShapeDigest {
        ShapeArtifact.canonicalDigest(
            name: name,
            relation: relation,
            lanes: lanes,
            publicHeaderSize: publicHeaderSize,
            defaultArity: defaultArity
        )
    }
}

/// Kernel dispatch configuration for a specific shape + device combo.
public struct KernelConfig: Sendable, Codable {
    public let threadgroupSize: UInt32
    public let threadExecutionWidthMultiple: UInt8
    public let tilesPerThreadgroup: UInt32
    public let laneTile: UInt16
    public let matrixRowTile: UInt16
    public let storageLayoutVersion: UInt16
    public let foldArity: UInt8
    public let decompositionWindow: UInt8
    public let queueDepth: UInt8
    public let sealChunkSize: UInt32
    public let merkleChunkSize: UInt32
    public let gpuFamilyTag: String

    public init(
        threadgroupSize: UInt32,
        threadExecutionWidthMultiple: UInt8,
        tilesPerThreadgroup: UInt32,
        laneTile: UInt16,
        matrixRowTile: UInt16,
        storageLayoutVersion: UInt16,
        foldArity: UInt8,
        decompositionWindow: UInt8,
        queueDepth: UInt8,
        sealChunkSize: UInt32,
        merkleChunkSize: UInt32,
        gpuFamilyTag: String
    ) {
        self.threadgroupSize = threadgroupSize
        self.threadExecutionWidthMultiple = threadExecutionWidthMultiple
        self.tilesPerThreadgroup = tilesPerThreadgroup
        self.laneTile = laneTile
        self.matrixRowTile = matrixRowTile
        self.storageLayoutVersion = storageLayoutVersion
        self.foldArity = foldArity
        self.decompositionWindow = decompositionWindow
        self.queueDepth = queueDepth
        self.sealChunkSize = sealChunkSize
        self.merkleChunkSize = merkleChunkSize
        self.gpuFamilyTag = gpuFamilyTag
    }

    /// Canonical packed form included in ShapePack signatures (order-sensitive).
    public func signingBytes() -> Data {
        var d = Data()
        var a = threadgroupSize
        d.append(contentsOf: withUnsafeBytes(of: &a) { Data($0) })
        d.append(threadExecutionWidthMultiple)
        var b = tilesPerThreadgroup
        d.append(contentsOf: withUnsafeBytes(of: &b) { Data($0) })
        var c = laneTile
        d.append(contentsOf: withUnsafeBytes(of: &c) { Data($0) })
        var e = matrixRowTile
        d.append(contentsOf: withUnsafeBytes(of: &e) { Data($0) })
        var f = storageLayoutVersion
        d.append(contentsOf: withUnsafeBytes(of: &f) { Data($0) })
        d.append(foldArity)
        d.append(decompositionWindow)
        d.append(queueDepth)
        var g = sealChunkSize
        d.append(contentsOf: withUnsafeBytes(of: &g) { Data($0) })
        var h = merkleChunkSize
        d.append(contentsOf: withUnsafeBytes(of: &h) { Data($0) })
        let famData = Data(gpuFamilyTag.utf8)
        var famLen = UInt32(famData.count)
        d.append(contentsOf: withUnsafeBytes(of: &famLen) { Data($0) })
        d.append(famData)
        return d
    }

    internal var isCanonicalProductionConfig: Bool {
        threadgroupSize > 0
            && threadExecutionWidthMultiple > 0
            && tilesPerThreadgroup > 0
            && laneTile == MetalStorageLayout.laneTile
            && matrixRowTile == MetalStorageLayout.matrixRowTile
            && storageLayoutVersion == MetalStorageLayout.currentVersion
            && foldArity > 0
            && decompositionWindow == NuProfile.canonical.decompBase
            && queueDepth == UInt8(SchedulerParams.production.queueDepth)
            && sealChunkSize > 0
            && merkleChunkSize > 0
            && gpuFamilyTag.isEmpty == false
    }
}

// MARK: - ShapePack signing

public enum ShapePackSigning: Sendable {
    public static func kernelConfigsBlob(_ configs: [KernelConfig]) -> Data {
        var d = Data()
        var n = UInt32(configs.count)
        d.append(contentsOf: withUnsafeBytes(of: &n) { Data($0) })
        for c in configs {
            d.append(c.signingBytes())
        }
        return d
    }
}

/// Build-time-compiled, signed asset bundle containing everything needed
/// to execute a shape on device without runtime CCS matrix lifting.
public struct ShapePack: Sendable {
    public static let currentVersion: UInt16 = 3

    /// Versioned GPU artifact ABI.
    public let version: UInt16

    /// Shape digest this pack was compiled for.
    public let shapeDigest: ShapeDigest

    /// Signed CCS shape metadata.
    public let shapeMetadata: Data

    /// Serialized lifted matrices in GPU-ready format (CSR packed for Metal buffer upload).
    public let liftedMatrices: Data

    /// Row-tiled CSR layout for the canonical Metal matrix kernel.
    public let gpuLiftedMatrices: Data

    /// Witness lane-width map: maps lane indices to offsets, lengths, and width classes.
    public let laneMap: Data

    /// Deterministic Ajtai public parameters derived from the frozen public seed.
    public let ajtaiPublicParameters: Data

    /// Rotation tables for the sparse commitment path.
    public let rotationTable: Data

    /// Transcript constants (domain separators, shape-dependent Fiat-Shamir seeds).
    public let transcriptConstants: Data

    /// Signed digest of the canonical Metal artifact bundle.
    public let gpuArtifactDigest: [UInt8]

    /// Canonical profile certificate bundle, including the Fq² irreducibility proof.
    public let profileCertificate: Data

    /// Compiler-emitted Hachi decider layout for D_Nu from the same CCS IR.
    public let deciderLayout: Data

    /// Per-GPU-family kernel configurations.
    public let kernelConfigs: [KernelConfig]

    /// ML-DSA signature over the full deterministic shape bundle.
    public let signature: Data

    public init(
        version: UInt16 = ShapePack.currentVersion,
        shapeDigest: ShapeDigest,
        shapeMetadata: Data,
        liftedMatrices: Data,
        gpuLiftedMatrices: Data,
        laneMap: Data,
        ajtaiPublicParameters: Data,
        rotationTable: Data,
        transcriptConstants: Data,
        gpuArtifactDigest: [UInt8],
        profileCertificate: Data,
        deciderLayout: Data,
        kernelConfigs: [KernelConfig],
        signature: Data
    ) {
        self.version = version
        self.shapeDigest = shapeDigest
        self.shapeMetadata = shapeMetadata
        self.liftedMatrices = liftedMatrices
        self.gpuLiftedMatrices = gpuLiftedMatrices
        self.laneMap = laneMap
        self.ajtaiPublicParameters = ajtaiPublicParameters
        self.rotationTable = rotationTable
        self.transcriptConstants = transcriptConstants
        self.gpuArtifactDigest = gpuArtifactDigest
        self.profileCertificate = profileCertificate
        self.deciderLayout = deciderLayout
        self.kernelConfigs = kernelConfigs
        self.signature = signature
    }

    public var sealCompilationBundle: Data { deciderLayout }
}

extension ShapePack {
    /// Payload signed at build time by numeqc (must stay in sync with `ShapeCompiler`).
    public func signingPayload() -> Data {
        var signPayload = Data()
        var versionLE = version.littleEndian
        signPayload.append(contentsOf: withUnsafeBytes(of: &versionLE) { Data($0) })
        signPayload.append(contentsOf: shapeDigest.bytes)
        signPayload.append(shapeMetadata)
        signPayload.append(liftedMatrices)
        signPayload.append(gpuLiftedMatrices)
        signPayload.append(laneMap)
        signPayload.append(ajtaiPublicParameters)
        signPayload.append(rotationTable)
        signPayload.append(transcriptConstants)
        signPayload.append(contentsOf: gpuArtifactDigest)
        signPayload.append(profileCertificate)
        signPayload.append(deciderLayout)
        signPayload.append(ShapePackSigning.kernelConfigsBlob(kernelConfigs))
        return signPayload
    }

    /// Runtime check using a platform verifier (e.g. Secure Enclave ML-DSA public key).
    public func isSignatureValid(verify: (Data, Data) throws -> Bool) rethrows -> Bool {
        try verify(signingPayload(), signature)
    }
}

public enum ShapePackValidationError: Error, Sendable {
    case digestMismatch
    case shapeArtifactMismatch
    case invalidSignature
    case invalidProfileCertificate
    case incompleteArtifacts
    case gpuArtifactUnavailable
}

/// Proof-ready bundle that binds the logical shape metadata to a signed
/// build-time ShapePack. SDK entrypoints require this verified wrapper so
/// device runtimes do not construct proving contexts from ad hoc lifted CCS.
public struct CompiledShape: Sendable {
    public let shape: Shape
    public let shapePack: ShapePack

    public init(shape: Shape, shapePack: ShapePack, verifySignature: PQVerifyClosure) throws {
        let canonicalDigest = Shape.canonicalDigest(
            name: shape.name,
            relation: shape.relation,
            lanes: shape.lanes,
            publicHeaderSize: shape.publicHeaderSize,
            defaultArity: shape.defaultArity
        )
        guard shape.digest == canonicalDigest, canonicalDigest == shapePack.shapeDigest else {
            throw ShapePackValidationError.digestMismatch
        }
        guard shapePack.version == ShapePack.currentVersion else {
            throw ShapePackValidationError.incompleteArtifacts
        }
        guard try shapePack.isSignatureValid(verify: verifySignature) else {
            throw ShapePackValidationError.invalidSignature
        }
        let certificate = try ProfileCertificate.decodeArtifactData(shapePack.profileCertificate)
        guard certificate.isValid, certificate.profile == .canonical else {
            throw ShapePackValidationError.invalidProfileCertificate
        }
        let expectedProfileCertificate = try ProfileCertificate.deterministicArtifactData(for: .canonical)
        guard !shapePack.shapeMetadata.isEmpty,
              !shapePack.liftedMatrices.isEmpty,
              !shapePack.gpuLiftedMatrices.isEmpty,
              !shapePack.laneMap.isEmpty,
              !shapePack.ajtaiPublicParameters.isEmpty,
              !shapePack.rotationTable.isEmpty,
              shapePack.gpuArtifactDigest.count == 32,
              !shapePack.deciderLayout.isEmpty,
              !shapePack.kernelConfigs.isEmpty,
              shapePack.kernelConfigs.allSatisfy(\.isCanonicalProductionConfig) else {
            throw ShapePackValidationError.incompleteArtifacts
        }
        let expectedGPUArtifactDigest: [UInt8]
        do {
            expectedGPUArtifactDigest = try ShapeArtifact.gpuArtifactDigest()
        } catch {
            throw ShapePackValidationError.gpuArtifactUnavailable
        }
        guard shapePack.shapeMetadata == ShapeArtifact.shapeMetadata(for: shape),
              shapePack.liftedMatrices == ShapeArtifact.liftedMatrices(shape.relation.matrices),
              shapePack.gpuLiftedMatrices == ShapeArtifact.gpuLiftedMatrices(shape.relation.matrices),
              shapePack.laneMap == ShapeArtifact.laneMap(for: shape.lanes),
              shapePack.ajtaiPublicParameters == ShapeArtifact.ajtaiPublicParameters(),
              shapePack.rotationTable == ShapeArtifact.rotationTableArtifact(),
              shapePack.transcriptConstants == ShapeArtifact.transcriptConstants(for: shape),
              shapePack.gpuArtifactDigest == expectedGPUArtifactDigest,
              shapePack.profileCertificate == expectedProfileCertificate,
              shapePack.deciderLayout == ShapeArtifact.deciderLayout(for: shape) else {
            throw ShapePackValidationError.shapeArtifactMismatch
        }
        self.shape = shape
        self.shapePack = shapePack
    }
}

internal enum ShapeArtifact {
    static func canonicalDigest(
        name: String,
        relation: CCSRelation,
        lanes: [LaneDescriptor],
        publicHeaderSize: Int,
        defaultArity: UInt8
    ) -> ShapeDigest {
        let encoded = canonicalDigestInput(
            name: name,
            relation: relation,
            lanes: lanes,
            publicHeaderSize: publicHeaderSize,
            defaultArity: defaultArity
        )
        return ShapeDigest(bytes: Array(SHA256.hash(data: encoded)))
    }

    static func canonicalDigestInput(
        name: String,
        relation: CCSRelation,
        lanes: [LaneDescriptor],
        publicHeaderSize: Int,
        defaultArity: UInt8
    ) -> Data {
        var writer = BinaryWriter()
        writer.appendLengthPrefixed(Data("NuMeQ.Shape.Digest.v2".utf8))
        writer.appendLengthPrefixed(Data(name.utf8))
        writer.append(UInt32(clamping: relation.m))
        writer.append(UInt32(clamping: relation.n))
        writer.append(UInt32(clamping: relation.nPublic))
        writer.append(UInt32(clamping: publicHeaderSize))
        writer.append(defaultArity)
        writer.append(liftedMatrices(relation.matrices))
        writer.append(UInt32(clamping: relation.gates.count))
        for gate in relation.gates {
            writer.append(gate.coefficient)
            writer.append(UInt32(clamping: gate.matrixIndices.count))
            for index in gate.matrixIndices {
                writer.append(index)
            }
        }
        writer.append(UInt32(clamping: lanes.count))
        for lane in lanes {
            writer.append(lane.index)
            writer.appendLengthPrefixed(Data(lane.name.utf8))
            writer.append(lane.width.rawValue)
            writer.append(lane.bound)
            writer.append(lane.length)
        }
        return writer.data
    }

    static func shapeMetadata(for shape: Shape) -> Data {
        var writer = BinaryWriter()
        writer.append(UInt32(clamping: Data(shape.name.utf8).count))
        writer.append(Data(shape.name.utf8))
        writer.append(UInt32(clamping: shape.relation.m))
        writer.append(UInt32(clamping: shape.relation.n))
        writer.append(UInt32(clamping: shape.relation.nPublic))
        writer.append(UInt32(clamping: shape.publicHeaderSize))
        writer.append(UInt32(clamping: shape.lanes.count))
        writer.append(UInt32(clamping: shape.relation.matrices.count))
        writer.append(UInt32(clamping: shape.relation.gates.count))
        writer.append(shape.defaultArity)
        return writer.data
    }

    static func liftedMatrices(_ matrices: [SparseMatrix]) -> Data {
        var writer = BinaryWriter()
        writer.append(UInt32(clamping: matrices.count))
        for matrix in matrices {
            writer.append(UInt32(clamping: matrix.rows))
            writer.append(UInt32(clamping: matrix.cols))
            writer.append(UInt32(clamping: matrix.nnz))
            for rowPointer in matrix.rowPtr {
                writer.append(rowPointer)
            }
            for columnIndex in matrix.colIdx {
                writer.append(columnIndex)
            }
            for value in matrix.values {
                writer.append(Data(value.toBytes()))
            }
        }
        return writer.data
    }

    static func laneMap(for lanes: [LaneDescriptor]) -> Data {
        var writer = BinaryWriter()
        writer.append(UInt32(clamping: lanes.count))
        var offset: UInt32 = 0
        for lane in lanes {
            writer.append(lane.index)
            writer.append(offset)
            writer.append(lane.length)
            writer.append(lane.width.rawValue)
            writer.append(MetalStorageLayout.laneTile)
            writer.append(UInt8(0))
            writer.append(UInt8(0))
            let ringStride = UInt32((Int(lane.length) + RingElement.degree - 1) / RingElement.degree)
            offset &+= ringStride
        }
        return writer.data
    }

    static func gpuLiftedMatrices(_ matrices: [SparseMatrix]) -> Data {
        var writer = BinaryWriter()
        writer.append(UInt32(clamping: matrices.count))
        writer.append(MetalStorageLayout.matrixRowTile)
        writer.append(MetalStorageLayout.currentVersion)
        for matrix in matrices {
            writer.append(TiledMatrixPacking.packRowTiledCSR(matrix))
        }
        return writer.data
    }

    static func ajtaiPublicParameters() -> Data {
        let key = NuParams.derive(from: .canonical).commitmentKey
        var writer = BinaryWriter()
        writer.append(UInt32(clamping: key.keys.count))
        writer.append(UInt32(clamping: RingElement.degree))
        for ring in key.keys {
            writer.append(Data(ring.toBytes()))
        }
        return writer.data
    }

    static func rotationTableArtifact() -> Data {
        let table = NuParams.derive(from: .canonical).commitmentKey.rotationTable
        var writer = BinaryWriter()
        writer.append(UInt32(clamping: table.keyCount))
        writer.append(UInt32(clamping: table.packedRows.count))
        for row in table.packedRows {
            writer.append(row.rowIndex)
            writer.append(UInt32(clamping: row.entries.count))
            for entry in row.entries {
                writer.append(entry.col)
                writer.append(Data(entry.value.toBytes()))
            }
        }
        return writer.data
    }

    static func transcriptConstants(for shape: Shape) -> Data {
        var writer = BinaryWriter()
        writer.append(Data(shape.digest.bytes))
        writer.append(Data(shape.name.utf8))
        writer.append(UInt32(clamping: shape.publicHeaderSize))
        return writer.data
    }

    static func gpuArtifactDigest() throws -> [UInt8] {
        try MetalArtifactBundle.artifactDigest()
    }

    static func deciderLayout(for shape: Shape) -> Data {
        let params = NuParams.derive(from: .canonical)
        let profile = NuProfile.canonical
        let witnessCount = shape.relation.n - shape.relation.nPublic
        let rowVariableCount = max(0, ceilLog2(shape.relation.m))
        let witnessVariableCount = max(0, ceilLog2(max(1, witnessCount)))
        let digestBundleFields = [
            "profile_digest",
            "shape_set_digest",
            "final_accumulator_digest",
            "canonical_header_bytes",
            "canonical_header_digest",
            "derivation_tree_digest",
            "transcript_digest",
            "provenance_digest",
        ]

        var writer = BinaryWriter()
        writer.appendLengthPrefixed(Data("D_Nu".utf8))
        writer.appendLengthPrefixed(Data(NuSealConstants.productionBackendID.utf8))
        writer.appendLengthPrefixed(Data(NuSealConstants.sealTranscriptID.utf8))
        writer.appendLengthPrefixed(Data(params.seal.parameterDigest))
        writer.append(UInt32(clamping: profile.hachiVariableCount))
        writer.append(UInt32(clamping: profile.batchingWidth))
        writer.append(UInt32(clamping: digestBundleFields.count))
        for field in digestBundleFields {
            writer.appendLengthPrefixed(Data(field.utf8))
        }
        writer.append(UInt32(clamping: shape.relation.m))
        writer.append(UInt32(clamping: witnessCount))
        writer.append(UInt32(clamping: rowVariableCount))
        writer.append(UInt32(clamping: witnessVariableCount))
        writer.append(UInt32(clamping: shape.relation.gates.count))
        writer.append(UInt32(clamping: shape.relation.matrices.count))

        for lane in shape.lanes {
            writer.append(lane.index)
            writer.appendLengthPrefixed(Data(lane.name.utf8))
            writer.append(lane.length)
            writer.append(lane.width.rawValue)
        }

        let scheduleSeed = NuParameterExpander.expandBytes(
            domain: "NuMeQ.Shape.Decider.BatchSchedule",
            seed: shape.digest.bytes + params.seal.seed,
            count: 32
        )
        writer.appendLengthPrefixed(scheduleSeed)
        return writer.data
    }

    static func sealCompilationBundle(for shape: Shape) -> Data {
        deciderLayout(for: shape)
    }
}
