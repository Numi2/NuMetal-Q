import Foundation
import CryptoKit

// MARK: - numeqc: Build-Time Shape Compiler
// Mac-only build-time compiler that emits signed ShapePack assets.
// One canonical CCS IR produces both proving artifacts:
//   1. SuperNeo fold artifacts
//   2. The Hachi D_Nu decider layout
// plus transcript constants and kernel configuration tables.
//
// No on-device CCS matrix lifting. This runs at build time only.

/// The numeqc shape compiler.
///
/// Takes a high-level circuit description and produces a signed ShapePack
/// ready for deployment to device. This runs on Mac at build time; devices
/// never perform CCS matrix lifting themselves, and they never synthesize the
/// terminal decider relation outside the signed compiler output.
@available(iOS, unavailable, message: "numeqc is a macOS build-time compiler only.")
public struct ShapeCompiler {

    public enum CompilerError: Error, Sendable {
        case signingFailed
        case nonCanonicalParameters
    }

    /// Compiler configuration.
    public struct Config {
        /// ML-DSA (build-time) signature over the ShapePack signing payload.
        public let signShapePack: PQSignClosure

        /// Target GPU families to generate kernel configs for.
        public let targetGPUFamilies: [String]

        /// Default fold arity.
        public let defaultArity: UInt8

        /// Decomposition base b.
        public let decompBase: UInt8

        /// Decomposition limbs.
        public let decompLimbs: UInt8

        public init(
            signShapePack: @escaping PQSignClosure,
            targetGPUFamilies: [String] = ["apple7", "apple8", "apple9"],
            defaultArity: UInt8 = 8,
            decompBase: UInt8 = 2,
            decompLimbs: UInt8 = 13
        ) {
            self.signShapePack = signShapePack
            self.targetGPUFamilies = targetGPUFamilies
            self.defaultArity = defaultArity
            self.decompBase = decompBase
            self.decompLimbs = decompLimbs
        }
    }

    private let config: Config

    public init(config: Config) {
        self.config = config
    }

    /// Compile a CCS relation and lane descriptors into a signed ShapePack.
    public func compile(
        name: String,
        relation: CCSRelation,
        lanes: [LaneDescriptor],
        publicHeaderByteCount: UInt32 = 0
    ) throws -> ShapePack {
        guard config.decompBase == NuProfile.canonical.decompBase,
              config.decompLimbs == NuProfile.canonical.decompLimbs,
              config.defaultArity > 0 else {
            throw CompilerError.nonCanonicalParameters
        }

        // 1. Compute shape digest
        let shapeDigest = ShapeArtifact.canonicalDigest(
            name: name,
            relation: relation,
            lanes: lanes,
            publicHeaderSize: Int(publicHeaderByteCount),
            defaultArity: config.defaultArity
        )

        // 2. Freeze all build-time artifacts. Devices do not synthesize these.
        let shape = Shape(
            digest: shapeDigest,
            name: name,
            relation: relation,
            lanes: lanes,
            publicHeaderSize: Int(publicHeaderByteCount),
            defaultArity: config.defaultArity
        )
        let shapeMetadata = ShapeArtifact.shapeMetadata(for: shape)
        let liftedMatrices = ShapeArtifact.liftedMatrices(relation.matrices)
        let gpuLiftedMatrices = ShapeArtifact.gpuLiftedMatrices(relation.matrices)
        let laneMap = ShapeArtifact.laneMap(for: lanes)
        let ajtaiPublicParameters = ShapeArtifact.ajtaiPublicParameters()
        let rotationTable = ShapeArtifact.rotationTableArtifact()

        // 3. Build transcript constants
        let transcriptConstants = ShapeArtifact.transcriptConstants(for: shape)
        let gpuArtifactDigest = ShapeArtifact.gpuArtifactDigest()
        let profileCertificate = try ProfileCertificate.deterministicArtifactData(for: .canonical)
        let deciderLayout = ShapeArtifact.deciderLayout(for: shape)

        // 4. Generate kernel configs per GPU family
        let kernelConfigs = config.targetGPUFamilies.map { family in
            generateKernelConfig(
                family: family,
                relation: relation,
                lanes: lanes
            )
        }

        // 5. Sign the pack (all build artifacts are part of the signed surface)
        var signPayload = Data()
        var version = ShapePack.currentVersion.littleEndian
        signPayload.append(contentsOf: withUnsafeBytes(of: &version) { Data($0) })
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

        let signature = try config.signShapePack(signPayload)

        return ShapePack(
            version: ShapePack.currentVersion,
            shapeDigest: shapeDigest,
            shapeMetadata: shapeMetadata,
            liftedMatrices: liftedMatrices,
            gpuLiftedMatrices: gpuLiftedMatrices,
            laneMap: laneMap,
            ajtaiPublicParameters: ajtaiPublicParameters,
            rotationTable: rotationTable,
            transcriptConstants: transcriptConstants,
            gpuArtifactDigest: gpuArtifactDigest,
            profileCertificate: profileCertificate,
            deciderLayout: deciderLayout,
            kernelConfigs: kernelConfigs,
            signature: signature
        )
    }

    // MARK: - Matrix Lifting

    // MARK: - Kernel Config Generation

    private func generateKernelConfig(
        family: String,
        relation: CCSRelation,
        lanes: [LaneDescriptor]
    ) -> KernelConfig {
        let totalWitness = lanes.reduce(0) { $0 + Int($1.length) }

        let tileSize: UInt32
        let tilesPerGroup: UInt32
        switch family {
        case "apple9":
            tileSize = 256
            tilesPerGroup = 4
        case "apple8":
            tileSize = 128
            tilesPerGroup = 4
        default:
            tileSize = 64
            tilesPerGroup = 2
        }

        let arity = totalWitness > 10000 ? config.defaultArity : min(config.defaultArity, 4)

        return KernelConfig(
            threadgroupSize: tileSize,
            threadExecutionWidthMultiple: MetalStorageLayout.threadExecutionWidthMultiple,
            tilesPerThreadgroup: tilesPerGroup,
            laneTile: MetalStorageLayout.laneTile,
            matrixRowTile: MetalStorageLayout.matrixRowTile,
            storageLayoutVersion: MetalStorageLayout.currentVersion,
            foldArity: arity,
            decompositionWindow: config.decompBase,
            queueDepth: UInt8(SchedulerParams.production.queueDepth),
            sealChunkSize: MetalStorageLayout.defaultSealChunkSize,
            merkleChunkSize: MetalStorageLayout.defaultMerkleChunkSize,
            gpuFamilyTag: family
        )
    }

}
