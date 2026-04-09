import Foundation

// MARK: - NuParams: Deterministic Public Parameter Generation
// Transparent, reproducible parameter expansion from one public root seed.

public struct NuParams: Sendable {
    private static let cacheLock = NSLock()
    nonisolated(unsafe)
    private static var cache = [String: NuParams]()

    public let profile: NuProfile
    public let fold: FoldParameterBundle
    public let seal: HachiSealParameterBundle

    public var commitmentKey: AjtaiKey { fold.commitmentKey }
    public var piRLCConstants: StageConstants { fold.piRLCConstants }
    public var piCCSConstants: StageConstants { fold.piCCSConstants }
    public var piDECConstants: StageConstants { fold.piDECConstants }
    public var liftedCCSConstants: [UInt8] { fold.liftedCCSConstants }

    public static func derive(from profile: NuProfile) -> NuParams {
        let cacheKey = Data(profile.profileID.bytes).base64EncodedString()
        cacheLock.lock()
        if let cached = cache[cacheKey] {
            cacheLock.unlock()
            return cached
        }
        cacheLock.unlock()

        let foldSeed = profile.foldParameterSeed
        let sealSeed = profile.sealParameterSeed

        let fold = FoldParameterBundle(
            seed: foldSeed,
            commitmentKey: expandCommitmentKey(
                seed: foldSeed,
                rank: profile.commitmentRank,
                slotCount: profile.commitmentRank * profile.ringDegree
            ),
            piRLCConstants: deriveStageConstants(
                seed: foldSeed,
                domain: "NuMeQ.Params.Fold.PiRLC"
            ),
            piCCSConstants: deriveStageConstants(
                seed: foldSeed,
                domain: "NuMeQ.Params.Fold.PiCCS"
            ),
            piDECConstants: deriveStageConstants(
                seed: foldSeed,
                domain: "NuMeQ.Params.Fold.PiDEC"
            ),
            liftedCCSConstants: NuParameterExpander.expandBytes(
                domain: "NuMeQ.Params.Fold.CCSLift",
                seed: foldSeed,
                count: 64
            ),
            transcriptID: NuSealConstants.foldTranscriptID
        )

        let seal = HachiSealParameterBundle(
            seed: sealSeed,
            backendID: NuSealConstants.productionBackendID,
            transcriptID: NuSealConstants.sealTranscriptID,
            commitmentParameters: NuParameterExpander.expandBytes(
                domain: "NuMeQ.Params.Seal.Hachi.Commitment",
                seed: sealSeed,
                count: 96
            ),
            batchingConstants: NuParameterExpander.expandBytes(
                domain: "NuMeQ.Params.Seal.Hachi.Batch",
                seed: sealSeed,
                count: 96
            ),
            verifierConstants: NuParameterExpander.expandBytes(
                domain: "NuMeQ.Params.Seal.Hachi.Verifier",
                seed: sealSeed,
                count: 96
            ),
            directPackedPoK: DirectPackedPoKParameters(
                witnessBindingSeed: NuParameterExpander.expandBytes(
                    domain: "NuMeQ.Params.Seal.Hachi.DirectPacked.Binding",
                    seed: sealSeed,
                    count: 32
                ),
                relationSeed: NuParameterExpander.expandBytes(
                    domain: "NuMeQ.Params.Seal.Hachi.DirectPacked.Relation",
                    seed: sealSeed,
                    count: 32
                ),
                outerSeed: NuParameterExpander.expandBytes(
                    domain: "NuMeQ.Params.Seal.Hachi.DirectPacked.Outer",
                    seed: sealSeed,
                    count: 32
                ),
                bindingImageSeed: NuParameterExpander.expandBytes(
                    domain: "NuMeQ.Params.Seal.Hachi.DirectPacked.BindingImage",
                    seed: sealSeed,
                    count: 32
                ),
                relationImageSeed: NuParameterExpander.expandBytes(
                    domain: "NuMeQ.Params.Seal.Hachi.DirectPacked.RelationImage",
                    seed: sealSeed,
                    count: 32
                ),
                evaluationImageSeed: NuParameterExpander.expandBytes(
                    domain: "NuMeQ.Params.Seal.Hachi.DirectPacked.EvaluationImage",
                    seed: sealSeed,
                    count: 32
                ),
                outerImageSeed: NuParameterExpander.expandBytes(
                    domain: "NuMeQ.Params.Seal.Hachi.DirectPacked.OuterImage",
                    seed: sealSeed,
                    count: 32
                ),
                decompositionBase: 2,
                decompositionLimbs: 64,
                foldArity: 2,
                challengeDistributionID: "centeredTernary",
                roundMaskSigma: 4096,
                finalMaskSigma: 8192,
                rejectionSlack: 12,
                maxAcceptedResponseBound: 1 << 16,
                maxRestartCount: 128,
                residualBlocksPerChunk: 2,
                accumulatorDomain: Data("NuMeQ.Decider.Hachi.DirectPacked.Accumulator".utf8),
                rejectionDomain: Data("NuMeQ.Decider.Hachi.DirectPacked.Rejection".utf8),
                securityProfileDigest: profile.profileID.bytes
            )
        )

        let params = NuParams(profile: profile, fold: fold, seal: seal)
        cacheLock.lock()
        cache[cacheKey] = params
        cacheLock.unlock()
        return params
    }

    public func verify() -> Bool {
        let expected = Self.derive(from: profile)
        return fold == expected.fold && seal == expected.seal
    }

    private static func expandCommitmentKey(
        seed: [UInt8],
        rank: Int,
        slotCount: Int
    ) -> AjtaiKey {
        AjtaiKey.expand(
            seed: seed,
            slotCount: rank * RingElement.degree
        )
    }

    private static func deriveStageConstants(seed: [UInt8], domain: String) -> StageConstants {
        let roundConstants = NuParameterExpander.expandFieldElements(
            domain: domain,
            seed: seed,
            label: "round_constants",
            count: 16
        )
        let domainSeparators = NuParameterExpander.expandFieldElements(
            domain: domain,
            seed: seed,
            label: "domain_separators",
            count: 4
        )

        return StageConstants(
            roundConstants: roundConstants,
            domainSeparators: domainSeparators
        )
    }
}

public struct FoldParameterBundle: Sendable, Equatable {
    public let seed: [UInt8]
    public let commitmentKey: AjtaiKey
    public let piRLCConstants: StageConstants
    public let piCCSConstants: StageConstants
    public let piDECConstants: StageConstants
    public let liftedCCSConstants: [UInt8]
    public let transcriptID: String

    public var parameterDigest: [UInt8] {
        let writer = canonicalWriter()
        return Array(NuSecurityDigest.sha256(writer.data))
    }

    private func canonicalWriter() -> BinaryWriter {
        var writer = BinaryWriter()
        writer.appendLengthPrefixed(seed)
        writer.appendLengthPrefixed(Data(transcriptID.utf8))
        encode(commitmentKey, into: &writer)
        encode(piRLCConstants, into: &writer)
        encode(piCCSConstants, into: &writer)
        encode(piDECConstants, into: &writer)
        writer.appendLengthPrefixed(liftedCCSConstants)
        return writer
    }

    public static func == (lhs: FoldParameterBundle, rhs: FoldParameterBundle) -> Bool {
        lhs.parameterDigest == rhs.parameterDigest
            && lhs.seed == rhs.seed
            && lhs.transcriptID == rhs.transcriptID
    }
}

public struct HachiSealParameterBundle: Sendable, Equatable {
    public let seed: [UInt8]
    public let backendID: String
    public let transcriptID: String
    public let commitmentParameters: [UInt8]
    public let batchingConstants: [UInt8]
    public let verifierConstants: [UInt8]
    public let directPackedPoK: DirectPackedPoKParameters

    public var parameterDigest: [UInt8] {
        let writer = canonicalWriter()
        return Array(NuSecurityDigest.sha256(writer.data))
    }

    private func canonicalWriter() -> BinaryWriter {
        var writer = BinaryWriter()
        writer.appendLengthPrefixed(seed)
        writer.appendLengthPrefixed(Data(backendID.utf8))
        writer.appendLengthPrefixed(Data(transcriptID.utf8))
        writer.appendLengthPrefixed(commitmentParameters)
        writer.appendLengthPrefixed(batchingConstants)
        writer.appendLengthPrefixed(verifierConstants)
        encodeDirectPackedPoK(directPackedPoK, into: &writer)
        return writer
    }

    public static func == (lhs: HachiSealParameterBundle, rhs: HachiSealParameterBundle) -> Bool {
        lhs.parameterDigest == rhs.parameterDigest
            && lhs.seed == rhs.seed
            && lhs.backendID == rhs.backendID
            && lhs.transcriptID == rhs.transcriptID
    }
}

public struct DirectPackedPoKParameters: Sendable, Equatable, Codable {
    public let witnessBindingSeed: [UInt8]
    public let relationSeed: [UInt8]
    public let outerSeed: [UInt8]
    public let bindingImageSeed: [UInt8]
    public let relationImageSeed: [UInt8]
    public let evaluationImageSeed: [UInt8]
    public let outerImageSeed: [UInt8]
    public let decompositionBase: UInt8
    public let decompositionLimbs: UInt8
    public let foldArity: UInt8
    public let challengeDistributionID: String
    public let roundMaskSigma: UInt32
    public let finalMaskSigma: UInt32
    public let rejectionSlack: UInt32
    public let maxAcceptedResponseBound: UInt64
    public let maxRestartCount: UInt16
    public let residualBlocksPerChunk: UInt8
    public let accumulatorDomain: Data
    public let rejectionDomain: Data
    public let securityProfileDigest: [UInt8]

    public var parameterDigest: [UInt8] {
        var writer = BinaryWriter()
        encodeDirectPackedPoK(self, into: &writer)
        return Array(NuSecurityDigest.sha256(writer.data))
    }
}

public struct StageConstants: Sendable, Equatable {
    public let roundConstants: [Fq]
    public let domainSeparators: [Fq]
}

private func encode(_ key: AjtaiKey, into writer: inout BinaryWriter) {
    writer.append(UInt32(clamping: key.keys.count))
    for ring in key.keys {
        writer.append(Data(ring.toBytes()))
    }
}

private func encode(_ constants: StageConstants, into writer: inout BinaryWriter) {
    writer.append(UInt32(clamping: constants.roundConstants.count))
    for value in constants.roundConstants {
        writer.append(Data(value.toBytes()))
    }
    writer.append(UInt32(clamping: constants.domainSeparators.count))
    for value in constants.domainSeparators {
        writer.append(Data(value.toBytes()))
    }
}

private func encodeDirectPackedPoK(_ parameters: DirectPackedPoKParameters, into writer: inout BinaryWriter) {
    writer.appendLengthPrefixed(parameters.witnessBindingSeed)
    writer.appendLengthPrefixed(parameters.relationSeed)
    writer.appendLengthPrefixed(parameters.outerSeed)
    writer.appendLengthPrefixed(parameters.bindingImageSeed)
    writer.appendLengthPrefixed(parameters.relationImageSeed)
    writer.appendLengthPrefixed(parameters.evaluationImageSeed)
    writer.appendLengthPrefixed(parameters.outerImageSeed)
    writer.append(parameters.decompositionBase)
    writer.append(parameters.decompositionLimbs)
    writer.append(parameters.foldArity)
    writer.appendLengthPrefixed(Data(parameters.challengeDistributionID.utf8))
    writer.append(parameters.roundMaskSigma)
    writer.append(parameters.finalMaskSigma)
    writer.append(parameters.rejectionSlack)
    writer.append(parameters.maxAcceptedResponseBound)
    writer.append(parameters.maxRestartCount)
    writer.append(parameters.residualBlocksPerChunk)
    writer.appendLengthPrefixed(parameters.accumulatorDomain)
    writer.appendLengthPrefixed(parameters.rejectionDomain)
    writer.appendLengthPrefixed(parameters.securityProfileDigest)
}
